import os
import json
import hashlib
import base58
import base64
import time
import string
import random
import logging
from typing import Optional, Dict

from Crypto.Hash import RIPEMD
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from bhrc_blockchain.utils.utils import generate_address

logger = logging.getLogger("Wallet")
logger.setLevel(logging.INFO)

ADDRESS_PREFIX = "xBHR"
ADDRESS_LENGTH = 64
AES_SALT = b"bhrc_salt_2024"


class MinerWallet:
    def __init__(
        self,
        wallet_path: Optional[str] = None,
        private_key: Optional[str] = None,
        force_new: bool = False,
        persist: bool = True,
        password: Optional[str] = None
    ) -> None:
        self.wallet_path = wallet_path
        self.persist = persist
        self.password = password

        if private_key:
            self.private_key = private_key
            self.public_key = self.generate_public_key(private_key)
            self.address = self.generate_address(self.public_key)
        elif wallet_path and not force_new and os.path.exists(wallet_path):
            self.load_from_file()
        else:
            self.private_key = self.generate_private_key()
            self.public_key = self.generate_public_key(self.private_key)
            self.address = self.generate_address(self.public_key)
            if persist and wallet_path:
                self.save_to_file()

    def generate_private_key(self) -> str:
        return SigningKey.generate(curve=SECP256k1).to_string().hex()

    def generate_public_key(self, private_key: str) -> str:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        return sk.verifying_key.to_string().hex()

    def generate_address(self, public_key: str, prefix: str = ADDRESS_PREFIX) -> str:
        pubkey_bytes = bytes.fromhex(public_key)
        sha256 = hashlib.sha256(pubkey_bytes).digest()
        ripemd160 = RIPEMD.new(sha256).digest()
        address_hex = ripemd160.hex().ljust(60, '0')
        return prefix + address_hex

    def encrypt_data(self, data_str: str) -> Dict[str, str]:
        if not self.password:
            raise ValueError("Şifreleme için parola belirtilmeli.")
        key = PBKDF2(self.password, AES_SALT, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data_str.encode())
        return {
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    def decrypt_data(self, enc_data: Dict[str, str]) -> str:
        if not self.password:
            raise ValueError("Deşifre için parola belirtilmeli.")
        key = PBKDF2(self.password, AES_SALT, dkLen=32, count=100_000)
        nonce = base64.b64decode(enc_data["nonce"])
        tag = base64.b64decode(enc_data["tag"])
        ciphertext = base64.b64decode(enc_data["ciphertext"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

    def save_to_file(self) -> None:
        data = {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address
        }
        enc_data = self.encrypt_data(json.dumps(data))
        with open(self.wallet_path, 'w') as file:
            json.dump(enc_data, file, indent=4)
        logger.info(f"🔐 Cüzdan şifrelenmiş olarak kaydedildi: {self.wallet_path}")

    def load_from_file(self) -> None:
        if not self.wallet_path or not os.path.exists(self.wallet_path):
            raise FileNotFoundError("Belirtilen cüzdan dosyası mevcut değil.")
        with open(self.wallet_path, 'r') as file:
            enc_data = json.load(file)
            raw_data = self.decrypt_data(enc_data)
            data = json.loads(raw_data)
            self.private_key = data.get("private_key")
            self.public_key = data.get("public_key")
            self.address = self.generate_address(self.public_key)
        logger.info(f"🔓 Cüzdan başarıyla yüklendi: {self.wallet_path}")


def generate_wallet(
    wallet_path: Optional[str] = None,
    force_new: bool = False,
    password: Optional[str] = None
) -> Dict[str, str]:
    if force_new or wallet_path is None:
        wallet_path = f"wallets/wallet_{int(time.time())}.json"

    if not password:
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

    wallet = MinerWallet(wallet_path=wallet_path, force_new=force_new, password=password)
    logger.info(f"🪙 Yeni cüzdan oluşturuldu: {wallet.address}")
    return {
        "private_key": wallet.private_key,
        "public_key": wallet.public_key,
        "address": wallet.address,
        "initial_password": password
    }


def get_address_from_private_key(private_key: str, prefix: str = ADDRESS_PREFIX) -> str:
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    vk = sk.verifying_key
    pubkey_bytes = vk.to_string()
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = RIPEMD.new(sha256).digest()
    return prefix + base58.b58encode(ripemd160).decode()


def get_public_key_from_private_key(private_key: str) -> str:
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    return sk.verifying_key.to_string().hex()


def sign_message(private_key: str, message: str) -> str:
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    signature = sk.sign(message.encode())
    return base64.b64encode(signature).decode()


def verify_signature(public_key: str, message: str, signature: str) -> bool:
    vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
    try:
        return vk.verify(base64.b64decode(signature), message.encode())
    except Exception:
        return False


def generate_private_key() -> str:
    return SigningKey.generate(curve=SECP256k1).to_string().hex()


def verify_address_from_key(private_key: str, expected_address: str) -> bool:
    return get_address_from_private_key(private_key) == expected_address


if __name__ == "__main__":
    wallet = generate_wallet()
    print(json.dumps(wallet, indent=4))

