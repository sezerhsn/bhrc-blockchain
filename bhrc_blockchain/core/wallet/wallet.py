import os
import json
import hashlib
import base64
import time
import logging
from typing import Optional, Dict
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from Crypto.Hash import RIPEMD160, SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

logger = logging.getLogger("Wallet")
logger.setLevel(logging.INFO)

ADDRESS_PREFIX = "xBHR"
ADDRESS_LENGTH = 64
AES_SALT = b"bhrc_salt_2024"
MAX_PASSWORD_ATTEMPTS = 5
PASSWORD_ATTEMPT_WINDOW = 60  # saniye

def generate_address(public_key_hex: str) -> str:
    public_key_bytes = bytes.fromhex(public_key_hex)
    sha256_hash = SHA256.new(public_key_bytes).digest()
    ripemd160 = RIPEMD160.new(sha256_hash).digest()
    address_hex = ripemd160.hex().ljust(60, '0')[:60]
    return ADDRESS_PREFIX + address_hex

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
        self.failed_attempts = 0
        self.last_attempt_time = 0

        if private_key:
            self.private_key = private_key
            self.public_key = self.generate_public_key(private_key)
            self.address = generate_address(self.public_key)
        elif wallet_path and not force_new and os.path.exists(wallet_path):
            self.load_from_file()
        else:
            self.private_key = self.generate_private_key()
            self.public_key = self.generate_public_key(self.private_key)
            self.address = generate_address(self.public_key)
            if persist and wallet_path:
                self.save_to_file()

    def generate_private_key(self) -> str:
        return SigningKey.generate(curve=SECP256k1).to_string().hex()

    def generate_public_key(self, private_key: str) -> str:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        return sk.verifying_key.to_string().hex()

    def encrypt_data(self, data_str: str) -> Dict[str, str]:
        if not self.password:
            raise ValueError("Şifreleme için parola belirtilmeli.")
        key = PBKDF2(self.password, AES_SALT, dkLen=32, count=300_000)
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

        now = time.time()
        if now - self.last_attempt_time < PASSWORD_ATTEMPT_WINDOW and self.failed_attempts >= MAX_PASSWORD_ATTEMPTS:
            raise ValueError("🔒 Çok fazla başarısız parola denemesi. Lütfen sonra tekrar deneyin.")

        key = PBKDF2(self.password, AES_SALT, dkLen=32, count=300_000)
        nonce = base64.b64decode(enc_data["nonce"])
        tag = base64.b64decode(enc_data["tag"])
        ciphertext = base64.b64decode(enc_data["ciphertext"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag).decode()
            self.failed_attempts = 0
            return decrypted
        except Exception:
            self.failed_attempts += 1
            self.last_attempt_time = now
            raise ValueError("Parola yanlış veya cüzdan dosyası bozulmuş olabilir.")

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

    def load_from_file(self):
        if not os.path.exists(self.wallet_path):
            raise FileNotFoundError("Cüzdan dosyası bulunamadı.")

        with open(self.wallet_path, "r") as f:
            encrypted_data = json.load(f)

        if not self.password:
            raise ValueError("Şifre gerekli")

        decrypted = self.decrypt_data(encrypted_data)
        data = json.loads(decrypted)

        self.private_key = data["private_key"]
        self.public_key = data["public_key"]
        self.address = generate_address(self.public_key)

def generate_mnemonic() -> str:
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)

def get_wallet_from_mnemonic(mnemonic_phrase: str, password: str = "") -> Dict[str, str]:
    seed_bytes = Bip39SeedGenerator(mnemonic_phrase).Generate(password)
    bip44_wallet = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    account = bip44_wallet.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

    private_key = account.PrivateKey().Raw().ToHex()
    public_key = account.PublicKey().RawCompressed().ToHex()
    address = generate_address(public_key)

    return {
        "mnemonic": mnemonic_phrase,
        "private_key": private_key,
        "public_key": public_key,
        "address": address
    }

def get_address_from_private_key(private_key: str) -> str:
    private_key = private_key.strip().lower()
    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    except ValueError as e:
        raise ValueError(f"Geçersiz hex private key (adres üretimi): {private_key[:12]}... ({str(e)})")
    public_key = sk.verifying_key.to_string().hex()
    return generate_address(public_key)

def sign_message(private_key: str, message: str) -> str:
    # Güvenli hex dönüşümü
    private_key = private_key.strip().lower()
    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    except ValueError as e:
        raise ValueError(f"Geçersiz hex private key: {private_key[:12]}... ({str(e)})")

    signature = sk.sign(message.encode())
    return base64.b64encode(signature).decode()

def verify_signature(public_key: str, message: str, signature: str) -> bool:
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
        sig_bytes = base64.b64decode(signature)
        return vk.verify(sig_bytes, message.encode())
    except Exception:
        return False

def get_public_key_from_private_key(private_key: str) -> str:
    private_key = private_key.strip().lower()
    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    except ValueError as e:
        raise ValueError(f"Geçersiz hex private key (public key türetimi): {private_key[:12]}... ({str(e)})")
    return sk.verifying_key.to_string().hex()

def generate_wallet(wallet_path: Optional[str] = None, password: Optional[str] = None, force_new: bool = False) -> Dict[str, str]:
    wallet = MinerWallet(wallet_path=wallet_path, password=password, force_new=force_new)
    return {
        "private_key": wallet.private_key,
        "public_key": wallet.public_key,
        "address": wallet.address
    }

def verify_address_from_key(private_key: str, address: str) -> bool:
    derived = get_address_from_private_key(private_key)
    return derived == address

def generate_private_key() -> str:
    return SigningKey.generate(curve=SECP256k1).to_string().hex()

__all__ = [
    "MinerWallet",
    "get_address_from_private_key",
    "sign_message",
    "verify_signature",
    "generate_mnemonic",
    "get_wallet_from_mnemonic",
    "get_public_key_from_private_key",
    "generate_wallet",
    "verify_address_from_key",
    "generate_private_key"
]

def load_wallet(path: str = "wallets/test_wallet.json") -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Cüzdan dosyası bulunamadı: {path}")
    with open(path, "r") as f:
        return json.load(f)

def sign_block(block, private_key_hex: str) -> str:
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    message = block.calculate_hash()
    signature = sk.sign(message.encode())
    return base64.b64encode(signature).decode()

def verify_block_signature(block, signature_b64: str, public_key_hex: str) -> bool:
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        message = block.calculate_hash().encode()
        signature = base64.b64decode(signature_b64)
        return vk.verify(signature, message)
    except BadSignatureError:
        return False

def get_address_from_public_key(public_key: bytes) -> str:
    public_key_hash = hashlib.sha256(public_key.encode()).digest()
    address = "xBHR" + public_key_hash.hex()[:60]
    return address

