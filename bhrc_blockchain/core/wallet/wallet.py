import os
import json
import hashlib
import base64
import time
import logging
import base58
from typing import Optional, Dict
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from Crypto.Hash import RIPEMD160, SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from bhrc_blockchain.config.config import settings

logger = logging.getLogger("Wallet")
logger.setLevel(logging.INFO)

ADDRESS_PREFIX = "xBHR"
ADDRESS_LENGTH = 64

FOUNDATION_WALLET_PATH = settings.FOUNDATION_WALLET_PATH

def base58check_encode(data: bytes) -> str:
    checksum = SHA256.new(SHA256.new(data).digest()).digest()[:4]
    return base58.b58encode(data + checksum).decode()

def generate_address(public_key_hex: str) -> str:
    public_key_bytes = bytes.fromhex(public_key_hex)
    sha256_hash = SHA256.new(public_key_bytes).digest()
    ripemd160 = RIPEMD160.new(sha256_hash).digest()

    hash1 = base58check_encode(ripemd160)
    hash2 = base58check_encode(sha256_hash)
    combined = (hash1 + hash2)[:60]

    return ADDRESS_PREFIX + combined

class MinerWallet:
    def __init__(
        self,
        wallet_path: Optional[str] = None,
        private_key: Optional[str] = None,
        force_new: bool = False,
        persist: bool = True,
        password: Optional[str] = None,
        mnemonic: Optional[str] = None,
    ) -> None:
        self.wallet_path = wallet_path
        self.persist = persist
        self.password = password
        self.failed_attempts = 0
        self.last_attempt_time = 0
        self.mnemonic = mnemonic

        if private_key:
            self.private_key = private_key
            self.public_key = self.generate_public_key(private_key)
            self.address = generate_address(self.public_key)
        elif wallet_path and not force_new and os.path.exists(wallet_path):
            try:
                self.load_from_file()
            except Exception as e:
                logger.error(f"🧨 Cüzdan dosyası yüklenemedi: {e}")
                raise ValueError("Cüzdan dosyası yüklenemedi veya şifre hatalı.")

        else:
            self.private_key = self.generate_private_key()
            self.public_key = self.generate_public_key(self.private_key)
            self.address = generate_address(self.public_key)
            if persist and wallet_path:
                self.save_to_file()

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address,
            "mnemonic": self.mnemonic
        }

    def generate_private_key(self) -> str:
        return SigningKey.generate(curve=SECP256k1).to_string().hex()

    def generate_public_key(self, private_key: str) -> str:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        return sk.verifying_key.to_string().hex()

    def encrypt_data(self, data_str: str) -> Dict[str, str]:
        if not self.password:
            raise ValueError("Şifreleme için parola belirtilmeli.")
        try:
            iterations = getattr(settings, "PBKDF2_ITERATIONS", 300_000)
            key_length = getattr(settings, "AES_KEY_LENGTH", 32)
            salt = getattr(settings, "AES_SALT", b"default_salt")
            aad = getattr(settings, "AES_ASSOCIATED_DATA", b"wallet_encryption_v1")

            key = PBKDF2(self.password, salt, dkLen=key_length, count=iterations)
        except (MemoryError, OverflowError, ValueError) as e:
            raise RuntimeError("Anahtar türetme sırasında sistem hatası oluştu.") from e

        nonce = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(data_str.encode())

        return {
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    def decrypt_data(self, enc_data: Dict[str, str]) -> str:
        if not self.password:
            raise ValueError("Deşifre için parola belirtilmeli.")

        now = time.time()
        if now - self.last_attempt_time < settings.PASSWORD_ATTEMPT_WINDOW and self.failed_attempts >= settings.MAX_PASSWORD_ATTEMPTS:
            remaining = max(0, int(settings.PASSWORD_ATTEMPT_WINDOW - (now - self.last_attempt_time)))
            raise ValueError(f"🔒 Çok fazla başarısız parola denemesi. Lütfen {remaining} saniye sonra tekrar deneyin.")

        try:
            iterations = getattr(settings, "PBKDF2_ITERATIONS", 300_000)
            key_length = getattr(settings, "AES_KEY_LENGTH", 32)
            salt = getattr(settings, "AES_SALT", b"default_salt")
            aad = getattr(settings, "AES_ASSOCIATED_DATA", b"wallet_encryption_v1")

            key = PBKDF2(self.password, salt, dkLen=key_length, count=iterations)
            nonce = base64.b64decode(enc_data["nonce"])
            tag = base64.b64decode(enc_data["tag"])
            ciphertext = base64.b64decode(enc_data["ciphertext"])

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag).decode()

            self.failed_attempts = 0
            return decrypted
        except (KeyError, ValueError, TypeError, base64.binascii.Error) as e:
            self.failed_attempts += 1
            self.last_attempt_time = now
            logger.warning("⚠️ Hatalı parola veya bozuk veri: %s (%d/%d)", self.wallet_path, self.failed_attempts, settings.MAX_PASSWORD_ATTEMPTS)
            raise ValueError("Parola yanlış, veri bozuk veya cüzdan formatı hatalı.") from e

    def save_to_file(self) -> None:
        data = {
            "mnemonic": self.mnemonic,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address,
        }
        enc_data = self.encrypt_data(json.dumps(data))
        os.makedirs(os.path.dirname(self.wallet_path), exist_ok=True)
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
        self.mnemonic = data.get("mnemonic")

    def reload(self) -> None:
        """Şifreli cüzdan dosyasını yeniden yükler."""
        if not self.wallet_path:
            raise ValueError("Yükleme işlemi için wallet_path tanımlı olmalı.")
        self.load_from_file()
        logger.info(f"♻️ Cüzdan dosyası yeniden yüklendi: {self.wallet_path}")

    def is_locked(self) -> bool:
        return not bool(self.password)

    def lock(self) -> None:
        """Cüzdanı kilitler (parolayı unutur)."""
        self.password = None

    def unlock(self, password: str) -> None:
        """Cüzdanı verilen parola ile açar."""
        self.password = password
        self.reload()

    def summary(self) -> Dict[str, str]:
        """Cüzdanın temel özetini döndürür."""
        return {
            "address": self.address,
            "public_key_short": self.public_key[:16] + "..." if self.public_key else "Yok",
            "is_locked": str(self.is_locked()),
            "wallet_path": self.wallet_path or "Yok",
            "has_mnemonic": str(bool(self.mnemonic))
        }

    def rename_wallet_file(self, new_path: str) -> None:
        """Cüzdan dosyasını yeni bir yola taşır ve iç referansı günceller."""
        if not self.wallet_path or not os.path.exists(self.wallet_path):
            raise FileNotFoundError("Cüzdan dosyası mevcut değil.")
        os.makedirs(os.path.dirname(new_path), exist_ok=True)
        os.rename(self.wallet_path, new_path)
        self.wallet_path = new_path
        logger.info(f"🗃️ Cüzdan dosyası yeniden adlandırıldı: {new_path}")

def is_valid_mnemonic(mnemonic: str) -> bool:
    """Verilen mnemonic geçerli mi kontrol eder."""
    mnemo = Mnemonic("english")
    return mnemo.check(mnemonic)

def generate_mnemonic() -> str:
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)

def get_wallet_from_mnemonic(mnemonic_phrase: str, password: str = "") -> Dict[str, str]:
    seed_bytes = Bip39SeedGenerator(mnemonic_phrase).Generate(password)
    bip44_wallet = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    account = bip44_wallet.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

    private_key = account.PrivateKey().Raw().ToHex()
    public_key = account.PublicKey().RawUncompressed().ToHex()[2:]
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

def generate_wallet(wallet_path: Optional[str] = None, password: Optional[str] = None, force_new: bool = False, mnemonic: Optional[str] = None) -> Dict[str, str]:
    if mnemonic:
        wallet_data = get_wallet_from_mnemonic(mnemonic, password or "")
        wallet = MinerWallet(
            private_key=wallet_data["private_key"],
            password=password,
            wallet_path=wallet_path,
            mnemonic=mnemonic,
            persist=True
        )
        if wallet_path:
            wallet.save_to_file()
    else:
        wallet = MinerWallet(wallet_path=wallet_path, password=password, force_new=force_new)
        if wallet_path:
            wallet.save_to_file()

    return {
        "private_key": wallet.private_key,
        "public_key": wallet.public_key,
        "address": wallet.address,
        "mnemonic": wallet.mnemonic
    }

def get_foundation_wallet(password: str = None) -> MinerWallet:
    path = settings.FOUNDATION_WALLET_PATH
    final_password = password or settings.FOUNDATION_WALLET_PASSWORD
    if os.path.exists(path):
        return MinerWallet(wallet_path=path, password=final_password, persist=False)
    else:
        return MinerWallet(wallet_path=path, password=final_password, persist=True)

def get_foundation_address() -> str:
    return get_foundation_wallet().address

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
    "generate_private_key",
    "is_valid_mnemonic",
    "generate_child_wallet",
    "verify_wallet_integrity",
    "from_hardware_wallet",
]

def load_wallet(path: str, password: Optional[str] = None) -> MinerWallet:
    """
    Şifreli cüzdan dosyasını yükler ve MinerWallet nesnesi döndürür.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Cüzdan dosyası bulunamadı: {path}")
    return MinerWallet(wallet_path=path, password=password, persist=False)

def sign_block(block, private_key_hex: str) -> str:
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    message = block.calculate_hash()
    signature = sk.sign(message.encode())
    return base64.b64encode(signature).decode()

def verify_block_signature(block, signature_b64: str, public_key_hex: str) -> bool:
    try:
        print("🔎 verify_block_signature > public_key_hex:", repr(public_key_hex))
        vk = VerifyingKey.from_string(b'\x04' + bytes.fromhex(public_key_hex), curve=SECP256k1)
        message = block.calculate_hash().encode()
        signature = base64.b64decode(signature_b64)
        return vk.verify(signature, message)
    except BadSignatureError:
        return False

def get_address_from_public_key(public_key: str) -> str:
    return generate_address(public_key)

def export_wallet(path, password, include_mnemonic=False, only_address=False):
    wallet = MinerWallet(wallet_path=path, password=password)

    if only_address:
        return {"address": wallet.address}

    data = wallet.to_dict()
    if not include_mnemonic:
        data["mnemonic"] = None
    return data

def import_wallet_from_mnemonic(mnemonic: str, password: str, path: Optional[str]) -> Dict[str, str]:
    wallet_data = get_wallet_from_mnemonic(mnemonic)
    return generate_wallet(wallet_path=path, password=password, mnemonic=mnemonic)

def import_wallet_from_private_key(private_key: str, password: str = "", path: str = "m/44'/0'/0'/0/0") -> Dict[str, str]:
    wallet = MinerWallet(private_key=private_key, password=password, wallet_path=path, persist=True)
    return {
        "private_key": wallet.private_key,
        "public_key": wallet.public_key,
        "address": wallet.address
    }

def is_valid_address(address: str) -> bool:
    if not address.startswith(ADDRESS_PREFIX):
        return False
    encoded_part = address[len(ADDRESS_PREFIX):]
    try:
        decoded = base58.b58decode(encoded_part)
        return len(decoded) >= 24
    except Exception:
        return False

def generate_child_wallet(mnemonic: str, index: int = 0, password: str = "") -> Dict[str, str]:
    """
    Belirli bir index üzerinden alt cüzdan üretir. BIP44 uyumludur.
    """
    if not is_valid_mnemonic(mnemonic):
        raise ValueError("Geçersiz mnemonic.")

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(password)
    bip44_wallet = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    account = bip44_wallet.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)

    private_key = account.PrivateKey().Raw().ToHex()
    public_key = account.PublicKey().RawUncompressed().ToHex()[2:]
    address = generate_address(public_key)

    return {
        "mnemonic": mnemonic,
        "private_key": private_key,
        "public_key": public_key,
        "address": address,
        "index": index
    }

def verify_wallet_integrity(wallet_data: Dict[str, str], password: str = "") -> bool:
    """
    Cüzdan verisinin bütünlüğünü doğrular:
    - private key → public key
    - public key → address
    - (varsa) mnemonic → aynı private key üretimi
    """
    try:
        priv = wallet_data["private_key"]
        pub_expected = wallet_data["public_key"]
        addr_expected = wallet_data["address"]
        mnemonic = wallet_data.get("mnemonic")

        pub_actual = get_public_key_from_private_key(priv)
        if pub_actual != pub_expected:
            return False

        addr_actual = generate_address(pub_actual)
        if addr_actual != addr_expected:
            return False

        if mnemonic:
            regenerated = get_wallet_from_mnemonic(mnemonic, password=password)
            if regenerated["private_key"] != priv:
                return False

        return True
    except Exception:
        return False

def from_hardware_wallet(device_id: str = "MOCK1234", index: int = 0) -> Dict[str, str]:
    """
    Donanım cüzdan simülasyonu üzerinden cüzdan üretir.
    Gerçek sistemde USB cihazı gibi davranır, burada sadece deterministik üretim yapılır.
    """
    mock_mnemonic = "kiss craft slush human fatigue clown train trust sport about bridge news"
    return generate_child_wallet(mock_mnemonic, index=index)

