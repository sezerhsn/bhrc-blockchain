import os
import json
import base64
import pytest
import tempfile
import shutil
import logging
import base58
from unittest.mock import patch, mock_open
from bhrc_blockchain.config.config import settings
from bhrc_blockchain.core.wallet.wallet import (
    MinerWallet,
    generate_wallet,
    generate_private_key,
    get_address_from_private_key,
    get_public_key_from_private_key,
    get_address_from_public_key,
    sign_message,
    verify_signature,
    verify_address_from_key,
    generate_address,
    verify_block_signature,
    export_wallet,
    generate_mnemonic,
    load_wallet,
    get_wallet_from_mnemonic,
    get_foundation_wallet,
    is_valid_mnemonic,
    generate_child_wallet,
    verify_wallet_integrity,
)

def test_address_generation():
    wallet = MinerWallet(password="test123", persist=False)
    assert wallet.address.startswith("xBHR")
    assert len(wallet.address) == 64

def test_signature_verification():
    wallet = MinerWallet(password="test123", persist=False)
    message = "deneme"
    sig = sign_message(wallet.private_key, message)
    assert verify_signature(wallet.public_key, message, sig) is True

@patch("builtins.open", new_callable=mock_open)
@patch("os.path.exists", return_value=True)
@patch("Crypto.Cipher.AES.new")
@patch("Crypto.Random.get_random_bytes", return_value=b"0" * 16)
def test_wallet_encryption_decryption(mock_nonce, mock_aes, mock_exists, mock_file):
    class FakeCipher:
        def __init__(self, key, mode, nonce):
            self.nonce = nonce
        def encrypt_and_digest(self, data):
            return b"ciphertext", b"tag"
        def decrypt_and_verify(self, ciphertext, tag):
            return json.dumps({
                "private_key": wallet.private_key,
                "public_key": wallet.public_key,
                "address": wallet.address
            }).encode()

def test_encrypt_data_without_password():
    wallet = MinerWallet(private_key=generate_private_key(), persist=False)
    with pytest.raises(ValueError):
        wallet.encrypt_data("test_secret")

def test_decrypt_data_without_password():
    wallet = MinerWallet(private_key=generate_private_key(), persist=False)
    with pytest.raises(ValueError):
        wallet.decrypt_data({
            "ciphertext": "x", "nonce": "x", "tag": "x"
        })

def test_load_from_nonexistent_file(tmp_path):
    fake_path = tmp_path / "not_exist.json"
    wallet = MinerWallet(wallet_path=str(fake_path), password="pw", persist=False)
    with pytest.raises(FileNotFoundError):
        wallet.load_from_file()

@patch("builtins.open", new_callable=mock_open)
@patch("json.dump", lambda *a, **kw: None)
def test_generate_wallet_creates_new_file(mock_file):
    result = generate_wallet(wallet_path="wallets/w1.json", password="pw", force_new=True)
    assert "address" in result
    assert "private_key" in result
    assert result["address"].startswith("xBHR")

def test_verify_signature_invalid_signature():
    private_key = generate_private_key()
    public_key = get_public_key_from_private_key(private_key)
    fake_sig = base64.b64encode(b"invalidsig").decode()
    assert not verify_signature(public_key, "bhrc", fake_sig)

@patch("builtins.open", new_callable=mock_open)
@patch("json.dump", lambda *a, **kw: None)
def test_generate_wallet_force_new_true_creates_default_path(mock_file):
    result = generate_wallet(wallet_path=None, password="pw", force_new=True)
    assert result["address"].startswith("xBHR")
    assert isinstance(result["private_key"], str)

def test_get_public_key_from_private_key():
    private_key = generate_private_key()
    public_key = get_public_key_from_private_key(private_key)
    assert isinstance(public_key, str)
    assert len(public_key) > 60

def test_get_address_from_private_key():
    private_key = generate_private_key()
    address = get_address_from_private_key(private_key)
    assert address.startswith("xBHR")
    assert len(address) == 64

def test_verify_address_from_key_validates_correctly():
    priv_key = generate_private_key()
    expected_addr = get_address_from_private_key(priv_key)
    assert verify_address_from_key(priv_key, expected_addr)

def test_get_wallet_from_mnemonic():
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, get_wallet_from_mnemonic

    mnemonic = generate_mnemonic()
    wallet_data = get_wallet_from_mnemonic(mnemonic)

    assert wallet_data["address"].startswith("xBHR")
    assert len(wallet_data["private_key"]) > 60
    assert len(wallet_data["public_key"]) > 60

@patch("builtins.open", new_callable=mock_open)
@patch("os.path.exists", return_value=True)
def test_load_wallet_success(mock_exists, mock_file):
    from bhrc_blockchain.core.wallet.wallet import load_wallet

    wallet = MinerWallet(password="test123", persist=False)
    encrypted = wallet.encrypt_data(json.dumps({
        "private_key": wallet.private_key,
        "public_key": wallet.public_key,
        "address": wallet.address
    }))

    mock_file().read.return_value = json.dumps(encrypted)

    result = load_wallet("wallets/test_wallet.json", password="test123")
    assert isinstance(result, MinerWallet)
    assert result.address == wallet.address

def test_verify_address_from_key_with_wrong_address():
    private_key = generate_private_key()
    wrong_address = "xBHR" + "F" * 60
    assert not verify_address_from_key(private_key, wrong_address)

def test_password_attempt_limit():
    wallet = MinerWallet(password="secure123", persist=False)
    encrypted = wallet.encrypt_data("test")

    wallet.password = "wrongpass"
    for _ in range(settings.MAX_PASSWORD_ATTEMPTS):
        with pytest.raises(ValueError):
            wallet.decrypt_data(encrypted)

    with pytest.raises(ValueError, match="başarısız parola denemesi"):
        wallet.decrypt_data(encrypted)

def test_get_address_from_public_key():
    private_key = generate_private_key()
    public_key = get_public_key_from_private_key(private_key)
    addr_1 = get_address_from_public_key(public_key)
    addr_2 = get_address_from_private_key(private_key)

    assert addr_1 == addr_2
    assert addr_1.startswith("xBHR")
    assert len(addr_1) == 64

def test_reload_wallet_from_disk():
    temp_dir = tempfile.mkdtemp()
    wallet_path = os.path.join(temp_dir, "test_wallet.json")

    wallet_1 = MinerWallet(wallet_path=wallet_path, password="secret", persist=True)
    original_address = wallet_1.address

    wallet_2 = MinerWallet(wallet_path=wallet_path, password="secret", persist=False)
    wallet_2.address = "xBHR" + "X" * 60

    assert wallet_2.address != original_address

    wallet_2.reload()

    assert wallet_2.address == original_address

    shutil.rmtree(temp_dir)

def test_load_wallet_returns_minerwallet_instance():
    import tempfile
    import shutil
    from bhrc_blockchain.core.wallet.wallet import load_wallet

    temp_dir = tempfile.mkdtemp()
    wallet_path = os.path.join(temp_dir, "test_wallet.json")

    wallet = MinerWallet(wallet_path=wallet_path, password="pw123", persist=True)
    original_address = wallet.address

    loaded_wallet = load_wallet(path=wallet_path, password="pw123")

    assert isinstance(loaded_wallet, MinerWallet)
    assert loaded_wallet.address == original_address

    shutil.rmtree(temp_dir)

def test_decrypt_data_rate_limit_triggered():
    wallet = MinerWallet(password="correctpw", persist=False)
    encrypted = wallet.encrypt_data("top_secret")

    wallet.password = "wrongpw"

    for _ in range(settings.MAX_PASSWORD_ATTEMPTS):
        with pytest.raises(ValueError, match="Parola yanlış"):
            wallet.decrypt_data(encrypted)

    with pytest.raises(ValueError, match="başarısız parola denemesi"):
        wallet.decrypt_data(encrypted)

def test_foundation_wallet_creation_and_load():
    if os.path.exists(settings.FOUNDATION_WALLET_PATH):
        os.remove(settings.FOUNDATION_WALLET_PATH)

    wallet_1 = get_foundation_wallet()

    assert os.path.exists(settings.FOUNDATION_WALLET_PATH)

    wallet_2 = get_foundation_wallet()

    assert wallet_1.public_key == wallet_2.public_key

@patch("bhrc_blockchain.core.wallet.wallet.PBKDF2", side_effect=ValueError("Simüle hata"))
def test_pbkdf2_failure_handling(mock_pbkdf2):
    wallet = MinerWallet(password="test123", persist=False)
    with pytest.raises(RuntimeError, match="sistem hatası oluştu"):
        wallet.encrypt_data("gizli veri")

def test_wrong_password_logs_warning(caplog):
    wallet = MinerWallet(password="correctpw", persist=False)
    encrypted = wallet.encrypt_data("top_secret")

    wallet.password = "wrongpw"

    with caplog.at_level(logging.WARNING):
        with pytest.raises(ValueError, match="Parola yanlış"):
            wallet.decrypt_data(encrypted)

    assert any("Hatalı parola" in message for message in caplog.messages)

def test_generate_address_base58check_format():
    private_key = generate_private_key()
    public_key = get_public_key_from_private_key(private_key)
    address = generate_address(public_key)

    assert address.startswith("xBHR")
    encoded_part = address[4:]
    decoded = base58.b58decode(encoded_part)

    assert len(decoded) >= 24

def test_import_wallet_from_mnemonic():
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, import_wallet_from_mnemonic

    mnemonic = generate_mnemonic()
    wallet_data = import_wallet_from_mnemonic(mnemonic, password="testpw", path=None)

    assert wallet_data["address"].startswith("xBHR")
    assert len(wallet_data["private_key"]) > 60

def test_import_wallet_from_private_key():
    from bhrc_blockchain.core.wallet.wallet import import_wallet_from_private_key, generate_private_key

    private_key = generate_private_key()
    wallet_data = import_wallet_from_private_key(private_key, password="pw", path=None)

    assert wallet_data["address"].startswith("xBHR")
    assert len(wallet_data["public_key"]) > 60

def test_export_wallet(tmp_path):
    from bhrc_blockchain.core.wallet.wallet import export_wallet

    wallet_path = tmp_path / "exp.json"
    wallet = MinerWallet(wallet_path=str(wallet_path), password="pw", persist=True)

    exported = export_wallet(path=str(wallet_path), password="pw")
    assert exported["address"] == wallet.address
    assert exported["private_key"] == wallet.private_key

class DummyBlock:
    def calculate_hash(self):
        return "dummyhash123"

def test_sign_and_verify_block_signature():
    from bhrc_blockchain.core.wallet.wallet import sign_block, verify_block_signature

    private_key = generate_private_key()
    public_key = get_public_key_from_private_key(private_key)

    block = DummyBlock()
    signature = sign_block(block, private_key)

    assert verify_block_signature(block, signature, public_key)

def test_verify_block_signature_invalid():
    from bhrc_blockchain.core.wallet.wallet import (
        sign_block,
        verify_block_signature,
        generate_mnemonic,
        get_wallet_from_mnemonic
    )
    import base64

    class DummyBlock:
        def calculate_hash(self):
            return "abc123"

    # 🔐 Geçerli anahtar ve imza oluştur
    mnemonic = generate_mnemonic()
    wallet_data = get_wallet_from_mnemonic(mnemonic)

    private_key = wallet_data["private_key"]
    public_key = wallet_data["public_key"]  # ✅ Doğru hex public key

    block = DummyBlock()
    valid_signature = sign_block(block, private_key)

    # ❌ Geçersiz imza üretiyoruz (son 4 karakteri boz)
    broken_signature = valid_signature[:-4] + "DEAD"

    # 🧪 Beklenen: verify_block_signature başarısız olur ama çökmez
    result = verify_block_signature(block, broken_signature, wallet_data["public_key"])  # ✅ DOĞRU

    assert result is False

def test_export_wallet_fails_if_incomplete(tmp_path):
    from bhrc_blockchain.core.wallet.wallet import export_wallet

    file_path = tmp_path / "invalid.json"
    with open(file_path, "w") as f:
        json.dump({
            "ciphertext": "x", "nonce": "x", "tag": "x"
        }, f)

    with pytest.raises(ValueError, match="yüklenemedi veya şifre hatalı"):
        export_wallet(str(file_path), password="pw")

@patch("bhrc_blockchain.core.wallet.wallet.PBKDF2", side_effect=MemoryError("Yetersiz bellek"))
def test_encrypt_data_pbkdf2_memory_error(mock_pbkdf2):
    wallet = MinerWallet(password="pw", persist=False)
    with pytest.raises(RuntimeError, match="sistem hatası oluştu"):
        wallet.encrypt_data("secret")

def test_load_from_file_without_password(tmp_path):
    path = tmp_path / "w.json"
    wallet = MinerWallet(wallet_path=str(path), password="pw", persist=True)
    wallet.password = None
    with pytest.raises(ValueError, match="Şifre gerekli"):
        wallet.load_from_file()


def test_decrypt_data_remaining_time_message():
    wallet = MinerWallet(password="pw", persist=False)
    encrypted = wallet.encrypt_data("sensitive")
    wallet.password = "wrong"
    for _ in range(settings.MAX_PASSWORD_ATTEMPTS):
        with pytest.raises(ValueError):
            wallet.decrypt_data(encrypted)

    with pytest.raises(ValueError, match="Lütfen"):
        wallet.decrypt_data(encrypted)


@patch("builtins.open", new_callable=mock_open)
def test_save_to_file_directly(mock_file, tmp_path):
    wallet = MinerWallet(wallet_path=str(tmp_path / "w.json"), password="pw", persist=False)
    wallet.save_to_file()
    assert mock_file.called


def test_reload_logs_reload_message(caplog, tmp_path):
    path = tmp_path / "wallet.json"
    wallet = MinerWallet(wallet_path=str(path), password="pw", persist=True)
    with caplog.at_level(logging.INFO):
        wallet.reload()
    assert "yeniden yüklendi" in caplog.text


def test_get_wallet_from_mnemonic_contains_phrase():
    mnemonic = generate_mnemonic()
    wallet_data = get_wallet_from_mnemonic(mnemonic)
    assert wallet_data["mnemonic"] == mnemonic


def test_verify_address_from_key_direct_call():
    priv = generate_private_key()
    addr = get_address_from_private_key(priv)
    assert verify_address_from_key(priv, addr) is True


def test_load_wallet_path_not_found():
    with pytest.raises(FileNotFoundError):
        load_wallet("/non/existent/path.json", password="pw")


def test_export_wallet_fails_if_incomplete(tmp_path):
    file_path = tmp_path / "invalid.json"
    with open(file_path, "w") as f:
        json.dump({
            "ciphertext": "x", "nonce": "x", "tag": "x"
        }, f)
    with pytest.raises(ValueError, match="yüklenemedi veya şifre hatalı"):
        export_wallet(str(file_path), password="pw")

def test__print_public_key_debug():
    from bhrc_blockchain.core.wallet.wallet import (
        generate_mnemonic,
        get_wallet_from_mnemonic
    )

    mnemonic = generate_mnemonic()
    wallet_data = get_wallet_from_mnemonic(mnemonic)

    public_key = wallet_data["public_key"]

    print("\n🧾 DEBUG INFO:")
    print(f"🔑 public_key: {public_key}")
    print(f"🔑 HEX? {'yes' if all(c in '0123456789abcdef' for c in public_key.lower()) else 'NO'}")
    print(f"🔢 length: {len(public_key)}")

def test__print_public_key_hex_fail_check():
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, get_wallet_from_mnemonic

    mnemonic = generate_mnemonic()
    wallet_data = get_wallet_from_mnemonic(mnemonic)
    public_key = wallet_data["public_key"]

    print("\n🔎 CHAR-CHECK:")
    for i, char in enumerate(public_key):
        if char.lower() not in "0123456789abcdef":
            print(f"❌ Non-hex character at position {i}: {repr(char)}")
    print(f"🔢 Length: {len(public_key)}")

def test__public_key_strict_bytes_check():
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, get_wallet_from_mnemonic

    mnemonic = generate_mnemonic()
    wallet_data = get_wallet_from_mnemonic(mnemonic)
    public_key = wallet_data["public_key"]

    print("\n🔍 STRICT BYTE DUMP:")
    print(" ".join(f"{ord(c):02x}" for c in public_key))
    print(f"Length: {len(public_key)}")

def test__print_public_key_repr():
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, get_wallet_from_mnemonic

    mnemonic = generate_mnemonic()
    wallet_data = get_wallet_from_mnemonic(mnemonic)
    public_key = wallet_data["public_key"]

    print("\n🧾 repr(public_key):")
    print(repr(public_key))
    print(f"🔢 Length: {len(public_key)}")

def test_minerwallet_to_dict():
    wallet = MinerWallet(password="pw", persist=False)
    data = wallet.to_dict()

    assert isinstance(data, dict)
    assert data["private_key"] == wallet.private_key
    assert data["public_key"] == wallet.public_key
    assert data["address"] == wallet.address
    assert data["mnemonic"] == wallet.mnemonic

def test_is_valid_address():
    from bhrc_blockchain.core.wallet.wallet import is_valid_address

    wallet = MinerWallet(password="pw", persist=False)
    assert is_valid_address(wallet.address) is True

    bad_prefix = "xXYZ" + wallet.address[4:]
    assert is_valid_address(bad_prefix) is False

    invalid_chars = "xBHR" + "!@#$%^&*()_+=-"
    assert is_valid_address(invalid_chars) is False

    short = "xBHRabc"
    assert is_valid_address(short) is False

def test_is_locked_method():
    wallet_1 = MinerWallet(password="securepw", persist=False)
    assert wallet_1.is_locked() is False

    wallet_2 = MinerWallet(private_key=wallet_1.private_key, persist=False)
    assert wallet_2.is_locked() is True

def test_generate_wallet_with_mnemonic():
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, generate_wallet, verify_address_from_key

    phrase = generate_mnemonic()
    result = generate_wallet(password="abc", mnemonic=phrase, force_new=True)

    assert result["mnemonic"] == phrase
    assert result["address"].startswith("xBHR")
    assert verify_address_from_key(result["private_key"], result["address"]) is True

def test_wallet_lock_unlock_behavior(tmp_path):
    path = tmp_path / "locked_wallet.json"
    wallet = MinerWallet(wallet_path=str(path), password="12345", persist=True)

    # 🧪 İlk hali açık olmalı
    assert wallet.is_locked() is False

    # 🔐 Kilitle
    wallet.lock()
    assert wallet.is_locked() is True

    # 🔓 Aç ve tekrar eriş
    wallet.unlock("12345")
    assert wallet.is_locked() is False
    assert wallet.address.startswith("xBHR")

def test_wallet_summary_fields(tmp_path):
    wallet = MinerWallet(wallet_path=str(tmp_path / "sum.json"), password="abc", persist=True)
    summary = wallet.summary()

    assert summary["address"].startswith("xBHR")
    assert "public_key_short" in summary
    assert "is_locked" in summary
    assert "wallet_path" in summary
    assert summary["has_mnemonic"] in ("True", "False")

def test_wallet_rename_file(tmp_path):
    old_path = tmp_path / "old_wallet.json"
    new_path = tmp_path / "renamed_wallet.json"

    wallet = MinerWallet(wallet_path=str(old_path), password="pw", persist=True)
    assert os.path.exists(old_path)

    wallet.rename_wallet_file(str(new_path))
    assert wallet.wallet_path == str(new_path)
    assert os.path.exists(new_path)
    assert not os.path.exists(old_path)

def test_is_valid_mnemonic_check():
    valid = generate_mnemonic()
    assert is_valid_mnemonic(valid) is True

    invalid = "apple banana cherry"  # geçersiz kısa örnek
    assert is_valid_mnemonic(invalid) is False

def test_decrypt_fails_if_aad_modified():
    wallet = MinerWallet(password="pw", persist=False)
    encrypted = wallet.encrypt_data("very_secret")

    # AAD'i geçersiz yaparak çözümlemeyi test et
    original_aad = settings.AES_ASSOCIATED_DATA
    try:
        settings.AES_ASSOCIATED_DATA = b"wrong_data"
        with pytest.raises(ValueError, match="Parola yanlış"):
            wallet.decrypt_data(encrypted)
    finally:
        settings.AES_ASSOCIATED_DATA = original_aad  # temizle

def test_decrypt_fails_if_base64_is_invalid():
    wallet = MinerWallet(password="pw", persist=False)
    encrypted = wallet.encrypt_data("test-data")

    # geçersiz base64 verisi enjekte ediliyor
    broken = encrypted.copy()
    broken["ciphertext"] = "!@#¤%&/()="  # geçersiz base64

    with pytest.raises(ValueError, match="Parola yanlış|veri bozuk"):
        wallet.decrypt_data(broken)

def test_pbkdf2_iteration_adjustment():
    original_iter = settings.PBKDF2_ITERATIONS
    wallet = MinerWallet(password="pw", persist=False)

    try:
        settings.PBKDF2_ITERATIONS = 100_000  # düşür
        enc = wallet.encrypt_data("deneme")
        assert isinstance(enc["ciphertext"], str)
    finally:
        settings.PBKDF2_ITERATIONS = original_iter

def test_generate_child_wallet_produces_different_addresses():
    phrase = generate_mnemonic()

    wallet_0 = generate_child_wallet(phrase, index=0)
    wallet_1 = generate_child_wallet(phrase, index=1)

    assert wallet_0["address"].startswith("xBHR")
    assert wallet_1["address"].startswith("xBHR")
    assert wallet_0["address"] != wallet_1["address"]
    assert wallet_0["public_key"] != wallet_1["public_key"]

    wallet_0_repeat = generate_child_wallet(phrase, index=0)
    assert wallet_0["private_key"] == wallet_0_repeat["private_key"]

def test_verify_wallet_integrity_success_and_failure():
    phrase = generate_mnemonic()
    wallet = generate_wallet(password="pw", mnemonic=phrase, force_new=True)

    assert verify_wallet_integrity(wallet, password="pw") is True

    wallet_bad = wallet.copy()
    wallet_bad["public_key"] = "0" * len(wallet["public_key"])
    assert verify_wallet_integrity(wallet_bad) is False

    wallet_bad2 = wallet.copy()
    wallet_bad2["mnemonic"] = "invalid word list ..."
    assert verify_wallet_integrity(wallet_bad2) is False

