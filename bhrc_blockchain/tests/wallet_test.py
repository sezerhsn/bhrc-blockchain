import os
import json
import base64
import pytest
from unittest.mock import patch, mock_open

from bhrc_blockchain.core.wallet.wallet import (
    MinerWallet,
    generate_wallet,
    generate_private_key,
    get_address_from_private_key,
    get_public_key_from_private_key,
    sign_message,
    verify_signature,
    verify_address_from_key,
    MAX_PASSWORD_ATTEMPTS
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
def test_wallet_encryption_decryption(mock_aes, mock_exists, mock_file):
    # AES şifreleme/deşifreleme mock
    class FakeCipher:
        def __init__(self):
            self.nonce = b"0" * 16
        def encrypt_and_digest(self, data):
            return b"ciphertext", b"tag"
        def decrypt_and_verify(self, ciphertext, tag):
            return json.dumps({
                "private_key": wallet.private_key,
                "public_key": wallet.public_key,
                "address": wallet.address
            }).encode()

    wallet = MinerWallet(password="test123", persist=False)
    encrypted_data = {
        "nonce": base64.b64encode(b"0" * 16).decode(),
        "tag": base64.b64encode(b"tag").decode(),
        "ciphertext": base64.b64encode(b"ciphertext").decode()
    }

    mock_file().read.return_value = json.dumps(encrypted_data)
    mock_aes.return_value = FakeCipher()

    # Cüzdan yükle
    loaded = MinerWallet(wallet_path="fake.json", password="test123")
    assert wallet.address == loaded.address

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

    fake_data = {
        "private_key": "abc",
        "public_key": "def",
        "address": "xBHR" + "0" * 60
    }
    encrypted_data = json.dumps(fake_data)
    mock_file().read.return_value = encrypted_data

    result = load_wallet("wallets/test_wallet.json")
    assert "address" in result
    assert result["address"].startswith("xBHR")

def test_verify_address_from_key_with_wrong_address():
    private_key = generate_private_key()
    wrong_address = "xBHR" + "F" * 60  # Rastgele yanlış adres
    assert not verify_address_from_key(private_key, wrong_address)

def test_password_attempt_limit():
    from bhrc_blockchain.core.wallet.wallet import MAX_PASSWORD_ATTEMPTS

    wallet = MinerWallet(password="secure123", persist=False)
    encrypted = wallet.encrypt_data("test")

    wallet.password = "wrongpass"
    for _ in range(MAX_PASSWORD_ATTEMPTS):
        with pytest.raises(ValueError):
            wallet.decrypt_data(encrypted)

    with pytest.raises(ValueError, match="başarısız parola denemesi"):
        wallet.decrypt_data(encrypted)

