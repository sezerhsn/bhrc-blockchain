# wallet_test.py
import os
import base64
import pytest
from unittest.mock import patch, mock_open

from bhrc_blockchain.core.wallet import (
    MinerWallet,
    generate_wallet,
    get_address_from_private_key,
    get_public_key_from_private_key,
    generate_private_key,
    sign_message,
    verify_signature,
    verify_address_from_key
)

def test_address_generation():
    wallet = MinerWallet(password="test123", persist=False)
    addr = wallet.address
    assert addr.startswith("xBHR")
    assert len(addr) > 30

def test_signature_verification():
    wallet = MinerWallet(password="test123", persist=False)
    message = "deneme"
    sig = sign_message(wallet.private_key, message)
    assert verify_signature(wallet.public_key, message, sig) is True

def test_wallet_encryption_decryption(tmp_path):
    path = tmp_path / "test_wallet.json"
    wallet = MinerWallet(wallet_path=str(path), password="test123", persist=True)
    wallet_loaded = MinerWallet(wallet_path=str(path), password="test123")
    assert wallet.address == wallet_loaded.address

def test_generate_address_with_invalid_key():
    wallet = MinerWallet(private_key=generate_private_key(), persist=False)
    with pytest.raises(ValueError):
        wallet.generate_address("not_a_valid_hex_public_key")

def test_encrypt_data_without_password():
    wallet = MinerWallet(private_key=generate_private_key(), persist=False)
    with pytest.raises(ValueError):
        wallet.encrypt_data("test")

def test_decrypt_data_without_password():
    wallet = MinerWallet(private_key=generate_private_key(), persist=False)
    with pytest.raises(ValueError):
        wallet.decrypt_data({"ciphertext": "x", "nonce": "x", "tag": "x"})

def test_load_from_nonexistent_file(tmp_path):
    fake_path = tmp_path / "nonexistent.json"
    wallet = MinerWallet(wallet_path=str(fake_path), password="pw", persist=False)
    with pytest.raises(FileNotFoundError):
        wallet.load_from_file()

def test_generate_wallet_creates_new_file(tmp_path):
    wallet_file = tmp_path / "wallet.json"
    result = generate_wallet(wallet_path=str(wallet_file), password="pw", force_new=False)
    assert os.path.exists(wallet_file)
    assert "address" in result
    assert "private_key" in result

def test_verify_signature_invalid_signature():
    private_key = generate_private_key()
    wallet = MinerWallet(private_key=private_key, persist=False)
    public_key = wallet.public_key
    message = "bhrc"
    fake_signature = base64.b64encode(b"invalidsig").decode()
    assert verify_signature(public_key, message, fake_signature) is False

def test_generate_wallet_force_new_true_creates_default_path():
    with patch("builtins.open", mock_open()), \
         patch("json.dump", lambda *a, **kw: None):
        result = generate_wallet(wallet_path=None, password="pw", force_new=True)
        assert "address" in result
        assert "private_key" in result

def test_get_public_key_from_private_key():
    private_key = generate_private_key()
    public_key = get_public_key_from_private_key(private_key)
    assert isinstance(public_key, str)
    assert len(public_key) > 60

def test_get_address_from_private_key():
    private_key = generate_private_key()
    address = get_address_from_private_key(private_key)
    assert address.startswith("xBHR")
    assert len(address) > 30

def test_verify_address_from_key_validates_correctly():
    priv_key = generate_private_key()
    expected_address = get_address_from_private_key(priv_key)
    assert verify_address_from_key(priv_key, expected_address)

