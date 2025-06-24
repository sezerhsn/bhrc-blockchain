import pytest
from bhrc_blockchain.utils import crypto

def test_rsa_sign_and_verify_success():
    private_key, public_key = crypto.generate_rsa_key_pair()
    message = "BHRC için imza testi"
    signature = crypto.sign_data_rsa(message, private_key)
    assert crypto.verify_signature_rsa(message, signature, public_key) is True

def test_rsa_sign_and_verify_failure():
    private_key1, public_key1 = crypto.generate_rsa_key_pair()
    private_key2, public_key2 = crypto.generate_rsa_key_pair()
    message = "Veri değişti"
    signature = crypto.sign_data_rsa(message, private_key1)
    assert crypto.verify_signature_rsa(message, signature, public_key2) is False

def test_rsa_key_serialization_cycle():
    private_key, public_key = crypto.generate_rsa_key_pair()
    private_bytes = crypto.serialize_private_key(private_key)
    public_bytes = crypto.serialize_public_key(public_key)
    loaded_private = crypto.load_private_key(private_bytes)
    loaded_public = crypto.load_public_key(public_bytes)
    msg = "serileştirme testi"
    sig = crypto.sign_data_rsa(msg, loaded_private)
    assert crypto.verify_signature_rsa(msg, sig, loaded_public)

def test_symmetric_encryption_decryption():
    key = crypto.generate_symmetric_key()
    message = "BHRC gizli veri"
    encrypted = crypto.encrypt_data(message, key)
    decrypted = crypto.decrypt_data(encrypted, key)
    assert decrypted == message

def test_symmetric_decryption_failure():
    key1 = crypto.generate_symmetric_key()
    key2 = crypto.generate_symmetric_key()
    encrypted = crypto.encrypt_data("veri", key1)
    with pytest.raises(Exception):
        crypto.decrypt_data(encrypted, key2)

