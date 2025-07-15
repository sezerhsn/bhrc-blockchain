import os
import tempfile
import json
from bhrc_blockchain.core.crypto.key_utils import generate_keypair, save_wallet

def test_generate_keypair_returns_valid_keys():
    private, public = generate_keypair()
    assert isinstance(private, str)
    assert isinstance(public, str)
    assert len(private) > 0
    assert len(public) > 0

def test_save_wallet_creates_json_file():
    data = {"address": "bhrc123", "balance": 100}
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tf:
        path = tf.name
    save_wallet(path, data)
    with open(path) as f:
        loaded = json.load(f)
    assert loaded == data
    os.remove(path)

