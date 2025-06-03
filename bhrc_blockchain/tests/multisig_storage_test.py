import os
import uuid
import pytest
from bhrc_blockchain.database import multisig_storage

TEST_DB = "test_multisig.db"

@pytest.fixture(autouse=True)
def setup_and_cleanup(monkeypatch):
    monkeypatch.setattr(multisig_storage, "DB_PATH", TEST_DB)
    multisig_storage.init_multisig_db()
    yield
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

def test_create_and_retrieve_multisig():
    txid = str(uuid.uuid4())
    data = {"action": "transfer", "amount": 100}
    required = ["user1", "user2"]
    multisig_storage.create_multisig_tx(txid, "admin", data, required)

    tx = multisig_storage.get_multisig_tx(txid)
    assert tx["txid"] == txid
    assert tx["status"] == "pending"
    assert tx["data"] == data

def test_add_signature_and_ready_status():
    txid = str(uuid.uuid4())
    multisig_storage.create_multisig_tx(txid, "admin", {"x": 1}, ["u1", "u2"])

    multisig_storage.add_signature(txid, "u1", "sig1")
    tx = multisig_storage.get_multisig_tx(txid)
    assert tx["status"] == "pending"
    assert len(tx["signatures"]) == 1

    multisig_storage.add_signature(txid, "u2", "sig2")
    tx = multisig_storage.get_multisig_tx(txid)
    assert tx["status"] == "ready"
    assert len(tx["signatures"]) == 2

def test_list_pending_and_ready_multisigs():
    # Pending işlem oluştur
    txid1 = str(uuid.uuid4())
    multisig_storage.create_multisig_tx(txid1, "a", {"z": 1}, ["x", "y"])

    # Ready işlem oluştur
    txid2 = str(uuid.uuid4())
    multisig_storage.create_multisig_tx(txid2, "a", {"z": 2}, ["x"])
    multisig_storage.add_signature(txid2, "x", "sig")

    pending = multisig_storage.list_pending_multisigs()
    ready = multisig_storage.list_ready_multisigs()

    pending_ids = [m["txid"] for m in pending]
    ready_ids = [m["txid"] for m in ready]

    assert txid1 in pending_ids
    assert txid2 in ready_ids

