import os
import sqlite3
import pytest
import tempfile
from bhrc_blockchain.core.contract import contract_state_storage as storage

@pytest.fixture(autouse=True)
def setup_and_teardown():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        storage.DB_PATH = tf.name
    storage.init_db()
    yield
    os.remove(storage.DB_PATH)

def test_save_and_load_contract():
    storage.save_contract_state("addr1", "print('hi')", {"state": 1})
    code, state = storage.load_contract_state("addr1")
    assert code == "print('hi')"
    assert state == {"state": 1}

def test_update_contract():
    storage.save_contract_state("addr1", "old_code", {"val": 1})
    storage.save_contract_state("addr1", "new_code", {"val": 2})
    code, state = storage.load_contract_state("addr1")
    assert code == "new_code"
    assert state == {"val": 2}

def test_delete_contract():
    storage.save_contract_state("addr1", "c", {"x": 1})
    storage.delete_contract_state("addr1")
    assert storage.load_contract_state("addr1") is None

def test_reset_all_contracts():
    storage.save_contract_state("a1", "code", {})
    storage.save_contract_state("a2", "code", {})
    storage.reset_all_contract_states()
    assert storage.load_contract_state("a1") is None
    assert storage.load_contract_state("a2") is None

def test_list_all_contracts():
    storage.save_contract_state("a1", "code", {})
    storage.save_contract_state("a2", "code", {})
    contracts = storage.list_all_contracts()
    addresses = [c["contract_address"] for c in contracts]
    assert "a1" in addresses
    assert "a2" in addresses

def test_load_contract_not_found():
    assert storage.load_contract_state("nonexistent") is None

