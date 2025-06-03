import os
import pytest
from bhrc_blockchain.database.storage import SQLiteDataStore

TEST_DB_PATH = "test_storage.db"

@pytest.fixture
def store():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    store = SQLiteDataStore(db_path=TEST_DB_PATH)
    yield store
    store.close()
    os.remove(TEST_DB_PATH)

def test_save_and_fetch_utxos(store):
    txid = "tx123"
    outputs = [{"address": "xBHRABC", "amount": 10.0}]
    store.save_utxos(txid, outputs)
    utxos = store.get_unspent_utxos("xBHRABC")
    assert len(utxos) == 1
    assert utxos[0][1] == "tx123"

def test_spend_utxos(store):
    txid = "txABC"
    outputs = [{"address": "xBHRDEF", "amount": 20.0}]
    store.save_utxos(txid, outputs)
    store.spend_utxos([{"txid": txid, "output_index": 0}])
    utxos = store.get_unspent_utxos("xBHRDEF")
    assert len(utxos) == 0

def test_apply_utxo_changes(store):
    txs = [
        {
            "type": "coinbase",
            "txid": "coinbaseX",
            "outputs": [{"recipient": "xBHRCBA", "amount": 40.0}]
        },
        {
            "type": "transfer",
            "txid": "txX",
            "inputs": [{"txid": "coinbaseX", "output_index": 0}],
            "outputs": [{"recipient": "xBHRNEW", "amount": 25.0}]
        }
    ]
    store.apply_utxo_changes(txs)
    utxos = store.get_unspent_utxos("xBHRNEW")
    assert len(utxos) == 1
    assert utxos[0][1] == "txX"

def test_get_all_utxos(store):
    txid = "tx999"
    outputs = [{"address": "xBHRZED", "amount": 100.0}]
    store.save_utxos(txid, outputs)
    all_utxos = store.get_all_utxos()
    assert ((txid, 0) in all_utxos)
    assert all_utxos[(txid, 0)]["amount"] == 100.0

def test_fetch_all_blocks_empty(store):
    blocks = store.fetch_all_blocks()
    assert blocks == []

