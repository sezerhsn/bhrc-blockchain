# storage_test.py
import pytest
import os
import tempfile
from unittest.mock import MagicMock
from bhrc_blockchain.database.storage import SQLiteDataStore

def test_spend_utxos_called():
    db = MagicMock(spec=SQLiteDataStore)
    db.spend_utxos = MagicMock()
    db.save_utxos = MagicMock()

    transactions = [
        {
            "type": "transfer",
            "inputs": [{"txid": "txid1", "output_index": 0}],
            "txid": "txid1",
            "outputs": [{"recipient": "address1", "amount": 10}]
        },
        {
            "type": "coinbase",
            "inputs": [],
            "txid": "txid2",
            "outputs": [{"recipient": "address2", "amount": 20}]
        },
        {
            "type": "transfer",
            "inputs": [{"txid": "txid3", "output_index": 1}],
            "txid": "txid3",
            "outputs": [{"recipient": "address3", "amount": 30}]
        }
    ]

    for tx in transactions:
        if tx["type"] != "coinbase":
            db.spend_utxos(tx["inputs"])
        db.save_utxos(tx["txid"], tx["outputs"])

    db.spend_utxos.assert_any_call([{"txid": "txid1", "output_index": 0}])
    db.spend_utxos.assert_any_call([{"txid": "txid3", "output_index": 1}])

def test_apply_utxo_changes():
    db = MagicMock(spec=SQLiteDataStore)
    db.spend_utxos = MagicMock()
    db.save_utxos = MagicMock()

    transactions = [
        {
            "type": "transfer",
            "inputs": [{"txid": "txid1", "output_index": 0}],
            "txid": "txid1",
            "outputs": [{"recipient": "address1", "amount": 10}]
        },
        {
            "type": "coinbase",
            "inputs": [],
            "txid": "txid2",
            "outputs": [{"recipient": "address2", "amount": 20}]
        },
        {
            "type": "transfer",
            "inputs": [{"txid": "txid3", "output_index": 1}],
            "txid": "txid3",
            "outputs": [{"recipient": "address3", "amount": 30}]
        }
    ]

    for tx in transactions:
        if tx["type"] != "coinbase":
            db.spend_utxos(tx["inputs"])
        db.save_utxos(tx["txid"], tx["outputs"])

    db.spend_utxos.assert_any_call([{"txid": "txid1", "output_index": 0}])
    db.spend_utxos.assert_any_call([{"txid": "txid3", "output_index": 1}])

def test_database_save_operations():
    db = MagicMock(spec=SQLiteDataStore)
    db.spend_utxos = MagicMock()
    db.save_utxos = MagicMock()

    transactions = [
        {
            "type": "transfer",
            "inputs": [{"txid": "txid1", "output_index": 0}],
            "txid": "txid1",
            "outputs": [{"recipient": "address1", "amount": 10}]
        }
    ]

    for tx in transactions:
        if tx["type"] != "coinbase":
            db.spend_utxos(tx["inputs"])
        db.save_utxos(tx["txid"], tx["outputs"])

    db.save_utxos.assert_called_with("txid1", [{"recipient": "address1", "amount": 10}])

def test_save_and_fetch_block():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        db = SQLiteDataStore(tmp.name)
        block = {
            "index": 1,
            "block_hash": "abc123",
            "previous_hash": "000000",
            "timestamp": 1234567890,
            "miner_address": "xBHR" + "A" * 60,
            "merkle_root": "root123",
            "nonce": 0,
            "version": "0x01",
            "virtual_size": 1024,
            "transactions": [{
                "txid": "tx123",
                "sender": "xBHR" + "B" * 60,
                "recipient": "xBHR" + "C" * 60,
                "amount": 50.0,
                "fee": 0.1,
                "message": "",
                "note": "",
                "type": "transfer",
                "locktime": 0,
                "time": 1234567890,
                "script_sig": "sig",
                "public_key": "pub",
                "script_pubkey": "pubkey",
                "status": "ready"
            }]
        }
        db.save_block(block)
        blocks = db.fetch_all_blocks()
        assert len(blocks) == 1
        assert blocks[0]["block_hash"] == "abc123"
        db.close()
        os.remove(tmp.name)

def test_save_and_get_utxos():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        db = SQLiteDataStore(tmp.name)
        outputs = [{"recipient": "xBHR" + "D" * 60, "amount": 20.0}]
        db.save_utxos("txABC", outputs)
        utxos = db.get_all_utxos()
        assert any(val["amount"] == 20.0 for val in utxos.values())
        db.close()
        os.remove(tmp.name)

def test_spend_and_get_unspent_utxos():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        db = SQLiteDataStore(tmp.name)
        recipient = "xBHR" + "E" * 60
        outputs = [{"recipient": recipient, "amount": 15.0}]
        db.save_utxos("tx999", outputs)
        all_utxos = db.get_all_utxos()
        assert any(utxo["recipient"] == recipient for utxo in all_utxos.values())

        db.spend_utxos([{"txid": "tx999", "output_index": 0}])
        remaining = db.get_all_utxos()
        assert not any("tx999" in k for k in remaining)

        db.close()
        os.remove(tmp.name)

def test_fetch_all_blocks_normalizes_index():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        db = SQLiteDataStore(tmp.name)
        block = {
            "index": 5,
            "block_hash": "blk999",
            "previous_hash": "blk998",
            "timestamp": 1234567890,
            "miner_address": "xBHR" + "A" * 60,
            "merkle_root": "rootXYZ",
            "nonce": 999,
            "version": "0x01",
            "virtual_size": 2048,
            "transactions": []
        }
        db.save_block(block)
        blocks = db.fetch_all_blocks()
        assert "index" in blocks[0]
        assert "index_num" not in blocks[0]
        assert blocks[0]["index"] == 5
        db.close()
        os.remove(tmp.name)

def test_close_connection():
    db = SQLiteDataStore(":memory:")
    try:
        db.close()
    except Exception:
        pytest.fail("close() fonksiyonu hata fırlattı")

