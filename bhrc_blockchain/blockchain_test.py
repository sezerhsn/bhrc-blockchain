# blockchain_test.py
import json
import pytest
import time
from unittest.mock import patch, MagicMock
from bhrc_blockchain.core.blockchain import Blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.database.storage import SQLiteDataStore

def make_block(index, previous_hash, nonce):
    return {
        "index": index,
        "previous_hash": previous_hash,
        "transactions": json.dumps([{"txid": "dummy"}]),  # ✅ düzeltme burada
        "timestamp": time.time(),
        "nonce": nonce,
        "miner_address": "miner",
        "block_hash": f"hash{index}",
        "merkle_root": "root",
        "version": "0x01",
        "virtual_size": 1000
    }

def test_blockchain_instance():
    bc = Blockchain()
    assert isinstance(bc.chain, list)

@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_load_chain_from_db_creates_genesis_block(mock_store):
    mock_instance = mock_store.return_value
    mock_instance.fetch_all_blocks.return_value = []
    with patch.object(Blockchain, "create_genesis_block") as mock_genesis:
        Blockchain(load_existing=False)
        mock_genesis.assert_called_once()

@patch("bhrc_blockchain.core.blockchain.blockchain.SQLiteDataStore")
def test_load_chain_from_db_reads_existing_chain(mock_store):
    mock_store.return_value.fetch_all_blocks.return_value = [make_block(0, "0", 0)]
    bc = Blockchain(load_existing=True)
    assert len(bc.chain) == 1

@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_save_chain_to_db(mock_store):
    bc = Blockchain()
    bc.chain = [MagicMock(to_dict=lambda: {"index": 0})]
    bc.db = MagicMock()
    bc.save_chain_to_db()
    assert bc.db.save_block.called

@patch("bhrc_blockchain.core.block.Block")
def test_create_genesis_block(mock_block):
    bc = Blockchain()
    bc.db = MagicMock()
    bc.miner_wallet.address = "xBHR" + "0" * 60
    mock_block.return_value.to_dict.return_value = {"index": 0}
    bc.create_genesis_block()
    bc.db.save_block.assert_called_once()
    bc.db.save_utxos.assert_called_once()

@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_block_validation_with_mocked_blocks(mock_store):
    bc = Blockchain()
    block1 = Block(
        index=0,
        previous_hash="0",
        transactions=[{"txid": "abc"}],
        miner_address="miner",
        nonce=0
    )
    block2 = Block(
        index=1,
        previous_hash=block1.block_hash,
        transactions=[{"txid": "def"}],
        miner_address="miner",
        nonce=0
    )
    bc.chain = [block1, block2]
    assert bc.validate_chain() is True

@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_adjust_difficulty_increase(mock_store):
    bc = Blockchain()
    bc.chain = [
        MagicMock(timestamp=100),
        MagicMock(timestamp=120)  # çok hızlı → zorlaştır
    ]
    bc.difficulty_prefix = "0000"
    bc.adjust_difficulty()
    assert bc.difficulty_prefix == "00000"

@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_adjust_difficulty_decrease(mock_store):
    bc = Blockchain()
    bc.chain = [
        MagicMock(timestamp=100),
        MagicMock(timestamp=1000)  # çok yavaş → kolaylaştır
    ]
    bc.difficulty_prefix = "0000"
    bc.adjust_difficulty()
    assert bc.difficulty_prefix == "000"

@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_validate_chain_detects_invalid_hash(mock_store):
    bc = Blockchain()
    block1 = Block(0, "0", [], "miner")
    block2 = Block(1, "hatalı_hash", [], "miner")
    bc.chain = [block1, block2]
    assert bc.validate_chain() is False

@pytest.mark.asyncio
@patch("bhrc_blockchain.core.mempool.get_ready_transactions", return_value=[])
async def test_mine_block_no_transactions(mock_mempool):
    bc = Blockchain()
    result = await bc.mine_block()
    assert result is None

@pytest.mark.asyncio
@patch("bhrc_blockchain.core.blockchain.blockchain.get_ready_transactions")
@patch("bhrc_blockchain.core.blockchain.blockchain.clear_mempool")
@patch("bhrc_blockchain.core.blockchain.blockchain.broadcast_new_block_async")
@patch("bhrc_blockchain.core.blockchain.blockchain.create_transaction")
async def test_mine_block_success(mock_create_tx, mock_broadcast, mock_clear, mock_ready):
    dummy_tx = {
        "txid": "tx123",
        "sender": "xBHR" + "A" * 60,
        "recipient": "xBHR" + "B" * 60,
        "amount": 10,
        "fee": 1,
        "message": "",
        "note": "",
        "type": "transfer",
        "locktime": 0,
        "time": time.time(),
        "script_sig": "sig",
        "public_key": "pub",
        "status": "ready",
        "inputs": [{"txid": "abc", "output_index": 0}],
        "outputs": [{"recipient": "xBHR" + "B" * 60, "amount": 10}]
    }
    mock_ready.return_value = [dummy_tx]
    mock_create_tx.return_value = dummy_tx
    bc = Blockchain()
    result = await bc.mine_block()
    assert isinstance(result, int)

