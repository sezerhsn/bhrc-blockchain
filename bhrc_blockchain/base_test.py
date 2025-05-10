# base_test.py
import time
import pytest
from unittest.mock import patch, MagicMock
from bhrc_blockchain.core.blockchain import Blockchain
from bhrc_blockchain.core.wallet import generate_private_key, get_address_from_private_key
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.database.storage import SQLiteDataStore
from bhrc_blockchain.core.blockchain.validation import ChainValidator
from bhrc_blockchain.config.config import Config

def test_blockchain_initialization_sets_properties():
    chain = Blockchain()
    assert isinstance(chain.chain, list)
    assert chain.block_reward == 64  # BLOCK_REWARD doğrudan kullanılıyor
    assert hasattr(chain.miner_wallet, "address")
    assert chain.difficulty_prefix.startswith("000")

@patch("bhrc_blockchain.core.block.Block")
@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_create_genesis_block(mock_db, mock_block):
    instance = Blockchain()
    instance.db = MagicMock()
    instance.miner_wallet.address = "xBHR" + "0" * 60
    mock_block.return_value.to_dict.return_value = {"index": 0}
    instance.create_genesis_block()
    instance.db.save_block.assert_called_once()
    instance.db.save_utxos.assert_called_once()

@patch("bhrc_blockchain.core.block.Block")
@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_load_chain_from_db_empty_triggers_genesis(mock_db, mock_block):
    store = MagicMock()
    store.fetch_all_blocks.return_value = []
    mock_db.return_value = store
    with patch.object(Blockchain, "create_genesis_block") as mock_genesis:
        bc = Blockchain(load_existing=False)
        mock_genesis.assert_called_once()

@patch("bhrc_blockchain.core.block.Block")
@patch("bhrc_blockchain.database.storage.SQLiteDataStore")
def test_load_chain_from_db_with_data(mock_db, mock_block):
    mock_block_data = [{
        "index": 0,
        "previous_hash": "0",
        "transactions": [],
        "timestamp": 1234567890,
        "nonce": 0,
        "miner_address": "xBHR" + "0" * 60,
        "block_hash": "abc123",
        "merkle_root": "def456",
        "difficulty": "0000",
        "version": "0x01",
        "virtual_size": 512
    }]
    store = MagicMock()
    store.fetch_all_blocks.return_value = mock_block_data
    mock_db.return_value = store
    bc = Blockchain(load_existing=False)
    assert len(bc.chain) == 1

def test_adjust_difficulty_logic():
    chain = Blockchain()
    chain.chain = [
        MagicMock(timestamp=100),
        MagicMock(timestamp=800)
    ]
    chain.difficulty_prefix = "0000"
    chain.adjust_difficulty()
    assert chain.difficulty_prefix == "000"

def test_validate_chain_correct_hashes():
    block1 = MagicMock()
    block1.index = 0
    block1.block_hash = "hash0"
    block1.transactions = []
    block1.previous_hash = "0"
    block1.timestamp = 1000
    block1.nonce = 0
    block1.miner_address = "miner"
    block1.merkle_root = "root"
    block1.difficulty = "0000"

    block2 = MagicMock()
    block2.index = 1
    block2.previous_hash = "hash0"
    block2.block_hash = "hash1"
    block2.transactions = []
    block2.timestamp = 2000
    block2.nonce = 1
    block2.miner_address = "miner"
    block2.merkle_root = "root"
    block2.difficulty = "0000"

    blockchain = Blockchain()
    blockchain.chain = [block1, block2]

    with patch.object(Block, "calculate_block_hash", return_value="hash1"), \
         patch.object(Block, "calculate_merkle_root", return_value="root"):
        assert blockchain.validate_chain() is True

def test_is_chain_valid_on_empty_chain():
    bc = Blockchain()
    bc.chain = []
    result = ChainValidator.validate_chain(bc)
    assert result is False

def test_create_genesis_block_exception_handling():
    bc = Blockchain()
    bc.miner_wallet.address = None
    with pytest.raises(ValueError, match="Miner address boş olamaz"):
        bc.create_genesis_block()

def test_create_genesis_block_print_output(capsys):
    bc = Blockchain(load_existing=False)  # bu zaten genesis bloğu oluşturur
    captured = capsys.readouterr()
    assert "✅ Genesis Block başarıyla oluşturuldu!" in captured.out
    assert len(bc.chain) == 1
    assert bc.chain[0].index == 0

