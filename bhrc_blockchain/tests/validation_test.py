import pytest
import time
from unittest.mock import patch
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.transaction.validation import ChainValidator, validate_block_structure

@pytest.fixture
def blockchain():
    bc = Blockchain(autoload=False)
    bc.reset_chain()
    return bc

def test_valid_chain(blockchain):
    last = blockchain.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="xBHR111",
        difficulty="0000",
        version="0x01",
        events=[]
    )
    blockchain.add_block(new_block)
    assert ChainValidator.validate_chain(blockchain) is True

def test_invalid_chain_due_to_previous_hash(blockchain):
    last = blockchain.get_last_block()
    broken_block = Block(
        index=1,
        previous_hash="tamper_hash",
        transactions=[],
        timestamp=time.time(),
        nonce=99,
        miner_address="xBHR111",
        difficulty="0000",
        version="0x01",
        events=[]
    )
    blockchain.chain.append(broken_block)
    assert ChainValidator.validate_chain(blockchain) is False

def test_invalid_chain_due_to_hash_mismatch(blockchain):
    last = blockchain.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="xBHR001",
        difficulty="0000",
        version="0x01",
        events=[]
    )
    new_block.block_hash = "manipulated_hash"
    blockchain.chain.append(new_block)
    assert ChainValidator.validate_chain(blockchain) is False

def test_validate_block_structure_success():
    valid_block = {
        "index": 0,
        "previous_hash": "0",
        "transactions": [],
        "timestamp": 1234567890.0,
        "nonce": 0,
        "miner_address": "xBHR111",
        "block_hash": "abc123",
        "merkle_root": "merkle"
    }
    assert validate_block_structure(valid_block) is True

def test_validate_block_structure_failure():
    invalid_block = {
        "index": 0,
        "previous_hash": "0"
    }
    assert validate_block_structure(invalid_block) is False

def test_invalid_chain_due_to_merkle_root_mismatch(blockchain):
    last = blockchain.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="xBHR222",
        difficulty="0000",
        version="0x01",
        events=[]
    )
    new_block.merkle_root = "tampered_root"
    blockchain.chain.append(new_block)
    assert ChainValidator.validate_chain(blockchain) is False

from unittest.mock import patch

@patch("bhrc_blockchain.core.transaction.validation.Block.validate_block", return_value=False)
def test_invalid_chain_due_to_block_validation(mock_validate, blockchain):
    last = blockchain.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="xBHR333",
        difficulty="0000",
        version="0x01",
        events=[]
    )
    blockchain.chain.append(new_block)
    assert ChainValidator.validate_chain(blockchain) is False

@patch("bhrc_blockchain.core.transaction.validation.verify_block_signature", return_value=False)
def test_invalid_chain_due_to_signature_verification(mock_verify, blockchain):
    last = blockchain.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="xBHR444",
        difficulty="0000",
        version="0x01",
        events=[]
    )
    blockchain.chain.append(new_block)
    assert ChainValidator.validate_chain(blockchain) is False

def test_invalid_chain_due_to_wrong_merkle_root(blockchain):
    last = blockchain.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="xBHR555",
        difficulty="0000",
        version="0x01",
        events=[]
    )
    new_block.merkle_root = "manipulated_root"
    new_block.block_hash = new_block.calculate_hash()
    blockchain.chain.append(new_block)
    assert ChainValidator.validate_chain(blockchain) is False

@patch("bhrc_blockchain.core.transaction.validation.verify_block_signature", return_value=False)
@patch("bhrc_blockchain.core.transaction.validation.Block.validate_block", return_value=True)
def test_invalid_chain_due_to_signature_only(mock_validate, mock_verify, blockchain):
    last = blockchain.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="xBHR557",
        difficulty="0000",
        version="0x01",
        events=[]
    )
    new_block.merkle_root = new_block.calculate_merkle_root()
    new_block.block_hash = new_block.calculate_hash()
    blockchain.chain.append(new_block)
    assert ChainValidator.validate_chain(blockchain) is False

