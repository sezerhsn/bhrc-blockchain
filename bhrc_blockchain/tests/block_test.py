import pytest
import time
from bhrc_blockchain.core.block import Block

def test_block_creation():
    transactions = [
        {"sender": "Alice", "recipient": "Bob", "amount": 10},
        {"sender": "Bob", "recipient": "Charlie", "amount": 5}
    ]
    block = Block(
        index=1,
        previous_hash="abc123",
        transactions=transactions,
        timestamp=time.time(),
        nonce=123,
        miner_address="miner123",
        difficulty="0000abcd",
        version="0x01",
        events=["Test block created"]
    )

    assert block.index == 1
    assert block.previous_hash == "abc123"
    assert block.transactions == transactions
    assert block.nonce == 123
    assert block.miner_address == "miner123"
    assert block.difficulty == "0000abcd"
    assert block.version == "0x01"
    assert isinstance(block.timestamp, float)
    assert isinstance(block.block_hash, str)
    assert len(block.block_hash) == 64

def test_block_hash_consistency():
    txs = [{"sender": "a", "recipient": "b", "amount": 10}]
    timestamp = time.time()

    block1 = Block(
        index=5,
        previous_hash="0000aaa",
        transactions=txs,
        timestamp=timestamp,
        nonce=777,
        miner_address="xBHR123",
        difficulty="001122",
    )
    block2 = Block(
        index=5,
        previous_hash="0000aaa",
        transactions=txs,
        timestamp=timestamp,
        nonce=777,
        miner_address="xBHR123",
        difficulty="001122",
    )

    assert block1.block_hash == block2.block_hash

def test_block_to_dict_and_from_dict():
    transactions = [{"sender": "X", "recipient": "Y", "amount": 50}]
    block = Block(
        index=2,
        previous_hash="prev456",
        transactions=transactions,
        timestamp=time.time(),
        nonce=42,
        miner_address="minerXYZ",
    )

    block_dict = block.to_dict()
    new_block = Block.from_dict(block_dict)

    assert new_block.index == block.index
    assert new_block.previous_hash == block.previous_hash
    assert new_block.transactions == block.transactions
    assert new_block.timestamp == block.timestamp
    assert new_block.nonce == block.nonce
    assert new_block.miner_address == block.miner_address
    assert new_block.block_hash == block.block_hash

def test_block_merkle_root():
    txs = [
        {"sender": "a", "recipient": "b", "amount": 1},
        {"sender": "c", "recipient": "d", "amount": 2},
        {"sender": "e", "recipient": "f", "amount": 3},
    ]
    block = Block(
        index=3,
        previous_hash="hash321",
        transactions=txs,
        timestamp=time.time(),
        nonce=101,
        miner_address="miner001"
    )

    merkle = block.calculate_merkle_root()
    assert isinstance(merkle, str)
    assert len(merkle) == 64

def test_virtual_size():
    txs = [{"sender": "foo", "recipient": "bar", "amount": 999}]
    block = Block(
        index=4,
        previous_hash="abc",
        transactions=txs,
        timestamp=time.time(),
        nonce=55,
        miner_address="x123"
    )

    size = block.calculate_virtual_size()
    assert isinstance(size, int)
    assert size > 0

