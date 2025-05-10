# block_test.py
import pytest
from bhrc_blockchain.core.block import Block

def test_block_hash_format():
    block = Block(
        index=0,
        previous_hash="0",
        transactions=[],
        miner_address="xBHR000000000000000000000000000000000000000000000000000000000000",
        nonce=0,
        version="0x01"
    )
    assert isinstance(block.block_hash, str)
    assert len(block.block_hash) == 64

def test_merkle_root_consistency():
    tx1 = {"txid": "abc123"}
    tx2 = {"txid": "def456"}
    block = Block(
        index=1,
        previous_hash="abc",
        transactions=[tx1, tx2],
        miner_address="xBHRxxx",
        nonce=42,
        version="0x01"
    )
    expected_root = block.calculate_merkle_root()
    assert block.merkle_root == expected_root

def test_merkle_root_with_odd_number_of_transactions():
    # Tek sayıda (3 adet) sahte işlem
    tx1 = {"sender": "A", "receiver": "B", "amount": 10}
    tx2 = {"sender": "B", "receiver": "C", "amount": 20}
    tx3 = {"sender": "C", "receiver": "D", "amount": 30}

    block = Block(
        index=1,
        transactions=[tx1, tx2, tx3],
        previous_hash="0" * 64,
        miner_address="test_miner",
        nonce=0,
        version="0x01"
    )
    merkle_root = block.calculate_merkle_root()

    # Sadece merkle_root hesaplandı mı kontrolü yeterli
    assert isinstance(merkle_root, str)
    assert len(merkle_root) == 64

def test_to_dict_output_and_virtual_size():
    txs = [{"sender": "a", "recipient": "b", "amount": 10}]
    block = Block(index=1, previous_hash="0", transactions=txs, miner_address="miner")

    block_dict = block.to_dict()
    assert isinstance(block_dict, dict)
    assert "block_hash" in block_dict
    assert block_dict["virtual_size"] == block.calculate_virtual_size()

    block_dict_no_hash = block.to_dict(include_hash=False)
    assert "block_hash" not in block_dict_no_hash

def test_calculate_block_hash_matches_initial():
    txs = [{"sender": "a", "recipient": "b", "amount": 5}]
    block = Block(index=2, previous_hash="xyz", transactions=txs, miner_address="miner123")
    recalculated = block.calculate_block_hash()
    assert block.block_hash == recalculated

