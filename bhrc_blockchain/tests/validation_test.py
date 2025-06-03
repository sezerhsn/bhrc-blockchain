import pytest
import time
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.transaction.validation import ChainValidator

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
    blockchain.chain.append(broken_block)  # doğrudan zincire eklenerek yapısı bozuluyor
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

