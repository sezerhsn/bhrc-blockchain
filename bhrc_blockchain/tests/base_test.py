import pytest
import time
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_public_key_from_private_key, sign_block

def generate_key_pair():
    priv = generate_private_key()
    pub = get_public_key_from_private_key(priv)
    return priv, pub

@pytest.fixture
def clean_blockchain():
    blockchain = Blockchain(autoload=False)
    blockchain.reset_chain()
    return blockchain

def test_chain_initialization(clean_blockchain):
    chain = clean_blockchain.chain
    assert isinstance(chain, list)
    assert len(chain) == 1
    assert chain[0].index == 0

def test_genesis_creation(clean_blockchain):
    block = clean_blockchain.get_last_block()
    assert block.index == 0
    assert block.previous_hash == "0"
    assert isinstance(block.transactions, list)
    assert block.miner_address == clean_blockchain.miner_wallet.address

def test_adding_block(clean_blockchain):
    private_key, public_key = generate_key_pair()
    prev_block = clean_blockchain.get_last_block()

    new_block = Block(
        index=1,
        previous_hash=prev_block.block_hash,
        transactions=[{"sender": "test", "recipient": "unit", "amount": 1}],
        timestamp=time.time(),
        nonce=123,
        miner_address="xBHR456",
        version="1.0.0",
        difficulty="00",
        merkle_root="abc123",
        producer_id=public_key,
    )
    new_block.block_hash = new_block.calculate_hash()
    new_block.block_signature = sign_block(new_block, private_key)

    result = clean_blockchain.add_block(new_block)
    assert result is True
    assert len(clean_blockchain.chain) == 2
    assert clean_blockchain.chain[1].index == 1

