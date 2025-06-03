import pytest
import time
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_public_key_from_private_key, sign_block, generate_wallet

@pytest.fixture
def bc():
    blockchain = Blockchain(autoload=False)
    blockchain.reset_chain()
    return blockchain

def test_genesis_block_creation(bc):
    assert len(bc.chain) == 1
    genesis = bc.chain[0]
    assert genesis.index == 0
    assert genesis.previous_hash == "0"
    assert isinstance(genesis.transactions, list)
    assert genesis.transactions[0]["type"] == "coinbase"

def test_add_valid_block(bc):
    priv = generate_private_key()
    pub = get_public_key_from_private_key(priv)
    prev_block = bc.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=prev_block.block_hash,
        transactions=[{
            "sender": "A",
            "recipient": "B",
            "amount": 10,
            "type": "transfer"
        }],
        timestamp=time.time(),
        nonce=12345,
        miner_address="miner001",
        difficulty="0000",
        version="0x01",
        producer_id=pub,
        events=["✅ Test blok eklendi."]
    )
    new_block.block_hash = new_block.calculate_hash()
    new_block.block_signature = sign_block(new_block, priv)

    added = bc.add_block(new_block)
    assert added is True
    assert len(bc.chain) == 2
    assert bc.chain[1].index == 1

def test_add_invalid_block(bc):
    invalid_block_data = {
        "index": 2,
        "previous_hash": "xyz",
        "transactions": []
    }
    added = bc.add_block(invalid_block_data)
    assert added is False
    assert len(bc.chain) == 1

def test_blockchain_validation(bc):
    wallet = generate_wallet()
    priv = wallet["private_key"]
    pub = wallet["public_key"]

    last = bc.get_last_block()

    block = Block(
        index=1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=999,
        miner_address="minerABC",
        difficulty="0000",
        version="0x01",
        producer_id=pub,
        events=[]
    )

    block.block_hash = block.calculate_hash()
    block.block_signature = sign_block(block, priv)

    print(f"\n🧾 Block Hash: {block.block_hash}")
    print(f"🖋️ Signature: {block.block_signature}")
    print(f"🔑 Producer ID: {block.producer_id}")

    bc.add_block(block)
    assert bc.validate_chain() is True

def test_get_last_block(bc):
    last_block = bc.get_last_block()
    assert last_block.index == 0
    assert last_block.previous_hash == "0"

def test_blockchain_rejects_invalid_block(bc):
    last = bc.get_last_block()
    invalid_block = Block(
        index=1,
        previous_hash="invalid_previous_hash",
        transactions=[],
        timestamp=time.time(),
        nonce=1234,
        miner_address="minerX",
        difficulty="0000",
        version="0x01",
        producer_id="FAKE"
    )
    result = bc.add_block(invalid_block)
    assert result is False
    assert len(bc.chain) == 1

def test_blockchain_mining_adds_block(bc):
    block_count_before = len(bc.chain)
    bc.mine_block(transactions=[{
        "txid": "tx123",
        "sender": "A",
        "recipient": "B",
        "amount": 15,
        "type": "transfer",
        "outputs": [{"recipient": "B", "address": "B", "amount": 15}]
    }])
    assert len(bc.chain) == block_count_before + 1
    assert bc.chain[-1].index == block_count_before

def test_get_chain_weight_and_difficulty(bc):
    bc.mine_block([])
    weight = bc.get_chain_weight()
    difficulty = bc.get_total_difficulty()
    assert weight >= 2
    assert isinstance(difficulty, int)
    assert difficulty >= 1

def test_reset_chain_resets_properly(bc):
    bc.mine_block([])
    assert len(bc.chain) > 1
    bc.reset_chain()
    assert len(bc.chain) == 1
    assert bc.chain[0].index == 0

