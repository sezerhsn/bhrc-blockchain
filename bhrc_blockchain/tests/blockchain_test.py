import os
import time
import pytest
import bhrc_blockchain.core.blockchain.blockchain as blockchain_module
from copy import deepcopy
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_public_key_from_private_key, sign_block, generate_wallet
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from unittest.mock import patch

@pytest.fixture
def bc():
    blockchain = Blockchain(autoload=False)
    blockchain.reset_chain()
    return blockchain

@patch.object(Blockchain, "validate_chain", return_value=True)
def test_replace_chain_success(mock_validate_chain):
    bc = Blockchain()
    chain_copy = deepcopy(bc.chain)

    priv_key = generate_private_key()
    pub_key = get_public_key_from_private_key(priv_key)

    new_block = Block(
        index=chain_copy[-1].index + 1,
        previous_hash=chain_copy[-1].block_hash,
        transactions=[{
            "sender": "A",
            "recipient": "B",
            "amount": 10,
            "type": "transfer"
        }],
        timestamp=time.time(),
        nonce=123,
        miner_address="minerX",
        difficulty="0000",
        version="0x01",
        producer_id=pub_key
    )
    new_block.block_hash = new_block.calculate_hash()
    new_block.block_signature = sign_block(new_block, priv_key)

    chain_copy.append(new_block)

    chain_data = [b.to_dict() for b in chain_copy]
    result = bc.replace_chain_if_better(chain_data)

    assert result["status"] == "accepted"
    assert result["message"] == "Zincir başarıyla güncellendi."

@patch.object(Blockchain, "save_chain", side_effect=Exception("disk full"))
@patch.object(Blockchain, "validate_chain", return_value=True)
def test_replace_chain_save_error(mock_validate_chain, mock_save_chain):
    bc = Blockchain()
    valid_chain = deepcopy(bc.chain)

    new_block = deepcopy(valid_chain[-1])
    new_block.index += 1
    new_block.previous_hash = valid_chain[-1].block_hash
    new_block.block_hash = "dummy"
    valid_chain.append(new_block)
    chain_data = [b.to_dict() for b in valid_chain]

    result = bc.replace_chain_if_better(chain_data)

    assert result["status"] == "error"
    assert "disk full" in result["message"]

def test_replace_chain_equal_length_rejected():
    bc = Blockchain()
    current_chain = [b.to_dict() for b in bc.chain]
    result = bc.replace_chain_if_better(current_chain)
    assert result["status"] == "rejected"
    assert "kısa veya eşit uzunlukta" in result["message"]

def test_blockchain_load_chain_after_save():
    bc = Blockchain()
    bc.save_chain()

    bc2 = Blockchain()
    assert isinstance(bc2.chain, list)
    assert len(bc2.chain) >= 1
    assert bc2.chain[0].index == 0

def test_blockchain_save_chain_creates_file():
    bc = Blockchain()
    result = bc.save_chain()
    assert result is True
    assert os.path.exists("chain.json")

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
        "transactions": [],
        "timestamp": time.time(),
        "nonce": 0,
        "miner_address": "miner",
        "difficulty": "0000",
        "version": "0x01",
        "producer_id": "fake"
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

def test_genesis_block_validation_failure(monkeypatch):
    def fake_validate_chain(self=None): return False
    monkeypatch.setattr("bhrc_blockchain.core.transaction.validation.ChainValidator.validate_chain", fake_validate_chain)
    blockchain = Blockchain(autoload=False)
    assert len(blockchain.chain) == 1

def test_block_validation_index_mismatch(bc):
    last = bc.get_last_block()
    block = Block(
        index=last.index + 2,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="test",
        difficulty="0000",
        version="0x01",
        producer_id="test"
    )
    assert bc.validate_block(block) is False

def test_replace_chain_rejects_shorter_chain(bc):
    shorter_chain = [b.to_dict() for b in bc.chain]
    result = bc.replace_chain_if_better(shorter_chain)
    assert result["status"] == "rejected"

def test_total_transaction_count(bc):
    tx = {
        "txid": "tx001",
        "sender": "A",
        "recipient": "B",
        "amount": 5,
        "type": "transfer",
        "outputs": [{"recipient": "B", "address": "B", "amount": 5}]
    }
    block = bc.mine_block([tx])
    assert len(block.transactions) == 1
    assert bc.get_total_transaction_count() >= 1

def test_validate_block_index_or_hash_mismatch(bc):
    last = bc.get_last_block()

    block_index_mismatch = Block(
        index=last.index + 2,
        previous_hash=last.block_hash,
        transactions=[], timestamp=time.time(),
        nonce=0, miner_address="A", difficulty="0000",
        version="0x01", producer_id="X"
    )
    assert bc.validate_block(block_index_mismatch) is False

    block_hash_mismatch = Block(
        index=last.index + 1,
        previous_hash="WRONG_HASH",
        transactions=[], timestamp=time.time(),
        nonce=0, miner_address="A", difficulty="0000",
        version="0x01", producer_id="X"
    )
    assert bc.validate_block(block_hash_mismatch) is False

def test_validate_block_previous_hash_mismatch(bc):
    last = bc.get_last_block()
    block = Block(
        index=last.index + 1,
        previous_hash="WRONG_HASH",
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="A",
        difficulty="0000",
        version="0x01",
        producer_id="X"
    )
    assert bc.validate_block(block) is False

def test_genesis_block_valid_chain_logs(caplog):
    bc = Blockchain(autoload=False)
    with caplog.at_level("INFO"):
        bc.create_genesis_block()
    assert "Zincir geçerli." in caplog.text

def test_validate_block_fails_structural(monkeypatch, bc):
    def fake_block_validate(block): return False
    monkeypatch.setattr("bhrc_blockchain.core.block.Block.validate_block", fake_block_validate)

    last = bc.get_last_block()
    block = Block(
        index=last.index + 1,
        previous_hash=last.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=123,
        miner_address="minerX",
        difficulty="0000",
        version="0x01",
        producer_id="test"
    )
    assert bc.validate_block(block) is False

def test_replace_chain_rejects_equal_length(bc):
    current_chain = [b.to_dict() for b in bc.chain]
    result = bc.replace_chain_if_better(current_chain)
    assert result["status"] == "rejected"
    assert "kısa veya eşit uzunlukta" in result["message"]

def test_replace_chain_invalid_validation(monkeypatch, bc):
    monkeypatch.setattr(bc, "validate_chain", lambda chain: False)

    block = bc.get_last_block()

    new_block = Block(
        index=block.index + 1,
        previous_hash=block.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1234,
        miner_address="minerX",
        difficulty="0000",
        version="0x01",
        producer_id="FAKE"
    )
    new_block.block_hash = new_block.calculate_hash()
    new_block.block_signature = sign_block(new_block, bc.miner_wallet.private_key)

    new_block_dict = new_block.to_dict()
    new_block_dict["producer_id"] = new_block.producer_id
    new_block_dict["block_signature"] = new_block.block_signature
    new_block_dict["merkle_root"] = new_block.calculate_merkle_root()

    genesis_block = bc.chain[0]
    genesis_dict = genesis_block.to_dict()
    genesis_dict["producer_id"] = "GENESIS"
    genesis_dict["block_signature"] = "GENESIS_SIG"
    genesis_dict["merkle_root"] = genesis_block.calculate_merkle_root()

    new_chain = [genesis_dict, new_block_dict]

    result = bc.replace_chain_if_better(new_chain)
    print("🚨 result:", result)
    assert result["status"] == "rejected"
    assert "geçersiz" in result["message"]

def test_total_transaction_count_zero_for_empty_chain():
    bc = Blockchain(autoload=False)
    bc.chain = []
    bc.create_genesis_block()
    assert bc.get_total_transaction_count() == 1

@patch.object(Blockchain, "validate_chain", return_value=False)
def test_replace_chain_invalid_validation(mock_validate):
    bc = Blockchain()
    chain_data = [b.to_dict() for b in bc.chain]

    invalid_block = deepcopy(chain_data[-1])
    invalid_block["index"] += 1
    invalid_block["previous_hash"] = chain_data[-1]["block_hash"]
    invalid_block["block_hash"] = "FAKE"
    chain_data.append(invalid_block)

    result = bc.replace_chain_if_better(chain_data)
    assert result["status"] == "rejected"
    assert "geçersiz" in result["message"]

def test_replace_chain_with_malformed_block(monkeypatch):
    bc = Blockchain()
    chain_data = [{"invalid": "block"}]

    result = bc.replace_chain_if_better(chain_data)
    assert result["status"] == "error"
    assert "message" in result

@patch.object(Blockchain, "save_chain", side_effect=Exception("disk full"))
@patch.object(Blockchain, "validate_chain", return_value=True)
def test_replace_chain_save_error(mock_validate_chain, mock_save_chain):
    bc = Blockchain()
    valid_chain = deepcopy(bc.chain)

    new_block = deepcopy(valid_chain[-1])
    new_block.index += 1
    new_block.previous_hash = valid_chain[-1].block_hash
    new_block.block_hash = "dummy"
    valid_chain.append(new_block)
    chain_data = [b.to_dict() for b in valid_chain]

    result = bc.replace_chain_if_better(chain_data)

    assert result["status"] == "error"
    assert "disk full" in result["message"]

