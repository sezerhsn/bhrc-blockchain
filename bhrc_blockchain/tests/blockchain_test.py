import os
import time
import pytest
import bhrc_blockchain.core.blockchain.blockchain as blockchain_module
from copy import deepcopy
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.mempool import mempool
from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_public_key_from_private_key, sign_block, generate_wallet
from bhrc_blockchain.core.blockchain.blockchain import Blockchain, get_blockchain
from unittest.mock import patch

def generate_key_pair():
    priv = generate_private_key()
    pub = get_public_key_from_private_key(priv)
    return priv, pub

@pytest.fixture
def bc():
    blockchain = Blockchain(autoload=False)
    blockchain.reset_chain()
    return blockchain

@pytest.fixture
def clean_blockchain():
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

@pytest.fixture(autouse=True)
def setup_and_cleanup():
    mempool.clear_mempool()
    yield
    mempool.clear_mempool()

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

    tx = {
        "txid": "tx123",
        "sender": "A",
        "recipient": "B",
        "amount": 15,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "B", "address": "B", "amount": 15}]
    }

    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

    assert len(bc.chain) == block_count_before + 1
    assert bc.chain[-1].index == block_count_before

def test_get_chain_weight_and_difficulty(bc):
    tx = {
        "txid": "tx456",
        "sender": "X",
        "recipient": "Y",
        "amount": 5,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "Y", "address": "Y", "amount": 5}]
    }

    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

    weight = bc.get_chain_weight()
    difficulty = bc.get_total_difficulty()

    assert weight >= 2
    assert isinstance(difficulty, int)
    assert difficulty >= 1

def test_reset_chain_resets_properly(bc):
    tx = {
        "txid": "tx777",
        "sender": "Z",
        "recipient": "W",
        "amount": 20,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "W", "address": "W", "amount": 20}]
    }

    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

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
        "status": "ready",
        "outputs": [{"recipient": "B", "address": "B", "amount": 5}]
    }

    mempool.add_transaction_to_mempool(tx)
    block = bc.mine_block()

    assert any(tx["txid"] == "tx001" for tx in block.transactions)
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

def test_foundation_cannot_mine_block():
    from bhrc_blockchain.core.blockchain.blockchain import Blockchain
    from bhrc_blockchain.core.wallet.wallet import load_wallet, MinerWallet
    from bhrc_blockchain.config.config import settings
    import os
    import pytest

    if not os.path.exists(settings.FOUNDATION_WALLET_PATH):
        MinerWallet(wallet_path=settings.FOUNDATION_WALLET_PATH, password=settings.FOUNDATION_WALLET_PASSWORD, persist=True)

    blockchain = Blockchain()
    foundation = load_wallet(settings.FOUNDATION_WALLET_PATH, password=settings.FOUNDATION_WALLET_PASSWORD)

    with pytest.raises(ValueError) as excinfo:
        blockchain.mine_block(
            miner_address=foundation.address,
            miner_private_key=foundation.private_key
        )

    assert "Vakfın blok kazma yetkisi yoktur" in str(excinfo.value)

def test_get_chain_weight(bc):
    from bhrc_blockchain.core.mempool import mempool

    tx = {
        "txid": "tx_weight_1",
        "sender": "A",
        "recipient": "B",
        "amount": 10,
        "fee": 1,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "B", "address": "B", "amount": 10}]
    }
    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

    weight = bc.get_chain_weight()
    assert isinstance(weight, int)
    assert weight >= 2

def test_save_chain_writes_to_file(tmp_path):
    from bhrc_blockchain.core.blockchain.blockchain import Blockchain
    import json
    import os

    fake_path = tmp_path / "chain.json"
    bc = Blockchain(autoload=False)
    bc.reset_chain()

    with open(fake_path, "w") as f:
        json.dump([b.to_dict() for b in bc.chain], f, indent=4)

    assert os.path.exists(fake_path)
    with open(fake_path) as f:
        data = json.load(f)
        assert isinstance(data, list)
        assert data[0]["index"] == 0

@patch.object(Blockchain, "validate_chain", return_value=True)
def test_replace_chain_accepts_valid_longer_chain(mock_validate_chain):
    bc = Blockchain()
    from copy import deepcopy

    # Şu anki zinciri yedekle
    old_chain = deepcopy(bc.chain)

    # Yeni zinciri oluştur (daha uzun olacak şekilde)
    priv = generate_private_key()
    pub = get_public_key_from_private_key(priv)

    block = Block(
        index=old_chain[-1].index + 1,
        previous_hash=old_chain[-1].block_hash,
        transactions=[{
            "sender": "A",
            "recipient": "B",
            "amount": 10,
            "type": "transfer",
            "status": "ready",
            "outputs": [{"recipient": "B", "address": "B", "amount": 10}]
        }],
        timestamp=time.time(),
        nonce=123,
        miner_address="minerX",
        difficulty="0000",
        version="0x01",
        producer_id=pub
    )
    block.block_hash = block.calculate_hash()
    block.block_signature = sign_block(block, priv)

    new_chain = old_chain + [block]
    new_chain_data = [b.to_dict() for b in new_chain]

    result = bc.replace_chain_if_better(new_chain_data)

    assert result["status"] == "accepted"
    assert result["message"] == "Zincir başarıyla güncellendi."
    assert len(bc.chain) == len(new_chain)

@patch.object(Blockchain, "validate_chain", return_value=False)
def test_replace_chain_rejects_invalid_block_in_long_chain(mock_validate_chain):
    bc = Blockchain()
    from copy import deepcopy

    old_chain = deepcopy(bc.chain)

    fake_block = deepcopy(old_chain[-1])
    fake_block.index += 1
    fake_block.previous_hash = old_chain[-1].block_hash
    fake_block.block_hash = "INVALID_HASH"

    new_chain = old_chain + [fake_block]
    new_chain_data = [b.to_dict() for b in new_chain]

    result = bc.replace_chain_if_better(new_chain_data)

    assert result["status"] == "rejected"
    assert "geçersiz" in result["message"]
    assert len(bc.chain) == len(old_chain)

@patch.object(Blockchain, "validate_chain", return_value=True)
def test_replace_chain_rejects_equal_length_with_different_content(mock_validate_chain):
    bc = Blockchain()
    from copy import deepcopy

    # Mevcut zincir
    old_chain = deepcopy(bc.chain)

    # Yeni zincir = aynı uzunlukta ama içerik değiştirilmiş
    modified_block = deepcopy(old_chain[-1])
    modified_block.transactions = [{"sender": "X", "recipient": "Y", "amount": 999}]
    modified_block.block_hash = "FAKE_HASH"

    new_chain = old_chain[:-1] + [modified_block]
    new_chain_data = [b.to_dict() for b in new_chain]

    result = bc.replace_chain_if_better(new_chain_data)

    assert result["status"] == "rejected"
    assert "kısa veya eşit uzunlukta" in result["message"]
    assert len(bc.chain) == len(old_chain)

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
        producer_id=public_key,
    )
    new_block.merkle_root = new_block.calculate_merkle_root()
    new_block.block_hash = new_block.calculate_hash()
    new_block.block_signature = sign_block(new_block, private_key)

    result = clean_blockchain.add_block(new_block)
    assert result is True
    assert len(clean_blockchain.chain) == 2
    assert clean_blockchain.chain[1].index == 1

def test_load_chain_from_db_block_parse_error(monkeypatch):
    class BadBlock:
        index = 0
        previous_hash = "0"
        timestamp = time.time()
        transactions = "not-a-json"
        block_hash = "h"
        nonce = 0
        difficulty = "0000"
        events = "[]"
        producer_id = "x"
        block_signature = "sig"
        miner_address = "m"
        merkle_root = "root"
        version = "0x01"

    monkeypatch.setattr("bhrc_blockchain.database.orm_storage.get_session", lambda: type("FakeSession", (), {
        "query": lambda self, model: type("Result", (), {"all": lambda: [BadBlock()]}),
        "close": lambda self: None,
    })())

    bc = Blockchain(autoload=False)
    bc.load_chain_from_db()


def test_replace_chain_from_dict_error(monkeypatch):
    bc = Blockchain()

    monkeypatch.setattr("bhrc_blockchain.core.block.Block.from_dict", lambda data: (_ for _ in ()).throw(Exception("parse error")))

    result = bc.replace_chain_if_better([{"invalid": "block"}])
    assert result["status"] == "error"
    assert "parse error" in result["message"]


def test_replace_chain_invalid(monkeypatch):
    bc = Blockchain()
    monkeypatch.setattr(bc, "validate_chain", lambda c: False)

    fake_chain = [b.to_dict() for b in bc.chain]
    fake_chain.append(fake_chain[0])

    result = bc.replace_chain_if_better(fake_chain)
    assert result["status"] == "rejected"
    assert "geçersiz" in result["message"]


def test_get_blockchain_singleton():
    bc1 = get_blockchain()
    bc2 = get_blockchain()
    assert bc1 is bc2

def test_get_block_by_index_valid(bc):
    tx = {
        "txid": "tx-index-1",
        "sender": "A",
        "recipient": "B",
        "amount": 10,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "B", "address": "B", "amount": 10}]
    }
    from bhrc_blockchain.core.mempool import mempool
    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

    block = bc.get_block_by_index(1)
    assert block is not None
    assert block.index == 1
    assert any(t["txid"] == "tx-index-1" for t in block.transactions)

def test_get_block_by_index_out_of_bounds(bc):
    block = bc.get_block_by_index(99)
    assert block is None

def test_get_block_by_index_negative(bc):
    block = bc.get_block_by_index(-1)
    assert block is None

def test_get_block_by_hash_valid(bc):
    tx = {
        "txid": "tx-hash-1",
        "sender": "X",
        "recipient": "Y",
        "amount": 7,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "Y", "address": "Y", "amount": 7}]
    }
    from bhrc_blockchain.core.mempool import mempool
    mempool.add_transaction_to_mempool(tx)
    new_block = bc.mine_block()

    found = bc.get_block_by_hash(new_block.block_hash)
    assert found is not None
    assert found.block_hash == new_block.block_hash
    assert any(t["txid"] == "tx-hash-1" for t in found.transactions)

def test_get_block_by_hash_not_found(bc):
    result = bc.get_block_by_hash("non_existing_hash_123")
    assert result is None

def test_get_block_range_valid(bc):
    from bhrc_blockchain.core.mempool import mempool

    for i in range(3):
        tx = {
            "txid": f"tx-range-{i}",
            "sender": "X",
            "recipient": "Y",
            "amount": i + 1,
            "type": "transfer",
            "status": "ready",
            "outputs": [{"recipient": "Y", "address": "Y", "amount": i + 1}]
        }
        mempool.add_transaction_to_mempool(tx)
        bc.mine_block()

    blocks = bc.get_block_range(1, 3)
    assert len(blocks) == 3
    assert blocks[0].index == 1
    assert blocks[-1].index == 3

def test_get_block_range_out_of_bounds(bc):
    blocks = bc.get_block_range(5, 10)
    assert blocks == []

def test_get_block_range_invalid_range(bc):
    blocks = bc.get_block_range(3, 1)
    assert blocks == []

def test_get_transaction_found(bc):
    from bhrc_blockchain.core.mempool import mempool
    tx = {
        "txid": "tx-find-me",
        "sender": "A",
        "recipient": "B",
        "amount": 42,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "B", "address": "B", "amount": 42}]
    }
    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

    found = bc.get_transaction("tx-find-me")
    assert found is not None
    assert found["txid"] == "tx-find-me"

def test_get_transaction_not_found(bc):
    result = bc.get_transaction("non-existent-txid-999")
    assert result is None

def test_get_blocks_by_miner_found(bc):
    from bhrc_blockchain.core.mempool import mempool
    miner = "xBHR-MINER-123"

    for i in range(2):
        tx = {
            "txid": f"tx-miner-{i}",
            "sender": "A",
            "recipient": "B",
            "amount": 10 + i,
            "type": "transfer",
            "status": "ready",
            "outputs": [{"recipient": "B", "address": "B", "amount": 10 + i}]
        }
        mempool.add_transaction_to_mempool(tx)
        bc.mine_block(miner_address=miner, miner_private_key=bc.miner_wallet.private_key)

    blocks = bc.get_blocks_by_miner(miner)
    assert isinstance(blocks, list)
    assert len(blocks) == 2
    for b in blocks:
        assert b.miner_address == miner

def test_get_blocks_by_miner_none(bc):
    blocks = bc.get_blocks_by_miner("non-existent-miner")
    assert blocks == []

def test_get_chain_stats_with_blocks(bc):
    from bhrc_blockchain.core.mempool import mempool

    tx = {
        "txid": "tx-stats-1",
        "sender": "A",
        "recipient": "B",
        "amount": 5,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "B", "address": "B", "amount": 5}]
    }
    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

    stats = bc.get_chain_stats()
    assert stats["total_blocks"] >= 2
    assert stats["total_transactions"] >= 2  # genesis + 1
    assert stats["avg_tx_per_block"] >= 1.0
    assert isinstance(stats["chain_weight"], int)
    assert isinstance(stats["total_difficulty"], int)
    assert isinstance(stats["last_block_time"], float)

def test_get_chain_stats_empty_chain():
    bc = Blockchain(autoload=False)
    bc.chain = []
    bc.create_genesis_block()
    stats = bc.get_chain_stats()
    assert stats["total_blocks"] == 1
    assert stats["total_transactions"] == 1
    assert stats["avg_tx_per_block"] == 1.0

def test_verify_transaction_in_chain_true(bc):
    from bhrc_blockchain.core.mempool import mempool

    tx = {
        "txid": "tx-verify-yes",
        "sender": "A",
        "recipient": "B",
        "amount": 50,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "B", "address": "B", "amount": 50}]
    }
    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

    result = bc.verify_transaction_in_chain("tx-verify-yes")
    assert result is True

def test_verify_transaction_in_chain_false(bc):
    result = bc.verify_transaction_in_chain("tx-not-in-chain-000")
    assert result is False

def test_detect_fork_false(bc):
    # Zincirde sadece genesis varsa fork yoktur
    assert bc.detect_fork() is False

def test_detect_fork_true_manual_injection(bc):
    last_block = bc.get_last_block()
    common_prev_hash = last_block.block_hash

    from bhrc_blockchain.core.block import Block
    import time

    block1 = Block(
        index=1,
        previous_hash=common_prev_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="miner1",
        difficulty="0000",
        version="0x01",
        producer_id="A"
    )
    block1.block_hash = block1.calculate_hash()
    block1.block_signature = sign_block(block1, bc.miner_wallet.private_key)

    block2 = Block(
        index=2,
        previous_hash=common_prev_hash,  # intentionally same
        transactions=[],
        timestamp=time.time() + 1,
        nonce=2,
        miner_address="miner2",
        difficulty="0000",
        version="0x01",
        producer_id="B"
    )
    block2.block_hash = block2.calculate_hash()
    block2.block_signature = sign_block(block2, bc.miner_wallet.private_key)

    # Manuel olarak iki blok da ekleniyor (doğrulama atlanarak)
    bc.chain.append(block1)
    bc.chain.append(block2)

    assert bc.detect_fork() is True

def test_get_fork_blocks_empty(bc):
    # Normal zincirde fork yoksa boş liste döner
    fork_blocks = bc.get_fork_blocks()
    assert isinstance(fork_blocks, list)
    assert len(fork_blocks) == 0

def test_get_fork_blocks_detects_fork(bc):
    last_block = bc.get_last_block()
    common_prev_hash = last_block.block_hash

    from bhrc_blockchain.core.block import Block
    import time

    block1 = Block(
        index=1,
        previous_hash=common_prev_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="miner1",
        difficulty="0000",
        version="0x01",
        producer_id="A"
    )
    block1.block_hash = block1.calculate_hash()
    block1.block_signature = sign_block(block1, bc.miner_wallet.private_key)

    block2 = Block(
        index=2,
        previous_hash=common_prev_hash,
        transactions=[],
        timestamp=time.time() + 1,
        nonce=2,
        miner_address="miner2",
        difficulty="0000",
        version="0x01",
        producer_id="B"
    )
    block2.block_hash = block2.calculate_hash()
    block2.block_signature = sign_block(block2, bc.miner_wallet.private_key)

    bc.chain.append(block1)
    bc.chain.append(block2)

    forks = bc.get_fork_blocks()
    assert isinstance(forks, list)
    assert len(forks) == 2
    assert all(b.previous_hash == common_prev_hash for b in forks)

def test_detect_reorg_false_on_clean_chain(bc):
    # Yeni zincirde reorg beklenmez
    assert bc.detect_reorg() is False

def test_detect_reorg_true_on_conflicting_history(bc):
    from bhrc_blockchain.core.block import Block
    import time

    last_block = bc.get_last_block()
    prev_hash = last_block.block_hash

    block1 = Block(
        index=1,
        previous_hash=prev_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=1,
        miner_address="miner1",
        difficulty="0000",
        version="0x01",
        producer_id="X"
    )
    block1.block_hash = block1.calculate_hash()
    block1.block_signature = sign_block(block1, bc.miner_wallet.private_key)

    block2 = Block(
        index=1,  # Aynı index ama farklı previous_hash
        previous_hash="DIFFERENT_HASH",
        transactions=[],
        timestamp=time.time() + 1,
        nonce=2,
        miner_address="miner2",
        difficulty="0000",
        version="0x01",
        producer_id="Y"
    )
    block2.block_hash = block2.calculate_hash()
    block2.block_signature = sign_block(block2, bc.miner_wallet.private_key)

    bc.chain.append(block1)
    bc.chain.append(block2)

    assert bc.detect_reorg(max_depth=5) is True

def test_get_block_time_stats(bc):
    from bhrc_blockchain.core.mempool import mempool
    import time

    # 2 blok kaz, farklı zamanlarda
    for i in range(2):
        tx = {
            "txid": f"tx-time-{i}",
            "sender": "A",
            "recipient": "B",
            "amount": i + 1,
            "type": "transfer",
            "status": "ready",
            "outputs": [{"recipient": "B", "address": "B", "amount": i + 1}]
        }
        mempool.add_transaction_to_mempool(tx)
        time.sleep(1)  # zaman farkı oluşsun
        bc.mine_block()

    stats = bc.get_block_time_stats()
    assert stats["total_blocks"] >= 3  # genesis + 2 kazım
    assert len(stats["intervals"]) == stats["total_blocks"] - 1
    assert stats["avg_time"] > 0
    assert stats["max_time"] >= stats["min_time"]

def test_get_chain_snapshot_hash(bc):
    snapshot1 = bc.get_chain_snapshot_hash()

    from bhrc_blockchain.core.mempool import mempool
    tx = {
        "txid": "tx-hash-test",
        "sender": "X",
        "recipient": "Y",
        "amount": 7,
        "type": "transfer",
        "status": "ready",
        "outputs": [{"recipient": "Y", "address": "Y", "amount": 7}]
    }
    mempool.add_transaction_to_mempool(tx)
    bc.mine_block()

    snapshot2 = bc.get_chain_snapshot_hash()

    assert isinstance(snapshot1, str)
    assert isinstance(snapshot2, str)
    assert snapshot1 != snapshot2  # blok eklendi, hash değişmeli

