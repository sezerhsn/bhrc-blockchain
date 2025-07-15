import time
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_public_key_from_private_key, sign_block
from bhrc_blockchain.api.consensus_routes import get_blockchain, evaluate_chain, validate_chain

client = TestClient(app)

def generate_key_pair():
    priv = generate_private_key()
    pub = get_public_key_from_private_key(priv)
    return priv, pub

def test_consensus_evaluate_accepts_heavier_chain():
    blockchain = Blockchain(autoload=False)
    private_key, public_key = generate_key_pair()
    producer_id = "xBHR" + public_key[:59]

    fake_chain = blockchain.chain.copy()
    new_block = Block(
        index=fake_chain[-1].index + 1,
        previous_hash=fake_chain[-1].block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="xFAKE",
        difficulty=blockchain.difficulty_prefix,
        events=["⚠️ Sahte blok eklendi."],
        version="1.0.0",
        merkle_root="abc123",
        producer_id=producer_id,
    )
    new_block.mine()
    new_block.block_signature = sign_block(new_block, private_key)
    fake_chain.append(new_block)

    chain_data = [block.to_dict() for block in fake_chain]

    response = client.post("/consensus/evaluate", json={"chain": chain_data})
    assert response.status_code == 200
    assert "Zincir" in response.json()["message"]

def test_consensus_evaluate_rejects_equal_chain():
    blockchain = Blockchain(autoload=False)
    chain_data = [block.to_dict() for block in blockchain.chain]

    response = client.post("/consensus/evaluate", json={"chain": chain_data})
    assert response.status_code == 200
    assert response.json()["message"] in [
        "✅ Zincir güncellendi. Yeni zincir kabul edildi.",
        "⚖️ Zincir daha ağır değil. Mevcut zincir korundu."
    ]

def test_evaluate_chain_missing_data():
    response = client.post("/consensus/evaluate", json={})
    assert response.status_code == 400
    assert "Zincir verisi eksik" in response.json()["detail"]

def test_evaluate_chain_invalid_block():
    bad_block_data = [{"invalid": "block"}]
    response = client.post("/consensus/evaluate", json={"chain": bad_block_data})
    assert response.status_code == 500
    assert "Hata" in response.json()["detail"]

def test_get_current_chain():
    response = client.get("/consensus/current_chain")
    assert response.status_code == 200
    assert "chain" in response.json()
    assert isinstance(response.json()["chain"], list)

def test_get_chain_weight():
    response = client.get("/consensus/chain_weight")
    assert response.status_code == 200
    assert "weight" in response.json()
    assert isinstance(response.json()["weight"], int)

def test_validate_chain_valid():
    import os
    if os.path.exists("chain.json"):
        os.remove("chain.json")

    blockchain = Blockchain(autoload=False)
    chain_data = [block.to_dict() for block in blockchain.chain]

    response = client.post("/consensus/validate_chain", json={"chain": chain_data})
    assert response.status_code == 200
    assert response.json()["message"] == "✅ Zincir geçerli."

def test_validate_chain_invalid():
    response = client.post("/consensus/validate_chain", json={"chain": [{"invalid": "data"}]})
    assert response.status_code in (400, 500)
    assert "detail" in response.json()

def test_validate_chain_empty():
    response = client.post("/consensus/validate_chain", json={"chain": []})
    assert response.status_code == 400
    assert "Zincir verisi eksik" in response.json()["detail"]

def test_validate_chain_fails_check():
    blockchain = Blockchain(autoload=False)
    fake_chain = blockchain.chain.copy()
    private_key, public_key = generate_key_pair()
    producer_id = "xBHR" + public_key[:59]

    new_block = Block(
        index=fake_chain[-1].index + 1,
        previous_hash="BOZUK_HASH",
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="xFAKE",
        difficulty=blockchain.difficulty_prefix,
        events=["❌ Geçersiz blok eklendi."],
        version="1.0.0",
        merkle_root="xyz789",
        producer_id=producer_id,
    )
    new_block.mine()
    new_block.block_signature = sign_block(new_block, private_key)
    fake_chain.append(new_block)
    chain_data = [b.to_dict() for b in fake_chain]

    response = client.post("/consensus/validate_chain", json={"chain": chain_data})
    assert response.status_code == 200
    assert "geçersiz" in response.json()["message"]

def test_get_blockchain_creates_genesis_block():
    blockchain = get_blockchain()
    assert blockchain.chain[0].index == 0
    assert isinstance(blockchain.chain[0], Block)

def test_evaluate_chain_false_path():
    blockchain = get_blockchain()
    payload = {"chain": [block.to_dict() for block in blockchain.chain]}
    response = evaluate_chain(payload, blockchain)
    assert "Zincir" in response["message"]

def test_validate_chain_false_branch():
    blockchain = get_blockchain()
    bozuk_blok = Block(
        index=1,
        previous_hash="yanlis_hash",
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="xFAKE",
        difficulty=blockchain.difficulty_prefix,
        events=["❌ geçersiz blok"],
        version="1.0.0",
        merkle_root="123",
        producer_id="test",
    )
    bozuk_blok.mine()
    blockchain.chain.append(bozuk_blok)
    chain_data = [b.to_dict() for b in blockchain.chain]
    response = validate_chain({"chain": chain_data}, blockchain)
    assert "geçersiz" in response["message"]

