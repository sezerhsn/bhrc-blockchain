from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_public_key_from_private_key, sign_block
import time
import json

client = TestClient(app)

def generate_key_pair():
    priv = generate_private_key()
    pub = get_public_key_from_private_key(priv)
    return priv, pub

def test_consensus_evaluate_accepts_heavier_chain():
    blockchain = Blockchain(autoload=False)
    original_weight = blockchain.get_chain_weight()

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

    # ✅ Blok hash'i dahil edilmeden zincir verisi hazırlanıyor
    chain_data = []
    for block in fake_chain:
        d = block.to_dict()
        d.pop("block_hash", None)
        chain_data.append(d)

    # 🔍 Log: Zincir JSON çıktısı
    # print("GÖNDERİLEN ZİNCİR JSON:")
    # print(json.dumps(chain_data, indent=2))

    # 🧪 API isteği
    response = client.post("/consensus/evaluate", json={"chain": chain_data})

    # 🔍 Log: API cevabı
    # print("API RESPONSE:")
    # print(response.status_code)
    # print(response.text)

    # ✅ Beklenen: 200 ve başarılı mesaj
    assert response.status_code == 200
    assert "Zincir" in response.json()["message"]

