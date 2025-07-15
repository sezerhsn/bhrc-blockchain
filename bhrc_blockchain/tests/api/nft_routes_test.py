import pytest
import uuid
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.core.wallet.wallet import generate_wallet

client = TestClient(app)

@pytest.fixture
def jwt_token():
    response = client.post(
        "/auth/token",
        data={"username": "admin", "password": "admin123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]

def test_mint_nft(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    payload = {
        "name": "Test NFT",
        "description": "Bu bir test NFT'sidir.",
        "uri": f"https://example.com/{uuid.uuid4()}.png"
    }

    response = client.post("/nft/mint", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "nft_id" in data
    assert data["message"] == "NFT başarıyla üretildi."

def test_list_all_nfts(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/nft/all", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["nfts"], list)

def test_list_owner_nfts(jwt_token):
    test_wallet = {"address": "admin"}
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get(f"/nft/owner/{test_wallet['address']}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["nfts"], list)

def test_mint_nft_exception_path(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    import bhrc_blockchain.api.nft_routes as nr

    def broken_mint_nft(nft_id, owner, name, desc, uri):
        raise Exception("Simulated minting failure")

    original = nr.mint_nft
    nr.mint_nft = broken_mint_nft

    try:
        payload = {
            "name": "Broken NFT",
            "description": "Should fail",
            "uri": "http://broken-uri"
        }
        response = client.post("/nft/mint", json=payload, headers=headers)
        assert response.status_code == 500
        assert "Simulated minting failure" in response.text  # ⬅️ BU ZORUNLU
    finally:
        nr.mint_nft = original

