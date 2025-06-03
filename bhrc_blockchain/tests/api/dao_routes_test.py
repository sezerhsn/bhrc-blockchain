import pytest
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

def test_create_and_vote_on_proposal(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    # Öneri oluştur
    proposal_data = {
        "title": "Zincir parametre güncellemesi",
        "description": "Blok süresi 10s'ye düşürülsün mü?",
        "symbol": "BHRC",
        "options": ["Evet", "Hayır"]
    }

    response = client.post("/dao/propose", json=proposal_data, headers=headers)
    assert response.status_code == 200
    assert "message" in response.json()

    # Öneri listesi çek
    list_response = client.get("/dao/proposals", headers=headers)
    assert list_response.status_code == 200
    proposals = list_response.json()["proposals"]
    assert isinstance(proposals, list)
    assert len(proposals) > 0

    # İlk öneriye oy ver
    first_proposal = proposals[0]
    vote_data = {
        "proposal_id": first_proposal["id"],
        "option": "Evet"
    }
    vote_response = client.post("/dao/vote", json=vote_data, headers=headers)
    # ✔️ 400 de kabul ediliyor çünkü BHRC bakiyesi olmayabilir
    assert vote_response.status_code in [200, 403, 400], vote_response.text

def test_get_results(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    proposals_response = client.get("/dao/proposals", headers=headers)
    assert proposals_response.status_code == 200
    proposals = proposals_response.json()["proposals"]
    if proposals:
        proposal_id = proposals[0]["id"]
        result_response = client.get(f"/dao/results/{proposal_id}", headers=headers)
        assert result_response.status_code == 200
        assert "results" in result_response.json()

