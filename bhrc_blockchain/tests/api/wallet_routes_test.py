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

def test_wallet_create(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.post("/wallet/create", json={"password": "testpass"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "address" in data
    assert "private_key" in data
    assert "public_key" in data

def test_wallet_address(jwt_token):
    wallet = generate_wallet(password="abc123")
    private_key = wallet["private_key"]
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/wallet/address", params={"private_key": private_key}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["address"].startswith("xBHR")

