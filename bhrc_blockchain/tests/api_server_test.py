import pytest
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app

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

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "message" in response.json()
    assert "Swagger" in response.json()["message"]

def test_wallet_address_endpoint_exists(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/wallet/address", params={"private_key": "dummykey"}, headers=headers)
    assert response.status_code in (200, 400, 422)

def test_invalid_endpoint_returns_404():
    response = client.get("/nonexistent-route")
    assert response.status_code == 404

