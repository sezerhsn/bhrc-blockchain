from fastapi.testclient import TestClient
from unittest.mock import patch
from bhrc_blockchain.api.api_server import app
import pytest

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

@patch("bhrc_blockchain.core.token.token_contract.TokenContract.balance_of", return_value=1000)
def test_token_balance_endpoint(mock_balance_of, jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get(
        "/token/balance",
        params={"address": "xBHR" + "0" * 60, "symbol": "ABC"},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["balance"] == 1000

