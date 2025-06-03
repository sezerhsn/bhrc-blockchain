import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from bhrc_blockchain.api.api_server import app

client = TestClient(app)

@pytest.mark.parametrize("url", [
    "/panel/login",
])
def test_public_panel_routes(url):
    response = client.get(url)
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

@pytest.mark.parametrize("url", [
    "/panel/wallet",
    "/panel/token",
    "/panel/nft",
    "/panel/explorer",
    "/panel/overview",
    "/panel/graph",
    "/panel/transfer",
    "/panel/history",
    "/panel/home"
])
@patch("bhrc_blockchain.api.panel_routes.get_current_user", return_value={"sub": "test_user"})
def test_protected_panel_routes(mock_user, url):
    response = client.get(url)
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_panel_status_data():
    with patch("bhrc_blockchain.api.panel_routes.get_current_user", return_value={"sub": "test_user"}):
        response = client.get("/panel/status-data")
        assert response.status_code == 200
        json_data = response.json()
        assert "total_blocks" in json_data
        assert "total_transactions" in json_data
        assert "mempool_size" in json_data
        assert "difficulty" in json_data
        assert "unique_addresses" in json_data

def test_panel_status_page():
    with patch("bhrc_blockchain.api.panel_routes.get_current_user", return_value={"sub": "test_user"}):
        response = client.get("/panel/status")
        assert response.status_code == 200
        assert isinstance(response.content, bytes)

def test_panel_admin_access_granted():
    with patch("bhrc_blockchain.api.panel_routes.verify_token", return_value={"sub": "admin_user", "role": "admin"}):
        response = client.get("/panel/admin")
        assert response.status_code == 200

def test_panel_admin_access_denied():
    from bhrc_blockchain.api import panel_routes

    # Sahte kullanıcı bilgisi
    def fake_verify_token():
        return {"sub": "regular_user", "role": "user"}

    # override et
    app.dependency_overrides[panel_routes.verify_token] = fake_verify_token

    response = client.get("/panel/admin")
    assert response.status_code == 403

    # override'ı temizle
    app.dependency_overrides = {}

