import pytest
from bhrc_blockchain.api import panel_routes
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from bhrc_blockchain.api.api_server import app

client = TestClient(app)

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

def test_protected_panel_routes(url):
    def fake_user():
        return {"sub": "admin"}
    app.dependency_overrides[panel_routes.get_current_user] = fake_user

    response = client.get(url)
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

    app.dependency_overrides = {}

def test_panel_status_data():
    def fake_user():
        return {"sub": "admin"}
    app.dependency_overrides[panel_routes.get_current_user] = fake_user

    response = client.get("/panel/status-data")
    assert response.status_code == 200
    json_data = response.json()
    assert "total_blocks" in json_data
    assert "total_transactions" in json_data
    assert "mempool_size" in json_data
    assert "difficulty" in json_data
    assert "unique_addresses" in json_data

    app.dependency_overrides = {}

def test_panel_status_page():
    def fake_user():
        return {"sub": "admin"}
    app.dependency_overrides[panel_routes.get_current_user] = fake_user

    response = client.get("/panel/status")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

    app.dependency_overrides = {}

def test_panel_admin_access_granted():
    def fake_admin():
        return {"sub": "admin_user", "role": "admin"}
    app.dependency_overrides[panel_routes.verify_token] = fake_admin

    response = client.get("/panel/admin")
    assert response.status_code == 200

    app.dependency_overrides = {}

def test_panel_admin_access_denied():
    def fake_verify_token():
        return {"sub": "regular_user", "role": "user"}
    app.dependency_overrides[panel_routes.verify_token] = fake_verify_token

    response = client.get("/panel/admin")
    assert response.status_code == 403

    app.dependency_overrides = {}

