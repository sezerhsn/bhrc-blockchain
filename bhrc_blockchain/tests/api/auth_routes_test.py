from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api.auth import verify_token
from bhrc_blockchain.api import auth_routes

client = TestClient(app)

def override_verify_token():
    return {
        "sub": "admin",
        "role": "super_admin",
        "permissions": ["clear-mempool", "active-sessions", "snapshot", "rollback", "reset-chain", "update_role", "deactivate_user", "view_logs"]
    }

def test_get_me():
    app.dependency_overrides[verify_token] = override_verify_token
    token = "mocktoken"
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == "admin"
    app.dependency_overrides = {}

def test_refresh_token():
    app.dependency_overrides[verify_token] = override_verify_token
    token = "mocktoken"
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/auth/refresh", headers=headers)
    assert response.status_code == 200
    assert "access_token" in response.json()
    app.dependency_overrides = {}

def test_logout():
    app.dependency_overrides[auth_routes.get_current_admin] = override_get_current_admin

    response = client.post("/auth/logout")

    assert response.status_code == 200
    assert response.json()["message"] == "Çıkış yapıldı"

    app.dependency_overrides = {}

def test_login_success():
    response = client.post("/auth/token", data={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_login_failure():
    response = client.post("/auth/token", data={"username": "admin", "password": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Giriş reddedildi"

def test_auth_status():
    response = client.get("/auth/status")
    assert response.status_code == 200
    assert response.json() == {
        "status": "Auth sistemi aktif",
        "login_required": True
    }

def override_get_current_admin():
    return {
        "sub": "admin",
        "role": "super_admin",
        "permissions": ["clear-mempool", "active-sessions", "snapshot", "rollback", "reset-chain", "update_role", "deactivate_user", "view_logs"]
    }

