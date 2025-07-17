from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api.auth import verify_token
from bhrc_blockchain.api import auth_routes
from bhrc_blockchain.api.auth import ROLE_PERMISSIONS

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

def test_admin_action_with_super_admin_token():
    app.dependency_overrides[verify_token] = override_verify_token
    token = "mocktoken"
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/auth/admin-action", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == "Admin işlemi başarıyla çalıştı."
    app.dependency_overrides = {}

def test_super_admin_action_with_super_admin_token():
    app.dependency_overrides[verify_token] = override_verify_token
    token = "mocktoken"
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/auth/super-admin-action", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == "Super admin işlemi başarıyla çalıştı."
    app.dependency_overrides = {}

def test_super_admin_action_forbidden_to_admin():
    def override_admin_token():
        return {
            "sub": "demo",
            "role": "admin",
            "permissions": ["active-sessions"]
        }

    app.dependency_overrides[verify_token] = override_admin_token
    token = "mocktoken"
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/auth/super-admin-action", headers=headers)
    assert response.status_code == 403
    assert "yetkiniz yok" in response.json()["detail"]
    app.dependency_overrides = {}

def test_log_access_with_super_admin():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "admin",
        "role": "super_admin",
        "permissions": list(ROLE_PERMISSIONS["super_admin"])
    }
    response = client.get("/auth/log-access")
    assert response.status_code == 200
    assert "Log erişimine izin verildi" in response.json()["message"]
    app.dependency_overrides = {}

def test_log_access_with_admin_without_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "demo",
        "role": "admin",
        "permissions": ["active-sessions"]
    }
    response = client.get("/auth/log-access")
    assert response.status_code == 403
    assert "view_logs" in response.json()["detail"]
    app.dependency_overrides = {}

def test_log_access_with_admin_with_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "logadmin",
        "role": "admin",
        "permissions": ["view_logs"]
    }
    response = client.get("/auth/log-access")
    assert response.status_code == 200
    assert response.json()["user"] == "logadmin"
    app.dependency_overrides = {}
