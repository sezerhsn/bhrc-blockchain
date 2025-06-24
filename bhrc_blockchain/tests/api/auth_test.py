import os
import pytest
from fastapi.testclient import TestClient
from fastapi import Request
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api import auth
from jose import jwt, JWTError
from bhrc_blockchain.api.auth import verify_token

client = TestClient(app)

def test_verify_token_missing_sub_key_explicit(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"role": "admin"})
    auth_header = f"Bearer {token}"
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(authorization=auth_header)
    assert excinfo.value.status_code == 401
    assert "Geçersiz kullanıcı" in excinfo.value.detail

def test_get_current_user_missing_token():
    request = Request(scope={"type": "http", "headers": []})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_user(request)
    assert excinfo.value.status_code == 401
    assert "Giriş yapılmamış" in excinfo.value.detail

def test_admin_required_forbidden_inner():
    admin_dep = auth.admin_required("admin")
    with pytest.raises(auth.HTTPException) as excinfo:
        admin_dep(user={"sub": "abc", "role": "user"})
    assert excinfo.value.status_code == 403
    assert "yetkiniz yok" in excinfo.value.detail

def test_get_current_admin_super_admin_token():
    token = auth.create_access_token({
        "sub": "admin",
        "role": "super_admin",
        "permissions": ["view_logs"]
    })
    result = auth.get_current_admin(token)
    assert result["sub"] == "admin"
    assert result["role"] == "super_admin"
    assert "permissions" in result
    assert "view_logs" in result["permissions"]

def test_verify_token_missing_sub_key(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    token = auth.create_access_token({"role": "admin"})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(authorization=f"Bearer {token}")
    assert excinfo.value.status_code == 401

def test_get_current_user_no_cookie_or_header():
    req = Request(scope={"type": "http", "headers": []})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_user(req)
    assert excinfo.value.status_code == 401

def test_admin_required_inner_dependency_triggered():
    dependency = auth.admin_required("admin")
    def fake_user():
        return {"sub": "abc", "role": "user"}
    with pytest.raises(auth.HTTPException) as excinfo:
        dependency(fake_user())
    assert excinfo.value.status_code == 403

def test_get_current_admin_valid_super_admin():
    token = auth.create_access_token({
        "sub": "admin",
        "role": "super_admin",
        "permissions": ["clear-mempool"]
    })
    result = auth.get_current_admin(token)
    assert result["sub"] == "admin"
    assert result["role"] == "super_admin"
    assert "permissions" in result

def test_verify_token_missing_username(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"role": "admin"})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(authorization=f"Bearer {token}")
    assert excinfo.value.status_code == 401

def test_get_current_user_no_token_anywhere():
    req = Request(scope={"type": "http", "headers": []})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_user(req)
    assert excinfo.value.status_code == 401

def test_admin_required_user_forbidden():
    dep = auth.admin_required("admin")
    with pytest.raises(auth.HTTPException) as excinfo:
        dep(user={"sub": "someuser", "role": "user"})
    assert excinfo.value.status_code == 403

def test_get_current_admin_success():
    token = auth.create_access_token({
        "sub": "admin",
        "role": "super_admin",
        "permissions": ["view_logs"]
    })
    result = auth.get_current_admin(token)
    assert result["sub"] == "admin"
    assert result["role"] == "super_admin"

def test_verify_token_invalid_token_raises(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("BHRC_TEST_MODE", "0")

    from jose import jwt
    invalid_token = jwt.encode({"sub": "test"}, "wrong-secret", algorithm=auth.ALGORITHM)
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(authorization=f"Bearer {invalid_token}")
    assert excinfo.value.status_code == 401

def test_verify_token_missing_sub_with_valid_token(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("BHRC_TEST_MODE", "0")

    token = auth.create_access_token({})
    headers = {"authorization": f"Bearer {token}"}
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(authorization=headers["authorization"], request=request)
    assert excinfo.value.status_code == 401

def test_get_current_user_missing_both():
    request = Request(scope={"type": "http", "headers": []})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_user(request)
    assert excinfo.value.status_code == 401

def test_admin_required_user_role():
    dependency = auth.admin_required("admin")
    with pytest.raises(auth.HTTPException) as excinfo:
        dependency(user={"sub": "abc", "role": "user"})
    assert excinfo.value.status_code == 403

def test_get_current_user_raises_when_no_token():
    req = Request(scope={"type": "http", "headers": []})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_user(req)
    assert excinfo.value.status_code == 401

def test_admin_required_forbidden():
    dep = auth.admin_required("admin")
    with pytest.raises(auth.HTTPException) as excinfo:
        dep(user={"sub": "demo", "role": "user"})
    assert excinfo.value.status_code == 403

def test_get_current_admin_returns_admin():
    token = auth.create_access_token({
        "sub": "admin",
        "role": "admin",
        "permissions": ["view_logs"]
    })
    result = auth.get_current_admin(token)
    assert result["sub"] == "admin"
    assert result["role"] == "admin"

def test_verify_token_no_token_raises(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(authorization=None)
    assert excinfo.value.status_code == 401

def test_verify_token_missing_sub_raises(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    token = auth.create_access_token({})
    auth_header = f"Bearer {token}"
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(authorization=auth_header)
    assert excinfo.value.status_code == 401

def test_get_current_user_no_token_raises():
    req = Request(scope={"type": "http", "headers": []})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_user(req)
    assert excinfo.value.status_code == 401

def test_admin_required_rejects_non_admin():
    dep = auth.admin_required("admin")
    with pytest.raises(auth.HTTPException) as excinfo:
        dep(user={"sub": "test", "role": "user"})
    assert excinfo.value.status_code == 403

def test_get_current_admin_insufficient_role():
    token = auth.create_access_token({"sub": "test", "role": "user"})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_admin(token)
    assert excinfo.value.status_code == 403

def test_get_current_admin_with_admin_token():
    token = auth.create_access_token({
        "sub": "admin",
        "role": "admin",
        "permissions": ["view_logs"]
    })
    result = auth.get_current_admin(token)
    assert result["role"] == "admin"
    assert result["sub"] == "admin"

def test_valid_login_returns_token():
    response = client.post(
        "/auth/token",
        data={"username": "admin", "password": "admin123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_invalid_login_rejected_wrong_password():
    response = client.post(
        "/auth/token",
        data={"username": "admin", "password": "wrongpw"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Giriş reddedildi"

def test_invalid_login_rejected_wrong_username():
    response = client.post(
        "/auth/token",
        data={"username": "notadmin", "password": "admin123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Giriş reddedildi"

def test_create_access_token_contains_sub():
    token = auth.create_access_token({"sub": "testuser"})
    payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
    assert payload["sub"] == "testuser"

def test_verify_token_returns_expected_user():
    os.environ.pop("PYTEST_CURRENT_TEST", None)
    os.environ.pop("BHRC_TEST_MODE", None)
    token = auth.create_access_token({"sub": "testuser"})
    auth_header = f"Bearer {token}"
    result = auth.verify_token(authorization=auth_header)
    assert result == {"sub": "testuser", "role": "user"}

def test_verify_token_invalid_signature():
    os.environ.pop("PYTEST_CURRENT_TEST", None)
    os.environ.pop("BHRC_TEST_MODE", None)
    invalid_token = jwt.encode({"sub": "anyuser"}, "wrong-secret", algorithm=auth.ALGORITHM)
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(invalid_token)
    assert excinfo.value.status_code == 401

def test_verify_token_bypasses_in_pytest_env(monkeypatch):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")

    result = verify_token()

    assert result == {
        "sub": "admin",
        "role": "super_admin",
        "permissions": [
            "clear-mempool",
            "active-sessions",
            "snapshot",
            "rollback",
            "reset-chain",
            "update_role",
            "deactivate_user",
            "view_logs"
        ]
    }

