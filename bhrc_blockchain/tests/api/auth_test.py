import pytest
from fastapi import Request
from bhrc_blockchain.api import auth
from jose import jwt
def test_verify_token_missing_sub_key_explicit(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"role": "admin"})
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(request)
    assert excinfo.value.status_code == 401
    assert "Geçersiz kullanıcı" in excinfo.value.detail

def test_verify_token_missing_sub_key(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"role": "admin"})
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(request)
    assert excinfo.value.status_code == 401

def test_verify_token_missing_username(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"role": "admin"})
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(request)
    assert excinfo.value.status_code == 401

def test_verify_token_invalid_token_raises(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    from jose import jwt
    invalid_token = jwt.encode({"sub": "test"}, "wrong-secret", algorithm=auth.ALGORITHM)
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {invalid_token}".encode())]})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(request)
    assert excinfo.value.status_code == 401

def test_verify_token_missing_sub_with_valid_token(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({})
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(request)
    assert excinfo.value.status_code == 401

def test_verify_token_no_token_raises(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    request = Request(scope={"type": "http", "headers": []})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(request)
    assert excinfo.value.status_code == 401

def test_verify_token_missing_sub_raises(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({})
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(request)
    assert excinfo.value.status_code == 401

def test_verify_token_returns_expected_user(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"sub": "testuser"})
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})
    result = auth.verify_token(request)
    assert result == {"sub": "testuser", "role": "user", "permissions": []}

def test_verify_token_invalid_signature(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    invalid_token = jwt.encode({"sub": "anyuser"}, "wrong-secret", algorithm=auth.ALGORITHM)
    request = Request(scope={"type": "http", "headers": [(b"authorization", f"Bearer {invalid_token}".encode())]})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.verify_token(request)
    assert excinfo.value.status_code == 401

def test_verify_token_bypasses_in_pytest_env(monkeypatch):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    request = Request(scope={"type": "http", "headers": []})
    result = auth.verify_token(request)
    assert result["sub"] == "admin"
    assert result["role"] == "super_admin"
    assert set(result["permissions"]) == set([
        "clear-mempool",
        "active-sessions",
        "snapshot",
        "rollback",
        "reset-chain",
        "update_role",
        "deactivate_user",
        "view_logs"
    ])

def test_get_current_user_reads_from_authorization_header(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"sub": "demo", "role": "admin"})
    headers = [(b"authorization", f"Bearer {token}".encode())]
    request = Request(scope={"type": "http", "headers": headers})
    request._cookies = {}
    result = auth.get_current_user(request)
    assert result["sub"] == "demo"
    assert result["role"] == "admin"

def test_admin_required_allows_exact_role(monkeypatch):
    dependency = auth.admin_required("admin")
    user = {
        "sub": "userx",
        "role": "admin",
        "permissions": []
    }
    result = dependency(user)
    assert result["sub"] == "userx"

def test_admin_required_blocks_if_permission_missing(monkeypatch):
    dependency = auth.admin_required("admin", required_permission="reset-chain")
    user = {
        "sub": "admin1",
        "role": "admin",
        "permissions": ["view_logs"]
    }
    with pytest.raises(auth.HTTPException) as excinfo:
        dependency(user)
    assert excinfo.value.status_code == 403
    assert "reset-chain" in excinfo.value.detail

def test_admin_required_allows_permission(monkeypatch):
    dependency = auth.admin_required("admin", required_permission="view_logs")
    user = {
        "sub": "admin2",
        "role": "admin",
        "permissions": ["view_logs"]
    }
    result = dependency(user)
    assert result["sub"] == "admin2"

def test_get_current_admin_rejects_insufficient_role():
    token = auth.create_access_token({"sub": "normaluser", "role": "user"})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_admin(token)
    assert excinfo.value.status_code == 403
    assert "Yetersiz yetki" in excinfo.value.detail

def test_get_current_admin_accepts_admin_role():
    token = auth.create_access_token({
        "sub": "adminuser",
        "role": "admin",
        "permissions": ["view_logs"]
    })
    result = auth.get_current_admin(token)
    assert result["sub"] == "adminuser"
    assert result["role"] == "admin"
    assert "view_logs" in result["permissions"]

def test_get_current_admin_accepts_super_admin_role():
    token = auth.create_access_token({
        "sub": "rootadmin",
        "role": "super_admin",
        "permissions": ["rollback"]
    })
    result = auth.get_current_admin(token)
    assert result["sub"] == "rootadmin"
    assert result["role"] == "super_admin"
    assert "rollback" in result["permissions"]

def test_verify_token_bypass_mode_has_full_permissions(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "1")
    request = Request(scope={"type": "http", "headers": []})
    result = auth.verify_token(request)
    assert result["role"] == "super_admin"
    assert set(result["permissions"]) == set(auth.ROLE_PERMISSIONS["super_admin"])

def test_get_current_user_fallbacks_to_header(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"sub": "admin", "role": "admin"})
    headers = [(b"authorization", f"Bearer {token}".encode())]
    request = Request(scope={"type": "http", "headers": headers})
    request._cookies = {}

    result = auth.get_current_user(request)
    assert result["sub"] == "admin"

def test_admin_required_without_permission_argument():
    dependency = auth.admin_required("admin")
    user = {
        "sub": "demo",
        "role": "admin",
        "permissions": []
    }
    result = dependency(user)
    assert result["role"] == "admin"

def test_get_current_admin_defaults_to_user_role():
    token = auth.create_access_token({"sub": "no_role"})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_admin(token)
    assert excinfo.value.status_code == 403
    assert "Yetersiz yetki" in excinfo.value.detail

def test_get_current_user_force_header_path(monkeypatch):
    monkeypatch.setenv("BHRC_TEST_MODE", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    token = auth.create_access_token({"sub": "x", "role": "admin"})
    headers = [(b"authorization", f"Bearer {token}".encode())]
    req = Request(scope={"type": "http", "headers": headers})
    req._cookies = {}
    _ = auth.get_current_user(req)

def test_admin_required_with_no_permission_param():
    user = {"sub": "admin", "role": "admin", "permissions": []}
    dep = auth.admin_required("admin", required_permission=None)
    result = dep(user)
    assert result["sub"] == "admin"

def test_get_current_admin_role_fallback_to_default_user():
    token = auth.create_access_token({"sub": "x"})
    with pytest.raises(auth.HTTPException) as excinfo:
        auth.get_current_admin(token)
    assert excinfo.value.status_code == 403

