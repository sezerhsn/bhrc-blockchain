import os
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api import auth
from jose import jwt, JWTError
import pytest

client = TestClient(app)

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

# 🔒 create_access_token fonksiyonu testi
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
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "true")
    result = auth.verify_token("anytoken")
    assert result == {"sub": "test_user", "role": "admin"}
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
