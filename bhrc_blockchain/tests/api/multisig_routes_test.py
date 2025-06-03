import pytest
import uuid
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

def test_create_multisig(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    payload = {
        "data": {"action": "sample-action", "value": str(uuid.uuid4())},
        "required_signers": ["admin", "demo"]
    }

    response = client.post("/multisig/create", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "txid" in data
    return data["txid"]

def test_sign_multisig(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    txid = test_create_multisig(jwt_token)

    sign_payload = {
        "txid": txid,
        "signature": "mocked-signature-hex"
    }

    response = client.post("/multisig/sign", json=sign_payload, headers=headers)
    assert response.status_code in [200, 400], response.text
    if response.status_code == 200:
        assert response.json()["message"] == "İmza eklendi"

def test_list_pending_and_ready(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    pending_resp = client.get("/multisig/pending", headers=headers)
    assert pending_resp.status_code == 200
    assert isinstance(pending_resp.json()["multisigs"], list)

    ready_resp = client.get("/multisig/ready", headers=headers)
    assert ready_resp.status_code == 200
    assert isinstance(ready_resp.json()["multisigs"], list)

def test_get_multisig_status(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    txid = test_create_multisig(jwt_token)

    status_resp = client.get(f"/multisig/status/{txid}", headers=headers)
    assert status_resp.status_code == 200
    assert "tx" in status_resp.json()

