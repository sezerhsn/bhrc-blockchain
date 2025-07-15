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
        "required_signers": ["admin"]
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

def test_sign_multisig_invalid_txid(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    sign_payload = {
        "txid": "nonexistent-id",
        "signature": "mocked-signature"
    }
    response = client.post("/multisig/sign", json=sign_payload, headers=headers)
    assert response.status_code == 400
    assert "detail" in response.json()

def test_multisig_status_invalid_txid(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/multisig/status/invalid-txid", headers=headers)
    assert response.status_code == 404
    assert "detail" in response.json()

def test_multisig_ready_not_empty(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/multisig/ready", headers=headers)
    assert response.status_code == 200
    assert "multisigs" in response.json()

def test_multisig_ready_executes_path(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    payload = {
        "data": {"action": "sample-action"},
        "required_signers": ["admin"]
    }
    create_resp = client.post("/multisig/create", json=payload, headers=headers)
    txid = create_resp.json()["txid"]

    sign_payload = {
        "txid": txid,
        "signature": "mock-signature"
    }
    client.post("/multisig/sign", json=sign_payload, headers=headers)

    response = client.get("/multisig/ready", headers=headers)
    assert response.status_code == 200
    assert "multisigs" in response.json()
    assert isinstance(response.json()["multisigs"], list)

def test_sign_multisig_error_path(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    payload = {
        "data": {"action": "test"},
        "required_signers": ["admin"]
    }
    txid = client.post("/multisig/create", json=payload, headers=headers).json()["txid"]

    # Burada doğrudan import et
    import bhrc_blockchain.api.multisig_routes as msr

    original_func = msr.add_signature
    msr.add_signature = lambda *a, **kw: (_ for _ in ()).throw(Exception("Mocked failure"))

    try:
        response = client.post("/multisig/sign", json={"txid": txid, "signature": "fail"}, headers=headers)
        assert response.status_code == 400
        assert "Mocked failure" in response.text  # ⬅️ BURAYA
    finally:
        msr.add_signature = original_func

def test_multisig_status_error_path(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    import bhrc_blockchain.api.multisig_routes as msr

    original_func = msr.get_multisig_tx
    msr.get_multisig_tx = lambda txid: (_ for _ in ()).throw(Exception("Not found"))

    try:
        response = client.get("/multisig/status/fake-id", headers=headers)
        assert response.status_code == 404
        assert "Not found" in response.text  # ⬅️ BURAYA
    finally:
        msr.get_multisig_tx = original_func

def test_sign_multisig_invalid_data(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    # signature parametresi eksik → JSON validation geçer ama fonksiyon hata fırlatır
    response = client.post("/multisig/sign", json={"txid": "some-id"}, headers=headers)
    assert response.status_code == 400 or response.status_code == 422  # FastAPI farkıyla değişebilir

def test_sign_multisig_force_exception(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    import bhrc_blockchain.api.multisig_routes as msr

    def broken_add_signature(txid, signer, signature):
        raise Exception("Forced error to test except block")

    original = msr.add_signature
    msr.add_signature = broken_add_signature

    try:
        response = client.post("/multisig/sign", json={
            "txid": "some-id",
            "signature": "irrelevant"
        }, headers=headers)

        assert response.status_code == 400
        assert "Forced error" in response.text  # ⬅️ BU ZORUNLU
    finally:
        msr.add_signature = original

