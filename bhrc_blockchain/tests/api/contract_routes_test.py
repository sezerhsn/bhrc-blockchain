import pytest
import uuid
from fastapi.testclient import TestClient
from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.core.wallet.wallet import generate_wallet

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

def test_submit_contract(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": "return True",
        "message": "Test contract execution",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender": recipient_wallet["address"],
        "sender_private_key": private_key
    }

    print("PAYLOAD:", payload)

    response = client.post("/contract/submit", json=payload, headers=headers)
    assert response.status_code in [200, 400], response.text

    data = response.json()
    if response.status_code == 200:
        assert "txid" in data
        assert data["message"].startswith("Contract işlemi mempool")
    else:
        assert "detail" in data

    app.dependency_overrides = {}

