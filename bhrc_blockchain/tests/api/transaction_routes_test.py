import pytest
from fastapi.testclient import TestClient
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

def test_send_transaction(jwt_token):
    wallet1 = generate_wallet(password="test1", force_new=True)
    wallet2 = generate_wallet(password="test2", force_new=True)
    headers = {"Authorization": f"Bearer {jwt_token}"}

    payload = {
        "sender_private_key": wallet1["private_key"],
        "sender": wallet1["address"],
        "recipient": wallet2["address"],
        "amount": 5.0,
        "message": "test transfer",
        "note": "testing"
    }

    response = client.post("/transaction/send", json=payload, headers=headers)
    assert response.status_code in [201, 400], response.text
    if response.status_code == 201:
        data = response.json()
        assert "txid" in data["data"]
        assert data["message"] == "İşlem kuyruğa alındı."

def test_get_transaction_history(jwt_token):
    wallet = generate_wallet(password="history", force_new=True)
    headers = {"Authorization": f"Bearer {jwt_token}"}

    response = client.get(f"/transaction/history/{wallet['address']}", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()
    assert "transactions" in data["data"]
    assert isinstance(data["data"]["transactions"], list)

def test_list_mempool_transactions(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/transaction/mempool", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()
    assert "transactions" in data["data"]
    assert isinstance(data["data"]["transactions"], list)

