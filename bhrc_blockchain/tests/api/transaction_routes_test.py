import pytest
from unittest.mock import patch
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

@patch("bhrc_blockchain.api.transaction_routes.watch_transaction_confirmation", return_value=None)
def test_send_transaction(mock_watch, jwt_token):
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

@patch("bhrc_blockchain.api.transaction_routes.watch_transaction_confirmation", return_value=None)
def test_simple_transfer(mock_watch, jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    payload = {
        "to_address": "bhrc_test_address_123",
        "amount": 1.5,
        "message": "panelden gönderim testi"
    }

    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code in [201, 400], response.text
    if response.status_code == 201:
        assert "txid" in response.json()["data"]

def test_send_transaction_missing_fields(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    payload = {
        "sender": "abc",  # eksik `sender_private_key`
        "recipient": "xyz",
        "amount": 1.0
    }
    response = client.post("/transaction/send", json=payload, headers=headers)
    assert response.status_code == 422  # Pydantic doğrulama hatası

def test_simple_transfer_invalid_token():
    payload = {
        "to_address": "xyz",
        "amount": 1.0,
        "message": "invalid token test"
    }
    response = client.post("/transaction/api/transfer", json=payload, headers={"Authorization": "Bearer FAKE_TOKEN"})
    assert response.status_code in [400, 403]  # geçersiz token nedeniyle reddedildi

def test_simple_transfer_invalid_payload(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    payload = {
        "to_address": "",  # geçersiz adres
        "amount": -1.0,    # geçersiz miktar
        "message": "hatalı giriş"
    }
    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code == 400
    assert "İşlem başarısız" in response.text

def test_list_mempool_transactions_exception(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def raise_error():
        raise Exception("Mempool bağlantı hatası")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.get_ready_transactions", raise_error)

    response = client.get("/transaction/mempool", headers=headers)
    assert response.status_code == 500
    assert "Mempool alınamadı" in response.text

def test_simple_transfer_wallet_load_error(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def broken_loader(path):
        raise Exception("Dosya bozuk")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.load_wallet", broken_loader)

    payload = {
        "to_address": "x123",
        "amount": 1.0,
        "message": "hata testi"
    }

    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code == 400
    assert "İşlem başarısız" in response.text

def test_simple_transfer_wallet_load_fail(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def broken_loader(path):
        raise Exception("Cüzdan yüklenemedi")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.load_wallet", broken_loader)

    payload = {
        "to_address": "xyz",
        "amount": 2.0,
        "message": "cüzdan hatası"
    }

    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code == 400
    assert "İşlem başarısız" in response.text

def test_get_transaction_history_with_error(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    class BrokenBlockchain:
        @property
        def chain(self):
            raise Exception("Blockchain erişimi başarısız")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.blockchain", BrokenBlockchain())

    response = client.get("/transaction/history/test_address", headers=headers)
    assert response.status_code == 500
    assert "Hata" in response.text

def test_simple_transfer_transaction_fail(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def broken_create_transaction(*args, **kwargs):
        raise Exception("Oluşturma başarısız")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.create_transaction", broken_create_transaction)

    payload = {
        "to_address": "xyz",
        "amount": 1.0,
        "message": "deneme"
    }

    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code == 400
    assert "İşlem başarısız" in response.text

def test_simple_transfer_explicit_exception(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def faulty_create_transaction(*args, **kwargs):
        raise Exception("zorunlu hata")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.create_transaction", faulty_create_transaction)

    payload = {
        "to_address": "abc",
        "amount": 1.0,
        "message": "zorunlu hata tetikleme"
    }

    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code == 400
    assert "İşlem başarısız" in response.text

def test_simple_transfer_observer_error(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def dummy_wallet(path):
        return {
            "address": "dummy",
            "private_key": "dummy_key"
        }

    def dummy_tx(*args, **kwargs):
        return {
            "txid": "tx123",
            "status": "ready"
        }

    def fail_watcher(txid, blockchain):
        raise Exception("gözlem hatası")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.load_wallet", dummy_wallet)
    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.create_transaction", dummy_tx)
    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.watch_transaction_confirmation", fail_watcher)

    payload = {
        "to_address": "receiver",
        "amount": 1.0,
        "message": "gözlem testi"
    }

    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code == 400
    assert "İşlem başarısız" in response.text

def test_get_transaction_history_with_chain_error(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    class BrokenBlockchain:
        @property
        def chain(self):
            raise Exception("Zincire erişilemedi")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.blockchain", BrokenBlockchain())

    response = client.get("/transaction/history/anyaddress", headers=headers)
    assert response.status_code == 500
    assert "Hata" in response.text

def test_simple_transfer_force_exception_block(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def broken(*args, **kwargs):
        raise Exception("zorunlu hata")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.load_wallet", broken)
    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.create_transaction", broken)

    payload = {
        "to_address": "xyz",
        "amount": 1.0,
        "message": "deneme"
    }

    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code == 400
    assert "İşlem başarısız" in response.text

def test_simple_transfer_watcher_exception(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def dummy_wallet(path):
        return {"address": "addr", "private_key": "key"}

    def dummy_tx(*args, **kwargs):
        return {"txid": "txid123", "status": "ready"}

    class FakeBackgroundTasks:
        def add_task(self, func, *args, **kwargs):
            raise Exception("gözlem hatası")

    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.load_wallet", dummy_wallet)
    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.create_transaction", dummy_tx)
    monkeypatch.setattr("bhrc_blockchain.api.transaction_routes.BackgroundTasks", lambda: FakeBackgroundTasks())

    payload = {
        "to_address": "abc",
        "amount": 1.0,
        "message": "watcher fail"
    }

    response = client.post("/transaction/api/transfer", json=payload, headers=headers)
    assert response.status_code == 400
    assert "İşlem başarısız" in response.text

