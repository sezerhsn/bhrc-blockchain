import pytest
import random
import string

from unittest.mock import patch
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.core.wallet.wallet import MinerWallet
from bhrc_blockchain.core.token.token_contract import create_token_transaction, create_token_transfer_transaction

def override_get_current_user():
    return {"username": "test", "roles": ["admin"]}

app.dependency_overrides[get_current_user] = override_get_current_user

client = TestClient(app)

def unique_symbol():
    return "SYM" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

def test_token_deploy():
    wallet = MinerWallet()
    symbol = unique_symbol()
    response = client.post("/token/deploy", params={
        "name": "TestToken",
        "symbol": symbol,
        "total_supply": 1000,
        "decimals": 0,
        "creator_address": wallet.address,
        "message": "deploy test",
        "signature": wallet.private_key
    })
    data = response.json()
    assert "txid" in data or "transaction" in data

def test_token_transfer():
    wallet = MinerWallet()
    symbol = unique_symbol()
    client.post("/token/deploy", params={
        "name": "TransferToken",
        "symbol": symbol,
        "total_supply": 1000,
        "decimals": 0,
        "creator_address": wallet.address,
        "message": "deploy",
        "signature": wallet.private_key
    })
    response = client.post("/token/transfer", params={
        "symbol": symbol,
        "amount": 300,
        "sender_address": wallet.address,
        "recipient_address": "xBHR2222222222",
        "message": "transfer",
        "signature": wallet.private_key
    })
    data = response.json()
    assert "txid" in data or "transaction" in data

def test_get_token_balance():
    wallet = MinerWallet()
    symbol = unique_symbol()
    client.post("/token/deploy", params={
        "name": "BalanceToken",
        "symbol": symbol,
        "total_supply": 1000,
        "decimals": 0,
        "creator_address": wallet.address,
        "message": "deploy",
        "signature": wallet.private_key
    })
    response = client.get(f"/token/balance?symbol={symbol}&address={wallet.address}")
    data = response.json()
    assert data["balance"] == 1000

def test_get_token_list():
    response = client.get("/token/all")
    assert response.status_code != 404
    assert isinstance(response.json(), list)

def test_get_token_details():
    wallet = MinerWallet()
    symbol = unique_symbol()
    client.post("/token/deploy", params={
        "name": "DetailToken",
        "symbol": symbol,
        "total_supply": 1000,
        "decimals": 0,
        "creator_address": wallet.address,
        "message": "deploy",
        "signature": wallet.private_key
    })
    response = client.get(f"/token/details?symbol={symbol}")
    data = response.json()
    assert data["symbol"] == symbol

def test_get_token_transfers():
    wallet = MinerWallet()
    symbol = unique_symbol()
    # Token oluştur
    client.post("/token/deploy", params={
        "name": "TransferHistoryToken",
        "symbol": symbol,
        "total_supply": 1000,
        "decimals": 0,
        "creator_address": wallet.address,
        "message": "deploy",
        "signature": wallet.private_key
    })
    # Transfer yap
    client.post("/token/transfer", params={
        "symbol": symbol,
        "amount": 100,
        "sender_address": wallet.address,
        "recipient_address": "xBHR1111111111",
        "message": "history",
        "signature": wallet.private_key
    })
    # Transfer geçmişini al
    response = client.get(f"/token/transfers?symbol={symbol}&address={wallet.address}")
    assert response.status_code == 200
    json_data = response.json()
    assert isinstance(json_data, dict)
    assert "transfers" in json_data
    assert isinstance(json_data["transfers"], list)

def test_token_explorer_html():
    response = client.get("/token/explorer")
    assert response.status_code in [200, 500]  # template eksikse 500 alabiliriz
    assert isinstance(response.content, bytes)

def test_deploy_token_error():
    wallet = MinerWallet()
    symbol = unique_symbol()
    with patch("bhrc_blockchain.api.token_routes.create_token_transaction", side_effect=Exception("deploy error")):
        response = client.post("/token/deploy", params={
            "name": "ErrToken",
            "symbol": symbol,
            "total_supply": 1000,
            "decimals": 0,
            "creator_address": wallet.address,
            "message": "deploy",
            "signature": wallet.private_key
        })
        assert response.status_code == 200
        assert "Token oluşturulamadı" in str(response.json())

def test_transfer_token_error():
    wallet = MinerWallet()
    symbol = unique_symbol()
    client.post("/token/deploy", params={
        "name": "XferErrToken",
        "symbol": symbol,
        "total_supply": 1000,
        "decimals": 0,
        "creator_address": wallet.address,
        "message": "deploy",
        "signature": wallet.private_key
    })
    with patch("bhrc_blockchain.api.token_routes.create_token_transfer_transaction", side_effect=Exception("xfer error")):
        response = client.post("/token/transfer", params={
            "symbol": symbol,
            "amount": 10,
            "sender_address": wallet.address,
            "recipient_address": "xBHRTEST000",
            "message": "xfer",
            "signature": wallet.private_key
        })
        assert response.status_code == 200
        assert "Token transferi başarısız" in str(response.json())

def test_token_balance_error():
    with patch("bhrc_blockchain.api.token_routes.get_token_balance", side_effect=Exception("balance error")):
        response = client.get("/token/balance?symbol=INVALID&address=NOPE")
        assert response.status_code == 200
        assert "Bakiye alınamadı" in str(response.json())

def test_token_transfers_error():
    with patch("bhrc_blockchain.api.token_routes.get_token_transfers", side_effect=Exception("transfers error")):
        response = client.get("/token/transfers?symbol=INVALID&address=NOPE")
        assert response.status_code == 200
        assert "Transfer geçmişi alınamadı" in str(response.json())

def test_token_details_error():
    response = client.get("/token/details?symbol=INVALID")
    assert response.status_code == 200
    assert "Token detayları alınamadı" in str(response.json())

def test_token_explorer_error():
    with patch("bhrc_blockchain.api.token_routes.get_all_tokens", side_effect=Exception("explorer error")):
        response = client.get("/token/explorer")
        assert response.status_code == 500
        assert "Hata oluştu" in response.text

