import pytest
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from unittest.mock import AsyncMock, patch

client = TestClient(app)

def test_get_chain(monkeypatch):
    mock_chain = [
        type("Block", (), {"to_dict": lambda self: {"index": 0}})(),
        type("Block", (), {"to_dict": lambda self: {"index": 1}})(),
    ]
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.chain", mock_chain)

    res = client.get("/chain")
    assert res.status_code == 200
    assert res.json()["message"] == "Zincir başarıyla getirildi."

@patch("bhrc_blockchain.api.chain_routes.blockchain.mine_block", new_callable=AsyncMock)
def test_mine_block_success(mock_mine_block):
    mock_block = type("Block", (), {"index": 1, "block_hash": "abc"})()
    mock_mine_block.return_value = mock_block

    with TestClient(app) as ac:  # <--- burada router yerine app
        response = ac.get("/mine")
        assert response.status_code == 201
        assert "Blok #1" in response.json()["message"]

@patch("bhrc_blockchain.api.chain_routes.blockchain.mine_block", new_callable=AsyncMock)
def test_mine_block_empty(mock_mine_block):
    mock_mine_block.return_value = None

    with TestClient(app) as ac:  # <--- burada da
        response = ac.get("/mine")
        assert response.status_code == 204

def test_explorer_search_found_tx(monkeypatch):
    block = type("Block", (), {
        "transactions": [{"txid": "abc123", "sender": "A", "recipient": "B"}],
        "block_hash": "xyz",
        "to_dict": lambda self: {"index": 1}
    })()
    mock_chain = [block]
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: type("B", (), {"chain": mock_chain})())

    res = client.get("/explorer/search?q=abc123")
    assert res.status_code == 200
    assert res.json()["type"] == "transaction"


def test_dashboard_data(monkeypatch):
    block = type("Block", (), {
        "transactions": [{"txid": "x"}],
    })()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: type("B", (), {"chain": [block]})())
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.get_ready_transactions", lambda: [{}])
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.connected_peers", ["peer1"])

    res = client.get("/dashboard/data")
    assert res.status_code == 200
    assert res.json()["total_blocks"] == 1
    assert res.json()["mempool_size"] == 1
    assert res.json()["active_peers"] == 1


def test_advanced_search_pagination(monkeypatch):
    block = type("Block", (), {
        "transactions": [{"txid": "abc", "sender": "X", "recipient": "Y", "note": "deneme", "amount": 10, "time": 100}],
        "index": 1
    })()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: type("B", (), {"chain": [block]})())

    res = client.get("/explorer/search/advanced?q=abc&tx_type=&start=50&end=200&page=1&limit=10")
    assert res.status_code == 200
    assert res.json()["total"] == 1

def test_explorer_html():
    response = client.get("/explorer")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_explorer_search_ui():
    response = client.get("/explorer/search/ui")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_dashboard_ui():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_dashboard_graph_data(monkeypatch):
    block = type("Block", (), {
        "transactions": [{"type": "token_transfer"}],
        "index": 1,
        "timestamp": 1710000000
    })()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: type("B", (), {"chain": [block]*20})())
    response = client.get("/dashboard/data/graph")
    assert response.status_code == 200
    assert "tx_counts" in response.json()

def test_notifications_test_ui():
    response = client.get("/notifications/test")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_notifications_subscribe_ui():
    response = client.get("/notifications/subscribe")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_explorer_search_exception(monkeypatch):
    def mock_blockchain_fail(*args, **kwargs):
        raise Exception("force error")

    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: mock_blockchain_fail())

    with TestClient(app, raise_server_exceptions=False) as client_with_exception:
        response = client_with_exception.get("/explorer/search?q=txid")
        assert response.status_code == 500
        assert "force error" in response.json()["detail"]

