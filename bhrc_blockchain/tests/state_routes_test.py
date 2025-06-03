from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app

client = TestClient(app)

test_address = "xBHR3a8d10c209f5ffa10dad76b170f949e1322a78d500000000000000000000"

def test_balance_endpoint():
    response = client.get(f"/state/balance/{test_address}")
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == test_address
    assert isinstance(data["balance"], float) or isinstance(data["balance"], int)

def test_all_balances():
    response = client.get("/state/all")
    assert response.status_code == 200
    data = response.json()
    assert "state" in data
    assert isinstance(data["state"], dict)
    assert test_address in data["state"]

def test_address_stats():
    response = client.get(f"/state/stats/{test_address}")
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == test_address
    assert "incoming_tx_count" in data
    assert "outgoing_tx_count" in data
    assert "net_gain" in data

