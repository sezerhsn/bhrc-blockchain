from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from unittest.mock import patch

client = TestClient(app)

test_address = "xBHR_TEST_ADDRESS"

def test_balance_endpoint():
    response = client.get(f"/state/balance/{test_address}")
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == test_address
    assert isinstance(data["balance"], (float, int))

def test_all_balances():
    response = client.get("/state/all")
    assert response.status_code == 200
    data = response.json()
    assert "state" in data
    assert isinstance(data["state"], dict)

def test_address_stats_full_coverage_fixed():
    fake_blockchain = type("FakeBlockchain", (), {})()
    fake_block = type("FakeBlock", (), {})()
    fake_block.transactions = [
        {"sender": test_address, "amount": 5},
        {"recipient": test_address, "amount": 10},
        {"outputs": [{"recipient": test_address, "amount": 20}]}
    ]
    fake_blockchain.chain = [fake_block]

    with patch("bhrc_blockchain.core.blockchain.blockchain.get_blockchain", return_value=fake_blockchain):
        response = client.get(f"/state/stats/{test_address}")
        assert response.status_code == 200
        data = response.json()
        assert data["incoming_tx_count"] == 2
        assert data["outgoing_tx_count"] == 1
        assert data["net_gain"] == 25.0  # +10 +20 -5

