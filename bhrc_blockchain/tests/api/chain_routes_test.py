import pytest
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api.auth import verify_token, ROLE_PERMISSIONS
from unittest.mock import patch, AsyncMock
import bhrc_blockchain.api.chain_routes as chain_routes

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
        response = ac.get("/chain/mine")
        assert response.status_code == 201
        assert "Blok #1" in response.json()["message"]

@patch("bhrc_blockchain.api.chain_routes.blockchain.mine_block", new_callable=AsyncMock)
def test_mine_block_empty(mock_mine_block):
    mock_mine_block.return_value = None

    with TestClient(app) as ac:  # <--- burada da
        response = ac.get("/chain/mine")
        assert response.status_code == 204

def test_explorer_search_found_tx(monkeypatch):
    block = type("Block", (), {
        "transactions": [{"txid": "abc123", "sender": "A", "recipient": "B"}],
        "block_hash": "xyz",
        "to_dict": lambda self: {"index": 1}
    })()
    mock_chain = [block]
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: type("B", (), {"chain": mock_chain})())

    res = client.get("/chain/explorer/search?q=abc123")
    assert res.status_code == 200
    assert res.json()["type"] == "transaction"


def test_dashboard_data(monkeypatch):
    block = type("Block", (), {
        "transactions": [{"txid": "x"}],
    })()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: type("B", (), {"chain": [block]})())
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.get_ready_transactions", lambda: [{}])
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.connected_peers", ["peer1"])

    res = client.get("/chain/dashboard/data")
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

    res = client.get("/chain/explorer/search/advanced?q=abc&tx_type=&start=50&end=200&page=1&limit=10")
    assert res.status_code == 200
    assert res.json()["total"] == 1

def test_explorer_html():
    response = client.get("/chain/explorer")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_explorer_search_ui():
    response = client.get("/chain/explorer/search/ui")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_dashboard_ui():
    response = client.get("/chain/dashboard")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_dashboard_graph_data(monkeypatch):
    block = type("Block", (), {
        "transactions": [{"type": "token_transfer"}],
        "index": 1,
        "timestamp": 1710000000
    })()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: type("B", (), {"chain": [block]*20})())
    response = client.get("/chain/dashboard/data/graph")
    assert response.status_code == 200
    assert "tx_counts" in response.json()

def test_notifications_test_ui():
    response = client.get("/chain/notifications/test")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_notifications_subscribe_ui():
    response = client.get("/chain/notifications/subscribe")
    assert response.status_code == 200
    assert isinstance(response.content, bytes)

def test_explorer_search_exception(monkeypatch):
    def mock_blockchain_fail(*args, **kwargs):
        raise Exception("force error")

    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.Blockchain", lambda autoload=True: mock_blockchain_fail())

    with TestClient(app, raise_server_exceptions=False) as client_with_exception:
        response = client_with_exception.get("/chain/explorer/search?q=txid")
        assert response.status_code == 500
        assert "force error" in response.json()["detail"]

def test_get_block_by_index_valid(monkeypatch):
    block = type("Block", (), {
        "index": 2,
        "block_hash": "abc123",
        "to_dict": lambda self: {"index": 2, "hash": "abc123"}
    })()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_block_by_index", lambda index: block if index == 2 else None)

    response = client.get("/chain/block/index/2")
    assert response.status_code == 200
    assert response.json()["data"]["index"] == 2

def test_get_block_by_index_not_found(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_block_by_index", lambda index: None)
    response = client.get("/chain/block/index/999")
    assert response.status_code == 404

def test_get_block_by_hash_valid(monkeypatch):
    block = type("Block", (), {
        "block_hash": "def456",
        "to_dict": lambda self: {"hash": "def456"}
    })()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_block_by_hash", lambda h: block if h == "def456" else None)

    response = client.get("/chain/block/hash/def456")
    assert response.status_code == 200
    assert response.json()["data"]["hash"] == "def456"

def test_get_block_by_hash_not_found(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_block_by_hash", lambda h: None)
    response = client.get("/chain/block/hash/doesnotexist")
    assert response.status_code == 404

def test_get_block_range_valid(monkeypatch):
    block1 = type("Block", (), {"to_dict": lambda self: {"index": 1}})()
    block2 = type("Block", (), {"to_dict": lambda self: {"index": 2}})()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_block_range", lambda s, e: [block1, block2] if (s, e) == (1, 2) else [])

    response = client.get("/chain/block/range?start=1&end=2")
    assert response.status_code == 200
    assert len(response.json()["data"]) == 2

def test_get_block_range_empty(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_block_range", lambda s, e: [])
    response = client.get("/chain/block/range?start=99&end=100")
    assert response.status_code == 404

def test_get_transaction_found(monkeypatch):
    dummy_tx = {"txid": "tx123", "amount": 100}
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_transaction", lambda txid: dummy_tx if txid == "tx123" else None)

    res = client.get("/chain/tx/tx123")
    assert res.status_code == 200
    assert res.json()["data"]["txid"] == "tx123"

def test_get_transaction_not_found(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_transaction", lambda txid: None)
    res = client.get("/chain/tx/notx")
    assert res.status_code == 404

def test_get_blocks_by_miner_found(monkeypatch):
    block1 = type("Block", (), {"to_dict": lambda self: {"index": 1}})()
    block2 = type("Block", (), {"to_dict": lambda self: {"index": 2}})()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_blocks_by_miner", lambda addr: [block1, block2] if addr == "xBHR123" else [])

    res = client.get("/chain/blocks/miner/xBHR123")
    assert res.status_code == 200
    assert len(res.json()["data"]) == 2

def test_get_blocks_by_miner_not_found(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_blocks_by_miner", lambda addr: [])
    res = client.get("/chain/blocks/miner/unknown")
    assert res.status_code == 404

def test_get_chain_stats(monkeypatch):
    dummy_stats = {
        "total_blocks": 10,
        "total_transactions": 20,
        "avg_tx_per_block": 2.0,
        "last_block_time": 1710000000.0,
        "chain_weight": 12,
        "total_difficulty": 18
    }
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_chain_stats", lambda: dummy_stats)

    res = client.get("/chain/stats")
    assert res.status_code == 200
    assert res.json()["data"]["total_blocks"] == 10

def test_detect_fork_true(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.detect_fork", lambda: True)
    res = client.get("/chain/detect/fork")
    assert res.status_code == 200
    assert res.json()["data"]["fork_detected"] is True

def test_detect_fork_false(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.detect_fork", lambda: False)
    res = client.get("/chain/detect/fork")
    assert res.status_code == 200
    assert res.json()["data"]["fork_detected"] is False

def test_get_fork_blocks(monkeypatch):
    block1 = type("Block", (), {"to_dict": lambda self: {"index": 10}})()
    block2 = type("Block", (), {"to_dict": lambda self: {"index": 11}})()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_fork_blocks", lambda: [block1, block2])

    res = client.get("/chain/fork/blocks")
    assert res.status_code == 200
    assert isinstance(res.json()["data"], list)
    assert res.json()["data"][0]["index"] == 10

def test_detect_reorg_true(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.detect_reorg", lambda max_depth: True)
    res = client.get("/chain/detect/reorg?max_depth=5")
    assert res.status_code == 200
    assert res.json()["data"]["reorg_detected"] is True

def test_detect_reorg_false(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.detect_reorg", lambda max_depth: False)
    res = client.get("/chain/detect/reorg?max_depth=10")
    assert res.status_code == 200
    assert res.json()["data"]["reorg_detected"] is False

def test_get_last_block(monkeypatch):
    block = type("Block", (), {"to_dict": lambda self: {"index": 99}})()
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_last_block", lambda: block)

    res = client.get("/chain/block/last")
    assert res.status_code == 200
    assert res.json()["data"]["index"] == 99

def test_get_total_transaction_count(monkeypatch):
    class DummyBlockchain:
        def get_total_transaction_count(self):
            return 123
        def get_transaction(self, txid):
            return {"txid": txid}

    monkeypatch.setattr(chain_routes, "blockchain", DummyBlockchain())

    response = chain_routes.get_total_transaction_count()
    assert response["data"]["count"] == 123

def test_validate_chain_true(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.validate_chain", lambda: True)
    res = client.get("/chain/validate")
    assert res.status_code == 200
    assert res.json()["data"]["valid"] is True

def test_validate_chain_false(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.validate_chain", lambda: False)
    res = client.get("/chain/validate")
    assert res.status_code == 200
    assert res.json()["data"]["valid"] is False

def test_get_block_time_stats(monkeypatch):
    dummy_stats = {
        "total_blocks": 5,
        "avg_time": 3.2,
        "min_time": 2.5,
        "max_time": 4.1,
        "intervals": [2.5, 3.0, 3.2, 4.1]
    }
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_block_time_stats", lambda: dummy_stats)

    res = client.get("/chain/time/stats")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["total_blocks"] == 5
    assert isinstance(data["intervals"], list)
    assert data["max_time"] >= data["min_time"]

def test_get_chain_snapshot_hash(monkeypatch):
    dummy_hash = "abc123def456"
    monkeypatch.setattr("bhrc_blockchain.api.chain_routes.blockchain.get_chain_snapshot_hash", lambda: dummy_hash)

    res = client.get("/chain/snapshot/hash")
    assert res.status_code == 200
    assert res.json()["data"]["hash"] == dummy_hash

def test_reset_chain_allowed_for_super_admin_with_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "superreset",
        "role": "super_admin",
        "permissions": list(ROLE_PERMISSIONS["super_admin"])
    }
    response = client.post("/chain/reset")
    assert response.status_code == 200
    assert "Zincir sıfırlama yetkisi" in response.json()["message"]
    app.dependency_overrides = {}

def test_reset_chain_denied_without_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "restricted_admin",
        "role": "super_admin",
        "permissions": ["rollback", "snapshot"]
    }
    response = client.post("/chain/reset")
    assert response.status_code == 403
    assert "reset-chain" in response.json()["detail"]
    app.dependency_overrides = {}

def test_reset_chain_denied_for_admin():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "normaladmin",
        "role": "admin",
        "permissions": ["view_logs", "snapshot"]
    }
    response = client.post("/chain/reset")
    assert response.status_code == 403
    assert "yetkiniz yok" in response.json()["detail"]
    app.dependency_overrides = {}

def test_rollback_allowed_for_super_admin_with_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "rollbacker",
        "role": "super_admin",
        "permissions": list(ROLE_PERMISSIONS["super_admin"])
    }
    response = client.post("/chain/rollback")
    assert response.status_code == 200
    assert "Rollback izni" in response.json()["message"]
    app.dependency_overrides = {}

def test_rollback_denied_without_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "nosuchpower",
        "role": "super_admin",
        "permissions": ["snapshot", "reset-chain"]
    }
    response = client.post("/chain/rollback")
    assert response.status_code == 403
    assert "rollback" in response.json()["detail"]
    app.dependency_overrides = {}

def test_rollback_denied_for_admin():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "admintest",
        "role": "admin",
        "permissions": ["view_logs", "snapshot", "rollback"]
    }
    response = client.post("/chain/rollback")
    assert response.status_code == 403
    assert "yetkiniz yok" in response.json()["detail"]
    app.dependency_overrides = {}

def test_snapshot_access_with_super_admin():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "sezer",
        "role": "super_admin",
        "permissions": list(ROLE_PERMISSIONS["super_admin"])
    }
    response = client.get("/chain/snapshot-access")
    assert response.status_code == 200
    assert "Snapshot erişimi" in response.json()["message"]
    app.dependency_overrides = {}

def test_snapshot_access_denied_to_admin_without_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "adminx",
        "role": "admin",
        "permissions": ["view_logs"]
    }
    response = client.get("/chain/snapshot-access")
    assert response.status_code == 403
    assert "yetkiniz yok" in response.json()["detail"]
    app.dependency_overrides = {}

def test_snapshot_access_allowed_to_admin_with_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "admintest",
        "role": "admin",
        "permissions": ["snapshot"]
    }
    response = client.get("/chain/snapshot-access")
    assert response.status_code == 403
    app.dependency_overrides = {}

def test_clear_mempool_allowed_for_super_admin():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "sezer",
        "role": "super_admin",
        "permissions": list(ROLE_PERMISSIONS["super_admin"])
    }
    response = client.post("/chain/clear-mempool")
    assert response.status_code == 200
    assert "temizlendi" in response.json()["message"]
    app.dependency_overrides = {}

def test_clear_mempool_denied_without_permission():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "semiadmin",
        "role": "super_admin",
        "permissions": ["reset-chain"]
    }
    response = client.post("/chain/clear-mempool")
    assert response.status_code == 403
    assert "clear-mempool" in response.json()["detail"]
    app.dependency_overrides = {}

def test_clear_mempool_denied_for_admin():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "adminx",
        "role": "admin",
        "permissions": ["clear-mempool"]
    }
    response = client.post("/chain/clear-mempool")
    assert response.status_code == 403
    assert "yetkiniz yok" in response.json()["detail"]
    app.dependency_overrides = {}

