import json
import os
import time
import pytest
from unittest.mock import patch, mock_open

from bhrc_blockchain.core.mempool.mempool import (
    add_transaction_to_mempool,
    get_ready_transactions,
    get_transaction_from_mempool,
    remove_transaction_from_mempool,
    clear_mempool,
    initialize_mempool,
    persist_mempool,
    purge_expired_transactions,
    Mempool,
    settings,
)


def test_add_transaction_to_mempool():
    clear_mempool()
    tx = {"txid": "abc123", "status": "ready", "fee": 0.1}
    add_transaction_to_mempool(tx)
    ready = get_ready_transactions()
    assert any(t["txid"] == "abc123" for t in ready)


def test_get_ready_transactions():
    clear_mempool()
    add_transaction_to_mempool({"txid": "a", "status": "ready", "fee": 0.05})
    add_transaction_to_mempool({"txid": "b", "status": "pending", "fee": 0.2})
    add_transaction_to_mempool({"txid": "c", "status": "ready", "fee": 0.1})
    ready = get_ready_transactions()
    assert [tx["txid"] for tx in ready] == ["c", "a"]


def test_remove_transaction_from_mempool():
    clear_mempool()
    add_transaction_to_mempool({"txid": "abc", "status": "ready"})
    add_transaction_to_mempool({"txid": "def", "status": "ready"})
    remove_transaction_from_mempool("abc")
    txids = [tx["txid"] for tx in get_ready_transactions()]
    assert "abc" not in txids
    assert "def" in txids


def test_clear_mempool():
    add_transaction_to_mempool({"txid": "abc", "status": "ready"})
    clear_mempool()
    assert get_ready_transactions() == []


def test_initialize_mempool_loads_data():
    fake_data = [{"txid": "xyz", "status": "ready", "fee": 0.2}]
    m_open = mock_open(read_data=json.dumps(fake_data))
    with patch("builtins.open", m_open), patch("os.path.exists", return_value=True):
        initialize_mempool("mock.json")
        ready = get_ready_transactions()
        assert any(tx["txid"] == "xyz" for tx in ready)


def test_initialize_mempool_file_not_exist():
    with patch("os.path.exists", return_value=False):
        clear_mempool()
        initialize_mempool("nonexistent.json")
        assert get_ready_transactions() == []


def test_get_transaction_from_mempool_not_found():
    clear_mempool()
    result = get_transaction_from_mempool("nonexistent")
    assert result is None


def test_mempool_class_triggers_initialization():
    with patch("bhrc_blockchain.core.mempool.mempool.initialize_mempool") as init:
        Mempool()
        init.assert_called_once()


@pytest.mark.no_patch
def test_persist_mempool_writes_file(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "TESTING", False)
    test_file = tmp_path / "mempool_out.json"

    clear_mempool(str(test_file))
    add_transaction_to_mempool({"txid": "write123", "status": "ready"}, str(test_file))
    assert test_file.exists()

    with open(test_file) as f:
        data = json.load(f)
    assert data[0]["txid"] == "write123"


@pytest.mark.no_patch
def test_disk_persistence_for_all_mempool_operations(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "TESTING", False)

    tx = {"txid": "z1", "status": "ready"}
    path = tmp_path / "mempool_data.json"

    clear_mempool(str(path))
    add_transaction_to_mempool(tx, str(path))
    assert path.exists()
    with open(path) as f:
        assert json.load(f) == [tx]

    remove_transaction_from_mempool("z1", str(path))
    with open(path) as f:
        assert json.load(f) == []

    add_transaction_to_mempool({"txid": "x2", "status": "ready"}, str(path))
    clear_mempool(str(path))
    with open(path) as f:
        assert json.load(f) == []


def test_initialize_mempool_assigns_empty_when_file_missing(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda _: False)
    add_transaction_to_mempool({"txid": "dummy", "status": "ready"})
    initialize_mempool("nonexistent.json")
    assert get_ready_transactions() == []


def test_mempool_ttl_behavior():
    clear_mempool()
    now = time.time()
    add_transaction_to_mempool({
        "txid": "ttl1", "status": "ready", "timestamp": now - 4000
    })
    add_transaction_to_mempool({
        "txid": "ttl2", "status": "ready", "timestamp": now
    })
    purge_expired_transactions()
    txids = [tx["txid"] for tx in get_ready_transactions()]
    assert "ttl1" not in txids
    assert "ttl2" in txids

def test_purge_expired_from_mempool_class_version():
    pool = Mempool()

    old_tx = {
        "txid": "expired001",
        "status": "ready",
        "timestamp": time.time() - 1000
    }

    fresh_tx = {
        "txid": "valid001",
        "status": "ready",
        "timestamp": time.time()
    }

    add_transaction_to_mempool(old_tx)
    add_transaction_to_mempool(fresh_tx)

    pool.purge_expired_transactions(ttl=300)
    txids = [tx["txid"] for tx in pool.transactions]

    assert "expired001" not in txids
    assert "valid001" in txids

