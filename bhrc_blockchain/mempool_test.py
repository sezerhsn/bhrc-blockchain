# mempool_test.py
import os
import json
import pytest
from bhrc_blockchain.core import mempool

MEMPOOL_FILE = "mempool_cache.json"

@pytest.fixture(autouse=True)
def clean_mempool():
    # Test öncesi ve sonrası mempool'u temizle
    mempool.clear_mempool()
    yield
    mempool.clear_mempool()

def test_add_transaction_to_mempool_writes_to_disk():
    tx = {"txid": "abc123", "status": "ready", "fee": 0.5}
    mempool.add_transaction_to_mempool(tx)

    assert any(t["txid"] == "abc123" for t in mempool.mempool)

    with open(MEMPOOL_FILE, "r") as f:
        data = json.load(f)
        assert any(t["txid"] == "abc123" for t in data)

def test_get_ready_transactions_returns_sorted():
    mempool.add_transaction_to_mempool({"txid": "1", "status": "ready", "fee": 0.2})
    mempool.add_transaction_to_mempool({"txid": "2", "status": "pending", "fee": 0.9})
    mempool.add_transaction_to_mempool({"txid": "3", "status": "ready", "fee": 0.7})

    ready = mempool.get_ready_transactions()
    assert len(ready) == 2
    assert ready[0]["txid"] == "3"
    assert ready[1]["txid"] == "1"

def test_clear_mempool_empties_list_and_disk():
    mempool.add_transaction_to_mempool({"txid": "xyz", "status": "ready"})
    mempool.clear_mempool()

    assert mempool.mempool == []

    with open(MEMPOOL_FILE, "r") as f:
        data = json.load(f)
        assert data == []

def test_mempool_file_created_if_missing(tmp_path, monkeypatch):
    # Dosya yoksa otomatik oluşturulmalı
    test_file = tmp_path / "test_mempool.json"
    monkeypatch.setattr(mempool, "MEMPOOL_FILE", str(test_file))
    monkeypatch.setattr(mempool, "mempool", [])

    mempool.add_transaction_to_mempool({"txid": "init", "status": "ready"})
    assert test_file.exists()

def test_initial_mempool_file_handling(tmp_path, monkeypatch):
    dummy_file = tmp_path / "dummy_mempool.json"
    monkeypatch.setattr(mempool, "MEMPOOL_FILE", str(dummy_file))
    monkeypatch.setattr(mempool, "mempool", [])

    # Dosya mevcut değilse → mempool dosyası oluşturulmalı
    if os.path.exists(dummy_file):
        os.remove(dummy_file)

    mempool.add_transaction_to_mempool({"txid": "boot", "status": "ready"})
    assert dummy_file.exists()

def test_initialize_mempool_handles_missing_file(tmp_path, monkeypatch):
    dummy_file = tmp_path / "missing_mempool.json"
    monkeypatch.setattr(mempool, "MEMPOOL_FILE", str(dummy_file))
    monkeypatch.setattr(mempool, "mempool", [])

    mempool.initialize_mempool()
    assert mempool.mempool == []

