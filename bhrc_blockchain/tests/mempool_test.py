import json
import pytest
from unittest.mock import patch, mock_open

from bhrc_blockchain.core.mempool import mempool as module

# Disk erişimini tamamen devre dışı bırak
patch("bhrc_blockchain.core.mempool.mempool.persist_mempool", lambda *args, **kwargs: None).start()
# patch("bhrc_blockchain.core.mempool.mempool.initialize_mempool", lambda *args, **kwargs: None).start()


def setup_function():
    module.mempool.clear()

def test_add_transaction_to_mempool():
    tx = {"txid": "abc123", "status": "ready", "fee": 0.1}
    module.add_transaction_to_mempool(tx)
    assert len(module.mempool) == 1
    assert module.mempool[0]["txid"] == "abc123"

def test_get_ready_transactions():
    module.mempool.append({"txid": "a", "status": "ready", "fee": 0.05})
    module.mempool.append({"txid": "b", "status": "pending", "fee": 0.2})
    module.mempool.append({"txid": "c", "status": "ready", "fee": 0.1})
    ready = module.get_ready_transactions()
    assert [tx["txid"] for tx in ready] == ["c", "a"]

def test_remove_transaction_from_mempool():
    module.mempool.append({"txid": "abc", "status": "ready", "fee": 0.01})
    module.mempool.append({"txid": "def", "status": "ready", "fee": 0.02})
    module.remove_transaction_from_mempool("abc")
    assert len(module.mempool) == 1
    assert module.mempool[0]["txid"] == "def"

def test_clear_mempool():
    module.mempool.append({"txid": "abc", "status": "ready", "fee": 0.01})
    module.clear_mempool()
    assert len(module.mempool) == 0

def test_initialize_mempool_loads_data():
    fake_data = [{"txid": "xyz", "status": "ready", "fee": 0.2}]
    m_open = mock_open(read_data=json.dumps(fake_data))
    with patch("builtins.open", m_open), patch("os.path.exists", return_value=True):
        module.initialize_mempool("mock.json")
        assert len(module.mempool) == 1
        assert module.mempool[0]["txid"] == "xyz"

def test_initialize_mempool_file_not_exist():
    with patch("os.path.exists", return_value=False):
        module.initialize_mempool("mock.json")
        assert module.mempool == []

