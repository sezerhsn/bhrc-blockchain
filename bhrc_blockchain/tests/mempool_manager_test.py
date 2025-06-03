import time
from bhrc_blockchain.core.mempool.mempool_manager import MempoolManager

def test_mempool_manager_flow():
    mp = MempoolManager()

    tx1 = {"txid": "tx1", "fee": 0.5}
    tx2 = {"txid": "tx2", "fee": 2.0}
    tx3 = {"txid": "tx3", "fee": 1.0}

    mp.add_transaction(tx1)
    mp.add_transaction(tx2)
    mp.add_transaction(tx3)

    sorted_txs = mp.get_sorted_transactions()
    assert [tx["txid"] for tx in sorted_txs] == ["tx2", "tx3", "tx1"]

    mp.remove_transaction("tx2")
    assert len(mp.pool) == 2
    assert all(tx["txid"] != "tx2" for tx in mp.pool)

    # expire işlemi simülasyonu
    mp.pool[0]["timestamp"] = time.time() - 999
    mp.cleanup_expired(ttl=100)
    assert len(mp.pool) == 1

    mp.clear()
    assert len(mp.pool) == 0

