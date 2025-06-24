import json
import os
import threading
from bhrc_blockchain.config.config import settings

MEMPOOL_FILE = ":memory:" if settings.TESTING else "mempool_cache.json"
mempool_lock = threading.Lock()
mempool = []

def initialize_mempool(file_path: str = MEMPOOL_FILE):
    """Verilen dosya yolundan mempool'u yükler. Dosya yoksa boş başlatır."""
    global mempool
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            mempool_data = json.load(f)
        with mempool_lock:
            mempool[:] = mempool_data
    else:
        with mempool_lock:
            mempool = []

def persist_mempool(file_path: str = MEMPOOL_FILE):
    """Mempool listesini diske yazar (TESTING modunda yazmaz)."""
    if settings.TESTING:
        return
    with mempool_lock:
        with open(file_path, "w") as f:
            json.dump(mempool, f, indent=2)

def remove_transaction_from_mempool(txid: str, file_path: str = MEMPOOL_FILE):
    global mempool
    with mempool_lock:
        mempool[:] = [tx for tx in mempool if tx["txid"] != txid]
        persist_mempool(file_path)

def get_ready_transactions():
    """Durumu 'ready' olan işlemleri, en yüksek ücrete göre sıralı verir."""
    with mempool_lock:
        ready = [tx for tx in mempool if tx.get("status") == "ready"]
        return sorted(ready, key=lambda x: x.get("fee", 0), reverse=True)

def clear_mempool(file_path: str = MEMPOOL_FILE):
    """Mempool'u temizler ve diskteki yedeği sıfırlar."""
    global mempool
    with mempool_lock:
        mempool.clear()
        persist_mempool(file_path)

def add_transaction_to_mempool(tx: dict, file_path: str = MEMPOOL_FILE):
    with mempool_lock:
        mempool.append(tx)
        persist_mempool(file_path)

class Mempool:
    def __init__(self):
        initialize_mempool()

    @property
    def transactions(self):
        return get_ready_transactions()

def get_transaction_from_mempool(txid: str):
    """txid'ye göre mempool içinden işlem döner (bulunamazsa None)."""
    with mempool_lock:
        for tx in mempool:
            if tx.get("txid") == txid:
                return tx
    return None

