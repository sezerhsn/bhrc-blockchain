import json
import os
import threading

MEMPOOL_FILE = "mempool_cache.json"
mempool_lock = threading.Lock()
mempool = []  # Global mempool listesi

def initialize_mempool():
    global mempool
    if os.path.exists(MEMPOOL_FILE):
        with open(MEMPOOL_FILE, "r") as f:
            mempool = json.load(f)
    else:
        mempool = []

# Başlangıçta bir kez çağrılır
initialize_mempool()

def persist_mempool():
    with mempool_lock:
        with open(MEMPOOL_FILE, "w") as f:
            json.dump(mempool, f, indent=2)

def add_transaction_to_mempool(tx):
    mempool.append(tx)
    persist_mempool()

def get_ready_transactions():
    ready = [tx for tx in mempool if tx.get("status") == "ready"]
    return sorted(ready, key=lambda x: x.get("fee", 0), reverse=True)

def clear_mempool():
    global mempool
    mempool.clear()
    persist_mempool()

