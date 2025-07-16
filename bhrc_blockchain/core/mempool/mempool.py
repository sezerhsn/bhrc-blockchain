# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import json
import os
import time
import threading
from bhrc_blockchain.config.config import settings

MEMPOOL_FILE = ":memory:" if settings.TESTING else "mempool_cache.json"
mempool_lock = threading.RLock()
mempool = []

class Mempool:
    def __init__(self):
        initialize_mempool()

    @property
    def transactions(self):
        return get_ready_transactions()

    def purge_expired_transactions(self, ttl: int = 300):
        purge_expired_transactions(ttl)

    def remove_transaction(self, txid: str):
        remove_transaction_from_mempool(txid)

    def remove_transactions(self, tx_list: list[dict]):
        for tx in tx_list:
            txid = tx.get("txid")
            if txid:
                self.remove_transaction(txid)

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
            mempool[:] = []

def persist_mempool(file_path: str = MEMPOOL_FILE):
    if settings.TESTING:
        return
    with mempool_lock:
        dir_path = os.path.dirname(file_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(file_path, "w") as f:
            json.dump(mempool, f, indent=2)

def remove_transaction_from_mempool(txid: str, file_path: str = MEMPOOL_FILE):
    global mempool
    with mempool_lock:
        mempool[:] = [tx for tx in mempool if tx["txid"] != txid]
        persist_mempool(file_path)

def get_ready_transactions():
    """Durumu 'ready' olan ve TTL süresi geçmemiş işlemleri, en yüksek ücrete göre sıralı verir."""
    now = time.time()
    with mempool_lock:
        ready = [
            tx for tx in mempool
            if tx.get("status") == "ready" and now - tx.get("timestamp", now) <= settings.MEMPOOL_TTL
        ]
        return sorted(ready, key=lambda x: x.get("fee", 0), reverse=True)

def clear_mempool(file_path: str = MEMPOOL_FILE):
    """Mempool'u temizler ve diskteki yedeği sıfırlar."""
    global mempool
    with mempool_lock:
        mempool.clear()
        persist_mempool(file_path)

def add_transaction_to_mempool(tx: dict, file_path: str = MEMPOOL_FILE):
    tx.setdefault("timestamp", time.time())
    with mempool_lock:
        mempool.append(tx)
        persist_mempool(file_path)

def get_transaction_from_mempool(txid: str):
    """txid'ye göre mempool içinden işlem döner (bulunamazsa None)."""
    with mempool_lock:
        for tx in mempool:
            if tx.get("txid") == txid:
                return tx
    return None

def purge_expired_transactions(ttl: int = 300, file_path: str = MEMPOOL_FILE):
    """TTL süresi dolmuş işlemleri mempool'dan temizler."""
    global mempool
    now = time.time()
    with mempool_lock:
        original_count = len(mempool)
        mempool[:] = [tx for tx in mempool if now - tx.get("timestamp", now) <= ttl]
        if len(mempool) < original_count:
            persist_mempool(file_path)

def queue_contract_transaction(tx: dict):
    """Contract işlemini mempool’e eklemek için dıştan erişilen standart API."""
    add_transaction_to_mempool(tx)

def find_contract_in_mempool(txid: str) -> dict | None:
    """Contract’a ait işlemi mempool içinde bulmak için erişilen API."""
    return get_transaction_from_mempool(txid)

