import time

class MempoolManager:
    def __init__(self):
        self.pool = []  # İşlem listesi

    def add_transaction(self, tx: dict):
        tx["timestamp"] = tx.get("timestamp", time.time())
        self.pool.append(tx)

    def get_sorted_transactions(self):
        # Önceliğe göre sıralama: fee yüksekse önce, sonra zaman
        return sorted(self.pool, key=lambda x: (-x.get("fee", 0), x["timestamp"]))

    def remove_transaction(self, txid: str):
        self.pool = [tx for tx in self.pool if tx.get("txid") != txid]

    def cleanup_expired(self, ttl: int = 300):
        now = time.time()
        self.pool = [tx for tx in self.pool if now - tx["timestamp"] <= ttl]

    def clear(self):
        self.pool = []

