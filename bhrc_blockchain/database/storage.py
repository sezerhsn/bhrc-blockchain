# storage.py
import json
import sqlite3
from typing import List

class SQLiteDataStore:
    def __init__(self, db_path="bhrc_blockchain.db"):
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cursor = self.connection.cursor()

        # Blocks tablosu
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            index_num INTEGER,
            block_hash TEXT,
            previous_hash TEXT,
            timestamp REAL,
            miner_address TEXT,
            merkle_root TEXT,
            nonce INTEGER,
            version TEXT,
            virtual_size INTEGER,
            transactions TEXT
        )
        """)

        # Transactions tablosu
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            txid TEXT,
            sender TEXT,
            recipient TEXT,
            amount REAL,
            fee REAL,
            message TEXT,
            note TEXT,
            type TEXT,
            locktime INTEGER,
            time TEXT,
            script_sig TEXT,
            public_key TEXT,
            script_pubkey TEXT,
            status TEXT,
            block_index INTEGER
        )
        """)

        # UTXO tablosu
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS utxos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            txid TEXT,
            output_index INTEGER,
            address TEXT,
            amount REAL,
            spent INTEGER DEFAULT 0
        )
        """)

        self.connection.commit()

    def save_block(self, block):
        cursor = self.connection.cursor()

        # Blok verisi
        cursor.execute("""
        INSERT INTO blocks (
            index_num, block_hash, previous_hash, timestamp,
            miner_address, merkle_root, nonce, version, virtual_size, transactions
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            block["index"],
            block["block_hash"],
            block["previous_hash"],
            block["timestamp"],
            block["miner_address"],
            block["merkle_root"],
            block["nonce"],
            block["version"],
            block["virtual_size"],
            json.dumps(block["transactions"])  # 🔁 işlemleri JSON olarak sakla
        ))

        # İşlemler
        for tx in block["transactions"]:
            cursor.execute("""
            INSERT INTO transactions (
                txid, sender, recipient, amount, fee,
                message, note, type, locktime, time,
                script_sig, public_key, script_pubkey, status, block_index
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tx.get("txid"),
                tx.get("sender"),
                tx.get("recipient"),
                tx.get("amount"),
                tx.get("fee"),
                tx.get("message"),
                tx.get("note"),
                tx.get("type"),
                tx.get("locktime"),
                tx.get("time"),
                tx.get("script_sig"),
                tx.get("public_key"),
                tx.get("script_pubkey"),
                tx.get("status"),
                block["index"]
            ))

        self.connection.commit()

    def fetch_all_blocks(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM blocks ORDER BY index_num ASC")
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def save_utxos(self, txid, outputs):
        cursor = self.connection.cursor()
        for idx, out in enumerate(outputs):
            cursor.execute("""
            INSERT INTO utxos (txid, output_index, address, amount, spent)
            VALUES (?, ?, ?, ?, 0)
            """, (txid, idx, out["recipient"], out["amount"]))
        self.connection.commit()

    def spend_utxos(self, txid_inputs):
        cursor = self.connection.cursor()
        for utxo in txid_inputs:
            cursor.execute("""
            UPDATE utxos SET spent = 1
            WHERE txid = ? AND output_index = ?
            """, (utxo["txid"], utxo["output_index"]))
        self.connection.commit()

    def get_unspent_utxos(self, address):
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT id, txid, output_index, recipient, amount FROM utxos
            WHERE recipient=? AND spent=0
        """, (address,))
        rows = cursor.fetchall()

        utxos = []
        for row in rows:
            txid = row[1]
            if txid.startswith("GENESIS_TXID"):
                continue  # Bu UTXO asla harcanamaz
            utxos.append(row)

        return utxos

    def apply_utxo_changes(self, transactions: List[dict]):
        for tx in transactions:
            if tx["type"] != "coinbase":
                self.spend_utxos(tx["inputs"])
            self.save_utxos(tx["txid"], tx["outputs"])

    def close(self):
        self.connection.close()

    def get_all_utxos(self):
        cursor = self.connection.cursor()
        cursor.execute("SELECT txid, output_index, address, amount FROM utxos WHERE spent=0")
        rows = cursor.fetchall()

        result = {}
        for txid, output_index, address, amount in rows:
            if txid.startswith("GENESIS_TXID"):
                continue  # Bu UTXO harcanamaz, dahil edilmesin
            result[(txid, output_index)] = {
                "recipient": address,
                "amount": amount
            }

        return result

    def fetch_all_blocks(self):
        with self.connection:
            rows = self.connection.execute("SELECT * FROM blocks ORDER BY index_num ASC").fetchall()
            blocks = []
            for row in rows:
                block = dict(zip(row.keys(), row))
                block["index"] = block.pop("index_num")  # ✅ normalize et
                blocks.append(block)
            return blocks
