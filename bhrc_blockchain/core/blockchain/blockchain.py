import json
import time
import datetime
import sqlite3
from typing import Optional, List

from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.mempool import get_ready_transactions, clear_mempool
from bhrc_blockchain.network.p2p import broadcast_new_block as broadcast_new_block_async
from bhrc_blockchain.core.transaction import create_transaction
from bhrc_blockchain.core.token import TokenContract as Token
from bhrc_blockchain.core.transaction_model import Transaction
from bhrc_blockchain.config.config import BLOCK_REWARD, Config
from bhrc_blockchain.core.wallet import MinerWallet
from bhrc_blockchain.utils.utils import get_readable_time
from bhrc_blockchain.core.blockchain.validation import validate_block_transactions


class SQLiteDataStore:
    _instance = None

    def __new__(cls, db_path: str = "bhrc_blockchain.db") -> "SQLiteDataStore":
        if cls._instance is None:
            cls._instance = super(SQLiteDataStore, cls).__new__(cls)
            cls._instance.conn = sqlite3.connect(db_path, check_same_thread=False)
            cls._instance._create_tables()
        return cls._instance

    def _create_tables(self) -> None:
        cursor = self.conn.cursor()
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
            virtual_size INTEGER
        )
        """)
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
        self.conn.commit()

    def save_block(self, block: dict) -> None:
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
            INSERT INTO blocks (index_num, block_hash, previous_hash, timestamp, miner_address, merkle_root, nonce, version, virtual_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                block["index"], block["block_hash"], block["previous_hash"], block["timestamp"],
                block["miner_address"], block["merkle_root"], block["nonce"],
                block["version"], block["virtual_size"]
            ))
            for tx in block["transactions"]:
                cursor.execute("""
                INSERT INTO transactions (
                    txid, sender, recipient, amount, fee, message, note, type,
                    locktime, time, script_sig, public_key, script_pubkey, status, block_index
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tx.get("txid"), tx.get("sender"), tx.get("recipient"), tx.get("amount"),
                    tx.get("fee"), tx.get("message"), tx.get("note"), tx.get("type"),
                    tx.get("locktime"), tx.get("time"), tx.get("script_sig"), tx.get("public_key"),
                    tx.get("script_pubkey"), tx.get("status"), block["index"]
                ))
            self.conn.commit()
        except sqlite3.OperationalError as e:
            print(f"❌ Veritabanı hatası: {e}")

    def fetch_all_blocks(self) -> List[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM blocks ORDER BY index_num ASC")
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def save_utxos(self, txid: str, outputs: List[dict]) -> None:
        cursor = self.conn.cursor()
        for idx, out in enumerate(outputs):
            cursor.execute("""
            INSERT INTO utxos (txid, output_index, address, amount, spent)
            VALUES (?, ?, ?, ?, 0)
            """, (txid, idx, out["recipient"], out["amount"]))
        self.conn.commit()

    def apply_utxo_changes(self, transactions: List[dict]) -> None:
        for tx in transactions:
            if tx["type"] != "coinbase":
                self.spend_utxos(tx["inputs"])
            self.save_utxos(tx["txid"], tx["outputs"])

    def spend_utxos(self, txid_inputs: List[dict]) -> None:
        cursor = self.conn.cursor()
        for utxo in txid_inputs:
            cursor.execute("""
            UPDATE utxos SET spent = 1
            WHERE txid = ? AND output_index = ?
            """, (utxo["txid"], utxo["output_index"]))
        self.conn.commit()


class Blockchain:
    def __init__(self, load_existing: bool = True) -> None:
        self.chain: List[Block] = []
        self.block_reward: float = 64
        self.difficulty_prefix: str = Config.INITIAL_DIFFICULTY
        self.db: SQLiteDataStore = SQLiteDataStore()
        self.miner_wallet: MinerWallet = MinerWallet(password="genesis", persist=False)

        if load_existing:
            self.load_chain_from_db()
        else:
            self.create_genesis_block()

    def create_genesis_block(self) -> None:
        try:
            genesis_transaction = {
                "txid": "GENESIS_TXID",
                "sender": "SYSTEM",
                "recipient": self.miner_wallet.address,
                "amount": self.block_reward,
                "fee": 0.0,
                "message": "BHRC ağının ilk bloğu 🎉",
                "note": "Genesis Block",
                "type": "coinbase",
                "locktime": 0,
                "time": get_readable_time(),
                "script_sig": "SIGN(SYSTEM)",
                "script_pubkey": f"PUBKEY({self.miner_wallet.address})",
                "status": "ready",
                "outputs": [{"recipient": self.miner_wallet.address, "amount": self.block_reward}]
            }

            block = Block(
                index=0,
                previous_hash="0",
                transactions=[genesis_transaction],
                miner_address=self.miner_wallet.address,
                nonce=0,
                version="0x01"
            )

            self.chain.append(block)
            self.db.save_block(block.to_dict())
            self.db.save_utxos(genesis_transaction["txid"], genesis_transaction["outputs"])
            print("✅ Genesis Block başarıyla oluşturuldu!")
        except Exception as e:
            print(f"🚨 Genesis bloğu oluşturulamadı: {e}")

    def load_chain_from_db(self) -> None:
        print("📦 Zincir veritabanından yükleniyor...")
        try:
            blocks_data = self.db.fetch_all_blocks()
            if not blocks_data:
                self.create_genesis_block()
                return

            for block_dict in blocks_data:
                try:
                    block = Block(
                        index=block_dict.get("index", 0),
                        previous_hash=block_dict.get("previous_hash", "0"),
                        transactions=block_dict.get("transactions", []),
                        timestamp=block_dict.get("timestamp", time.time()),
                        nonce=block_dict.get("nonce", 0),
                        miner_address=block_dict.get("miner_address", "miner"),
                        version=block_dict.get("version", "0x01")
                    )
                    self.chain.append(block)
                except Exception as e:
                    print(f"🚨 Blok atlandı: {e}")
        except Exception as e:
            print(f"🚨 Zincir yüklenemedi: {e}")
        print(f"✅ Zincir yüklendi. Toplam blok: {len(self.chain)}")

    def adjust_difficulty(self) -> None:
        if len(self.chain) < 2:
            return
        prev, curr = self.chain[-2], self.chain[-1]
        elapsed = curr.timestamp - prev.timestamp
        if elapsed > 600:
            self.difficulty_prefix = self.difficulty_prefix[:-1] or "0"
        elif elapsed < 60:
            self.difficulty_prefix += "0"

    def validate_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            previous = self.chain[i - 1]
            current = self.chain[i]
            temp_block = Block(
                index=current.index,
                previous_hash=current.previous_hash,
                transactions=current.transactions,
                timestamp=current.timestamp,
                nonce=current.nonce,
                miner_address=current.miner_address
            )
            temp_block.merkle_root = current.merkle_root
            temp_block.difficulty = current.difficulty
            if current.block_hash != temp_block.calculate_block_hash():
                return False
            if current.previous_hash != previous.block_hash:
                return False
            if current.merkle_root != temp_block.calculate_merkle_root():
                return False
        return True

    def save_chain_to_db(self) -> None:
        for block in self.chain:
            self.db.save_block(block.to_dict())

    async def mine_block(self) -> Optional[int]:
        ready_txs = get_ready_transactions()
        if not ready_txs:
            print("⛔ Geçerli işlem yok, blok kazılamaz.")
            return None

        coinbase_tx = create_transaction(
            sender="SYSTEM",
            recipient=self.miner_wallet.address,
            amount=self.block_reward,
            tx_type="coinbase"
        )

        txs = [coinbase_tx] + ready_txs
        last_block = self.chain[-1]
        new_block = Block(
            index=last_block.index + 1,
            previous_hash=last_block.block_hash,
            transactions=txs,
            miner_address=self.miner_wallet.address
        )

        new_block.merkle_root = new_block.calculate_merkle_root()
        new_block.block_hash = new_block.calculate_block_hash()
        new_block.readable_time = datetime.datetime.utcnow().isoformat()
        new_block.virtual_size = len(json.dumps(txs).encode("utf-8"))

        try:
            self.chain.append(new_block)
            self.db.save_block(new_block.to_dict())
            self.db.apply_utxo_changes(txs)
            clear_mempool()
            await broadcast_new_block_async(new_block.to_dict())
            return new_block.index
        except Exception as e:
            print("🚨 Blok işlenemedi, rollback uygulanıyor.")

