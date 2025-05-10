# token.py
from dataclasses import dataclass
from typing import Dict
import sqlite3
import os
import time
import bhrc_blockchain.core.wallet as wallet
from bhrc_blockchain.core.wallet import sign_message, get_public_key_from_private_key
from bhrc_blockchain.core.transaction_model import Transaction, TransactionInput, TransactionOutput
from bhrc_blockchain.utils.utils import get_readable_time

TOKEN_DB = "bhrc_token.db"

@dataclass
class TokenContract:
    name: str
    symbol: str
    decimals: int
    total_supply: float
    creator: str

    def deploy(self, sender_private_key):
        if not self.validate():
            raise ValueError("Token bilgileri eksik veya hatalı.")

        conn = sqlite3.connect(TOKEN_DB)
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                symbol TEXT PRIMARY KEY,
                name TEXT,
                decimals INTEGER,
                total_supply REAL,
                creator TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS token_balances (
                address TEXT,
                symbol TEXT,
                balance REAL,
                PRIMARY KEY (address, symbol)
            )
        """)

        c.execute("INSERT INTO tokens (symbol, name, decimals, total_supply, creator) VALUES (?, ?, ?, ?, ?)",
                  (self.symbol, self.name, self.decimals, self.total_supply, self.creator))

        c.execute("INSERT INTO token_balances (address, symbol, balance) VALUES (?, ?, ?)",
                  (self.creator, self.symbol, self.total_supply))

        conn.commit()
        conn.close()

        # Zincire deploy işlemini yaz (optional tx kaydı)
        timestamp = get_readable_time()
        msg = f"Deploy:{self.symbol}:{self.total_supply}:{timestamp}"
        public_key = get_public_key_from_private_key(sender_private_key)
        signature = sign_message(sender_private_key, msg)

        deploy_tx = Transaction(
            sender=self.creator,
            recipient="TOKEN_CONTRACT",
            amount=0.0,
            fee=0.0,
            message=f"Token deploy: {self.name}",
            note=self.symbol,
            type="token_deploy",
            locktime=0,
            time=time.time(),
            inputs=[],
            outputs=[],
            public_key=public_key,
            script_sig=signature
        )
        deploy_tx.txid = deploy_tx.compute_txid()
        return deploy_tx.to_dict()

    def validate(self):
        return (
            isinstance(self.name, str)
            and isinstance(self.symbol, str)
            and self.symbol.isupper()
            and self.decimals >= 0
            and self.total_supply > 0
        )

    @staticmethod
    def balance_of(address: str, symbol: str) -> float:
        conn = sqlite3.connect(TOKEN_DB)
        c = conn.cursor()
        c.execute("SELECT balance FROM token_balances WHERE address=? AND symbol=?", (address, symbol))
        row = c.fetchone()
        conn.close()
        return row[0] if row else 0.0

    @staticmethod
    def transfer(symbol: str, from_addr: str, to_addr: str, amount: float, sender_private_key: str) -> bool:
        from bhrc_blockchain.core import wallet

        # Adres doğrulama
        if not wallet.verify_address_from_key(sender_private_key, from_addr):
            raise ValueError("Özel anahtar, gönderici adresiyle eşleşmiyor.")

        conn = sqlite3.connect(TOKEN_DB)
        c = conn.cursor()

        # Bakiye kontrolü
        c.execute("SELECT balance FROM token_balances WHERE address=? AND symbol=?", (from_addr, symbol))
        row = c.fetchone()
        if not row or row[0] < amount:
            conn.close()
            raise ValueError("Yetersiz token bakiyesi.")

        # Güncelle
        c.execute("UPDATE token_balances SET balance = balance - ? WHERE address=? AND symbol=?",
                  (amount, from_addr, symbol))
        c.execute("""
            INSERT INTO token_balances (address, symbol, balance)
            VALUES (?, ?, ?)
            ON CONFLICT(address, symbol) DO UPDATE SET balance = balance + excluded.balance
        """, (to_addr, symbol, amount))

        conn.commit()
        conn.close()
        return True

