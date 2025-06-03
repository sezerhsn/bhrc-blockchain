import sqlite3
import os
import time
from dataclasses import dataclass
from bhrc_blockchain.core.wallet.wallet import (
    get_public_key_from_private_key,
    verify_address_from_key,
    get_address_from_private_key,
    sign_message,
    generate_address
)
from bhrc_blockchain.core.transaction.transaction_model import Transaction
from bhrc_blockchain.utils.utils import get_readable_time
from fastapi import APIRouter, Depends
from bhrc_blockchain.core.blockchain.blockchain import get_blockchain

TOKEN_DB = os.path.join(os.getcwd(), "bhrc_token.db")

router = APIRouter()

def init_token_db():
    conn = sqlite3.connect(TOKEN_DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            name TEXT,
            symbol TEXT PRIMARY KEY,
            total_supply REAL,
            decimals INTEGER,
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
    conn.commit()
    conn.close()

@dataclass
class TokenContract:
    name: str
    symbol: str
    decimals: int
    total_supply: float
    creator: str

    def validate(self):
        return (
            isinstance(self.name, str)
            and isinstance(self.symbol, str)
            and self.symbol.isupper()
            and self.decimals >= 0
            and self.total_supply > 0
        )

    def deploy(self, sender_private_key):
        if not self.validate():
            raise ValueError("Token bilgileri eksik veya hatalı.")

        init_token_db()
        public_key = get_public_key_from_private_key(sender_private_key)
        sender_address = generate_address(public_key)

        if sender_address != self.creator:
            raise ValueError("İmza adresi ile token yaratıcısı uyuşmuyor")

        conn = sqlite3.connect(TOKEN_DB)
        c = conn.cursor()
        c.execute("SELECT * FROM tokens WHERE symbol = ?", (self.symbol,))
        if c.fetchone():
            conn.close()
            raise ValueError(f"{self.symbol} zaten var")

        c.execute("INSERT INTO tokens (name, symbol, total_supply, decimals, creator) VALUES (?, ?, ?, ?, ?)",
                  (self.name, self.symbol, self.total_supply, self.decimals, self.creator))
        c.execute("INSERT INTO token_balances (address, symbol, balance) VALUES (?, ?, ?)",
                  (self.creator, self.symbol, self.total_supply))
        conn.commit()
        conn.close()

        msg = f"Deploy:{self.symbol}:{self.total_supply}:{get_readable_time()}"
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

    @staticmethod
    def transfer(symbol, from_addr, to_addr, amount, sender_private_key):
        if not verify_address_from_key(sender_private_key, from_addr):
            raise ValueError("Özel anahtar, gönderici adresiyle eşleşmiyor.")

        init_token_db()
        conn = sqlite3.connect(TOKEN_DB)
        c = conn.cursor()

        c.execute("SELECT balance FROM token_balances WHERE address = ? AND symbol = ?", (from_addr, symbol))
        row = c.fetchone()
        if not row or row[0] < amount:
            conn.close()
            raise ValueError("Yetersiz token bakiyesi.")

        c.execute("UPDATE token_balances SET balance = balance - ? WHERE address = ? AND symbol = ?",
                  (amount, from_addr, symbol))
        c.execute("""
            INSERT INTO token_balances (address, symbol, balance)
            VALUES (?, ?, ?)
            ON CONFLICT(address, symbol) DO UPDATE SET balance = balance + excluded.balance
        """, (to_addr, symbol, amount))

        conn.commit()
        conn.close()

        return {
            "sender": from_addr,
            "recipient": to_addr,
            "amount": amount,
            "note": symbol,
            "txid": f"tx_{symbol.lower()}_{from_addr[:6]}"
        }

    @staticmethod
    def balance_of(address, symbol):
        conn = sqlite3.connect(TOKEN_DB)
        c = conn.cursor()
        c.execute("SELECT balance FROM token_balances WHERE address=? AND symbol=?", (address, symbol))
        row = c.fetchone()
        conn.close()
        return row[0] if row else 0.0

    @staticmethod
    def get(symbol):
        conn = sqlite3.connect(TOKEN_DB)
        c = conn.cursor()
        c.execute("SELECT name, symbol, total_supply, decimals, creator FROM tokens WHERE symbol = ?", (symbol,))
        row = c.fetchone()
        conn.close()
        if not row:
            raise ValueError("Token bulunamadı")
        return TokenContract(name=row[0], symbol=row[1], total_supply=row[2], decimals=row[3], creator=row[4])

def create_token_transaction(name, symbol, total_supply, decimals, creator_address, message, signature, blockchain):
    contract = TokenContract(name, symbol, decimals, total_supply, creator_address)
    tx = contract.deploy(signature)
    return {"txid": tx["txid"], "transaction": tx}

def create_token_transfer_transaction(symbol, amount, sender_address, recipient_address, message, signature, blockchain):
    tx = TokenContract.transfer(symbol, sender_address, recipient_address, amount, signature)
    return {"txid": tx["txid"], "transaction": tx}

def get_token_balance(symbol, address, blockchain):
    return {
        "balance": TokenContract.balance_of(address, symbol),
        "symbol": symbol,
        "address": address
    }

def get_token_transfers(symbol, address, blockchain):
    return {"transfers": []}  # Placeholder

def get_all_tokens(blockchain):
    conn = sqlite3.connect(TOKEN_DB)
    c = conn.cursor()
    c.execute("SELECT name, symbol, total_supply, decimals, creator FROM tokens")
    tokens = c.fetchall()
    conn.close()
    return [
        {"name": t[0], "symbol": t[1], "total_supply": t[2], "decimals": t[3], "creator": t[4]}
        for t in tokens
    ]

def get_token_details(symbol, blockchain):
    conn = sqlite3.connect(TOKEN_DB)
    c = conn.cursor()
    c.execute("SELECT name, symbol, total_supply, decimals, creator FROM tokens WHERE symbol = ?", (symbol,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise ValueError("Token bulunamadı")
    return {
        "name": row[0],
        "symbol": row[1],
        "total_supply": row[2],
        "decimals": row[3],
        "creator": row[4]
    }

