# multisig_storage.py

import sqlite3
import json
import time
from typing import List, Dict

DB_PATH = "multisig.db"

def init_multisig_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS multisig (
        txid TEXT PRIMARY KEY,
        initiator TEXT,
        data TEXT,
        required_signers TEXT,
        signatures TEXT,
        status TEXT,
        created_at REAL
    )
    """)
    conn.commit()
    conn.close()

def create_multisig_tx(txid: str, initiator: str, data: dict, required_signers: List[str]):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    created_at = time.time()
    c.execute("""
    INSERT INTO multisig (txid, initiator, data, required_signers, signatures, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?)
    """, (
        txid,
        initiator,
        json.dumps(data),
        json.dumps(required_signers),
        json.dumps([]),
        created_at
    ))
    conn.commit()
    conn.close()

def add_signature(txid: str, signer: str, signature: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT signatures, required_signers FROM multisig WHERE txid = ?", (txid,))
    row = c.fetchone()
    if not row:
        raise ValueError("İşlem bulunamadı.")

    signatures = json.loads(row[0])
    required = json.loads(row[1])

    if signer not in required:
        raise ValueError("Bu adres imza yetkisine sahip değil.")
    if any(sig["address"] == signer for sig in signatures):
        raise ValueError("Bu adres zaten imza verdi.")

    signatures.append({"address": signer, "signature": signature})
    new_status = "ready" if len(signatures) >= len(required) else "pending"

    c.execute("""
    UPDATE multisig SET signatures = ?, status = ?
    WHERE txid = ?
    """, (json.dumps(signatures), new_status, txid))
    conn.commit()
    conn.close()

def get_multisig_tx(txid: str) -> Dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM multisig WHERE txid = ?", (txid,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise ValueError("İşlem bulunamadı.")
    return {
        "txid": row[0],
        "initiator": row[1],
        "data": json.loads(row[2]),
        "required_signers": json.loads(row[3]),
        "signatures": json.loads(row[4]),
        "status": row[5],
        "created_at": row[6]
    }

def list_pending_multisigs() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT txid, data, status FROM multisig WHERE status = 'pending'")
    rows = c.fetchall()
    conn.close()
    return [
        {"txid": row[0], "data": json.loads(row[1]), "status": row[2]}
        for row in rows
    ]

def list_ready_multisigs() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT txid, data, status FROM multisig WHERE status = 'ready'")
    rows = c.fetchall()
    conn.close()
    return [
        {"txid": row[0], "data": json.loads(row[1]), "status": row[2]}
        for row in rows
    ]

