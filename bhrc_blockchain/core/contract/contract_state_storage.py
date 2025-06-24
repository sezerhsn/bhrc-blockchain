import sqlite3
import json
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "contract_state.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS contracts (
        contract_address TEXT PRIMARY KEY,
        code TEXT,
        state_json TEXT,
        created_at INTEGER,
        updated_at INTEGER
    )
    """)
    conn.commit()
    conn.close()

def save_contract_state(contract_address: str, code: str, state_dict: dict):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    now_ts = int(time.time())
    state_json = json.dumps(state_dict)

    c.execute("""
    INSERT INTO contracts (contract_address, code, state_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(contract_address) DO UPDATE SET
        code=excluded.code,
        state_json=excluded.state_json,
        updated_at=excluded.updated_at
    """, (contract_address, code, state_json, now_ts, now_ts))

    conn.commit()
    conn.close()

def load_contract_state(contract_address: str):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT code, state_json FROM contracts WHERE contract_address = ?", (contract_address,))
    row = c.fetchone()
    conn.close()

    if row:
        code, state_json = row
        state_dict = json.loads(state_json)
        return code, state_dict
    else:
        return None

def delete_contract_state(contract_address: str):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM contracts WHERE contract_address = ?", (contract_address,))
    conn.commit()
    conn.close()

def reset_all_contract_states():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM contracts")
    conn.commit()
    conn.close()

def list_all_contracts():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT contract_address, created_at, updated_at FROM contracts")
    rows = c.fetchall()
    conn.close()

    result = []
    for row in rows:
        addr, created_at, updated_at = row
        result.append({
            "contract_address": addr,
            "created_at": created_at,
            "updated_at": updated_at
        })

    return result
