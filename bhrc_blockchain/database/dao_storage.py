import sqlite3
import time
from typing import List, Dict

DB_PATH = "dao.db"

def init_dao_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        creator TEXT,
        symbol TEXT,
        created_at REAL,
        options TEXT,
        status TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proposal_id INTEGER,
        voter TEXT,
        option TEXT,
        weight REAL,
        timestamp REAL
    )""")
    conn.commit()
    conn.close()

def add_proposal(title: str, description: str, creator: str, symbol: str, options: List[str]):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    created_at = time.time()
    options_str = ",".join(options)
    c.execute("""
    INSERT INTO proposals (title, description, creator, symbol, created_at, options, status)
    VALUES (?, ?, ?, ?, ?, ?, 'open')
    """, (title, description, creator, symbol, created_at, options_str))
    conn.commit()
    conn.close()

def list_proposals() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, title, description, creator, created_at, symbol, options, status FROM proposals ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": row[0],
            "title": row[1],
            "description": row[2],
            "creator": row[3],
            "created_at": row[4],
            "symbol": row[5],
            "options": row[6].split(","),
            "status": row[7]
        }
        for row in rows
    ]

def cast_vote(proposal_id: int, voter: str, option: str, weight: float):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = time.time()
    c.execute("""
    INSERT INTO votes (proposal_id, voter, option, weight, timestamp)
    VALUES (?, ?, ?, ?, ?)
    """, (proposal_id, voter, option, weight, timestamp))
    conn.commit()
    conn.close()

def get_results(proposal_id: int) -> Dict[str, float]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    SELECT option, SUM(weight) FROM votes
    WHERE proposal_id=?
    GROUP BY option
    """, (proposal_id,))
    results = {row[0]: row[1] for row in c.fetchall()}
    conn.close()
    return results

class DAOStorage:
    def get_all_tokens(self):
        """Her bir 'proposal' bir token olarak kabul edilirse token sayısını verir."""
        return list_proposals()

