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
        status TEXT,
        start_time REAL,
        end_time REAL
    )
    """)

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

def add_proposal(title: str, description: str, creator: str, symbol: str, options: List[str], start_time=None, end_time=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    created_at = time.time()
    options_str = ",".join(options)

    if start_time and hasattr(start_time, "timestamp"):
        start_time = start_time.timestamp()
    if end_time and hasattr(end_time, "timestamp"):
        end_time = end_time.timestamp()

    c.execute("""
    INSERT INTO proposals (title, description, creator, symbol, created_at, options, status, start_time, end_time)
    VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)
    """, (title, description, creator, symbol, created_at, options_str, start_time, end_time))
    conn.commit()
    conn.close()

def list_proposals() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, title, description, creator, created_at, symbol, options, status, start_time, end_time FROM proposals ORDER BY created_at DESC")
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
            "status": row[7],
            "start_time": row[8],
            "end_time": row[9]
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

def get_proposal_by_id(proposal_id: int) -> Dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    SELECT id, title, description, creator, created_at, symbol, options, status, start_time, end_time
    FROM proposals WHERE id=?
    """, (proposal_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0],
            "title": row[1],
            "description": row[2],
            "creator": row[3],
            "created_at": row[4],
            "symbol": row[5],
            "options": row[6].split(","),
            "status": row[7],
            "start_time": row[8],
            "end_time": row[9]
        }
    return {}

def close_proposal(proposal_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    UPDATE proposals
    SET status='closed'
    WHERE id=?
    """, (proposal_id,))
    conn.commit()
    conn.close()

def delete_proposal(proposal_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("DELETE FROM votes WHERE proposal_id=?", (proposal_id,))
    c.execute("DELETE FROM proposals WHERE id=?", (proposal_id,))

    conn.commit()
    conn.close()

def list_open_proposals() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    SELECT id, title, description, creator, created_at, symbol, options, status
    FROM proposals WHERE status='open'
    ORDER BY created_at DESC
    """)
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

def list_closed_proposals() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    SELECT id, title, description, creator, created_at, symbol, options, status
    FROM proposals WHERE status='closed'
    ORDER BY created_at DESC
    """)
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

def get_votes_for_proposal(proposal_id: int) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    SELECT voter, option, weight, timestamp FROM votes
    WHERE proposal_id=?
    ORDER BY timestamp ASC
    """, (proposal_id,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            "voter": row[0],
            "option": row[1],
            "weight": row[2],
            "timestamp": row[3]
        }
        for row in rows
    ]

class DAOStorage:
    def get_all_tokens(self):
        """Her bir 'proposal' bir token olarak kabul edilirse token sayısını verir."""
        return list_proposals()

    def get_proposal(self, proposal_id: int):
        return get_proposal_by_id(proposal_id)

    def close(self, proposal_id: int):
        return close_proposal(proposal_id)

    def delete(self, proposal_id: int):
        return delete_proposal(proposal_id)

    def get_open_proposals(self):
        return list_open_proposals()

    def get_closed_proposals(self):
        return list_closed_proposals()

    def get_votes(self, proposal_id: int):
        return get_votes_for_proposal(proposal_id)

    def add_vote(self, proposal_id: int, voter: str, option: str, weight: float):
        return cast_vote(proposal_id, voter, option, weight)

