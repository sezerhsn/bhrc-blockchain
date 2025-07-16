# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import sqlite3
import time
from typing import List, Dict

NFT_DB_PATH = "nft.db"

def init_nft_db():
    conn = sqlite3.connect(NFT_DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS nfts (
        id TEXT PRIMARY KEY,
        owner TEXT,
        name TEXT,
        description TEXT,
        uri TEXT,
        created_at REAL
    )
    """)
    conn.commit()
    conn.close()

def mint_nft(nft_id: str, owner: str, name: str, description: str, uri: str):
    conn = sqlite3.connect(NFT_DB_PATH)
    c = conn.cursor()
    created_at = time.time()
    c.execute("""
    INSERT INTO nfts (id, owner, name, description, uri, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (nft_id, owner, name, description, uri, created_at))
    conn.commit()
    conn.close()

def get_all_nfts() -> List[Dict]:
    conn = sqlite3.connect(NFT_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, owner, name, description, uri, created_at FROM nfts ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": row[0],
            "owner": row[1],
            "name": row[2],
            "description": row[3],
            "uri": row[4],
            "created_at": row[5]
        } for row in rows
    ]

def get_nfts_by_owner(address: str) -> List[Dict]:
    conn = sqlite3.connect(NFT_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, description, uri, created_at FROM nfts WHERE owner = ?", (address,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": row[0],
            "name": row[1],
            "description": row[2],
            "uri": row[3],
            "created_at": row[4]
        } for row in rows
    ]

class NFTStorage:
    def get_all_nfts(self):
        return get_all_nfts()

