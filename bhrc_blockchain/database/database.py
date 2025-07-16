# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from bhrc_blockchain.database.models import Base

DATABASE_URL = "sqlite:///bhrc_blockchain.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Session = SessionLocal

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

