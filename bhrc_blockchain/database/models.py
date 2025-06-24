from sqlalchemy import Column, Integer, Float, String, Text, JSON, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from datetime import datetime
from pydantic import BaseModel

Base = declarative_base()

class BlockModel(Base):
    __tablename__ = "blocks"

    id = Column(Integer, primary_key=True)
    block_index = Column("index", Integer)
    block_hash = Column(String)
    block_signature = Column(String)
    difficulty = Column(Integer)
    previous_hash = Column(String)
    timestamp = Column(Float)
    miner_address = Column(String)
    merkle_root = Column(String)
    events = Column(Text)
    producer_id = Column(String)
    nonce = Column(Integer)
    version = Column(String)
    virtual_size = Column(Integer)
    transactions = Column(JSON)

    @hybrid_property
    def index(self):
        return self.block_index

    @index.setter
    def index(self, value):
        self.block_index = value

class TransactionModel(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True)
    txid = Column(String)
    sender = Column(String)
    recipient = Column(String)
    amount = Column(Float)
    fee = Column(Float)
    message = Column(Text)
    note = Column(Text)
    type = Column(String)
    locktime = Column(Integer)
    time = Column(Float)
    script_sig = Column(Text)
    public_key = Column(Text)
    script_pubkey = Column(Text)
    status = Column(String)
    block_index = Column(Integer)

class UTXOModel(Base):
    __tablename__ = "utxos"

    id = Column(Integer, primary_key=True)
    txid = Column(String)
    output_index = Column(Integer)
    address = Column(String)
    amount = Column(Float)
    spent = Column(Integer, default=0)

class TokenTransferPayload(BaseModel):
    sender: str
    recipient: str
    symbol: str
    amount: float
    message: str
    signature: str

class LogModel(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    level = Column(String)
    message = Column(Text)
    source = Column(String)


class UndoLog(Base):
    __tablename__ = "undo_logs"

    id = Column(Integer, primary_key=True)
    action_type = Column(String, nullable=False)
    snapshot_ref = Column(String, nullable=True)
    meta_data = Column(JSON, nullable=True)
    reversed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class SessionLog(Base):
    __tablename__ = "session_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    username = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    login_time = Column(DateTime, default=datetime.utcnow)
    active = Column(Boolean, default=True)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="admin")
    status = Column(Boolean, default=True)


