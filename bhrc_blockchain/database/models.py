from sqlalchemy import Column, Integer, Float, String, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property

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

from pydantic import BaseModel

class TokenTransferPayload(BaseModel):
    sender: str
    recipient: str
    symbol: str
    amount: float
    message: str
    signature: str

