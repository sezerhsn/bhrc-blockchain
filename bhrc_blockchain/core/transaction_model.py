# transaction_model.py
from dataclasses import dataclass, field
from typing import List, Optional
import time
import hashlib
import json

@dataclass
class TransactionInput:
    txid: str
    output_index: int

    def __init__(self, txid, output_index):
        self.txid = txid
        self.output_index = output_index

    def to_dict(self):
        return {
            "txid": self.txid,
            "output_index": self.output_index
        }

@dataclass
class TransactionOutput:
    recipient: str
    amount: float

    def __init__(self, recipient, amount):
        self.recipient = recipient
        self.amount = amount

    def to_dict(self):
        return {
            "recipient": self.recipient,
            "amount": self.amount
        }

@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: float
    fee: float
    message: str = ""
    note: str = ""
    type: str = "transfer"
    locktime: int = 0
    time: float = field(default_factory=time.time)
    inputs: List[TransactionInput] = field(default_factory=list)
    outputs: List[TransactionOutput] = field(default_factory=list)
    public_key: Optional[str] = None
    script_sig: Optional[str] = None
    txid: Optional[str] = None

    def to_dict(self):
        data = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "fee": self.fee,
            "message": self.message,
            "note": self.note,
            "type": self.type,
            "locktime": self.locktime,
            "time": self.time,
            "inputs": [inp.to_dict() for inp in self.inputs],
            "outputs": [out.to_dict() for out in self.outputs],
            "txid": self.txid
        }
        if self.script_sig is not None:
            data["script_sig"] = self.script_sig
        if self.public_key is not None:
            data["public_key"] = self.public_key
        return data

    def compute_txid(self):
        tx_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(tx_str.encode()).hexdigest()

