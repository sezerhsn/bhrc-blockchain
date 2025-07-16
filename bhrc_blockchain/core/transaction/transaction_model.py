# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from dataclasses import dataclass, field
from typing import List, Optional
import time
import hashlib
import json

@dataclass
class TransactionInput:
    txid: str
    output_index: int

    def to_dict(self) -> dict:
        return {
            "txid": self.txid,
            "output_index": self.output_index
        }

@dataclass
class TransactionOutput:
    recipient: str
    amount: float
    locked: bool = False

    def to_dict(self) -> dict:
        return {
            "recipient": self.recipient,
            "amount": self.amount,
            "locked": self.locked
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
    script: Optional[str] = None  # ✅ YENİ
    txid: Optional[str] = None
    contract_result: Optional[dict] = None
    status: str = "ready"

    def to_dict(self) -> dict:
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
            "status": self.status,
        }
        if self.script_sig is not None:
            data["script_sig"] = self.script_sig
        if self.public_key is not None:
            data["public_key"] = self.public_key
        if self.script is not None:  # ✅ YENİ
            data["script"] = self.script
        if self.txid is not None:
            data["txid"] = self.txid
        if self.contract_result is not None:
            data["contract_result"] = self.contract_result
        return data

    def compute_txid(self) -> str:
        data = self.to_dict()
        data.pop("txid", None)  # txid kendisi hesaba dahil edilmemeli
        tx_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(tx_str.encode()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            sender=data.get("sender"),
            recipient=data.get("recipient"),
            amount=data.get("amount"),
            fee=data.get("fee", 0),
            message=data.get("message", ""),
            note=data.get("note", ""),
            type=data.get("type", "transfer"),
            locktime=data.get("locktime", 0),
            time=data.get("time", time.time()),
            inputs=[TransactionInput(**i) for i in data.get("inputs", [])],
            outputs=[TransactionOutput(**o) for o in data.get("outputs", [])],
            public_key=data.get("public_key"),
            script_sig=data.get("script_sig"),
            script=data.get("script"),
            contract_result=data.get("contract_result")
        )

