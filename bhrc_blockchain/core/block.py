# block.py
from dataclasses import dataclass, field
import hashlib
import json
import time
from bhrc_blockchain.utils.utils import get_readable_time

@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: list
    miner_address: str
    nonce: int = 0
    version: str = "0x01"
    timestamp: float = field(default_factory=time.time)
    difficulty: str = "0000"
    merkle_root: str = field(init=False)
    block_hash: str = field(init=False)
    virtual_size: int = field(init=False)
    readable_time: str = field(init=False)

    def __post_init__(self):
        if not self.miner_address:
            raise ValueError("Miner address boş olamaz.")
        self.merkle_root = self.calculate_merkle_root()
        self.virtual_size = self.calculate_virtual_size()
        self.readable_time = get_readable_time(self.timestamp)
        self.block_hash = self.calculate_block_hash()


    def calculate_merkle_root(self):
        if not self.transactions:
            return "N/A"
        tx_hashes = [hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
                     for tx in self.transactions]
        while len(tx_hashes) > 1:
            if len(tx_hashes) % 2 != 0:
                tx_hashes.append(tx_hashes[-1])
            tx_hashes = [hashlib.sha256((tx_hashes[i] + tx_hashes[i+1]).encode()).hexdigest()
                         for i in range(0, len(tx_hashes), 2)]
        return tx_hashes[0]

    def calculate_block_hash(self):
        block_dict = self.to_dict(include_hash=False)
        block_string = json.dumps(block_dict, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def calculate_virtual_size(self):
        transaction_size = 200
        metadata_size = 500
        total_size = len(self.transactions) * transaction_size + metadata_size
        return total_size

    def to_dict(self, include_hash=True):
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "miner_address": self.miner_address,
            "nonce": self.nonce,
            "version": self.version,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "virtual_size": self.virtual_size,
            "readable_time": self.readable_time
        }
        if include_hash:
            block_data["block_hash"] = self.block_hash
        return block_data

