import hashlib
import json
import time
from typing import List, Dict, Any, Optional, Union
from .wallet.wallet import verify_signature

class Block:
    def __init__(
        self,
        index: int,
        previous_hash: str,
        transactions: List[Dict[str, Any]],
        timestamp: float,
        nonce: int,
        miner_address: str,
        difficulty: str = "",
        version: str = "0x01",
        events: Optional[List[str]] = None,
        block_hash: Optional[str] = None,
        merkle_root: Optional[str] = None,
        block_signature: Optional[str] = None,
        producer_id: Optional[str] = None
    ):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.nonce = nonce
        self.miner_address = miner_address
        self.difficulty = difficulty
        self.version = version
        self.events = events if events is not None else []
        self.block_signature = block_signature
        self.producer_id = producer_id
        self.merkle_root = merkle_root or self.calculate_merkle_root()
        self.block_hash = block_hash or self.calculate_hash()

    def calculate_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "nonce": self.nonce,
            "miner_address": self.miner_address,
            "difficulty": self.difficulty,
            "version": self.version,
            "merkle_root": self.merkle_root
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def calculate_merkle_root(self) -> str:
        tx_hashes = [hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest() for tx in self.transactions]
        if not tx_hashes:
            return "0" * 64
        while len(tx_hashes) > 1:
            if len(tx_hashes) % 2 != 0:
                tx_hashes.append(tx_hashes[-1])
            tx_hashes = [
                hashlib.sha256((tx_hashes[i] + tx_hashes[i + 1]).encode()).hexdigest()
                for i in range(0, len(tx_hashes), 2)
            ]
        return tx_hashes[0]

    def calculate_virtual_size(self) -> int:
        size_dict = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "miner_address": self.miner_address,
            "difficulty": self.difficulty,
            "version": self.version,
            "events": self.events,
            "block_signature": self.block_signature,
            "producer_id": self.producer_id,
            "merkle_root": self.merkle_root,
            "block_hash": self.block_hash
        }
        return len(json.dumps(size_dict))

    def to_dict(self, include_hash: bool = True) -> Dict[str, Any]:
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "miner_address": self.miner_address,
            "difficulty": self.difficulty,
            "version": self.version,
            "events": self.events,
            "block_signature": self.block_signature,
            "producer_id": self.producer_id,
            "merkle_root": self.merkle_root,
        }

        if include_hash:
            block_data["block_hash"] = self.block_hash

        block_data["virtual_size"] = self.calculate_virtual_size()
        return block_data

    def mine(self) -> None:
        """Blok için nonce hesaplayarak geçerli hash bulur."""
        prefix = self.difficulty or "00"
        self.nonce = 0
        while True:
            self.block_hash = self.calculate_hash()
            if self.block_hash.startswith(prefix):
                break
            self.nonce += 1

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Block":
        return Block(
            index=data["index"],
            previous_hash=data["previous_hash"],
            transactions=data["transactions"],
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            miner_address=data["miner_address"],
            difficulty=data.get("difficulty", ""),
            version=data.get("version", "0x01"),
            events=data.get("events", []),
            block_signature=data.get("block_signature"),
            producer_id=data.get("producer_id"),
            merkle_root=data.get("merkle_root"),
            block_hash=data.get("block_hash")
        )

    @staticmethod
    def validate_block(block_like: Union['Block', dict]) -> bool:
        try:
            block_obj = Block.from_dict(block_like) if isinstance(block_like, dict) else block_like
            calculated = block_obj.calculate_hash()
            expected = block_obj.block_hash

            if calculated != expected:
                print(f"❌ Hatalı hash doğrulama!\nBeklenen: {expected}\nHesaplanan: {calculated}")
                return False

            if not verify_block_signature(block_obj):
                print("❌ Blok imzası geçersiz!")
                return False

        except Exception as e:
            print(f"❌ Hata oluştu: {e}")
            return False

        return True

def verify_block_signature(block: Block) -> bool:
    if not block.block_signature or not block.producer_id:
        return False

    try:
        message = block.calculate_hash()

        print("\n🔎 Doğrulama sırasında:")
        print(f"🔁 Hesaplanan hash (calculate_hash): {message}")
        print(f"🔒 Bloktaki hash (block_hash): {block.block_hash}")
        print(f"🔑 Public key (producer_id): {block.producer_id}")
        print(f"🖋️ Signature: {block.block_signature}")

        return verify_signature(
            message=message,
            signature=block.block_signature,
            public_key=block.producer_id
        )
    except Exception:
        return False

