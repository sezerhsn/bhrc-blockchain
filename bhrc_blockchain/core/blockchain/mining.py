import time
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.logger.logging_utils import setup_logger
from bhrc_blockchain.core.wallet.wallet import get_foundation_address
from bhrc_blockchain.config.config import settings

logger = setup_logger("Mining")

def adjust_difficulty(self):
    if len(self.chain) < self.adjustment_interval + 1:
        return

    latest_block = self.chain[-1]
    comparison_block = self.chain[-1 - self.adjustment_interval]

    actual_time = latest_block.timestamp - comparison_block.timestamp
    expected_time = self.adjustment_interval * self.target_block_time
    ratio = actual_time / expected_time

    ratio = max(0.25, min(ratio, 4.0))

    zero_count = len(self.difficulty_prefix)

    if ratio < 0.9:
        zero_count += 1
    elif ratio > 1.1 and zero_count > 1:
        zero_count -= 1

    self.difficulty_prefix = "0" * zero_count
    logger.info(f"🎯 Zorluk güncellendi: Yeni prefix → '{self.difficulty_prefix}' | Oran: {ratio:.2f}")

def mine_block(chain, transactions=None, miner_address=None):
    if transactions is None:
        transactions = []

    total_fees = sum(tx.get("fee", 0) for tx in transactions)
    fee_foundation = total_fees / 2
    fee_miner = total_fees - fee_foundation

    previous_block = chain[-1]
    index = previous_block.index + 1
    difficulty = "0000"
    nonce = 0
    version = "0x01"
    timestamp = time.time()

    foundation_address = get_foundation_address()

    coinbase_tx = {
        "txid": f"COINBASE_{index}",
        "sender": "SYSTEM",
        "recipient": miner_address,
        "amount": 64.0 + fee_miner,
        "fee": 0.0,
        "message": f"Blok {index} coinbase ödülü",
        "note": "Coinbase Transaction",
        "type": "coinbase",
        "locktime": 0,
        "time": time.strftime("%d-%m-%Y %H:%M:%S"),
        "script_sig": "SIGN(SYSTEM)",
        "script_pubkey": f"PUBKEY({miner_address})",
        "status": "ready",
        "outputs": [
            {
                "recipient": miner_address,
                "address": miner_address,
                "amount": 64.0 + fee_miner
            },
            {
                "recipient": foundation_address,
                "address": foundation_address,
                "amount": fee_foundation
            }
        ]
    }

    transactions = [coinbase_tx] + transactions

    while True:
        block = Block(
            index=index,
            previous_hash=previous_block.block_hash,
            transactions=transactions,
            timestamp=timestamp,
            nonce=nonce,
            miner_address=miner_address,
            difficulty=difficulty,
            version=version,
            events=[f"⛏ Blok {index} kazıldı."]
        )
        if block.block_hash.startswith(difficulty):
            logger.info(f"✅ Blok {index} başarıyla kazıldı. Nonce: {nonce}")
            return block
        nonce += 1

