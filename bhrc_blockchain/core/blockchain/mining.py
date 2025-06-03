import time
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.logger.logging_utils import setup_logger

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


def mine_block(chain, transactions, miner_address):
    previous_block = chain[-1]
    index = previous_block.index + 1
    difficulty = "0000"
    nonce = 0
    version = "0x01"
    timestamp = time.time()

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

