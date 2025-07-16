# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.logger.logger import setup_logger
from bhrc_blockchain.core.wallet.wallet import verify_block_signature

logger = setup_logger("Validation")

def validate_block_structure(block_data: dict) -> bool:
    required_fields = [
        "index", "previous_hash", "transactions", "timestamp",
        "nonce", "miner_address", "block_hash", "merkle_root"
    ]
    return all(field in block_data for field in required_fields)


class ChainValidator:
    @staticmethod
    def validate_chain(blockchain) -> bool:
        chain = blockchain.chain
        for i in range(1, len(chain)):
            current = chain[i]
            previous = chain[i - 1]

            if current.previous_hash != previous.block_hash:
                logger.warning(f"Blok #{i} önceki hash ile eşleşmiyor.")
                return False

            if current.block_hash != current.calculate_hash():
                logger.warning(f"Blok #{i} hash doğrulaması başarısız.")
                return False

            if current.merkle_root != current.calculate_merkle_root():
                logger.warning(f"Blok #{i} merkle root doğrulaması başarısız.")
                return False

            if not Block.validate_block(current.to_dict()):
                logger.warning(f"Blok #{i} yapısal olarak geçersiz.")
                return False

            if not verify_block_signature(current, current.block_signature, current.producer_id):
                logger.warning(f"Blok #{i} imza doğrulaması başarısız.")
                return False

        logger.info("Tüm bloklar başarıyla doğrulandı.")
        return True

