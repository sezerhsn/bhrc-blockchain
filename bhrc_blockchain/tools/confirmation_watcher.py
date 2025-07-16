# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import asyncio
from bhrc_blockchain.core.logger.logging_utils import setup_logger

logger = setup_logger("Watcher")

async def watch_transaction_confirmation(txid: str, blockchain, timeout: int = 60):
    # Blockchain sınıfını buraya taşıyoruz
    from bhrc_blockchain.core.blockchain.blockchain import Blockchain

    logger.info(f"🔍 İşlem izleniyor: {txid} (timeout: {timeout}s)")
    for _ in range(timeout):
        for block in blockchain.chain:
            for tx in block.transactions:
                tx_data = tx if isinstance(tx, dict) else tx.to_dict()
                if tx_data.get("txid") == txid:
                    logger.info(f"✅ İşlem {txid} blok #{block.index} içinde onaylandı.")
                    return True
        await asyncio.sleep(1)

    logger.warning(f"⏱️ İşlem {txid} {timeout}s içinde onaylanmadı.")
    return False

