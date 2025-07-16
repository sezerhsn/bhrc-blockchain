# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from pydantic_settings import BaseSettings
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

class Config(BaseSettings):
    # Blockchain Ayarları
    INITIAL_DIFFICULTY: str = "0000"
    BLOCK_REWARD: float = 64
    TRANSACTION_FEE_PERCENTAGE: float = 0.001
    MIN_TRANSACTION_FEE: float = 0.0001
    MAX_BLOCK_SIZE: int = 1453000
    TARGET_TIME_PER_BLOCK: float = 3.5 * 60
    TOTAL_SUPPLY: float = 64000000
    HALVING_INTERVAL: int = 210000
    DIFFICULTY_ADJUSTMENT_INTERVAL: int = 5760

    # Dosya Yolları
    CHAIN_DB_PATH: str = "bhrc_blockchain.db"
    TOKEN_DB_PATH: str = "bhrc_token.db"
    MEMPOOL_CACHE_PATH: str = "mempool_cache.json"
    LOG_FILE_PATH: str = "bhrc_blockchain/logs/bhrc.log"
    FOUNDATION_WALLET_PATH: str = str(BASE_DIR / "wallets" / "foundation.json")
    FOUNDATION_WALLET_PASSWORD: str

    # Wallet Ayarları
    AES_SALT: bytes = b"bhrc_salt_2024"
    MAX_PASSWORD_ATTEMPTS: int = 5
    PASSWORD_ATTEMPT_WINDOW: int = 60  # saniye

    PBKDF2_ITERATIONS: int = 300_000
    AES_KEY_LENGTH: int = 32
    AES_ASSOCIATED_DATA: bytes = b"wallet_encryption_v1"

    # Mempool Ayarları
    MEMPOOL_TTL: int = 300 # saniye

    # Ağ tipi
    NETWORK: str = "testnet"

    # Test modu (memory-only mempool vs)
    TESTING: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Config()

