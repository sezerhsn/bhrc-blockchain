import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Blockchain Ayarları
    INITIAL_DIFFICULTY = os.getenv("INITIAL_DIFFICULTY", "0000")
    BLOCK_REWARD = float(os.getenv("BLOCK_REWARD", 64))
    TRANSACTION_FEE_PERCENTAGE = float(os.getenv("TRANSACTION_FEE_PERCENTAGE", 0.001))
    MIN_TRANSACTION_FEE = float(os.getenv("MIN_TRANSACTION_FEE", 0.0001))
    MAX_BLOCK_SIZE = int(os.getenv("MAX_BLOCK_SIZE", 1453000))
    TARGET_TIME_PER_BLOCK = float(os.getenv("TARGET_TIME_PER_BLOCK", 3.5 * 60))
    TOTAL_SUPPLY = float(os.getenv("TOTAL_SUPPLY", 64000000))
    HALVING_INTERVAL = int(os.getenv("HALVING_INTERVAL", 210000))
    DIFFICULTY_ADJUSTMENT_INTERVAL = int(os.getenv("DIFFICULTY_ADJUSTMENT_INTERVAL", 5760))

    # Dosya Yolları
    CHAIN_DB_PATH = os.getenv("CHAIN_DB_PATH", "bhrc_blockchain.db")
    TOKEN_DB_PATH = os.getenv("TOKEN_DB_PATH", "bhrc_token.db")
    MEMPOOL_CACHE_PATH = os.getenv("MEMPOOL_CACHE_PATH", "mempool_cache.json")
    LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "bhrc_blockchain/logs/bhrc.log")

