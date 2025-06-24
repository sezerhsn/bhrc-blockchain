from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

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

    # Ağ tipi
    NETWORK: str = "testnet"

    # Test modu (memory-only mempool vs)
    TESTING: bool = True  # Test sırasında True olmalı

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Config()

