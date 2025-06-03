import os
import json
import time
from typing import Optional, List
from bhrc_blockchain.core.utxo.utxo_manager import UTXOManager
from bhrc_blockchain.core.block import Block, verify_block_signature
from bhrc_blockchain.core.mempool.mempool import get_ready_transactions, clear_mempool, remove_transaction_from_mempool
from bhrc_blockchain.core.transaction.transaction import validate_transaction, create_transaction, Transaction
from bhrc_blockchain.config.config import Config
from bhrc_blockchain.core.wallet.wallet import MinerWallet, sign_block, get_public_key_from_private_key
from bhrc_blockchain.utils.utils import get_readable_time
import bhrc_blockchain.database.orm_storage as orm_storage
from bhrc_blockchain.database.models import BlockModel, UTXOModel
from bhrc_blockchain.database.orm_storage import get_session
from bhrc_blockchain.core.transaction.validation import ChainValidator
from bhrc_blockchain.core.logger.logger import setup_logger
from bhrc_blockchain.core.blockchain.mining import adjust_difficulty, mine_block as mining_function
from bhrc_blockchain.core.state.state_manager import StateManager

logger = setup_logger("Blockchain")

class Blockchain:
    def __init__(self, autoload: bool = True) -> None:
        self.chain: List[Block] = []
        self.block_reward: float = Config.BLOCK_REWARD
        self.difficulty_prefix: str = Config.INITIAL_DIFFICULTY
        self.miner_wallet: MinerWallet = MinerWallet(password="genesis", persist=False)
        self.utxos = {}
        self.current_transactions = []
        self.utxo_manager = UTXOManager()
        self.state = StateManager()
        self.adjustment_interval = Config.DIFFICULTY_ADJUSTMENT_INTERVAL
        self.target_block_time = Config.TARGET_TIME_PER_BLOCK

        self.mempool = []
        self.peers = []

        if autoload:
            self.load_chain_from_db()
        if not self.chain:
            self.create_genesis_block()

    def create_genesis_block(self) -> None:
        try:
            session = get_session()
            session.query(BlockModel).delete()
            session.query(UTXOModel).delete()
            session.commit()
            session.close()
            logger.info("🧹 Zincir ve UTXO veritabanı temizlendi (Genesis öncesi)")

            genesis_transaction = {
                "txid": "GENESIS_TXID",
                "sender": "SYSTEM",
                "recipient": self.miner_wallet.address,
                "amount": self.block_reward,
                "fee": 0.0,
                "message": "BHRC ağının ilk bloğu 🎉",
                "note": "Genesis Block",
                "type": "coinbase",
                "locktime": 0,
                "time": get_readable_time(),
                "script_sig": "SIGN(SYSTEM)",
                "script_pubkey": f"PUBKEY({self.miner_wallet.address})",
                "status": "ready",
                "outputs": [{
                    "recipient": self.miner_wallet.address,
                    "address": self.miner_wallet.address,
                    "amount": self.block_reward
                }]
            }

            block = Block(
                index=0,
                previous_hash="0",
                transactions=[genesis_transaction],
                timestamp=time.time(),
                nonce=0,
                miner_address=self.miner_wallet.address,
                difficulty=self.difficulty_prefix,
                version="0x01",
                events=["🎉 Genesis Block oluşturuldu."]
            )

            self.chain.append(block)
            orm_storage.save_block(block.to_dict())
            orm_storage.save_utxos(genesis_transaction["txid"], genesis_transaction["outputs"])
            self.utxo_manager.add_utxos(genesis_transaction["txid"], genesis_transaction["outputs"])
            self.state.init_genesis_state(self.miner_wallet.address, self.block_reward)

            logger.info("✅ Genesis Block başarıyla oluşturuldu!")

            if not self.validate_chain():
                logger.error("🚨 Zincir doğrulaması başarısız!")
            else:
                logger.info("✅ Zincir geçerli.")
        except Exception as e:
            logger.error(f"🚨 Genesis bloğu oluşturulamadı: {e}")

    def load_chain_from_db(self):
        logger.info("📦 Zincir veritabanından yükleniyor...")

        try:
            session = orm_storage.get_session()
            blocks = session.query(BlockModel).all()
            session.close()

            if blocks:
                self.chain = []
                for block in blocks:
                    try:
                        block_dict = {
                            "index": block.index,
                            "previous_hash": block.previous_hash,
                            "timestamp": block.timestamp,
                            "transactions": json.loads(block.transactions),
                            "block_hash": block.block_hash,
                            "nonce": block.nonce,
                            "difficulty": block.difficulty,
                            "events": json.loads(block.events) if isinstance(block.events, str) else [],
                            "producer_id": block.producer_id,
                            "block_signature": block.block_signature,
                            "miner_address": block.miner_address,
                            "merkle_root": block.merkle_root,
                            "version": block.version,
                        }

                        self.chain.append(Block.from_dict(block_dict))

                    except Exception as e:
                        logger.error(f"🚨 Zincir bloğu yüklenemedi: {e}")
                        continue
            else:
                logger.warning("⚠️ Zincir veritabanında hiçbir blok bulunamadı.")

        except Exception as e:
            logger.error(f"🚨 Zincir yüklenemedi: {e}")

    def validate_chain(self) -> bool:
        return ChainValidator.validate_chain(self)

    def get_last_block(self):
        return self.chain[-1] if self.chain else None

    def add_block(self, block: Block) -> bool:
        if self.validate_block(block):
            self.chain.append(block)
            orm_storage.save_block(block.to_dict())
            logger.info(f"✅ Yeni blok eklendi: {block.index}")
            return True
        return False

    def validate_block(self, block):
        # Yapısal doğrulama
        if not Block.validate_block(block):
            return False

        # Zincirle uyumluluk
        last_block = self.get_last_block()

        if block.index != last_block.index + 1:
            return False

        if block.previous_hash != last_block.block_hash:
            return False

        return True

    def reset_chain(self):
        self.chain = []
        self.create_genesis_block()
        logger.info("🔄 Zincir sıfırlandı.")

    def mine_block(self, transactions: List[dict] = None, miner_address: Optional[str] = None):
        miner = miner_address or self.miner_wallet.address
        transactions = transactions or []

        new_block = mining_function(self.chain, transactions, miner)
        new_block.producer_id = self.miner_wallet.public_key
        new_block.block_hash = new_block.calculate_hash()
        new_block.block_signature = sign_block(new_block, self.miner_wallet.private_key)

        self.add_block(new_block)
        return new_block

    def get_chain_weight(self):
        return sum(len(getattr(block, "difficulty", "")) for block in self.chain)

    def get_total_difficulty(self):
        return sum(len(getattr(block, "difficulty", "")) for block in self.chain)

    def replace_chain_if_better(self, new_chain_data: list) -> dict:
        """
        Zinciri dışarıdan gelen zincirle kıyasla ve gerekirse değiştir.
        """
        try:
            new_chain = [Block.from_dict(b) for b in new_chain_data]

            if len(new_chain) <= len(self.chain):
                return {"status": "rejected", "message": "Zincir daha kısa veya eşit uzunlukta."}

            # Eğer zincir geçerliyse ve daha uzunsa değiştir
            if self.validate_chain(new_chain):
                self.chain = new_chain
                self.save_chain()
                return {"status": "accepted", "message": "Zincir başarıyla güncellendi."}
            else:
                return {"status": "rejected", "message": "Zincir geçersiz."}

        except Exception as e:
            return {"status": "error", "message": str(e)}

def get_blockchain():
    if not hasattr(get_blockchain, "instance"):
        get_blockchain.instance = Blockchain()
    return get_blockchain.instance

