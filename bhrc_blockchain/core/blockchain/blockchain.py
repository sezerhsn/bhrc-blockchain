# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────
import os
import json
import time
import bhrc_blockchain.database.orm_storage as orm_storage
from typing import Optional, List
from bhrc_blockchain.core.utxo.utxo_manager import UTXOManager
from bhrc_blockchain.core.block import Block, verify_block_signature
from bhrc_blockchain.core.transaction.transaction import validate_transaction, create_transaction, Transaction
from bhrc_blockchain.config.config import settings
from bhrc_blockchain.core.wallet.wallet import MinerWallet, sign_block, get_public_key_from_private_key, get_foundation_address
from bhrc_blockchain.utils.utils import get_readable_time
from bhrc_blockchain.database.models import BlockModel, UTXOModel
from bhrc_blockchain.database.orm_storage import get_session
from bhrc_blockchain.core.transaction.validation import ChainValidator
from bhrc_blockchain.core.logger.logger import setup_logger
from bhrc_blockchain.core.blockchain.mining import adjust_difficulty, mine_block as mining_function
from bhrc_blockchain.core.state.state_manager import StateManager
from bhrc_blockchain.network.notifications import emit_admin_alert
from bhrc_blockchain.core.mempool.mempool import Mempool

logger = setup_logger("Blockchain")

class Blockchain:
    def __init__(self, autoload: bool = True) -> None:
        self.chain: List[Block] = []
        self.block_reward: float = settings.BLOCK_REWARD
        self.difficulty_prefix: str = settings.INITIAL_DIFFICULTY
        self.miner_wallet: MinerWallet = MinerWallet(password="genesis", persist=False)
        self.utxos = {}
        self.current_transactions = []
        self.utxo_manager = UTXOManager()
        self.state = StateManager()
        self.mempool = Mempool()
        self.adjustment_interval = settings.DIFFICULTY_ADJUSTMENT_INTERVAL
        self.target_block_time = settings.TARGET_TIME_PER_BLOCK

        self.peers = []

        if autoload:
            logger.info("📦 Zincir başlatılıyor ve veritabanı yükleniyor...")
            self.load_chain_from_db()

        if autoload and not self.chain and os.path.exists("chain.json"):
            with open("chain.json", "r") as f:
                data = json.load(f)
                self.chain = [Block.from_dict(b) for b in data]
                logger.info("📂 chain.json dosyasından zincir yüklendi.")

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
                    "amount": self.block_reward,
                    "locked": True,
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

            block.block_hash = block.calculate_hash()
            block.producer_id = get_public_key_from_private_key(self.miner_wallet.private_key)
            block.block_signature = sign_block(block, self.miner_wallet.private_key)

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

                from bhrc_blockchain.core.wallet.wallet import MinerWallet
                from bhrc_blockchain.config.config import settings

                foundation_path = settings.FOUNDATION_WALLET_PATH
                foundation_pass = settings.FOUNDATION_WALLET_PASSWORD

                if not os.path.exists(foundation_path):
                    MinerWallet(wallet_path=foundation_path, password=foundation_pass, persist=True)
                    logger.info("🏛️ Foundation cüzdanı otomatik olarak oluşturuldu.")

        except Exception as e:
            logger.error(f"🚨 Genesis bloğu oluşturulamadı: {e}")

    def load_chain_from_db(self):
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
        if isinstance(block, dict):
            block = Block.from_dict(block)

        if not self.validate_block(block):
            return False

        try:
            self.chain.append(block)
            orm_storage.save_block(block.to_dict())

            self.state.apply_transactions(block.transactions)
            self.utxo_manager.remove_utxos(block.transactions)

            for tx in block.transactions:
                if "txid" in tx and "outputs" in tx:
                    orm_storage.save_utxos(tx["txid"], tx["outputs"])

            logger.info(f"✅ Yeni blok eklendi: {block.index}")

            emit_admin_alert("block_added", {
                "index": block.index,
                "hash": block.block_hash,
                "producer": getattr(block, "producer_id", "unknown")
            })

            return True

        except Exception as e:
            logger.error(f"🚨 Blok ekleme sırasında hata: {e}")
            self.chain.pop()
            return False

    def validate_block(self, block):
        if not isinstance(block, Block):
            return False

        if not Block.validate_block(block):
            return False

        if block.index == 0:
            logger.warning("⛔ Genesis blok dışarıdan eklenemez.")
            return False

        last_block = self.get_last_block()

        if block.index != last_block.index + 1:
            logger.warning(f"📛 Blok sırası hatalı: {block.index} bekleniyor: {last_block.index + 1}")
            return False

        if block.previous_hash != last_block.block_hash:
            logger.warning("📛 Önceki hash uyuşmuyor.")
            return False

        if block.timestamp <= last_block.timestamp:
            logger.warning("⏱️ Zaman damgası önceki bloktan küçük veya eşit.")
            return False

        if block.calculate_hash() != block.block_hash:
            logger.warning("🔐 Blok hash'i tutarsız.")
            return False

        if block.calculate_merkle_root() != block.merkle_root:
            logger.warning("🌿 Merkle root tutarsız.")
            return False

        if not verify_block_signature(block):
            logger.warning("✍️ İmza doğrulaması başarısız.")
            return False

        return True

    def reset_chain(self):
        self.chain = []
        self.create_genesis_block()
        logger.info("🔄 Zincir sıfırlandı.")

    def mine_block(self, transactions: List[dict] = None, miner_address: Optional[str] = None, miner_private_key: Optional[str] = None):
        miner = miner_address or self.miner_wallet.address

        foundation_address = get_foundation_address()
        if miner == foundation_address:
            raise ValueError("Vakfın blok kazma yetkisi yoktur (tüzük gereği).")

        last_block = self.get_last_block()

        if transactions is None:
            self.mempool.purge_expired_transactions(ttl=300)
            transactions = self.mempool.transactions
            logger.info(f"🧾 Mempool'dan {len(transactions)} işlem alındı.")

        if not transactions and last_block.index >= 1:
            logger.warning("⛔ Mempool boş! Blok kazımı için en az 1 işlem gerekli.")
            raise Exception("Mempool boş! Blok kazımı için en az 1 işlem gerekli.")

        new_block = mining_function(self.chain, transactions, miner)
        new_block.producer_id = get_public_key_from_private_key(miner_private_key or self.miner_wallet.private_key)
        new_block.block_hash = new_block.calculate_hash()
        new_block.block_signature = sign_block(new_block, miner_private_key or self.miner_wallet.private_key)

        self.add_block(new_block)
        self.mempool.remove_transactions(transactions)
        return new_block

    def get_chain_weight(self):
        return sum(len(str(getattr(block, "difficulty", ""))) for block in self.chain)

    def get_total_difficulty(self):
        return sum(len(str(getattr(block, "difficulty", ""))) for block in self.chain)

    def replace_chain_if_better(self, new_chain_data: list) -> dict:
        """
        Zinciri dışarıdan gelen zincirle kıyasla ve gerekirse değiştir.
        """
        try:

            new_chain = [Block.from_dict(b) for b in new_chain_data]

            if len(new_chain) <= len(self.chain):
                return {"status": "rejected", "message": "Zincir daha kısa veya eşit uzunlukta."}

            if self.validate_chain(new_chain):
                self.chain = new_chain
                self.save_chain()
                return {"status": "accepted", "message": "Zincir başarıyla güncellendi."}
            else:
                return {"status": "rejected", "message": "Zincir geçersiz."}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_total_transaction_count(self):
        return sum(len(block.transactions) for block in self.chain)

    def save_chain(self):
        """Zinciri veritabanına kaydeder."""
        with open("chain.json", "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=4)
        return True

    def get_block_by_index(self, index: int) -> Optional[Block]:
        """Verilen index'e karşılık gelen bloğu döner."""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """Verilen hash'e karşılık gelen bloğu döner."""
        for block in self.chain:
            if block.block_hash == block_hash:
                return block
        return None

    def get_block_range(self, start: int, end: int) -> List[Block]:
        """Verilen index aralığındaki blokları döner."""
        return self.chain[start:end + 1] if 0 <= start <= end < len(self.chain) else []

    def get_transaction(self, txid: str) -> Optional[dict]:
        """Verilen txid'ye ait işlemi zincir boyunca arar ve döner."""
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("txid") == txid:
                    return tx
        return None

    def verify_transaction_in_chain(self, txid: str) -> bool:
        """Bir işlemin zincirde olup olmadığını doğrular."""
        return any(
            tx.get("txid") == txid
            for block in self.chain
            for tx in block.transactions
        )

    def get_blocks_by_miner(self, address: str) -> List[Block]:
        """Belirli bir madenci adresine ait tüm blokları döner."""
        return [block for block in self.chain if block.miner_address == address]

    def get_chain_stats(self) -> dict:
        """Zincire dair temel istatistikleri döner."""
        total_blocks = len(self.chain)
        total_tx = sum(len(b.transactions) for b in self.chain)
        avg_tx_per_block = total_tx / total_blocks if total_blocks else 0
        last_block_time = self.chain[-1].timestamp if self.chain else None

        return {
            "total_blocks": total_blocks,
            "total_transactions": total_tx,
            "avg_tx_per_block": avg_tx_per_block,
            "last_block_time": last_block_time,
            "chain_weight": self.get_chain_weight(),
            "total_difficulty": self.get_total_difficulty(),
        }

    def get_block_time_stats(self) -> dict:
        """Bloklar arası zaman farkı istatistiklerini döner."""
        times = [
            self.chain[i].timestamp - self.chain[i - 1].timestamp
            for i in range(1, len(self.chain))
        ]
        return {
            "total_blocks": len(self.chain),
            "avg_time": sum(times) / len(times) if times else 0,
            "min_time": min(times) if times else 0,
            "max_time": max(times) if times else 0,
            "intervals": times
        }

    def get_chain_snapshot_hash(self) -> str:
        """Zincirdeki tüm blok hash’lerinden zincirin toplam özetini üretir."""
        from hashlib import sha256
        concatenated = ''.join(block.block_hash for block in self.chain)
        return sha256(concatenated.encode()).hexdigest()

    def detect_fork(self) -> bool:
        """Zincirde aynı previous_hash'e sahip birden fazla blok varsa fork vardır."""
        prev_hash_counts = {}
        for block in self.chain[1:]:  # genesis hariç
            prev = block.previous_hash
            prev_hash_counts[prev] = prev_hash_counts.get(prev, 0) + 1
            if prev_hash_counts[prev] > 1:
                return True
        return False

    def get_fork_blocks(self) -> List[Block]:
        """Fork oluşturan blokları döner (aynı previous_hash'e sahip olanlar)."""
        prev_hash_map = {}
        fork_blocks = []

        for block in self.chain[1:]:  # genesis hariç
            prev = block.previous_hash
            if prev not in prev_hash_map:
                prev_hash_map[prev] = [block]
            else:
                prev_hash_map[prev].append(block)

        for blocks in prev_hash_map.values():
            if len(blocks) > 1:
                fork_blocks.extend(blocks)

        return fork_blocks

    def detect_reorg(self, max_depth: int = 5) -> bool:
        """Son max_depth blok içinde reorg (geçmişte hash değişimi) olup olmadığını tespit eder."""
        seen = {}
        for block in reversed(self.chain[-max_depth:]):
            idx = block.index
            prev_hash = block.previous_hash
            if idx in seen:
                if seen[idx] != prev_hash:
                    return True
            else:
                seen[idx] = prev_hash
        return False

def get_blockchain():
    if not hasattr(get_blockchain, "instance"):
        get_blockchain.instance = Blockchain()
    return get_blockchain.instance

