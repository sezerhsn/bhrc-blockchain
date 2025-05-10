import time
import traceback
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.transaction import create_transaction
from bhrc_blockchain.core.mempool import get_ready_transactions, clear_mempool
from bhrc_blockchain.network.p2p import broadcast_new_block
from bhrc_blockchain.utils.utils import get_readable_time

def create_genesis_block(self):
    try:
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
                "amount": self.block_reward
            }]
        }

        block = Block(
            index=0,
            previous_hash="0",
            transactions=[genesis_transaction],
            miner_address=self.miner_wallet.address,
            nonce=0,
            version="0x01"
        )

        block_data = block.to_dict()
        self.chain.append(block_data)
        self.db.save_block(block_data)
        self.db.save_utxos(genesis_transaction["txid"], genesis_transaction["outputs"])
        print("✅ Genesis Block başarıyla oluşturuldu!")

    except Exception as e:
        print("🚨 Genesis bloğu oluşturulamadı:", e)


def adjust_difficulty(self):
    if len(self.chain) < self.adjustment_interval + 1:
        return

    latest_block = self.chain[-1]
    comparison_block = self.chain[-1 - self.adjustment_interval]

    actual_time = latest_block["timestamp"] - comparison_block["timestamp"]
    expected_time = self.adjustment_interval * self.target_block_time
    ratio = actual_time / expected_time
    zero_count = len(self.difficulty_prefix)

    if ratio < 0.5:
        zero_count += 1
    elif ratio > 2.0 and zero_count > 1:
        zero_count -= 1

    self.difficulty_prefix = "0" * zero_count
    print(f"🎯 Zorluk güncellendi: Yeni prefix → {self.difficulty_prefix} (Oran: {ratio:.2f})")

__all__ = ["create_genesis_block", "adjust_difficulty", "mine_block", "create_transaction"]

