# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

# ──────────────────────────────────────────────
# 🔒 This file is part of the BHRC Blockchain Project
# 📛 Author: Sezer H.
# 📨 Contact: sezerhsn@gmail.com
# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain
# 📜 License: MIT License (see LICENSE file for details)
# ──────────────────────────────────────────────
import asyncio
import random
import argparse
from bhrc_blockchain.core.wallet.wallet import MinerWallet
from bhrc_blockchain.core.transaction.transaction import create_transaction
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.network.notifications import start_notification_server

def parse_arguments():
    parser = argparse.ArgumentParser(description="BHRC Blockchain Simülasyon Aracı")
    parser.add_argument("--mode", choices=["simulate", "websocket"], required=True, help="Çalışma modu")
    parser.add_argument("--tx-count", type=int, default=None)
    parser.add_argument("--wallet-count", type=int, default=3)
    parser.add_argument("--block-limit", type=int, default=None)
    parser.add_argument("--block-until-mempool-empty", action="store_true")
    parser.add_argument("--sleep-time", type=float, default=0.1)
    return parser.parse_args()

def simulate():
    print("⛏️ Madencilik simülasyonu başlatılıyor...")  # pragma: no cover
    args = parse_arguments()

    chain, wallets = asyncio.run(MiningSimulation(
        tx_count=args.tx_count,
        wallet_count=args.wallet_count,
        block_limit=args.block_limit,
        block_until_mempool_empty=args.block_until_mempool_empty,
        sleep_time=args.sleep_time
    ).simulate())

    print_block_summary(chain, wallets)

    import json
    with open("simulated_chain.json", "w") as f:
        json.dump([b.to_dict() for b in chain], f, indent=2)

    return chain, wallets

class MiningSimulation:
    def __init__(
        self,
        block_limit=None,
        tx_count=None,
        wallet_count=3,
        block_until_mempool_empty=False,
        persist_wallets=True,
        sleep_time=0.1
    ):
        self.blockchain = Blockchain()
        self.wallets = []
        self.block_limit = block_limit
        self.tx_count = tx_count
        self.wallet_count = wallet_count
        self.block_until_mempool_empty = block_until_mempool_empty
        self.persist_wallets = persist_wallets
        self.sleep_time = sleep_time
        self._initialize_wallets()

    def _initialize_wallets(self):
        for _ in range(self.wallet_count):
            self.create_random_wallet()

    def create_random_wallet(self):
        wallet = MinerWallet(password=None, persist=self.persist_wallets)
        self.wallets.append(wallet)
        return wallet

    def pick_random_wallet(self, exclude=None):
        candidates = [w for w in self.wallets if w != exclude]
        return random.choice(candidates)

    def create_random_transfer(self):
        sender = self.pick_random_wallet()
        recipient = self.pick_random_wallet(exclude=sender)
        amount = round(random.uniform(1, 5), 2)

        tx = create_transaction(
            sender=sender.address,
            recipient=recipient.address,
            amount=amount,
            sender_private_key=sender.private_key,
            message="Simülasyon transferi",
            note="",
            tx_type="transfer"
        )
        return tx

    async def simulate(self):
        tx_created = 0
        block_mined = 0

        while True:
            if self.tx_count is not None and tx_created >= self.tx_count:
                pass
            else:
                try:
                    tx = self.create_random_transfer()
                    self.blockchain.add_transaction_to_mempool(tx)
                    tx_created += 1
                except Exception:
                    pass

            await asyncio.sleep(self.sleep_time)

            mempool_size = len(self.blockchain.mempool.transactions)
            block = self.blockchain.mine_block()
            if block:
                block.mempool_size_before = mempool_size
                block_mined += 1

            if self.block_limit is not None and block_mined >= self.block_limit:
                break
            if self.tx_count is not None and tx_created >= self.tx_count:
                if not self.block_until_mempool_empty:
                    break
                elif self.blockchain.mempool.is_empty():
                    break

        return self.blockchain.chain, self.wallets

def print_block_summary(chain, wallets):
    for block in chain[1:]:
        print(f"\n🧱 Blok #{block.index}")
        print(f"  ⛏️ Miner: {block.miner}")
        print(f"  📦 İşlem sayısı: {len(block.transactions)}")
        print(f"  🧃 Mempool yoğunluğu (öncesi): {getattr(block, 'mempool_size_before', '?')}")
        print(f"  💰 Coinbase: {block.coinbase_amount}")
        print(f"  💸 Toplam ücret: {block.total_fees}")
        print(f"  🕓 Zaman: {block.timestamp}")

async def main():
    print("🚀 WebSocket + Simülasyon başlatılıyor...") # pragma: no cover
    await asyncio.gather(
        start_notification_server(),
        MiningSimulation().simulate()
    )

if __name__ == "__main__": # pragma: no cover
    args = parse_arguments()

    if getattr(args, "mode", None) == "simulate":
        simulate()
    elif args.mode == "websocket":
        asyncio.run(main())
    else:
        print("Lütfen '--mode simulate' veya '--mode websocket' belirtin.")

