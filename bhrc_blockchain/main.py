import asyncio
import random
from bhrc_blockchain.core.wallet.wallet import MinerWallet
from bhrc_blockchain.core.transaction.transaction import create_transaction
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.network.notifications import start_notification_server

class MiningSimulation:
    def __init__(self, block_limit=3):
        self.blockchain = Blockchain()
        self.wallets = []
        self.block_limit = block_limit
        self._initialize_wallets()

    def _initialize_wallets(self):
        for _ in range(3):
            self.create_random_wallet()

    def create_random_wallet(self):
        wallet = MinerWallet(password=None, persist=False)
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
        for _ in range(self.block_limit):
            try:
                tx = self.create_random_transfer()
                self.blockchain.add_transaction_to_mempool(tx)
            except Exception:
                pass
            await asyncio.sleep(0.1)
            await self.blockchain.mine_block()
        return self.blockchain.chain, self.wallets

# ✅ Testler tarafından import edilebilecek dış fonksiyon
def simulate():
    print("⛏️ Madencilik simülasyonu başlatılıyor...")
    return asyncio.run(MiningSimulation().simulate())

# ✅ CLI başlatma noktası
async def main():
    print("🚀 WebSocket + Simülasyon başlatılıyor...")
    await asyncio.gather(
        start_notification_server(),
        MiningSimulation().simulate()
    )

if __name__ == "__main__":
    asyncio.run(main())

