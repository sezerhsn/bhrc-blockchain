# main.py
import random
import asyncio
from bhrc_blockchain.core.wallet import MinerWallet
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.transaction import create_transaction
from bhrc_blockchain.core.mempool import add_transaction_to_mempool, mempool

class MiningSimulation:
    def __init__(self, block_limit=100):
        self.blockchain = Blockchain()
        self.wallets = [MinerWallet(persist=False) for _ in range(3)]
        self.block_limit = block_limit

    def create_random_wallet(self):
        wallet = MinerWallet(persist=False)
        self.wallets.append(wallet)
        return wallet

    def pick_random_wallet(self, exclude=None):
        candidates = [w for w in self.wallets if w != exclude]
        return random.choice(candidates)

    def create_random_transfer(self):
        sender = self.pick_random_wallet()
        recipient = self.pick_random_wallet(exclude=sender)
        amount = round(random.uniform(1, 10), 2)

        try:
            tx = create_transaction(
                sender=sender.address,
                recipient=recipient.address,
                amount=amount,
                sender_private_key=sender.private_key
            )
            add_transaction_to_mempool(tx)
            print(f"💸 Transfer: {amount} BHRC | {sender.address[:16]}... → {recipient.address[:16]}...")
        except Exception as e:
            print(f"⛔ Transfer başarısız: {e}")

    async def simulate(self):
        for _ in range(self.block_limit):
            self.blockchain.miner_wallet = self.pick_random_wallet()

            # İlk coinbase bloğu sonrası işlem üretimi zorunlu hale gelir
            if len(self.blockchain.chain) >= 2:
                for _ in range(random.randint(1, 3)):
                    self.create_random_transfer()

            # %10 ihtimalle yeni cüzdan oluştur
            if random.random() < 0.1:
                self.create_random_wallet()

            await self.blockchain.mine_block()

        return self.blockchain.chain, mempool

if __name__ == "__main__":
    sim = MiningSimulation()
    chain, mempool_state = asyncio.run(sim.simulate())

    print(f"Toplam blok: {len(chain)}")
    print(f"Mempool boyutu: {len(mempool_state)}")
    print("Son 5 blok:")
    for block in chain[-5:]:
        print(f"  - Blok #{block.index}, {len(block.transactions)} işlem, Madenci: {block.miner_address}")
