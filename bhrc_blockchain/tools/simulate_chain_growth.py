import asyncio
import argparse
from bhrc_blockchain.core.blockchain.blockchain import Blockchain

async def simulate_chain_growth(block_count: int = 5, delay: float = 0.5):
    blockchain = Blockchain(autoload=False)
    print(f"⛏️ Simülasyon başlıyor. Mevcut blok sayısı: {len(blockchain.chain)}")

    for i in range(block_count):
        block = await blockchain.mine_block()
        if block:
            print(f"✅ Blok #{block.index} kazıldı | Hash: {block.block_hash[:16]}...")
        else:
            print(f"⚠️ Blok #{len(blockchain.chain)} kazılamadı (işlem yok)")
        await asyncio.sleep(delay)

    print(f"🎯 Simülasyon tamamlandı. Yeni blok sayısı: {len(blockchain.chain)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=5, help="Kaç blok kazılsın?")
    parser.add_argument("--delay", type=float, default=0.5, help="Kazımalar arası bekleme süresi (sn)")
    args = parser.parse_args()

    asyncio.run(simulate_chain_growth(block_count=args.count, delay=args.delay))

