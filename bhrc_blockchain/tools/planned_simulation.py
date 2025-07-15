
import os
import time
import random
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.wallet.wallet import generate_wallet
from bhrc_blockchain.config.config import settings
from bhrc_blockchain.core.transaction.transaction import create_transaction
from bhrc_blockchain.core.mempool.mempool import add_transaction_to_mempool, get_ready_transactions
from bhrc_blockchain.database.storage import SQLiteDataStore
from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract
from bhrc_blockchain.core.contract.bhrc721 import BHRC721Contract

def planned_simulation():
    print("🧹 Zincir sıfırlanıyor...")
    open("chain.json", "w").write("[]")
    try:
        os.remove("chain.json")
    except FileNotFoundError:
        pass

    blockchain = Blockchain(autoload=False)
    db = SQLiteDataStore()
    foundation_addr = settings.FOUNDATION_ADDRESS

    print("🏦 Kullanıcı cüzdanları oluşturuluyor...")
    users = [generate_wallet(password=f"user{i}", force_new=True) for i in range(1, 21)]
    multisig_wallet = generate_wallet(password="multisig", force_new=True)
    exchange_wallet = generate_wallet(password="exchange", force_new=True)
    all_wallets = users + [multisig_wallet, exchange_wallet]
    rich_wallets = []

    # ⛏ 1. blok → mempoolsüz kaz
    print("\n⛏ 1. blok mempoolsüz kazılıyor...")
    miner1 = random.choice(all_wallets)
    block1 = blockchain.mine_block(miner_address=miner1["address"], miner_private_key=miner1["private_key"])
    rich_wallets.append(miner1)

    # 🪙 Bu miner bakiyesini birkaç cüzdana böl
    print("\n💸 1. blok miner'ı bakiyesini küçük parçalara bölüyor...")
    recipients = random.sample([u for u in users if u["address"] != miner1["address"]], 4)
    for r in recipients:
        try:
            tx = create_transaction(
                sender=miner1["address"],
                recipient=r["address"],
                amount=5.0,
                sender_private_key=miner1["private_key"]
            )
            add_transaction_to_mempool(tx)
        except Exception as e:
            print(f"⛔ Transfer hatası: {e}")

    # ⛏ 2. blok → mempool dolu
    print("\n⛏ 2. blok kazılıyor...")
    miner2 = random.choice(all_wallets)
    block2 = blockchain.mine_block(miner_address=miner2["address"], miner_private_key=miner2["private_key"])
    rich_wallets.append(miner2)

    # 💸 1. ve 2. blok miner'ları bakiyelerini tekrar dağıtıyor
    print("\n💸 İlk 2 miner mempool'a yeni işlemler gönderiyor...")
    for rich in rich_wallets:
        for r in random.sample([u for u in users if u["address"] != rich["address"]], 3):
            try:
                tx = create_transaction(
                    sender=rich["address"],
                    recipient=r["address"],
                    amount=2.0,
                    sender_private_key=rich["private_key"]
                )
                add_transaction_to_mempool(tx)
            except Exception:
                pass

    # 🔁 Tüm cüzdanlar rastgele transfer yapsın
    print("\n🔁 Cüzdanlar arası yaygın transferler...")
    for _ in range(30):
        sender = random.choice(users)
        recipient = random.choice([u for u in all_wallets if u["address"] != sender["address"]])
        amount = round(random.uniform(0.1, 3.0), 4)
        try:
            tx = create_transaction(
                sender=sender["address"],
                recipient=recipient["address"],
                amount=amount,
                sender_private_key=sender["private_key"]
            )
            add_transaction_to_mempool(tx)
        except Exception:
            pass

    # ⛏ Mempool boşalana kadar blok kaz
    print("\n⛏ Mempool boşalana kadar blok kazımı...")
    while get_ready_transactions():
        miner = random.choice(all_wallets)
        blockchain.mine_block(
            miner_address=miner["address"],
            miner_private_key=miner["private_key"]
        )
        print(f"⛏ Blok kazıldı → {miner['address'][:10]}...")

    # 🖼️ NFT işlemleri
    print("\n🖼️ NFT mint ve transfer işlemleri...")
    nft_contract = BHRC721Contract(name="MyNFT", symbol="NFT")
    minted_nfts = []
    for i in range(3):
        owner = random.choice(users)
        token_id = 20000 + i
        try:
            nft_contract.mint(token_id, owner["address"])
            minted_nfts.append((token_id, owner["address"]))
        except Exception:
            pass

    for token_id, from_addr in minted_nfts:
        new_owner = random.choice([u for u in users if u["address"] != from_addr])
        try:
            nft_contract.transfer(from_addr, new_owner["address"], token_id)
        except Exception:
            pass

    # 💎 BRHC20 işlemleri
    print("\n💎 BRHC20 işlemleri başlıyor...")
    token_contract = BHRC20Contract(name="TestToken", symbol="BHR", total_supply=0, owner=users[0]["address"])
    for i in range(3):
        w = random.choice(users)
        token_contract.mint(w["address"], round(random.uniform(100, 300), 2))

    for _ in range(10):
        s = random.choice(users)
        r = random.choice([u for u in users if u["address"] != s["address"]])
        try:
            token_contract.transfer(s["address"], r["address"], round(random.uniform(1, 10), 2))
        except Exception:
            pass

    for _ in range(3):
        b = random.choice(users)
        try:
            token_contract.burn(b["address"], round(random.uniform(1, 5), 2))
        except Exception:
            pass

    # 📊 Sonuç raporu
    print("\n📊 UTXO Bakiyeleri:")
    for w in users + [multisig_wallet, exchange_wallet, {"address": foundation_addr}]:
        utxos = db.get_unspent_utxos(w["address"])
        total = sum(u[4] for u in utxos)
        print(f"{w['address'][:14]}...: {total:.6f} BHR")

    print("\n🖼️ NFT Sahipleri:")
    for tid, _ in minted_nfts:
        try:
            owner = nft_contract.owner_of(tid)
            print(f"{tid} → {owner[:14]}...")
        except Exception:
            pass

    print("\n💎 BRHC20 Bakiyeleri:")
    for w in users:
        try:
            bal = token_contract.balance_of(w["address"])
            if bal > 0:
                print(f"{w['address'][:14]}...: {bal} BHR")
        except Exception:
            pass

    print("\n✅ Gelişmiş zincir simülasyonu tamamlandı.")

if __name__ == "__main__":
    planned_simulation()
