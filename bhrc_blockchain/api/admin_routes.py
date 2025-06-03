from fastapi import APIRouter, Depends
from bhrc_blockchain.core.blockchain.blockchain import get_blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.api.auth import admin_required
import time

router = APIRouter()


@router.post("/admin/reset-chain")
def reset_chain(_: dict = Depends(admin_required)):
    blockchain = get_blockchain()
    blockchain.reset_chain()
    return {"message": "Zincir genesis bloğa sıfırlandı"}


@router.post("/admin/add-fake-block")
def add_fake_block(_: dict = Depends(admin_required)):
    blockchain = get_blockchain()
    last_block = blockchain.get_last_block()

    fake_block = Block(
        index=last_block.index + 1,
        previous_hash=last_block.block_hash,
        transactions=[{"sender": "test", "recipient": "fake", "amount": 0}],
        timestamp=time.time(),
        nonce=0,
        miner_address="xADMIN",
        difficulty=blockchain.difficulty_prefix,
        events=["⚠️ Admin tarafından eklenen sahte blok"]
    )

    fake_block.block_signature = "FAKE_SIGNATURE"
    fake_block.producer_id = "xADMIN"
    fake_block.block_hash = fake_block.calculate_hash()

    blockchain.add_block(fake_block)
    return {"message": "Sahte blok eklendi"}


@router.post("/admin/clear-mempool")
def clear_mempool(_: dict = Depends(admin_required)):
    blockchain = get_blockchain()
    blockchain.mempool.clear()
    return {"message": "Mempool temizlendi."}


@router.get("/admin/network-stats")
def network_stats(_: dict = Depends(admin_required)):
    blockchain = get_blockchain()
    return {
        "peers": blockchain.peers,
        "total_blocks": len(blockchain.chain),
        "difficulty": blockchain.difficulty_prefix
    }


@router.get("/admin/sessions")
def active_sessions(_: dict = Depends(admin_required)):
    return {"message": "Oturum yönetimi şu an devre dışı"}

