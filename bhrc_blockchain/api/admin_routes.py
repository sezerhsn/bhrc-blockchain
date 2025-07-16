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
import asyncio
from fastapi import APIRouter, Depends, HTTPException, Body, Form
from bhrc_blockchain.core.blockchain.blockchain import get_blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.api.auth import admin_required, get_current_admin
from bhrc_blockchain.config.config import settings
from datetime import datetime
from bhrc_blockchain.network.notifications import emit_admin_alert, notify_admin
from bhrc_blockchain.core.snapshot.snapshot_manager import save_snapshot
from bhrc_blockchain.database.models import UndoLog, User, SessionLog
from bhrc_blockchain.database.database import SessionLocal
from bhrc_blockchain.core.snapshot.snapshot_manager import save_snapshot, load_snapshot
from bhrc_blockchain.core.mempool.mempool import clear_mempool

ROLE_PERMISSIONS = {
    "super_admin": {"reset-chain", "clear-mempool", "snapshot", "rollback", "update_role", "deactivate_user", "view_logs"},
    "admin": {"add_fake_block", "network_stats"},
    "observer": {"network_stats"},
}

def permission_required(permission: str):
    def dependency(user: dict = Depends(get_current_admin)):
        role = user.get("role", "")
        permissions = set(user.get("permissions", []))

        if permission not in ROLE_PERMISSIONS.get(role, set()) and permission not in permissions:
            raise HTTPException(status_code=403, detail="Bu işlem için yetkiniz yok.")

        return user.get("sub", "anonymous")
    return Depends(dependency)

def log_admin_action(action: str, user: str = "admin"):
    log_dir = "bhrc_blockchain/logs"
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "admin.log")

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "action": action
    }

    with open(log_path, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

router = APIRouter()

@router.post("/admin/add-fake-block")
def add_fake_block(_: dict = Depends(admin_required)):
    if settings.NETWORK != "testnet":
        raise HTTPException(status_code=403, detail="Bu işlem sadece testnet üzerinde yapılabilir.")

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
    log_admin_action("Test amaçlı sahte blok eklendi")
    return {"message": "Sahte blok eklendi"}

@router.get("/admin/network-stats")
def network_stats(_: dict = Depends(admin_required)):
    try:
        blockchain = get_blockchain()

        if len(blockchain.chain) >= 2:
            time_diffs = [
                blockchain.chain[i].timestamp - blockchain.chain[i - 1].timestamp
                for i in range(1, len(blockchain.chain))
            ]
            avg_block_time = sum(time_diffs) / len(time_diffs)
        else:
            avg_block_time = 0

        log_admin_action("Ağ istatistikleri sorgulandı")

        return {
            "peers": blockchain.peers,
            "total_blocks": len(blockchain.chain),
            "difficulty": blockchain.difficulty_prefix,
            "mempool_size": len(blockchain.mempool_transactions),
            "last_block_index": blockchain.chain[-1].index if blockchain.chain else None,
            "avg_block_time": round(avg_block_time, 2)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/admin/sessions")
def active_sessions(current_admin: str = permission_required("view_logs")):
    session = SessionLocal()
    active_logs = session.query(SessionLog).filter_by(active=True).order_by(SessionLog.login_time.desc()).limit(100).all()

    return [{
        "username": log.username,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "login_time": log.login_time.isoformat()
    } for log in active_logs]

@router.post("/admin/test-notification")
async def test_notification():
    await notify_admin({
        "event_type": "test_notification",
        "timestamp": int(time.time())
    })
    return {"status": "ok"}

@router.get("/admin/logs")
def get_admin_logs(current_admin: str = permission_required("view_logs")):
    log_path = "bhrc_blockchain/logs/admin.log"
    if not os.path.exists(log_path):
        return {"logs": []}

    try:
        with open(log_path, "r") as f:
            lines = f.readlines()[-100:]
            logs = [json.loads(line) for line in lines]
            return {"logs": logs[::-1]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log okunamadı: {str(e)}")

@router.post("/admin/undo/{undo_id}")
def undo_action(undo_id: int, current_admin: str = permission_required("rollback")):
    session = SessionLocal()
    log = session.query(UndoLog).filter_by(id=undo_id).first()

    if not log or log.reversed:
        raise HTTPException(400, "İşlem bulunamadı ya da zaten geri alınmış.")

    if log.action_type == "snapshot_rollback" and log.snapshot_ref:
        load_snapshot(log.snapshot_ref)
        log_admin_action(f"Snapshot geri alındı: {log.snapshot_ref}", user=current_admin)

    elif log.action_type == "user_deactivation":
        if not log.meta_data or not isinstance(log.meta_data, dict):
            raise HTTPException(400, "Eksik meta veri")

        user_id = log.meta_data.get("user_id")
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.status = True
            log_admin_action(f"Kullanıcı yeniden aktifleştirildi: ID {user_id}", user=current_admin)

    else:
        raise HTTPException(400, "Bu tür işlem için undo tanımlı değil.")

    log.reversed = True
    session.commit()
    return {"status": "undo_applied", "undo_id": undo_id}

@router.get("/admin/users")
async def list_users():
    session = SessionLocal()
    users = session.query(User).all()
    return users

@router.post("/admin/users/{user_id}/update_role")
async def update_role(user_id: int, new_role: str = Body(...), current_admin: str = permission_required("update_role")):
    session = SessionLocal()
    user = session.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")
    user.role = new_role
    session.commit()
    return {"updated": True}

@router.post("/admin/users/{user_id}/deactivate")
async def deactivate_user(user_id: int, current_admin: str = permission_required("deactivate_user")):
    session = SessionLocal()
    user = session.query(User).filter_by(id=user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")

    if not user.status:
        raise HTTPException(status_code=400, detail="Kullanıcı zaten pasif durumda.")

    user.status = False

    undo_log = UndoLog(
        action_type="user_deactivation",
        snapshot_ref=None,
        meta_data={"user_id": user_id},
        reversed=False
    )
    session.add(undo_log)

    session.commit()

    log_admin_action(f"Kullanıcı pasifleştirildi → ID {user_id}", user=current_admin)
    return {"deactivated": True, "undo_id": undo_log.id}

@router.get("/admin/undo")
def list_undo_logs(current_admin: str = permission_required("rollback")):
    session = SessionLocal()
    logs = session.query(UndoLog).order_by(UndoLog.created_at.desc()).limit(50).all()
    return logs

@router.post("/admin/reset-chain")
def reset_chain(current_admin: str = permission_required("reset-chain")):
    blockchain = get_blockchain()
    try:
        blockchain.reset_chain()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    log_admin_action("Zincir sıfırlandı", user=current_admin)

    try:
        asyncio.get_running_loop().create_task(
            emit_admin_alert("snapshot_created", {"by": current_admin, "timestamp": time.time()})
        )
    except RuntimeError:
        pass

    return {"message": "Zincir genesis bloğa sıfırlandı"}

@router.post("/admin/clear-mempool")
def clear_mempool_route(current_admin: str = permission_required("clear-mempool")):
    clear_mempool()
    log_admin_action("Mempool temizlendi", user=current_admin)

    try:
        asyncio.get_running_loop().create_task(
            emit_admin_alert("snapshot_created", {"by": current_admin, "timestamp": time.time()})
        )
    except RuntimeError:
        pass

    return {"message": "Mempool temizlendi."}

@router.post("/admin/snapshot")
def snapshot(current_admin: str = permission_required("snapshot")):
    blockchain = get_blockchain()
    save_snapshot(blockchain, current_admin=current_admin)
    log_admin_action("Snapshot kaydedildi", user=current_admin)

    try:
        asyncio.get_running_loop().create_task(
            emit_admin_alert("snapshot_created", {
                "by": current_admin,
                "timestamp": time.time()
            })
        )
    except RuntimeError:
        pass

    return {"status": "snapshot_saved"}

@router.post("/snapshot-rollback")
def rollback_snapshot(rollback_id: str = Form(...), current_admin: str = Depends(admin_required)):
    try:
        load_snapshot(rollback_id)
        log_admin_action(f"Snapshot rollback: {rollback_id}")
        return {"rolled_back_to": rollback_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

