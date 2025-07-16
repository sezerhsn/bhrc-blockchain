# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List
from uuid import uuid4

from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.database.multisig_storage import (
    init_multisig_db, create_multisig_tx, add_signature,
    get_multisig_tx, list_pending_multisigs, list_ready_multisigs
)

router = APIRouter()
init_multisig_db()

# === Modeller ===

class MultisigCreateRequest(BaseModel):
    data: dict  # zincire yazılacak işlem verisi
    required_signers: List[str]

class MultisigSignRequest(BaseModel):
    txid: str
    signature: str  # base64 imza

# === Uç Noktalar ===

@router.post("/create", summary="Yeni multisig işlem oluştur")
def create_multisig(
    req: MultisigCreateRequest,
    current_user: dict = Depends(get_current_user)
):
    initiator = current_user["sub"]
    txid = str(uuid4())
    try:
        create_multisig_tx(txid, initiator, req.data, req.required_signers)
        return {"message": "İşlem oluşturuldu", "txid": txid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/sign", summary="İşleme imza ekle")
def sign_multisig(
    req: MultisigSignRequest,
    current_user: dict = Depends(get_current_user)
):
    signer = current_user["sub"]
    try:
        add_signature(req.txid, signer, req.signature)
        return {"message": "İmza eklendi"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/status/{txid}", summary="İşlem durumu")
def multisig_status(txid: str, current_user: dict = Depends(get_current_user)):
    try:
        tx = get_multisig_tx(txid)
        return {"tx": tx}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/pending", summary="Bekleyen multisig işlemler")
def pending_multisigs(current_user: dict = Depends(get_current_user)):
    return {"multisigs": list_pending_multisigs()}

@router.get("/ready", summary="İmzaları tamamlanmış işlemler")
def ready_multisigs(current_user: dict = Depends(get_current_user)):
    return {"multisigs": list_ready_multisigs()}

