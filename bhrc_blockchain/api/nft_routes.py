# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Dict
from uuid import uuid4

from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.database.nft_storage import (
    init_nft_db, mint_nft, get_all_nfts, get_nfts_by_owner
)

router = APIRouter()
init_nft_db()  # Sunucu başında bir kez çağrılır

# === Veri Modeli ===

class MintNFTRequest(BaseModel):
    name: str
    description: str
    uri: str  # IPFS bağlantısı veya görsel URL

# === Uç Noktalar ===

@router.post("/mint", summary="Yeni NFT üret")
def mint_nft_route(
    data: MintNFTRequest,
    current_user: dict = Depends(get_current_user)
):
    try:
        nft_id = str(uuid4())
        owner = current_user["sub"]
        mint_nft(nft_id, owner, data.name, data.description, data.uri)
        return {"message": "NFT başarıyla üretildi.", "nft_id": nft_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/all", summary="Tüm NFT'leri getir")
def list_all_nfts(current_user: dict = Depends(get_current_user)):
    return {"nfts": get_all_nfts()}

@router.get("/owner/{address}", summary="Adrese ait NFT'leri getir")
def list_owner_nfts(address: str, current_user: dict = Depends(get_current_user)):
    return {"nfts": get_nfts_by_owner(address)}

