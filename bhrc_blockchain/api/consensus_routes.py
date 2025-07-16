# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import traceback
from fastapi import APIRouter, Request, HTTPException, Depends
from typing import Dict
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.block import Block

router = APIRouter()

def get_blockchain():
    blockchain = Blockchain(autoload=False)
    blockchain.create_genesis_block()
    return blockchain

@router.get("/chain_weight", summary="Mevcut zincirin ağırlığını getir")
def get_chain_weight(blockchain: Blockchain = Depends(get_blockchain)):
    try:
        weight = blockchain.get_chain_weight()
        return {"weight": weight}
    except Exception as e:
        tb = traceback.format_exc()
        print("🛑 evaluate_chain HATASI:\n", tb)
        raise HTTPException(status_code=500, detail=f"Hata: {str(e)}\n{tb}")

@router.post("/evaluate", summary="Gelen zinciri değerlendir ve kıyasla")
def evaluate_chain(payload: Dict, blockchain: Blockchain = Depends(get_blockchain)):
    try:
        incoming_chain_raw = payload.get("chain", [])
        incoming_chain = [Block.from_dict(b) for b in incoming_chain_raw]

        if not incoming_chain:
            raise HTTPException(status_code=400, detail="Zincir verisi eksik")

        success = blockchain.replace_chain_if_better(incoming_chain)

        if success:
            return {"message": "✅ Zincir güncellendi. Yeni zincir kabul edildi."}
        return {"message": "⚖️ Zincir daha ağır değil. Mevcut zincir korundu."}

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        tb = traceback.format_exc()
        print("🛑 evaluate_chain HATASI:\n", tb)
        raise HTTPException(status_code=500, detail=f"Hata: {str(e)}\n{tb}")

@router.get("/current_chain", summary="Mevcut zinciri getir")
def get_current_chain(blockchain: Blockchain = Depends(get_blockchain)):
    try:
        current_chain = blockchain.chain
        chain_data = [block.to_dict() for block in current_chain]
        return {"chain": chain_data}
    except Exception as e:
        tb = traceback.format_exc()
        print("🛑 evaluate_chain HATASI:\n", tb)
        raise HTTPException(status_code=500, detail=f"Hata: {str(e)}\n{tb}")

@router.get("/chain_weight", summary="Mevcut zincirin ağırlığını getir")
def get_chain_weight():
    try:
        weight = blockchain.get_chain_weight()
        return {"weight": weight}
    except Exception as e:
        tb = traceback.format_exc()
        print("🛑 evaluate_chain HATASI:\n", tb)
        raise HTTPException(status_code=500, detail=f"Hata: {str(e)}\n{tb}")

@router.post("/validate_chain", summary="Verilen zinciri doğrula")
def validate_chain(payload: Dict, blockchain: Blockchain = Depends(get_blockchain)):
    try:
        incoming_chain_raw = payload.get("chain", [])
        incoming_chain = [Block.from_dict(b) for b in incoming_chain_raw]

        if not incoming_chain:
            raise HTTPException(status_code=400, detail="Zincir verisi eksik")

        original_chain = blockchain.chain
        blockchain.chain = incoming_chain
        is_valid = blockchain.validate_chain()
        blockchain.chain = original_chain

        if is_valid:
            return {"message": "✅ Zincir geçerli."}
        return {"message": "❌ Zincir geçersiz."}

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hata: {str(e)}")

