from fastapi import APIRouter, Request, HTTPException
from typing import Dict
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.block import Block

router = APIRouter()
blockchain = Blockchain()

@router.post("/evaluate", summary="Gelen zinciri değerlendir ve kıyasla")
def evaluate_chain(payload: Dict):
    try:
        incoming_chain_raw = payload.get("chain", [])
        incoming_chain = [Block.from_dict(b) for b in incoming_chain_raw]

        if not incoming_chain:
            raise HTTPException(status_code=400, detail="Zincir verisi eksik")

        success = blockchain.replace_chain_if_better(incoming_chain)

        if success:
            return {"message": "✅ Zincir güncellendi. Yeni zincir kabul edildi."}
        return {"message": "⚖️ Zincir daha ağır değil. Mevcut zincir korundu."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hata: {str(e)}")

