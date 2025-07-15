from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict

from bhrc_blockchain.api.auth import get_current_user, verify_token
from bhrc_blockchain.core.transaction.transaction import create_transaction
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.mempool.mempool import get_ready_transactions, add_transaction_to_mempool
from bhrc_blockchain.tools.confirmation_watcher import watch_transaction_confirmation
from bhrc_blockchain.core.wallet.wallet import load_wallet

router = APIRouter()
blockchain = Blockchain()

# === Veri Modelleri ===

class CoinTransferRequest(BaseModel):
    sender_private_key: str
    sender: str
    recipient: str
    amount: float
    message: str = ""
    note: str = ""

class SimpleTransferRequest(BaseModel):
    to_address: str
    amount: float
    message: str = ""

class APIResponse(BaseModel):
    message: str
    data: Dict = None

# === API Uçları ===

@router.post("/send", summary="Coin transferi yap", response_model=APIResponse)
def send_transaction(
    req: CoinTransferRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    try: # pragma: no cover
        tx = create_transaction(
            sender=req.sender,
            recipient=req.recipient,
            amount=req.amount,
            message=req.message,
            note=req.note,
            sender_private_key=req.sender_private_key,
            tx_type="transfer"
        )
        tx["status"] = "ready"
        add_transaction_to_mempool(tx)
        background_tasks.add_task(watch_transaction_confirmation, tx["txid"], blockchain)

        return JSONResponse(status_code=201, content={"message": "İşlem kuyruğa alındı.", "data": {"txid": tx["txid"]}})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"İşlem başarısız: {e}") # pragma: no cover

@router.get("/history/{address}", summary="Adresin işlem geçmişini getir", response_model=APIResponse)
def get_transaction_history(
    address: str,
    current_user: dict = Depends(get_current_user)
):
    try: # pragma: no cover
        history = []
        for block in blockchain.chain:
            for tx in block.transactions:
                if tx["sender"] == address or tx["recipient"] == address:
                    history.append(tx)
        return JSONResponse(status_code=200, content={"message": "İşlem geçmişi getirildi", "data": {"transactions": history}})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hata: {e}") # pragma: no cover

@router.get("/mempool", summary="Mempool'daki işlemleri getir", response_model=APIResponse)
def list_mempool_transactions(current_user: dict = Depends(get_current_user)):
    try: # pragma: no cover
        transactions = get_ready_transactions()
        return JSONResponse(status_code=200, content={"message": "Mempool listelendi", "data": {"transactions": transactions}})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Mempool alınamadı: {e}") # pragma: no cover

@router.post("/api/transfer", summary="Panelden gönderilen basit transfer formu")
def simple_transfer(
    req: SimpleTransferRequest,
    background_tasks: BackgroundTasks,
    token_data=Depends(verify_token)
):
    try: # pragma: no cover
        wallet = load_wallet("wallets/test_wallet.json")  # Gerçek cüzdan entegresi yapılabilir

        tx = create_transaction(
            sender=wallet["address"],
            recipient=req.to_address,
            amount=req.amount,
            message=req.message,
            note="",
            sender_private_key=wallet["private_key"],
            tx_type="transfer"
        )

        tx["status"] = "ready"
        add_transaction_to_mempool(tx)
        background_tasks.add_task(watch_transaction_confirmation, tx["txid"], blockchain)

        return JSONResponse(status_code=201, content={"message": "✅ İşlem kuyruğa alındı", "data": {"txid": tx["txid"]}})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"İşlem başarısız: {e}")  # pragma: no cover
