from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.core.transaction.transaction import create_transaction
from bhrc_blockchain.core.mempool.mempool import add_transaction_to_mempool

router = APIRouter()

class ContractRequest(BaseModel):
    recipient: str
    amount: float
    script: str
    message: str = ""
    note: str = ""
    sender_private_key: str

@router.post("/submit", summary="Yeni smart contract işlemi gönder")
def submit_contract(
    data: ContractRequest,
    current_user: dict = Depends(get_current_user)
):
    sender = current_user["sub"]

    try:
        tx = create_transaction(
            sender=sender,
            recipient=data.recipient,
            amount=data.amount,
            sender_private_key=data.sender_private_key,
            tx_type="contract",
            script=data.script,
            message=data.message,
            note=data.note,
            locktime=0,
            fee=0.01
        )
        add_transaction_to_mempool(tx)
        return {"message": "Contract işlemi mempool'a eklendi", "txid": tx["txid"]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"İşlem oluşturulamadı: {str(e)}")

