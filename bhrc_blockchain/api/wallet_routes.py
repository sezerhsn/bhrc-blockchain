from fastapi import APIRouter, Query, HTTPException, Depends
from pydantic import BaseModel
from bhrc_blockchain.core.wallet.wallet import (
    generate_wallet,
    get_public_key_from_private_key,
    get_address_from_private_key
)
from bhrc_blockchain.api.auth import get_current_user

router = APIRouter()

# 🎯 Yeni wallet oluşturmak için kullanılacak model
class WalletCreateRequest(BaseModel):
    password: str

# ✅ Yeni endpoint: POST /wallet/create
@router.post("/create")
def create_wallet(
    payload: WalletCreateRequest,
    user: str = Depends(get_current_user)
):
    """
    Yeni bir cüzdan oluşturur.
    """
    try:
        wallet = generate_wallet(password=payload.password)
        return wallet
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/address")
def get_address(
    private_key: str = Query(...),
    user: str = Depends(get_current_user)
):
    """
    Özel anahtara karşılık gelen adresi ve public key'i döndür.
    """
    try:
        address = get_address_from_private_key(private_key)
        public_key = get_public_key_from_private_key(private_key)
        return {"address": address, "public_key": public_key}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/generate")
def generate(
    password: str = Query(...),
    user: str = Depends(get_current_user)
):
    """
    Yeni bir cüzdan üret.
    """
    wallet = generate_wallet(password=password)
    return wallet

