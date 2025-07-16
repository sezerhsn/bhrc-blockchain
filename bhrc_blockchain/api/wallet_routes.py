# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from fastapi import APIRouter, Query, HTTPException, Depends
from pydantic import BaseModel
from bhrc_blockchain.core.wallet.wallet import (
    generate_wallet,
    get_public_key_from_private_key,
    get_address_from_private_key,
    from_hardware_wallet,
    verify_wallet_integrity,
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

class WalletIntegrityRequest(BaseModel):
    private_key: str
    public_key: str
    address: str
    mnemonic: str | None = None
    password: str | None = ""

@router.post("/verify_integrity")
def verify_wallet_integrity_api(data: WalletIntegrityRequest):
    wallet_dict = {
        "private_key": data.private_key,
        "public_key": data.public_key,
        "address": data.address,
        "mnemonic": data.mnemonic,
    }

    result = verify_wallet_integrity(wallet_dict, password=data.password or "")
    if not result:
        raise HTTPException(status_code=400, detail="Cüzdan bütünlüğü doğrulanamadı.")
    return {"status": "ok", "message": "Cüzdan bütünlüğü doğrulandı."}

@router.get("/from_hardware")
def simulate_hardware_wallet(index: int = Query(0, ge=0, le=100)):
    """
    Donanım cüzdan simülasyonu üzerinden adres ve key üretir.
    Gerçek cihaz bağlantısı içermez.
    """
    wallet = from_hardware_wallet(index=index)
    return {
        "address": wallet["address"],
        "public_key": wallet["public_key"],
        "index": wallet["index"]
    }

class SignMessageRequest(BaseModel):
    private_key: str
    message: str

@router.post("/sign_message")
def sign_message_api(data: SignMessageRequest):
    """
    Özel anahtarla mesaj imzala.
    """
    try:
        from bhrc_blockchain.core.wallet.wallet import sign_message
        signature = sign_message(data.private_key, data.message)
        return {"signature": signature}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

class VerifySignatureRequest(BaseModel):
    public_key: str
    message: str
    signature: str

@router.post("/verify_signature")
def verify_signature_api(data: VerifySignatureRequest):
    """
    Public key ile mesaj imzasını doğrula.
    """
    try:
        from bhrc_blockchain.core.wallet.wallet import verify_signature
        valid = verify_signature(data.public_key, data.message, data.signature)
        return {"valid": valid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/foundation_address")
def get_foundation_address_api():
    """
    Vakıf cüzdan adresini döner.
    """
    try:
        from bhrc_blockchain.core.wallet.wallet import get_foundation_address
        address = get_foundation_address()
        return {"foundation_address": address}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ImportMnemonicRequest(BaseModel):
    mnemonic: str
    password: str | None = ""

@router.post("/import_mnemonic")
def import_wallet_from_mnemonic_api(data: ImportMnemonicRequest):
    """
    Mnemonic (ve varsa parolası) ile wallet import eder.
    """
    try:
        from bhrc_blockchain.core.wallet.wallet import import_wallet_from_mnemonic
        wallet = import_wallet_from_mnemonic(
            data.mnemonic,
            password=data.password or "",
            path=None
        )
        return {
            "address": wallet["address"],
            "public_key": wallet["public_key"],
            "private_key": wallet["private_key"],
            "mnemonic": wallet["mnemonic"]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

class ImportPrivateKeyRequest(BaseModel):
    private_key: str

@router.post("/import_private_key")
def import_wallet_from_private_key_api(data: ImportPrivateKeyRequest):
    """
    Özel anahtar ile wallet içe aktarımı.
    """
    try:
        from bhrc_blockchain.core.wallet.wallet import import_wallet_from_private_key
        wallet = import_wallet_from_private_key(data.private_key)
        return {
            "address": wallet["address"],
            "public_key": wallet["public_key"],
            "private_key": wallet["private_key"]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/is_valid_address")
def is_valid_address_api(address: str):
    """
    Adres geçerliliğini kontrol eder.
    """
    try:
        from bhrc_blockchain.core.wallet.wallet import is_valid_address
        valid = is_valid_address(address)
        return {"valid": valid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

class VerifyAddressRequest(BaseModel):
    private_key: str
    address: str

@router.post("/verify_address_from_key")
def verify_address_from_key_api(data: VerifyAddressRequest):
    """
    Private key'in gerçekten bu adrese ait olup olmadığını doğrular.
    """
    try:
        from bhrc_blockchain.core.wallet.wallet import verify_address_from_key
        match = verify_address_from_key(data.private_key, data.address)
        return {"match": match}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

