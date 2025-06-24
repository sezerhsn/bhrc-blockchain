import time
import hashlib
from eth_hash.auto import keccak
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.core.transaction.transaction import create_transaction
from bhrc_blockchain.core.mempool.mempool import add_transaction_to_mempool, get_transaction_from_mempool
from bhrc_blockchain.core.wallet.wallet import verify_signature, get_public_key_from_private_key
from bhrc_blockchain.core.contract.contract_engine import execute_script, contract_registry, SmartContractEngine, contract_engine

def compute_manifest_hash(script: str, timestamp: int, nonce: int) -> str:
    payload = f"{script}|{timestamp}|{nonce}".encode()
    return keccak(payload).hex()

router = APIRouter()
contract_engine = SmartContractEngine()

class ContractRequest(BaseModel):
    recipient: str
    amount: float
    script: str
    timestamp: int = None
    nonce: int = None
    manifest_hash: str = None
    script_hash: str = None
    signature: str
    type: str = "BHRC-Logic-1.0"
    message: str = ""
    note: str = ""
    sender_private_key: str
    fee: float = 0.0

@router.post("/submit", summary="Yeni smart contract işlemi gönder")
def submit_contract(
    data: ContractRequest,
    current_user: dict = Depends(get_current_user)
):
    sender = current_user["sub"]

    try:
        if data.type == "BHRC-Logic-1.1":
            computed_hash = compute_manifest_hash(data.script, data.timestamp, data.nonce)
            if computed_hash != data.manifest_hash:
                raise HTTPException(status_code=400, detail="Manifest hash doğrulaması başarısız.")
            contract_address = data.manifest_hash
        else:
            computed_hash = hashlib.sha256(data.script.encode()).hexdigest()
            if computed_hash != data.script_hash:
                raise HTTPException(status_code=400, detail="Script hash doğrulaması başarısız (v1.0).")
            contract_address = data.script_hash

        if data.type == "BHRC-Logic-1.1":
            hash_for_signature = data.manifest_hash
        else:
            hash_for_signature = data.script_hash

        public_key = get_public_key_from_private_key(data.sender_private_key)
        is_valid = verify_signature(public_key, hash_for_signature, data.signature)
        if not is_valid:
            raise HTTPException(status_code=400, detail="Script imzası geçersiz.")

        context = {
            "sender": sender,
            "recipient": data.recipient,
            "amount": data.amount,
            "message": data.message,
            "note": data.note
        }

        execution_result = execute_script(data.type, data.script, context)

        if execution_result["status"] != "success":
            raise HTTPException(status_code=400, detail=f"Contract yürütme hatası: {execution_result.get('error', 'Bilinmeyen hata')}")

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
            fee=data.fee,
            contract_result=execution_result
        )

        add_transaction_to_mempool(tx)

        return {
            "message": "Contract işlemi mempool'a eklendi",
            "txid": tx["txid"],
            "execution_result": execution_result
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"İşlem oluşturulamadı: {str(e)}")

@router.post("/simulate", summary="Contract simülasyon yürütme")
def simulate_contract(
    data: ContractRequest,
    current_user: dict = Depends(get_current_user)
):
    sender = current_user["sub"]

    try:
        computed_hash = hashlib.sha256(data.script.encode()).hexdigest()
        if computed_hash != data.script_hash:
            raise HTTPException(status_code=400, detail="Script hash doğrulaması başarısız (simulate).")

        public_key = get_public_key_from_private_key(data.sender_private_key)
        is_valid = verify_signature(public_key, data.script_hash, data.signature)
        if not is_valid:
            raise HTTPException(status_code=400, detail="Script imzası geçersiz (simulate).")

        context = {
            "sender": sender,
            "recipient": data.recipient,
            "amount": data.amount,
            "message": data.message,
            "note": data.note
        }

        execution_result = execute_script(data.type, data.script, context)

        return {
            "execution_result": execution_result
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Simülasyon sırasında hata: {str(e)}")

@router.get("/tx/{txid}", summary="Contract transaction durumunu sorgula")
def get_contract_status(txid: str):
    try:
        tx = get_transaction_from_mempool(txid)

        if not tx:
            raise HTTPException(status_code=404, detail="Transaction bulunamadı.")

        if tx["type"] != "contract":
            raise HTTPException(status_code=400, detail="Bu işlem bir contract işlemi değil.")

        execution_result = tx.get("contract_result", None)
        state = execution_result.get("state", {}) if execution_result else {}

        return {
            "txid": txid,
            "executed": execution_result is not None,
            "execution_result": execution_result,
            "state": state,
            "logs": execution_result.get("logs", []) if execution_result else [],
            "gas_used": execution_result.get("gas_used", 0) if execution_result else 0,
            "tx": tx
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Durum sorgulama hatası: {str(e)}")

class DeployRequest(BaseModel):
    script: str
    timestamp: int = None
    nonce: int = None
    manifest_hash: str = None
    script_hash: str = None
    signature: str
    type: str = "BHRC-Logic-1.0"
    sender_private_key: str

class CallRequest(BaseModel):
    contract_address: str
    params: dict

@router.post("/deploy", summary="Yeni contract deploy et")
def deploy_contract(
    data: DeployRequest,
    current_user: dict = Depends(get_current_user)
):
    sender = current_user["sub"]

    try:
        if data.type == "BHRC-Logic-1.1":
            computed_hash = compute_manifest_hash(data.script, data.timestamp, data.nonce)
            if computed_hash != data.manifest_hash:
                raise HTTPException(status_code=400, detail="Manifest hash doğrulaması başarısız.")
        else:
            computed_hash = hashlib.sha256(data.script.encode()).hexdigest()
            if computed_hash != data.script_hash:
                raise HTTPException(status_code=400, detail="Script hash doğrulaması başarısız (v1.0).")

        if data.type == "BHRC-Logic-1.1":
            hash_for_signature = data.manifest_hash
        else:
            hash_for_signature = data.script_hash

        public_key = get_public_key_from_private_key(data.sender_private_key)
        is_valid = verify_signature(public_key, hash_for_signature, data.signature)
        if not is_valid:
            raise HTTPException(status_code=400, detail="Script imzası geçersiz.")

        if data.type == "BHRC-Logic-1.1":
            contract_address = data.manifest_hash
        else:
            contract_address = data.script_hash

        ok = contract_engine.deploy_contract(contract_address, data.script)
        if not ok:
            raise HTTPException(status_code=400, detail="Bu contract zaten deploy edilmiş.")

        return {
            "contract_address": contract_address,
            "message": "Contract deployed"
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Deploy hatası: {str(e)}")

@router.post("/call", summary="Deploy edilmiş contract'ı çalıştır")
def call_contract(
    data: CallRequest,
    current_user: dict = Depends(get_current_user)
):
    sender = current_user["sub"]

    try:
        execution_result = contract_engine.call_contract_with_state(data.contract_address, data.params)

        return {
            "contract_address": data.contract_address,
            "execution_result": execution_result
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Contract çağırma hatası: {str(e)}")

class DeployTemplateRequest(BaseModel):
    template: str
    contract_address: str
    name: str = "MyTokenOrNFT"
    symbol: str = "MTK"
    total_supply: int = 0
    owner: str = "xOWNER"

@router.post("/contracts/deploy", summary="BHRC20/BHRC721 template deploy")
def deploy_template(
    request: DeployTemplateRequest,
    current_user: dict = Depends(get_current_user)
):
    success = contract_engine.deploy_template(
        request.template,
        request.contract_address,
        name=request.name,
        symbol=request.symbol,
        total_supply=request.total_supply,
        owner=request.owner
    )

    if not success:
        raise HTTPException(status_code=400, detail="Deployment failed (duplicate address or unknown template).")

    return {
        "status": "success",
        "contract_address": request.contract_address,
        "template": request.template
    }

@router.get("/contracts/list", summary="Mevcut deploy edilmiş tüm sözleşmeleri getir")
def list_contracts():
    result = []

    for addr, data in contract_engine.contracts.items():
        item = {
            "contract_address": addr,
            "template": data.get("template", "unknown"),
            "version": data.get("version", "unknown"),
        }

        obj = data.get("object")
        if obj and hasattr(obj, "metadata"):
            item["metadata"] = obj.metadata()
            if hasattr(obj, "get_abi"):
                item["abi"] = obj.get_abi()
        else:
            item["metadata"] = {}
            item["abi"] = {}

        result.append(item)

    return {
        "count": len(result),
        "contracts": result
    }

class CallTemplateRequest(BaseModel):
    contract_address: str
    method: str
    args: dict = {}

@router.post("/contracts/call", summary="BHRC20/BHRC721 contract method çağır")
def call_template_method(
    request: CallTemplateRequest,
    current_user: dict = Depends(get_current_user)
):
    contract_entry = contract_engine.contracts.get(request.contract_address)

    if not contract_entry:
        raise HTTPException(status_code=404, detail="Contract bulunamadı.")

    obj = contract_entry.get("object")

    if not obj or not hasattr(obj, request.method):
        raise HTTPException(status_code=400, detail="Bu method mevcut değil.")

    method_fn = getattr(obj, request.method)

    try:
        result = method_fn(**request.args)

        contract_entry["events"].append({
            "timestamp": int(time.time()),
            "method": request.method,
            "args": request.args,
            "result": result
        })

        return {
            "status": "success",
            "contract_address": request.contract_address,
            "method": request.method,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Method çalıştırma hatası: {str(e)}")

@router.post("/contracts/reset", summary="Tüm template sözleşmeleri temizle (test ve geliştirme için)")
def reset_contracts(
    current_user: dict = Depends(get_current_user)
):
    count = len(contract_engine.contracts)
    contract_engine.contracts.clear()

    return {
        "status": "success",
        "cleared": count,
        "message": f"Tüm {count} sözleşme temizlendi."
    }

class SimulateTemplateRequest(BaseModel):
    contract_address: str
    method: str
    args: dict = {}

@router.post("/contracts/simulate_call", summary="BHRC20/BHRC721 method dry-run (state değişmeden)")
def simulate_template_call(
    request: SimulateTemplateRequest,
    current_user: dict = Depends(get_current_user)
):
    contract_entry = contract_engine.contracts.get(request.contract_address)

    if not contract_entry:
        raise HTTPException(status_code=404, detail="Contract bulunamadı.")

    obj = contract_entry.get("object")

    if not obj or not hasattr(obj, request.method):
        raise HTTPException(status_code=400, detail="Bu method mevcut değil.")

    method_fn = getattr(obj, request.method)

    import copy
    try:
        pre_state = copy.deepcopy(vars(obj))

        result = method_fn(**request.args)

        obj.__dict__.update(pre_state)

        return {
            "status": "success",
            "contract_address": request.contract_address,
            "method": request.method,
            "simulated_result": result
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Simulate call hatası: {str(e)}")

@router.get("/contracts/events", summary="Tüm sözleşme event loglarını getir")
def list_contract_events():
    result = []

    for addr, data in contract_engine.contracts.items():
        events = data.get("events", [])
        for event in events:
            result.append({
                "contract_address": addr,
                "template": data.get("template", "unknown"),
                "version": data.get("version", "unknown"),
                "timestamp": event.get("timestamp"),
                "method": event.get("method"),
                "args": event.get("args"),
                "result": event.get("result"),
            })

    return {
        "count": len(result),
        "events": result
    }

