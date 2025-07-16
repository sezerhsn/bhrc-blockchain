# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import re
import time
from typing import Dict, Optional, Any

from bhrc_blockchain.database.storage import SQLiteDataStore
from bhrc_blockchain.core.transaction.transaction_model import Transaction, TransactionInput, TransactionOutput
from bhrc_blockchain.config.config import settings
from bhrc_blockchain.core.wallet.wallet import (
    get_address_from_private_key,
    sign_message,
    get_public_key_from_private_key,
    verify_signature
)
from bhrc_blockchain.core.contract.evaluator import evaluate_contract

def validate_transaction(tx_dict: Dict[str, Any]) -> bool:
    required_fields = {"sender", "recipient", "amount", "txid"}
    if not required_fields.issubset(tx_dict):
        raise ValueError("Eksik alanlar: sender, recipient, amount, txid gereklidir.")

    if tx_dict["amount"] <= 0:
        raise ValueError("Miktar sıfırdan büyük olmalıdır.")

    pattern = r"^xBHR[a-zA-Z0-9]{60}$"
    if not re.fullmatch(pattern, tx_dict["sender"]) or not re.fullmatch(pattern, tx_dict["recipient"]):
        raise ValueError("Adres biçimi geçersizdir.")

    if tx_dict["type"] != "coinbase":
        if "script_sig" not in tx_dict or "public_key" not in tx_dict:
            raise ValueError("İmza verisi eksik.")

        raw_message = f"{tx_dict['sender']}{tx_dict['recipient']}{tx_dict['amount']}{tx_dict['fee']}" \
                      f"{tx_dict['message']}{tx_dict['note']}{tx_dict['type']}{tx_dict['locktime']}{tx_dict['time']}"

        if not verify_signature(tx_dict["public_key"], raw_message, tx_dict["script_sig"]):
            raise ValueError("İmza doğrulaması başarısız.")

        if tx_dict.get("type") == "contract":
            if not evaluate_contract(tx_dict):
                raise ValueError("Smart contract koşulları sağlanmadı.")

    return True

def create_transaction(
    sender: str,
    recipient: str,
    amount: float,
    message: str = "",
    note: str = "",
    fee: Optional[float] = None,
    tx_type: str = "transfer",
    locktime: int = 0,
    sender_private_key: Optional[str] = None,
    db: Optional[SQLiteDataStore] = None,
    script: Optional[str] = None,
    contract_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:

    if tx_type not in ["coinbase", "token_transfer", "token_deploy", "transfer", "contract"]:
        raise ValueError("Geçersiz işlem tipi")

    if fee is None:
        fee = 0.0 if tx_type == "coinbase" else max(settings.MIN_TRANSACTION_FEE, amount * settings.TRANSACTION_FEE_PERCENTAGE)

    print("🔑 [DEBUG] sender_private_key type:", type(sender_private_key))
    print("🔑 [DEBUG] sender_private_key value:", sender_private_key)

    if sender_private_key:
        derived_address = get_address_from_private_key(sender_private_key)
        if derived_address != sender:
            raise ValueError("Özel anahtar, gönderici adresiyle eşleşmiyor.")

    tx_time = time.time()
    raw_msg = f"{sender}{recipient}{amount}{fee}{message}{note}{tx_type}{locktime}{tx_time}"

    public_key = None
    signature = None

    if tx_type in ["token_transfer", "token_deploy"]:
        inputs = [TransactionInput(txid="TOKEN", output_index=0)]
        outputs = [TransactionOutput(recipient=recipient, amount=amount)]

        if sender_private_key:
            public_key = get_public_key_from_private_key(sender_private_key)
            signature = sign_message(sender_private_key, raw_msg)

    elif tx_type == "coinbase":
        inputs = []
        outputs = [TransactionOutput(recipient=recipient, amount=amount)]
        public_key = "SYSTEM_PUB"
        signature = "SYSTEM_SIG"

    else:
        db = db or SQLiteDataStore()
        unspent = db.get_unspent_utxos(sender)
        unspent = [utxo for utxo in unspent if not utxo[1].startswith("GENESIS_TXID")]

        selected = []
        total = 0.0
        for utxo in unspent:
            selected.append(utxo)
            total += utxo[4]
            if total >= amount + fee:
                break

        if total < amount + fee:
            raise ValueError("Yetersiz bakiye: UTXO'lar toplamı yeterli değil.")

        inputs = [TransactionInput(txid=utxo[1], output_index=utxo[2]) for utxo in selected]
        outputs = [TransactionOutput(recipient=recipient, amount=amount)]

        change = total - amount - fee
        if change > 0:
            outputs.append(TransactionOutput(recipient=sender, amount=change))

        if sender_private_key:
            public_key = get_public_key_from_private_key(sender_private_key)
            signature = sign_message(sender_private_key, raw_msg)

    tx = Transaction(
        sender=sender,
        recipient=recipient,
        amount=amount,
        fee=fee,
        message=message,
        note=note,
        type=tx_type,
        locktime=locktime,
        time=tx_time,
        inputs=inputs,
        outputs=outputs,
        public_key=public_key,
        script_sig=signature,
        script=script,
        contract_result=contract_result
    )
    tx.txid = tx.compute_txid()
    return tx.to_dict()

@classmethod
def from_dict(cls, data: dict):
    return cls(
        sender=data.get("sender"),
        recipient=data.get("recipient"),
        amount=data.get("amount"),
        signature=data.get("signature"),
        timestamp=data.get("timestamp", time.time()),
        fee=data.get("fee", 0),
        token=data.get("token", None)
    )

