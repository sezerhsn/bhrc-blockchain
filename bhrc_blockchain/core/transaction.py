import re
import time
from typing import Dict, Optional, Any

from bhrc_blockchain.database.storage import SQLiteDataStore
from bhrc_blockchain.core.transaction_model import Transaction, TransactionInput, TransactionOutput
from bhrc_blockchain.config.config import Config
from bhrc_blockchain.core.wallet import (
    get_address_from_private_key,
    sign_message,
    get_public_key_from_private_key,
    verify_signature
)


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

        raw_message = f"{tx_dict['sender']}{tx_dict['recipient']}{tx_dict['amount']}{tx_dict['fee']}{tx_dict['message']}{tx_dict['note']}{tx_dict['type']}{tx_dict['locktime']}{tx_dict['time']}"
        if not verify_signature(tx_dict["public_key"], raw_message, tx_dict["script_sig"]):
            raise ValueError("İmza doğrulaması başarısız.")

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
    db: Optional[SQLiteDataStore] = None
) -> Dict[str, Any]:

    if tx_type not in ["coinbase", "token_transfer", "transfer"]:
        raise ValueError("Geçersiz işlem tipi")

    if fee is None:
        fee = 0.0 if tx_type == "coinbase" else max(Config.MIN_TRANSACTION_FEE, amount * Config.TRANSACTION_FEE_PERCENTAGE)

    if sender_private_key:
        derived_address = get_address_from_private_key(sender_private_key)
        if derived_address != sender:
            raise ValueError("Özel anahtar, gönderici adresiyle eşleşmiyor.")

    tx_time = time.time()
    raw_msg = f"{sender}{recipient}{amount}{fee}{message}{note}{tx_type}{locktime}{tx_time}"

    if tx_type == "token_transfer":
        from bhrc_blockchain.core.token import TokenContract
        if not TokenContract.transfer(note, sender, recipient, amount):
            raise ValueError("Token transfer başarısız veya yetersiz bakiye.")

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
            inputs=[TransactionInput(txid="TOKEN", output_index=0)],
            outputs=[TransactionOutput(recipient=recipient, amount=amount)],
            public_key=public_key,
            script_sig=signature
        )
        tx.txid = tx.compute_txid()
        return tx.to_dict()

    if tx_type == "coinbase":
        public_key = "SYSTEM"
        signature = "SYSTEM_SIG"
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
            inputs=[],
            outputs=[TransactionOutput(recipient=recipient, amount=amount)],
            public_key=public_key,
            script_sig=signature
        )
        tx.txid = tx.compute_txid()
        return tx.to_dict()

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

    public_key = get_public_key_from_private_key(sender_private_key) if sender_private_key else None
    signature = sign_message(sender_private_key, raw_msg) if sender_private_key else None

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
        script_sig=signature
    )
    tx.txid = tx.compute_txid()
    return tx.to_dict()

