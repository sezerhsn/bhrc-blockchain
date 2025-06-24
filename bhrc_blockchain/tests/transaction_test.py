import pytest
import time
from ecdsa import SigningKey, SECP256k1
from unittest.mock import patch, MagicMock
from bhrc_blockchain.config.config import settings
from bhrc_blockchain.core.transaction.transaction_model import TransactionInput, TransactionOutput
from bhrc_blockchain.core.transaction.transaction import (
    verify_signature,
    sign_message,
    create_transaction,
    validate_transaction
)
from bhrc_blockchain.core.wallet.wallet import (
    MinerWallet,
    get_public_key_from_private_key
)

wallet = MinerWallet()
privkey = wallet.private_key
sender = wallet.address

def test_create_coinbase_transaction():
    tx = create_transaction(
        sender="SYSTEM",
        recipient="xBHR" + "A"*60,
        amount=50.0,
        tx_type="coinbase"
    )
    assert tx["type"] == "coinbase"

def test_create_transaction_invalid_key():
    wrong_sender = "xBHR" + "Z"*60
    with pytest.raises(ValueError):
        create_transaction(
            sender=wrong_sender,
            recipient=sender,
            amount=10,
            sender_private_key=privkey
        )

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos", return_value=[])
def test_create_transaction_insufficient_utxo(mock_utxo):
    with pytest.raises(ValueError):
        create_transaction(
            sender=sender,
            recipient="xBHR" + "B"*60,
            amount=10,
            sender_private_key=privkey
        )

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_with_change(mock_utxo):
    mock_utxo.return_value = [(1, "txid1", 0, sender, 20.0)]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "C"*60,
        amount=10.0,
        fee=1.0,
        sender_private_key=privkey
    )
    assert any(out["recipient"] == sender for out in tx["outputs"])

@patch("bhrc_blockchain.core.token.token_contract.TokenContract.transfer", return_value=True)
def test_create_token_transfer_success(mock_transfer):
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "D"*60,
        amount=5.0,
        note="TOKEN123",
        tx_type="token_transfer",
        sender_private_key=privkey
    )
    assert tx["type"] == "token_transfer"

def test_validate_transaction_missing_fields():
    with pytest.raises(ValueError):
        validate_transaction({"sender": sender})

def test_validate_transaction_invalid_amount():
    tx = {
        "sender": sender,
        "recipient": "xBHR" + "B"*60,
        "amount": 0,
        "txid": "abc",
        "type": "transfer"
    }
    with pytest.raises(ValueError):
        validate_transaction(tx)

def test_validate_transaction_bad_address():
    tx = {
        "sender": "INVALID",
        "recipient": "xBHR" + "C"*60,
        "amount": 10,
        "txid": "abc",
        "type": "transfer"
    }
    with pytest.raises(ValueError):
        validate_transaction(tx)

def test_validate_transaction_bad_signature():
    tx = {
        "sender": sender,
        "recipient": "xBHR" + "B"*60,
        "amount": 10,
        "txid": "abc",
        "fee": 0.1,
        "message": "test",
        "note": "note",
        "type": "transfer",
        "locktime": 0,
        "time": time.time(),
        "script_sig": "fake_sig",
        "public_key": "fake_pub"
    }
    with pytest.raises(ValueError):
        validate_transaction(tx)

def test_validate_transaction_valid_signature():
    tx_time = time.time()
    raw_msg = f"{sender}{'xBHR' + 'C'*60}10{0.1}msgnote"+"transfer0"+str(tx_time)
    sig = sign_message(privkey, raw_msg)
    pub = get_public_key_from_private_key(privkey)

    tx = {
        "sender": sender,
        "recipient": "xBHR" + "C"*60,
        "amount": 10,
        "fee": 0.1,
        "message": "msg",
        "note": "note",
        "type": "transfer",
        "locktime": 0,
        "time": tx_time,
        "txid": "txid123",
        "script_sig": sig,
        "public_key": pub
    }
    assert validate_transaction(tx) is True

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_with_explicit_fee(mock_utxo):
    mock_utxo.return_value = [(1, "txidX", 0, sender, 100.0)]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "X" * 60,
        amount=50.0,
        fee=2.0,
        sender_private_key=privkey
    )
    assert tx["fee"] == 2.0

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_with_custom_db(mock_utxo):
    db_mock = MagicMock()
    db_mock.get_unspent_utxos.return_value = [
        (1, "txid_custom", 0, sender, 20.0)
    ]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "B" * 60,
        amount=10.0,
        fee=1.0,
        sender_private_key=privkey,
        db=db_mock
    )
    assert tx["amount"] == 10.0
    db_mock.get_unspent_utxos.assert_called_once()

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_fee_none_coinbase(mock_utxo):
    tx = create_transaction(
        sender="SYSTEM",
        recipient="xBHR" + "A" * 60,
        amount=50.0,
        tx_type="coinbase"
    )
    assert tx["fee"] == 0.0
    assert tx["type"] == "coinbase"
    assert tx["script_sig"] == "SYSTEM_SIG"

def test_verify_signature_invalid_signature():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    pubkey_hex = vk.to_string().hex()
    fake_signature = "00" * 64
    result = verify_signature(pubkey_hex, fake_signature, "test")
    assert result is False

@patch("bhrc_blockchain.core.contract.contract_engine.evaluate_contract", return_value=False)
def test_validate_transaction_contract_failure(mock_eval):
    recipient = "xBHR" + "Z" * 60
    tx_time = time.time()
    raw_msg = (
        str(sender) +
        str(recipient) +
        str(1.0) +
        str(0.1) +
        "" + "" +
        "contract" +
        str(0) +
        str(tx_time)
    )
    sig = sign_message(privkey, raw_msg)
    pub = get_public_key_from_private_key(privkey)

    tx = {
        "sender": sender,
        "recipient": recipient,
        "amount": 1.0,
        "txid": "tx123",
        "fee": 0.1,
        "message": "",
        "note": "",
        "type": "contract",
        "locktime": 0,
        "time": tx_time,
        "script_sig": sig,
        "public_key": pub
    }
    with pytest.raises(ValueError, match="Smart contract koşulları sağlanmadı"):
        validate_transaction(tx)

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_with_script(mock_utxo):
    mock_utxo.return_value = [(1, "txid1", 0, sender, 20.0)]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "S"*60,
        amount=5.0,
        fee=0.5,
        sender_private_key=privkey,
        script="custom logic"
    )
    assert tx["script"] == "custom logic"

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_auto_fee(mock_utxo):
    mock_utxo.return_value = [(1, "txid1", 0, sender, 20.0)]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "F"*60,
        amount=10.0,
        sender_private_key=privkey
    )
    expected_fee = max(settings.MIN_TRANSACTION_FEE, 10.0 * settings.TRANSACTION_FEE_PERCENTAGE)
    assert abs(tx["fee"] - expected_fee) < 0.0001

def test_validate_coinbase_missing_sig_fields():
    tx = {
        "sender": "xBHR" + "0" * 60,
        "recipient": "xBHR" + "B"*60,
        "amount": 50.0,
        "txid": "coinbase_txid",
        "type": "coinbase"
    }
    assert validate_transaction(tx) is True

