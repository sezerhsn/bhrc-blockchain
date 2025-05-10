# transaction_test.py
import pytest
import time

from ecdsa import SigningKey, SECP256k1
from bhrc_blockchain.core.transaction import verify_signature, sign_message, create_transaction, validate_transaction
from bhrc_blockchain.core.wallet import generate_private_key, get_address_from_private_key, sign_message, get_public_key_from_private_key
from bhrc_blockchain.core.transaction_model import TransactionInput, TransactionOutput
from unittest.mock import patch, MagicMock

def test_create_coinbase_transaction():
    tx = create_transaction(
        sender="SYSTEM",
        recipient="xBHR" + "A"*60,
        amount=50.0,
        tx_type="coinbase"
    )
    assert tx["type"] == "coinbase"

def test_create_transaction_invalid_key():
    priv_key = generate_private_key()
    correct_address = get_address_from_private_key(priv_key)
    wrong_address = "xBHR" + "Z"*60
    with pytest.raises(ValueError):
        create_transaction(
            sender=wrong_address,
            recipient=correct_address,
            amount=10,
            sender_private_key=priv_key
        )

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos", return_value=[])
def test_create_transaction_insufficient_utxo(mock_utxo):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    with pytest.raises(ValueError):
        create_transaction(
            sender=sender,
            recipient="xBHR" + "B"*60,
            amount=10,
            sender_private_key=priv_key
        )

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_with_change(mock_utxo):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    mock_utxo.return_value = [(1, "txid1", 0, sender, 20.0)]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "C"*60,
        amount=10.0,
        fee=1.0,
        sender_private_key=priv_key
    )
    assert any(out["recipient"] == sender for out in tx["outputs"])

@patch("bhrc_blockchain.core.token.TokenContract.transfer", return_value=True)
def test_create_token_transfer_success(mock_transfer):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "D"*60,
        amount=5.0,
        note="TOKEN123",
        tx_type="token_transfer",
        sender_private_key=priv_key
    )
    assert tx["type"] == "token_transfer"

@patch("bhrc_blockchain.core.token.TokenContract.transfer", return_value=False)
def test_create_token_transfer_failure(mock_transfer):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    with pytest.raises(ValueError):
        create_transaction(
            sender=sender,
            recipient="xBHR" + "E"*60,
            amount=5.0,
            note="TOKEN123",
            tx_type="token_transfer",
            sender_private_key=priv_key
        )

def test_validate_transaction_missing_fields():
    with pytest.raises(ValueError):
        validate_transaction({"sender": "xBHR" + "A"*60})

def test_validate_transaction_invalid_amount():
    tx = {
        "sender": "xBHR" + "A"*60,
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
        "sender": "xBHR" + "A"*60,
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
        priv_key = generate_private_key()
        sender = get_address_from_private_key(priv_key)
        recipient = "xBHR" + "C"*60
        assert len(sender) == 64
        assert len(recipient) == 64

        tx_time = time.time()
        raw_msg = f"{sender}{recipient}10{0.1}msgnote"+"transfer0"+str(tx_time)
        sig = sign_message(priv_key, raw_msg)
        pub = get_public_key_from_private_key(priv_key)

        tx = {
            "sender": sender,
            "recipient": recipient,
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

    def test_validate_coinbase_transaction_passes():
        tx = {
            "sender": "xBHR" + "A"*60,
            "recipient": "xBHR" + "B"*60,
            "amount": 50.0,
            "txid": "coinbase123",
            "type": "coinbase",
            "fee": 0.0,
            "message": "",
            "note": "",
            "locktime": 0,
            "time": time.time()
        }
        assert validate_transaction(tx) is True

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_without_change_output(mock_utxo):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    mock_utxo.return_value = [(1, "txid1", 0, sender, 10.0)]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "F"*60,
        amount=9.0,
        fee=1.0,
        sender_private_key=priv_key
    )
    # Sadece bir çıkış olmalı (alıcıya)
    assert len(tx["outputs"]) == 1
    assert tx["outputs"][0]["recipient"] != sender

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_without_private_key(mock_utxo):
    sender = "xBHR" + "G"*60
    mock_utxo.return_value = [(1, "txid2", 0, sender, 15.0)]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "H"*60,
        amount=10.0,
        fee=1.0,
        sender_private_key=None
    )
    assert "script_sig" not in tx
    assert "public_key" not in tx

def test_create_transaction_invalid_amount():
    with pytest.raises(ValueError, match="Miktar sıfırdan büyük olmalıdır."):
        validate_transaction({
            "sender": "xBHR" + "A"*60,
            "recipient": "xBHR" + "B"*60,
            "amount": 0,
            "txid": "abc123",
            "type": "transfer",
            "script_sig": "sig",
            "public_key": "pub",
            "fee": 1,
            "message": "",
            "note": "",
            "locktime": 0,
            "time": time.time()
        })

def test_create_transaction_invalid_address_format():
    with pytest.raises(ValueError, match="Adres biçimi geçersizdir."):
        validate_transaction({
            "sender": "INVALIDADDRESS",
            "recipient": "xBHR" + "B"*60,
            "amount": 10,
            "txid": "abc123",
            "type": "transfer",
            "script_sig": "sig",
            "public_key": "pub",
            "fee": 1,
            "message": "",
            "note": "",
            "locktime": 0,
            "time": time.time()
        })

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_create_transaction_with_change_output(mock_utxo):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    mock_utxo.return_value = [(1, "txid1", 0, sender, 12.0)]

    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "J"*60,
        amount=10.0,
        fee=1.0,
        sender_private_key=priv_key
    )

    assert len(tx["outputs"]) == 2
    assert any(out["recipient"] == sender and out["amount"] == 1.0 for out in tx["outputs"])

def test_validate_transaction_missing_fields():
    invalid_tx = {
        "sender": "xBHR" + "A" * 60,
        "recipient": "xBHR" + "B" * 60,
        "amount": 10.0
        # txid eksik
    }
    with pytest.raises(ValueError, match="Eksik alanlar"):
        validate_transaction(invalid_tx)


def test_validate_transaction_negative_amount():
    tx = {
        "sender": "xBHR" + "A" * 60,
        "recipient": "xBHR" + "B" * 60,
        "amount": -5.0,
        "txid": "abc123",
        "type": "coinbase"
    }
    with pytest.raises(ValueError, match="Miktar sıfırdan büyük olmalıdır"):
        validate_transaction(tx)


def test_validate_transaction_invalid_address():
    tx = {
        "sender": "INVALID_ADDRESS",
        "recipient": "xBHR" + "B" * 60,
        "amount": 5.0,
        "txid": "abc123",
        "type": "coinbase"
    }
    with pytest.raises(ValueError, match="Adres biçimi geçersizdir"):
        validate_transaction(tx)


def test_validate_coinbase_transaction_passes_without_signature():
    tx = {
        "sender": "xBHR" + "A" * 60,
        "recipient": "xBHR" + "B" * 60,
        "amount": 10.0,
        "txid": "coinbase123",
        "type": "coinbase"
    }
    assert validate_transaction(tx) is True

def test_create_transaction_with_invalid_private_key():
    priv_key = generate_private_key()
    wrong_priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)

    with pytest.raises(ValueError, match="Özel anahtar, gönderici adresiyle eşleşmiyor."):
        create_transaction(
            sender=sender,
            recipient="xBHR" + "Z"*60,
            amount=5.0,
            fee=1.0,
            sender_private_key=wrong_priv_key
        )

def test_create_transaction_with_explicit_fee():
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)

    with patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos") as mock_utxo:
        mock_utxo.return_value = [(1, "txidX", 0, sender, 100.0)]
        tx = create_transaction(
            sender=sender,
            recipient="xBHR" + "X" * 60,
            amount=50.0,
            fee=2.0,
            sender_private_key=priv_key
        )
        assert tx["fee"] == 2.0

def test_create_transaction_with_wrong_private_key():
    priv_key_1 = generate_private_key()
    priv_key_2 = generate_private_key()
    sender = get_address_from_private_key(priv_key_1)

    with pytest.raises(ValueError, match="Özel anahtar, gönderici adresiyle eşleşmiyor."):
        create_transaction(
            sender=sender,
            recipient="xBHR" + "Y" * 60,
            amount=5.0,
            sender_private_key=priv_key_2  # Hatalı private key
        )

def test_create_transaction_no_change_output():
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)

    with patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos") as mock_utxo:
        mock_utxo.return_value = [(1, "txidZ", 0, sender, 11.0)]
        tx = create_transaction(
            sender=sender,
            recipient="xBHR" + "Z" * 60,
            amount=10.0,
            fee=1.0,
            sender_private_key=priv_key
        )
        assert len(tx["outputs"]) == 1  # sadece alıcıya giden output olmalı
        assert tx["outputs"][0]["recipient"].startswith("xBHRZ")

from bhrc_blockchain.core.transaction import create_transaction
from bhrc_blockchain.core.wallet import generate_private_key, get_address_from_private_key
from unittest.mock import patch

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_fee_none_coinbase(mock_utxo):
    # fee=None ve tx_type="coinbase" durumunu tetikler
    tx = create_transaction(
        sender="SYSTEM",
        recipient="xBHR" + "A" * 60,
        amount=50.0,
        tx_type="coinbase"
    )
    assert tx["fee"] == 0.0
    assert tx["type"] == "coinbase"
    assert tx["script_sig"] == "SYSTEM_SIG"

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_exact_amount_no_change(mock_utxo):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    # Tam miktarda UTXO: 10 (amount) + 1 (fee) = 11
    mock_utxo.return_value = [(1, "txid1", 0, sender, 11.0)]

    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "B" * 60,
        amount=10.0,
        fee=1.0,
        sender_private_key=priv_key
    )
    assert len(tx["outputs"]) == 1
    assert tx["outputs"][0]["amount"] == 10.0


@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_no_private_key_no_signature(mock_utxo):
    sender = "xBHR" + "C" * 60
    mock_utxo.return_value = [(1, "txid2", 0, sender, 10.0)]

    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "D" * 60,
        amount=9.0,
        fee=1.0,
        sender_private_key=None
    )
    assert "script_sig" not in tx
    assert "public_key" not in tx

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_transaction_exact_amount_no_change(mock_utxo):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    mock_utxo.return_value = [(1, "txidX", 0, sender, 10.0)]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "Y" * 60,
        amount=9.0,
        fee=1.0,
        sender_private_key=priv_key
    )
    assert len(tx["outputs"]) == 1
    assert tx["outputs"][0]["amount"] == 9.0

def test_invalid_private_key_for_sender():
    priv_key = generate_private_key()
    wrong_sender = get_address_from_private_key(generate_private_key())
    with pytest.raises(ValueError, match="Özel anahtar, gönderici adresiyle eşleşmiyor."):
        create_transaction(
            sender=wrong_sender,
            recipient="xBHR" + "Z" * 60,
            amount=5.0,
            sender_private_key=priv_key
        )

@patch("bhrc_blockchain.database.storage.SQLiteDataStore.get_unspent_utxos")
def test_explicit_fee_and_no_change(mock_utxo):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    mock_utxo.return_value = [(1, "txid1", 0, sender, 11.0)]

    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "Z" * 60,
        amount=10.0,
        fee=1.0,
        sender_private_key=priv_key
    )

    assert tx["fee"] == 1.0
    assert len(tx["outputs"]) == 1
    assert tx["outputs"][0]["recipient"] != sender

def test_verify_signature_invalid_signature():
    from ecdsa import SigningKey, SECP256k1
    from bhrc_blockchain.core.transaction import verify_signature, sign_message

    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    pubkey_hex = vk.to_string().hex()

    message = "test"
    fake_signature = "00" * 64  # geçersiz ama hex formatında

    result = verify_signature(pubkey_hex, fake_signature, message)
    assert result is False

def test_create_transaction_invalid_type_raises():
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)

    with pytest.raises(ValueError, match="Geçersiz işlem tipi"):
        create_transaction(
            sender=sender,
            recipient="xBHR" + "D"*60,
            amount=0.0,
            fee=0.0,
            tx_type="invalid_type",
            sender_private_key=priv_key
        )

def test_create_transaction_invalid_type_raises_explicit():
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)

    with pytest.raises(ValueError, match="Geçersiz işlem tipi"):
        create_transaction(
            sender=sender,
            recipient="xBHR" + "D"*60,
            amount=0.0,
            fee=0.0,
            tx_type="bilerek_boztuk",  # geçersiz
            sender_private_key=priv_key
        )

@patch("bhrc_blockchain.core.token.TokenContract.transfer", return_value=False)
def test_token_transfer_without_note_fails(mock_transfer):
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    with pytest.raises(ValueError, match="Token transfer başarısız"):
        create_transaction(
            sender=sender,
            recipient="xBHR" + "E" * 60,
            amount=5.0,
            tx_type="token_transfer",
            sender_private_key=priv_key
        )

def test_create_transaction_with_custom_db():
    priv_key = generate_private_key()
    sender = get_address_from_private_key(priv_key)
    db_mock = MagicMock()
    db_mock.get_unspent_utxos.return_value = [
        (1, "txid_custom", 0, sender, 20.0)
    ]
    tx = create_transaction(
        sender=sender,
        recipient="xBHR" + "B" * 60,
        amount=10.0,
        fee=1.0,
        sender_private_key=priv_key,
        db=db_mock
    )
    assert tx["amount"] == 10.0
    db_mock.get_unspent_utxos.assert_called_once()

