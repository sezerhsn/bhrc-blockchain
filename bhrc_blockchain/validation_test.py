# validation_test.py
import time
from bhrc_blockchain.core.blockchain.validation import ChainValidator
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.blockchain.validation import validate_block_structure, validate_block_transactions

class FakeBlockchain:
    def __init__(self):
        tx = {"txid": "abc", "type": "coinbase", "outputs": [{"recipient": "x", "amount": 10}]}
        block = Block(index=0, previous_hash="0", transactions=[tx], miner_address="miner")
        self.chain = [block.to_dict()]

def test_validate_chain_valid_case():
    fb = FakeBlockchain()
    assert ChainValidator.validate_chain(fb) is True

def test_validate_chain_fails_on_previous_hash_mismatch():
    tx = {"txid": "abc", "type": "coinbase", "outputs": [{"recipient": "x", "amount": 10}]}
    block1 = Block(index=0, previous_hash="0", transactions=[tx], miner_address="miner")
    block2 = Block(index=1, previous_hash="WRONG_HASH", transactions=[tx], miner_address="miner")
    chain = [block1.to_dict(), block2.to_dict()]

    class FakeBC:
        def __init__(self):
            self.chain = chain

    assert ChainValidator.validate_chain(FakeBC()) is False

def test_validate_chain_fails_on_merkle_root_mismatch():
    tx = {"txid": "abc", "type": "coinbase", "outputs": [{"recipient": "x", "amount": 10}]}
    block = Block(index=0, previous_hash="0", transactions=[tx], miner_address="miner")
    block_dict = block.to_dict()
    block_dict["merkle_root"] = "tampered"

    class FakeBC:
        def __init__(self):
            self.chain = [block_dict]

    assert ChainValidator.validate_chain(FakeBC()) is False

def test_validate_chain_fails_on_missing_input_utxo():
    tx = {
        "txid": "tx2",
        "type": "transfer",
        "inputs": [{"txid": "nonexistent", "output_index": 0}],
        "outputs": [{"recipient": "x", "amount": 10}]
    }
    coinbase = {
        "txid": "cb1",
        "type": "coinbase",
        "outputs": [{"recipient": "x", "amount": 10}]
    }
    b1 = Block(index=0, previous_hash="0", transactions=[coinbase], miner_address="miner").to_dict()
    b2 = Block(index=1, previous_hash=b1["block_hash"], transactions=[tx], miner_address="miner").to_dict()

    class Dummy:
        def __init__(self):
            self.chain = [b1, b2]

    assert ChainValidator.validate_chain(Dummy()) is False

def test_validate_chain_passes_with_input_and_output_tracking():
    cb_tx = {
        "txid": "tx1",
        "type": "coinbase",
        "outputs": [{"recipient": "x", "amount": 10}]
    }
    tx = {
        "txid": "tx2",
        "type": "transfer",
        "inputs": [{"txid": "tx1", "output_index": 0}],
        "outputs": [{"recipient": "y", "amount": 10}]
    }
    b1 = Block(index=0, previous_hash="0", transactions=[cb_tx], miner_address="miner").to_dict()
    b2 = Block(index=1, previous_hash=b1["block_hash"], transactions=[tx], miner_address="miner").to_dict()

    class Dummy:
        def __init__(self):
            self.chain = [b1, b2]

    assert ChainValidator.validate_chain(Dummy()) is True

def test_validate_chain_multiple_coinbase_and_outputs():
    cb1 = {
        "txid": "cb1",
        "type": "coinbase",
        "outputs": [{"recipient": "x", "amount": 10}]
    }
    cb2 = {
        "txid": "cb2",
        "type": "coinbase",
        "outputs": [{"recipient": "x", "amount": 20}]
    }
    tx = {
        "txid": "tx3",
        "type": "transfer",
        "inputs": [{"txid": "cb1", "output_index": 0}],
        "outputs": [{"recipient": "z", "amount": 10}]
    }

    b1 = Block(index=0, previous_hash="0", transactions=[cb1, cb2], miner_address="miner").to_dict()
    b2 = Block(index=1, previous_hash=b1["block_hash"], transactions=[tx], miner_address="miner").to_dict()

    class Dummy:
        def __init__(self):
            self.chain = [b1, b2]

    assert ChainValidator.validate_chain(Dummy()) is True

def test_validate_block_structure_invalid_miner_address():
    block = {
        "index": 0,
        "block_hash": "hash",
        "previous_hash": "0",
        "timestamp": time.time(),
        "miner_address": "INVALID_ADDRESS",
        "merkle_root": "root",
        "nonce": 0,
        "version": "0x01",
        "virtual_size": 1000,
        "transactions": []
    }
    try:
        validate_block_structure(block)
        assert False, "Beklenen ValueError alınmadı"
    except ValueError as e:
        assert "miner_address biçimi geçersiz" in str(e)

def test_validate_block_structure_missing_field():
    block = {
        # intentionally missing 'virtual_size'
        "index": 0,
        "block_hash": "hash",
        "previous_hash": "0",
        "timestamp": time.time(),
        "miner_address": "xBHR" + "A" * 60,
        "merkle_root": "root",
        "nonce": 0,
        "version": "0x01",
        "transactions": []
    }
    try:
        validate_block_structure(block)
        assert False, "Eksik alan ValueError fırlatmalıydı"
    except ValueError as e:
        assert "eksik alanlar" in str(e)

def test_validate_block_transactions_filters_ready():
    txs = [
        {"txid": "1", "status": "pending"},
        {"txid": "2", "status": "ready"},
        {"txid": "3", "status": "ready"},
    ]
    filtered = validate_block_transactions(txs)
    assert len(filtered) == 2
    assert all(tx["status"] == "ready" for tx in filtered)

def test_validate_block_structure_missing_transaction_fields():
    block = {
        "index": 0,
        "block_hash": "hash",
        "previous_hash": "0",
        "timestamp": time.time(),
        "miner_address": "xBHR" + "A" * 60,
        "merkle_root": "root",
        "nonce": 0,
        "version": "0x01",
        "virtual_size": 1000,
        "transactions": [{
            "txid": "tx1",
            "sender": "xBHR" + "B" * 60,
            # recipient alanı eksik
            "amount": 10,
            "fee": 0.1,
            "message": "",
            "note": "",
            "type": "transfer",
            "locktime": 0,
            "time": time.time(),
            "script_sig": "sig",
            "public_key": "pub"
        }]
    }
    try:
        validate_block_structure(block)
        assert False, "Eksik işlem alanı ValueError fırlatmalıydı"
    except ValueError as e:
        assert "İşlem sözleşmesi eksik" in str(e)

def test_validate_block_structure_missing_signature_fields():
    block = {
        "index": 0,
        "block_hash": "hash",
        "previous_hash": "0",
        "timestamp": time.time(),
        "miner_address": "xBHR" + "A" * 60,
        "merkle_root": "root",
        "nonce": 0,
        "version": "0x01",
        "virtual_size": 1000,
        "transactions": [{
            "txid": "tx2",
            "sender": "xBHR" + "B" * 60,
            "recipient": "xBHR" + "C" * 60,
            "amount": 15,
            "fee": 0.2,
            "message": "",
            "note": "",
            "type": "transfer",  # coinbase değil
            "locktime": 0,
            "time": time.time()
            # script_sig ve public_key eksik
        }]
    }
    try:
        validate_block_structure(block)
        assert False, "Eksik imza alanları ValueError fırlatmalıydı"
    except ValueError as e:
        assert "İmza verisi eksik" in str(e)

