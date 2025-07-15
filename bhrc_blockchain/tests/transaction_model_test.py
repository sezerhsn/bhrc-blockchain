from bhrc_blockchain.core.transaction.transaction_model import Transaction, TransactionInput, TransactionOutput

def test_transaction_input_to_dict():
    txin = TransactionInput(txid="abc123", output_index=0)
    result = txin.to_dict()
    assert result == {"txid": "abc123", "output_index": 0}

def test_transaction_output_to_dict():
    txout = TransactionOutput(recipient="xBHRabc", amount=10.5)
    result = txout.to_dict()
    assert result == {"recipient": "xBHRabc", "amount": 10.5, "locked": False}

def test_transaction_to_dict_and_txid():
    tx = Transaction(
        sender="xBHR1",
        recipient="xBHR2",
        amount=5.0,
        fee=0.1,
        inputs=[TransactionInput("prev_tx", 0)],
        outputs=[TransactionOutput("xBHR2", 5.0)]
    )
    tx.txid = tx.compute_txid()
    d = tx.to_dict()

    assert "sender" in d and d["sender"] == "xBHR1"
    assert "txid" in d and isinstance(d["txid"], str)
    assert len(d["txid"]) > 10, "txid boş olmamalı veya geçersiz üretildi"

