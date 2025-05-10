# transaction_model_test.py
from bhrc_blockchain.core.transaction_model import Transaction, TransactionInput, TransactionOutput

def test_transaction_to_dict_and_txid():
    tx = Transaction(
        sender="xBHR" + "A"*60,
        recipient="xBHR" + "B"*60,
        amount=10.0,
        fee=0.1,
        message="hello",
        note="note",
        inputs=[TransactionInput(txid="abc", output_index=0)],
        outputs=[TransactionOutput(recipient="xBHR" + "C"*60, amount=10.0)],
        public_key="pubkey123",
        script_sig="sig456"
    )

    tx_dict = tx.to_dict()
    txid = tx.compute_txid()

    assert isinstance(tx_dict, dict)
    assert tx_dict["sender"] == tx.sender
    assert isinstance(txid, str)
    assert len(txid) == 64

