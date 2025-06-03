from bhrc_blockchain.core.utxo.utxo_manager import UTXOManager

def test_exactly_return_true():
    utxo_manager = UTXOManager()
    utxo_manager.add_utxos("final", [
        {"index": 0, "recipient": "Z", "amount": 1},
        {"index": 1, "recipient": "Z", "amount": 2}
    ])

    inputs = [
        {"txid": "final", "index": 0},
        {"txid": "final", "index": 1}
    ]

    assert utxo_manager.is_utxo_owner(inputs, "Z") is True

