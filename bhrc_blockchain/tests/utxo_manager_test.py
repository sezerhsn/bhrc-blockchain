import pytest
from bhrc_blockchain.core.utxo.utxo_manager import UTXOManager

@pytest.fixture
def utxo_manager():
    return UTXOManager()

def test_add_and_get_utxo(utxo_manager):
    utxo_manager.add_utxos("tx123", [{"index": 0, "recipient": "Alice", "amount": 50}])
    utxo = utxo_manager.get_utxo("tx123", 0)
    assert utxo["recipient"] == "Alice"
    assert utxo["amount"] == 50

def test_remove_utxos(utxo_manager):
    utxo_manager.add_utxos("tx456", [{"index": 0, "recipient": "Bob", "amount": 30}])
    utxo_manager.remove_utxos([{"txid": "tx456", "index": 0}])
    assert utxo_manager.get_utxo("tx456", 0) is None

def test_is_utxo_owner_true(utxo_manager):
    utxo_manager.add_utxos("tx789", [{"index": 0, "recipient": "Carol", "amount": 75}])
    assert utxo_manager.get_utxo("tx789", 0)["recipient"] == "Carol"
    assert utxo_manager.is_utxo_owner([{"txid": "tx789", "index": 0}], "Carol") is True

def test_is_utxo_owner_false(utxo_manager):
    utxo_manager.add_utxos("tx999", [{"index": 0, "recipient": "Dave", "amount": 60}])
    assert utxo_manager.is_utxo_owner([{"txid": "tx999", "index": 0}], "Eve") is False

def test_update_with_transaction(utxo_manager):
    tx = {
        "txid": "tx101",
        "inputs": [{"txid": "tx102", "index": 0}],
        "outputs": [{"index": 0, "recipient": "Frank", "amount": 40}]
    }
    utxo_manager.add_utxos("tx102", [{"index": 0, "recipient": "George", "amount": 40}])
    utxo_manager.update_with_transaction(tx)
    assert utxo_manager.get_utxo("tx102", 0) is None
    assert utxo_manager.get_utxo("tx101", 0)["recipient"] == "Frank"

def test_reset(utxo_manager):
    utxo_manager.add_utxos("tx105", [{"index": 0, "recipient": "Henry", "amount": 100}])
    utxo_manager.reset()
    assert utxo_manager.utxos == {}

def test_is_utxo_owner_true_full(utxo_manager):
    utxo_manager.add_utxos("tx123", [{"index": 0, "recipient": "Alice", "amount": 50}])
    assert utxo_manager.is_utxo_owner([{"txid": "tx123", "index": 0}], "Alice") is True

def test_update_with_transaction_full(utxo_manager):
    utxo_manager.add_utxos("txOLD", [{"index": 0, "recipient": "Bob", "amount": 40}])
    tx = {
        "txid": "txNEW",
        "inputs": [{"txid": "txOLD", "index": 0}],
        "outputs": [{"index": 0, "recipient": "Eve", "amount": 40}]
    }
    utxo_manager.update_with_transaction(tx)
    assert utxo_manager.get_utxo("txOLD", 0) is None
    assert utxo_manager.get_utxo("txNEW", 0)["recipient"] == "Eve"

def test_is_utxo_owner_positive_path(utxo_manager):
    utxo_manager.add_utxos("txABC", [{"index": 0, "recipient": "TestUser", "amount": 10}])
    result = utxo_manager.is_utxo_owner([{"txid": "txABC", "index": 0}], "TestUser")
    assert result is True

def test_update_with_transaction_inputs_outputs(utxo_manager):
    utxo_manager.add_utxos("oldTx", [{"index": 0, "recipient": "X", "amount": 5}])
    tx = {
        "txid": "newTx",
        "inputs": [{"txid": "oldTx", "index": 0}],
        "outputs": [{"index": 0, "recipient": "Y", "amount": 5}]
    }
    utxo_manager.update_with_transaction(tx)
    assert utxo_manager.get_utxo("oldTx", 0) is None
    assert utxo_manager.get_utxo("newTx", 0)["recipient"] == "Y"

def test_is_utxo_owner_empty_inputs(utxo_manager):
    assert utxo_manager.is_utxo_owner([], "any_address") is True

def test_update_with_transaction_full_execution(utxo_manager):
    utxo_manager.add_utxos("t1", [{"index": 0, "recipient": "A", "amount": 1}])
    tx = {
        "txid": "t2",
        "inputs": [{"txid": "t1", "index": 0}],
        "outputs": [{"index": 0, "recipient": "B", "amount": 1}]
    }
    utxo_manager.update_with_transaction(tx)
    assert utxo_manager.get_utxo("t1", 0) is None
    assert utxo_manager.get_utxo("t2", 0)["recipient"] == "B"

def test_is_utxo_owner_true_path(utxo_manager):
    utxo_manager.add_utxos("tx999", [{"index": 0, "recipient": "Zeynep", "amount": 10}])
    assert utxo_manager.is_utxo_owner([{"txid": "tx999", "index": 0}], "Zeynep") is True

def test_update_with_transaction_both_paths(utxo_manager):
    utxo_manager.add_utxos("tx_old", [{"index": 0, "recipient": "Ali", "amount": 15}])
    tx = {
        "txid": "tx_new",
        "inputs": [{"txid": "tx_old", "index": 0}],
        "outputs": [{"index": 0, "recipient": "Veli", "amount": 15}]
    }
    utxo_manager.update_with_transaction(tx)
    assert utxo_manager.get_utxo("tx_old", 0) is None
    assert utxo_manager.get_utxo("tx_new", 0)["recipient"] == "Veli"

def test_is_utxo_owner_empty_input(utxo_manager):
    assert utxo_manager.is_utxo_owner([], "hiç_fark_etmez") is True

def test_is_utxo_owner_returns_true_when_inputs_empty(utxo_manager):
    result = utxo_manager.is_utxo_owner([], "KimOlursa")
    assert result is True

def test_update_with_transaction_full(utxo_manager):
    utxo_manager.add_utxos("oldTx", [{"index": 0, "recipient": "Mert", "amount": 20}])
    tx = {
        "txid": "newTx",
        "inputs": [{"txid": "oldTx", "index": 0}],
        "outputs": [{"index": 0, "recipient": "Derya", "amount": 20}]
    }
    utxo_manager.update_with_transaction(tx)
    assert utxo_manager.get_utxo("oldTx", 0) is None
    assert utxo_manager.get_utxo("newTx", 0)["recipient"] == "Derya"

def test_validate_input(utxo_manager):
    utxo_manager.add_utxos("valtx", [{"index": 0, "recipient": "Fatma", "amount": 99}])
    tx_input = {"txid": "valtx", "index": 0}
    assert utxo_manager.validate_input(tx_input, "Fatma") is True

def test_apply_transaction(utxo_manager):
    utxo_manager.add_utxos("txOLD", [{"index": 0, "recipient": "Esra", "amount": 80}])
    tx = {
        "txid": "txNEW",
        "inputs": [{"txid": "txOLD", "index": 0}],
        "outputs": [{"index": 0, "recipient": "Kemal", "amount": 80}]
    }
    utxo_manager.apply_transaction(tx)
    assert utxo_manager.get_utxo("txOLD", 0) is None
    assert utxo_manager.get_utxo("txNEW", 0)["recipient"] == "Kemal"

def test_is_utxo_owner_complete_pass(utxo_manager):
    utxo_manager.add_utxos("txX", [{"index": 0, "recipient": "Zehra", "amount": 55}])
    inputs = [{"txid": "txX", "index": 0}]
    assert utxo_manager.is_utxo_owner(inputs, "Zehra") is True

def test_is_utxo_owner_all_inputs_match(utxo_manager):
    utxo_manager.add_utxos("tx100", [
        {"index": 0, "recipient": "Cem", "amount": 10},
        {"index": 1, "recipient": "Cem", "amount": 20}
    ])

    inputs = [
        {"txid": "tx100", "index": 0},
        {"txid": "tx100", "index": 1}
    ]

    assert utxo_manager.get_utxo("tx100", 0)["recipient"] == "Cem"
    assert utxo_manager.get_utxo("tx100", 1)["recipient"] == "Cem"

    assert utxo_manager.is_utxo_owner(inputs, "Cem") is True

def test_trace_utxo_owner_return_path(utxo_manager):
    utxo_manager.add_utxos("debug_tx", [
        {"index": 0, "recipient": "Cem", "amount": 10},
        {"index": 1, "recipient": "Cem", "amount": 20}
    ])

    for i in range(2):
        print("DEBUG:", utxo_manager.get_utxo("debug_tx", i))

    inputs = [
        {"txid": "debug_tx", "index": 0},
        {"txid": "debug_tx", "index": 1}
    ]

    print("RESULT:", utxo_manager.is_utxo_owner(inputs, "Cem"))

def test_is_utxo_owner_final_coverage_hit(utxo_manager):
    utxo_manager.add_utxos("final_tx", [
        {"index": 0, "recipient": "Cem", "amount": 10},
        {"index": 1, "recipient": "Cem", "amount": 20}
    ])

    inputs = [
        {"txid": "final_tx", "index": 0},
        {"txid": "final_tx", "index": 1}
    ]

    assert utxo_manager.is_utxo_owner(inputs, "Cem") is True

def test_is_utxo_owner_exact_match_for_return_true(utxo_manager):
    utxo_manager.add_utxos("return_tx", [
        {"index": 0, "recipient": "TestUser", "amount": 1},
        {"index": 1, "recipient": "TestUser", "amount": 2}
    ])

    inputs = [
        {"txid": "return_tx", "index": 0},
        {"txid": "return_tx", "index": 1}
    ]

    result = utxo_manager.is_utxo_owner(inputs, "TestUser")
    assert result is True

def test_is_utxo_owner_final_true_path(utxo_manager):
    utxo_manager.add_utxos("utxox", [
        {"index": 0, "recipient": "Z", "amount": 1},
        {"index": 1, "recipient": "Z", "amount": 2}
    ])
    inputs = [{"txid": "utxox", "index": 0}, {"txid": "utxox", "index": 1}]
    assert utxo_manager.is_utxo_owner(inputs, "Z") is True

def test_return_true_hit_directly(utxo_manager):
    utxo_manager.add_utxos("return_path", [{"index": 0, "recipient": "Zeynep", "amount": 50}])
    inputs = [{"txid": "return_path", "index": 0}]
    result = utxo_manager.is_utxo_owner(inputs, "Zeynep")
    assert result is True

def test_return_true_single_input(utxo_manager):
    utxo = {"index": 0, "recipient": "Fatma", "amount": 50}
    utxo_manager.add_utxos("tx-final", [utxo])

    inputs = [{"txid": "tx-final", "index": 0}]

    result = utxo_manager.is_utxo_owner(inputs, "Fatma")
    assert result is True

