import os
import pytest
from bhrc_blockchain.core.state.state_manager import StateManager

TEST_STATE_FILE = "test_state.json"

@pytest.fixture
def state():
    # Testten önce dosya varsa sil
    if os.path.exists(TEST_STATE_FILE):
        os.remove(TEST_STATE_FILE)
    sm = StateManager(TEST_STATE_FILE)
    yield sm
    # Testten sonra dosya temizliği
    if os.path.exists(TEST_STATE_FILE):
        os.remove(TEST_STATE_FILE)

def test_init_genesis_state(state):
    state.init_genesis_state("wallet1", 100.0)
    assert state.get_balance("wallet1") == 100.0

def test_apply_single_transaction(state):
    state.init_genesis_state("wallet1", 100.0)
    tx = {
        "sender": "wallet1",
        "recipient": "wallet2",
        "amount": 30
    }
    state.apply_transactions([tx])
    assert state.get_balance("wallet1") == 70
    assert state.get_balance("wallet2") == 30

def test_apply_multiple_transactions(state):
    state.init_genesis_state("wallet1", 100.0)
    txs = [
        {"sender": "wallet1", "recipient": "wallet2", "amount": 30},
        {"sender": "wallet2", "recipient": "wallet3", "amount": 10},
        {"sender": "wallet1", "recipient": "wallet3", "amount": 20}
    ]
    state.apply_transactions(txs)
    assert state.get_balance("wallet1") == 50
    assert state.get_balance("wallet2") == 20
    assert state.get_balance("wallet3") == 30

def test_coinbase_transaction(state):
    tx = {
        "sender": "SYSTEM",
        "recipient": "miner123",
        "amount": 50,
        "type": "coinbase"
    }
    state.apply_transactions([tx])
    assert state.get_balance("miner123") == 50

