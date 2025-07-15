import pytest
from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract

@pytest.fixture
def contract():
    return BHRC20Contract("MyToken", "MTK", 1000, "alice")

def test_metadata(contract):
    meta = contract.metadata()
    assert meta["name"] == "MyToken"
    assert meta["symbol"] == "MTK"
    assert meta["total_supply"] == 1000

def test_get_abi(contract):
    abi = contract.get_abi()
    assert "methods" in abi
    assert "transfer" in abi["methods"]

def test_balance_of_existing_and_nonexisting(contract):
    assert contract.balance_of("alice") == 1000
    assert contract.balance_of("bob") == 0

def test_transfer_success(contract):
    success = contract.transfer("alice", "bob", 300)
    assert success
    assert contract.balance_of("alice") == 700
    assert contract.balance_of("bob") == 300

def test_transfer_fail_insufficient_balance(contract):
    assert not contract.transfer("bob", "alice", 50)

def test_mint_increases_total_supply(contract):
    contract.mint("bob", 200)
    assert contract.total_supply == 1200
    assert contract.balance_of("bob") == 200

def test_burn_success(contract):
    contract.transfer("alice", "bob", 200)
    success = contract.burn("bob", 100)
    assert success
    assert contract.balance_of("bob") == 100
    assert contract.total_supply == 900

def test_burn_fail(contract):
    assert not contract.burn("bob", 500)

def test_approve_and_allowance(contract):
    contract.approve("alice", "bob", 150)
    assert contract.allowance("alice", "bob") == 150

def test_allowance_without_approve(contract):
    assert contract.allowance("alice", "bob") == 0

def test_transfer_from_success(contract):
    contract.approve("alice", "bob", 100)
    success = contract.transfer_from("bob", "alice", "charlie", 100)
    assert success
    assert contract.balance_of("charlie") == 100
    assert contract.allowance("alice", "bob") == 0

def test_transfer_from_fail_insufficient_allowance(contract):
    assert not contract.transfer_from("bob", "alice", "charlie", 50)

def test_transfer_from_fail_insufficient_balance(contract):
    contract.approve("alice", "bob", 1000)
    contract.transfer("alice", "dave", 1000)  # alice balance = 0
    assert not contract.transfer_from("bob", "alice", "eve", 100)

