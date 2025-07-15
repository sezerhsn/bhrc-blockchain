import pytest
from bhrc_blockchain.core.contract.bhrc721 import BHRC721Contract

@pytest.fixture
def contract():
    return BHRC721Contract("NFTee", "NFT")

def test_metadata(contract):
    meta = contract.metadata()
    assert meta["name"] == "NFTee"
    assert meta["symbol"] == "NFT"
    assert meta["total_supply"] == 0

def test_get_abi(contract):
    abi = contract.get_abi()
    assert "mint" in abi["methods"]
    assert abi["name"] == "NFTee"

def test_mint_success(contract):
    result = contract.mint(1, "alice", {"rarity": "legendary"})
    assert result is True
    assert contract.owner_of(1) == "alice"

def test_mint_duplicate_fails(contract):
    contract.mint(1, "alice")
    result = contract.mint(1, "bob")
    assert result is False
    assert contract.owner_of(1) == "alice"

def test_owner_of_missing_token(contract):
    assert contract.owner_of(999) is None

def test_transfer_success(contract):
    contract.mint(1, "alice")
    result = contract.transfer(1, "alice", "bob")
    assert result is True
    assert contract.owner_of(1) == "bob"

def test_transfer_fail_wrong_owner(contract):
    contract.mint(1, "alice")
    result = contract.transfer(1, "charlie", "dave")
    assert result is False
    assert contract.owner_of(1) == "alice"

def test_burn_success(contract):
    contract.mint(1, "alice")
    result = contract.burn(1)
    assert result is True
    assert contract.owner_of(1) is None
    assert contract.metadata()["total_supply"] == 0

def test_burn_fail_missing_token(contract):
    assert contract.burn(1234) is False

