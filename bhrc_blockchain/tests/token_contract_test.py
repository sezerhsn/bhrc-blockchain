import os
import random
import string
import pytest
from unittest.mock import patch

from bhrc_blockchain.core.token.token_contract import TokenContract, init_token_db
from bhrc_blockchain.core.wallet.wallet import MinerWallet

def unique_symbol():
    return "SYM" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

@pytest.fixture(autouse=True)
def clear_token_db():
    if os.path.exists("bhrc_token.db"):
        os.remove("bhrc_token.db")

def test_token_validation():
    valid_token = TokenContract("TokenName", "ABC", 2, 1000, "creator")
    invalid_token = TokenContract("TokenName", "abc", 2, 1000, "creator")
    assert valid_token.validate() is True
    assert invalid_token.validate() is False

def test_token_deploy_and_get():
    wallet = MinerWallet()
    symbol = unique_symbol()
    token = TokenContract(name="Test", symbol=symbol, decimals=0, total_supply=500, creator=wallet.address)

    with patch("bhrc_blockchain.core.wallet.wallet.verify_address_from_key", return_value=True):
        result = token.deploy(sender_private_key=wallet.private_key)

    assert result["sender"] == wallet.address
    assert result["recipient"] == "TOKEN_CONTRACT"
    assert TokenContract.balance_of(wallet.address, symbol) == 500

    fetched = TokenContract.get(symbol)
    assert fetched.name == token.name
    assert fetched.symbol == token.symbol

def test_token_transfer_success():
    wallet = MinerWallet()
    addr1 = wallet.address
    addr2 = "xBHR" + "B" * 60
    symbol = unique_symbol()
    token = TokenContract(name="MyToken", symbol=symbol, decimals=0, total_supply=1000, creator=addr1)

    with patch("bhrc_blockchain.core.wallet.wallet.verify_address_from_key", return_value=True):
        token.deploy(sender_private_key=wallet.private_key)
        result = TokenContract.transfer(
            symbol=symbol,
            from_addr=addr1,
            to_addr=addr2,
            amount=200,
            sender_private_key=wallet.private_key
        )
        assert isinstance(result, dict) and "txid" in result
        assert TokenContract.balance_of(addr1, symbol) == 800
        assert TokenContract.balance_of(addr2, symbol) == 200

def test_token_transfer_insufficient_balance():
    wallet = MinerWallet()
    addr1 = wallet.address
    addr2 = "xBHR" + "Z" * 60
    symbol = unique_symbol()
    token = TokenContract(name="FailToken", symbol=symbol, decimals=0, total_supply=50, creator=addr1)

    with patch("bhrc_blockchain.core.wallet.wallet.verify_address_from_key", return_value=True):
        token.deploy(sender_private_key=wallet.private_key)

        with pytest.raises(ValueError, match="Yetersiz token bakiyesi."):
            TokenContract.transfer(
                symbol=symbol,
                from_addr=addr1,
                to_addr=addr2,
                amount=100,
                sender_private_key=wallet.private_key
            )

def test_token_deploy_invalid_creator():
    wallet = MinerWallet()
    other_address = "xBHR" + "0" * 60  # Uyuşmayan adres
    symbol = unique_symbol()
    token = TokenContract(name="ErrToken", symbol=symbol, decimals=0, total_supply=1000, creator=other_address)

    with pytest.raises(ValueError, match="yaratıcısı uyuşmuyor"):
        token.deploy(sender_private_key=wallet.private_key)

def test_get_nonexistent_token():
    init_token_db()  # tablo yok hatasını önler
    with pytest.raises(ValueError, match="Token bulunamadı"):
        TokenContract.get("YOK123")
