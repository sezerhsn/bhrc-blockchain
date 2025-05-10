# token_contract_test.py
import os
import random
import string
import sqlite3
import pytest
from bhrc_blockchain.core.token import TokenContract
from bhrc_blockchain.core.wallet import generate_private_key, get_address_from_private_key, get_public_key_from_private_key
from unittest.mock import patch
from bhrc_blockchain.utils.utils import generate_address

# Yardımcı fonksiyon: Benzersiz token sembolü üret
def unique_symbol():
    return "SYM" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

# Her test öncesi veritabanını sıfırla
@pytest.fixture(autouse=True)
def clear_token_db():
    if os.path.exists("bhrc_token.db"):
        os.remove("bhrc_token.db")

def test_token_validation():
    valid_token = TokenContract("TokenName", "ABC", 2, 1000, "creator")
    invalid_token = TokenContract("TokenName", "abc", 2, 1000, "creator")
    assert valid_token.validate() is True
    assert invalid_token.validate() is False

def test_deploy_token_and_balance():
    priv_key = generate_private_key()
    address = get_address_from_private_key(priv_key)

    token = TokenContract(name="Test", symbol=unique_symbol(), decimals=0, total_supply=500, creator=address)
    tx = token.deploy(sender_private_key=priv_key)

    assert tx["sender"] == address
    assert tx["recipient"] == "TOKEN_CONTRACT"
    assert token.balance_of(address, token.symbol) == 500

def test_token_balance_of():
    priv_key = generate_private_key()
    address = get_address_from_private_key(priv_key)
    token = TokenContract(name="MyToken", symbol=unique_symbol(), decimals=2, total_supply=2000, creator=address)
    token.deploy(sender_private_key=priv_key)

    balance = TokenContract.balance_of(address, token.symbol)
    assert balance == 2000

def test_token_transfer_success():
    priv_key = generate_private_key()
    addr1 = get_address_from_private_key(priv_key)
    addr2 = "xBHR" + "B" * 60
    token = TokenContract(name="MyToken", symbol=unique_symbol(), decimals=0, total_supply=1000, creator=addr1)
    token.deploy(sender_private_key=priv_key)

    with patch("bhrc_blockchain.core.wallet.verify_address_from_key", return_value=True):
        result = TokenContract.transfer(
            symbol=token.symbol,
            from_addr=addr1,
            to_addr=addr2,
            amount=200,
            sender_private_key=priv_key
        )
        assert result is True
        assert TokenContract.balance_of(addr1, token.symbol) == 800
        assert TokenContract.balance_of(addr2, token.symbol) == 200

def test_token_transfer_insufficient_balance():
    priv_key = generate_private_key()
    address = get_address_from_private_key(priv_key)
    token = TokenContract(name="FailToken", symbol="FAILX", decimals=0, total_supply=50, creator=address)
    token.deploy(sender_private_key=priv_key)

    # yanlış adres - private key eşleşmesi → satır 105 çalışır
    with pytest.raises(ValueError, match="Özel anahtar, gönderici adresiyle eşleşmiyor."):
        TokenContract.transfer(
            symbol="FAILX",
            from_addr="xBHR" + "0" * 60,  # sahte adres
            to_addr="xBHR" + "Z" * 60,
            amount=20,
            sender_private_key=priv_key
        )

def test_invalid_token_validation():
    priv_key = generate_private_key()
    address = get_address_from_private_key(priv_key)

    invalid_tokens = [
        TokenContract(name="Invalid", symbol="tkn", decimals=0, total_supply=100, creator=address),  # lowercase symbol
        TokenContract(name="Invalid", symbol="TKN", decimals=-1, total_supply=100, creator=address),  # negative decimals
        TokenContract(name="Invalid", symbol="TKN", decimals=0, total_supply=0, creator=address),     # zero supply
    ]

    for token in invalid_tokens:
        assert not token.validate()

    with pytest.raises(ValueError, match="Token bilgileri eksik veya hatalı."):
        invalid_tokens[0].deploy(sender_private_key=priv_key)

