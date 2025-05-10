# utils_test.py
from bhrc_blockchain.utils.utils import get_readable_time, get_random_quote, generate_address
import time

def test_get_readable_time_with_timestamp():
    ts = 1700000000  # örnek timestamp
    result = get_readable_time(ts)
    assert isinstance(result, str)
    assert "20" in result or "202" in result  # yıl bilgisi kontrolü gibi

def test_get_readable_time_without_timestamp():
    result = get_readable_time()
    assert isinstance(result, str)
    assert len(result) >= 16  # 'dd-mm-yyyy hh:mm' formatı

def test_get_random_quote_returns_valid_quote():
    quote = get_random_quote()
    assert quote in [
        "Coin'ler geçer, kod kalır.",
        "Blockchain, güvenin yeni adıdır.",
        "Gelecek, kodla yazılmıştır.",
        "Her blok bir hikayedir.",
        "Gerçek özgürlük, merkeziyetsizliktir.",
        "Rastgelelik, evrenin temel yasasıdır.",
    ]

def test_generate_address_returns_prefixed_hash():
    public_key = "MyDummyPublicKey1234567890"
    address = generate_address(public_key)
    assert address.startswith("xBHR")
    assert len(address) == 64
