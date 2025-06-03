import os
import uuid
import pytest
from bhrc_blockchain.database import nft_storage

TEST_DB = "test_nft.db"

@pytest.fixture(autouse=True)
def setup_and_cleanup(monkeypatch):
    monkeypatch.setattr(nft_storage, "NFT_DB_PATH", TEST_DB)
    nft_storage.init_nft_db()
    yield
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

def test_mint_and_get_all_nfts():
    nft_id = str(uuid.uuid4())
    nft_storage.mint_nft(
        nft_id=nft_id,
        owner="user123",
        name="Test NFT",
        description="Bu bir test NFT'sidir.",
        uri="https://example.com/test.png"
    )

    all_nfts = nft_storage.get_all_nfts()
    assert isinstance(all_nfts, list)
    assert any(nft["id"] == nft_id for nft in all_nfts)

def test_get_nfts_by_owner():
    owner = "owner456"
    nft_id = str(uuid.uuid4())
    nft_storage.mint_nft(
        nft_id=nft_id,
        owner=owner,
        name="Owner NFT",
        description="Özel NFT",
        uri="https://example.com/owner.png"
    )

    nfts = nft_storage.get_nfts_by_owner(owner)
    assert isinstance(nfts, list)
    assert any(nft["id"] == nft_id for nft in nfts)

