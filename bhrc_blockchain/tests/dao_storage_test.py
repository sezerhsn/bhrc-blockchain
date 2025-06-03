import os
import pytest
from bhrc_blockchain.database import dao_storage

TEST_DB = "test_dao.db"

@pytest.fixture(autouse=True)
def clean_test_db(monkeypatch):
    # Test boyunca kullanılacak veritabanını değiştir
    monkeypatch.setattr(dao_storage, "DB_PATH", TEST_DB)

    # DB'yi oluştur
    dao_storage.init_dao_db()
    yield
    # Testten sonra dosyayı sil
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

def test_add_and_list_proposals():
    dao_storage.add_proposal(
        title="Test Öneri",
        description="Bu bir testtir.",
        creator="admin",
        symbol="BHRC",
        options=["Evet", "Hayır"]
    )

    proposals = dao_storage.list_proposals()
    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal["title"] == "Test Öneri"
    assert "Evet" in proposal["options"]

def test_cast_vote_and_get_results():
    # Öneri oluştur
    dao_storage.add_proposal(
        title="Oylama",
        description="Oylama açıklaması",
        creator="admin",
        symbol="BHRC",
        options=["A", "B"]
    )
    proposal_id = dao_storage.list_proposals()[0]["id"]

    # Oy kullan
    dao_storage.cast_vote(proposal_id, "user1", "A", 3.0)
    dao_storage.cast_vote(proposal_id, "user2", "B", 1.5)
    dao_storage.cast_vote(proposal_id, "user3", "A", 2.5)

    results = dao_storage.get_results(proposal_id)
    assert results["A"] == 5.5
    assert results["B"] == 1.5

