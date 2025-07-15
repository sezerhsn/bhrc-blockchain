import os
import pytest
from bhrc_blockchain.database import dao_storage

TEST_DB = "test_dao.db"

@pytest.fixture(autouse=True)
def clean_test_db(monkeypatch):
    monkeypatch.setattr(dao_storage, "DB_PATH", TEST_DB)

    dao_storage.init_dao_db()
    yield
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
    dao_storage.add_proposal(
        title="Oylama",
        description="Oylama açıklaması",
        creator="admin",
        symbol="BHRC",
        options=["A", "B"]
    )
    proposal_id = dao_storage.list_proposals()[0]["id"]

    dao_storage.cast_vote(proposal_id, "user1", "A", 3.0)
    dao_storage.cast_vote(proposal_id, "user2", "B", 1.5)
    dao_storage.cast_vote(proposal_id, "user3", "A", 2.5)

    results = dao_storage.get_results(proposal_id)
    assert results["A"] == 5.5
    assert results["B"] == 1.5

def test_close_proposal():
    dao_storage.add_proposal(
        title="Kapatılacak Öneri",
        description="Oylama bitecek",
        creator="admin",
        symbol="BHRC",
        options=["Evet", "Hayır"]
    )
    proposal_id = dao_storage.list_proposals()[0]["id"]
    dao_storage.close_proposal(proposal_id)
    proposal = dao_storage.get_proposal_by_id(proposal_id)
    assert proposal["status"] == "closed"

def test_delete_proposal():
    dao_storage.add_proposal(
        title="Silinecek Öneri",
        description="Geçici oylama",
        creator="user1",
        symbol="BHRC",
        options=["X", "Y"]
    )
    proposal_id = dao_storage.list_proposals()[0]["id"]
    dao_storage.cast_vote(proposal_id, "user1", "X", 1.0)
    dao_storage.delete_proposal(proposal_id)

    proposal = dao_storage.get_proposal_by_id(proposal_id)
    assert proposal == {}

    results = dao_storage.get_results(proposal_id)
    assert results == {}

def test_list_open_proposals():
    dao_storage.add_proposal(
        title="Açık Öneri",
        description="Açık",
        creator="a",
        symbol="BHRC",
        options=["1", "2"]
    )
    dao_storage.add_proposal(
        title="Kapalı Öneri",
        description="Kapandı",
        creator="b",
        symbol="BHRC",
        options=["X", "Y"]
    )
    all_proposals = dao_storage.list_proposals()
    second_id = all_proposals[0]["id"] if all_proposals[0]["title"] == "Kapalı Öneri" else all_proposals[1]["id"]
    dao_storage.close_proposal(second_id)

    open_proposals = dao_storage.list_open_proposals()
    assert all(p["status"] == "open" for p in open_proposals)
    assert any(p["title"] == "Açık Öneri" for p in open_proposals)
    assert all(p["title"] != "Kapalı Öneri" for p in open_proposals)

def test_list_closed_proposals():
    dao_storage.add_proposal(
        title="Kapalı Test Öneri",
        description="Kapanmış",
        creator="user",
        symbol="BHRC",
        options=["1", "2"]
    )
    pid = dao_storage.list_proposals()[0]["id"]
    dao_storage.close_proposal(pid)
    closed = dao_storage.list_closed_proposals()
    assert any(p["title"] == "Kapalı Test Öneri" for p in closed)
    assert all(p["status"] == "closed" for p in closed)

def test_get_votes_for_proposal():
    dao_storage.add_proposal(
        title="Oylu Öneri",
        description="Oylama yapıldı",
        creator="voterX",
        symbol="BHRC",
        options=["A", "B"]
    )
    pid = dao_storage.list_proposals()[0]["id"]
    dao_storage.cast_vote(pid, "v1", "A", 1.0)
    dao_storage.cast_vote(pid, "v2", "B", 2.0)
    votes = dao_storage.get_votes_for_proposal(pid)
    assert len(votes) == 2
    assert any(v["voter"] == "v1" for v in votes)
    assert any(v["option"] == "B" for v in votes)

def test_get_closed_proposals_via_class():
    dao = dao_storage.DAOStorage()
    dao_storage.add_proposal(
        title="Kapanacak",
        description="Test",
        creator="x",
        symbol="BHRC",
        options=["1", "2"]
    )
    pid = dao.get_all_tokens()[0]["id"]
    dao.close(pid)
    closed = dao.get_closed_proposals()
    assert all(p["status"] == "closed" for p in closed)

def test_get_votes_via_class():
    dao = dao_storage.DAOStorage()
    dao_storage.add_proposal(
        title="Oylu",
        description="Test",
        creator="x",
        symbol="BHRC",
        options=["A", "B"]
    )
    pid = dao.get_all_tokens()[0]["id"]
    dao.add_vote(pid, "voter1", "A", 3.0)
    votes = dao.get_votes(pid)
    assert len(votes) == 1
    assert votes[0]["voter"] == "voter1"

def test_add_vote_via_class():
    dao = dao_storage.DAOStorage()
    dao_storage.add_proposal(
        title="Sınıf Üzerinden Oy",
        description="Wrapper test",
        creator="x",
        symbol="BHRC",
        options=["X", "Y"]
    )
    pid = dao.get_all_tokens()[0]["id"]
    dao.add_vote(pid, "wraptest", "X", 2.0)
    result = dao_storage.get_results(pid)
    assert result["X"] == 2.0

def test_get_proposal_by_id_returns_empty_if_not_found():
    result = dao_storage.get_proposal_by_id(9999)
    assert result == {}

def test_get_votes_for_nonexistent_proposal():
    votes = dao_storage.get_votes_for_proposal(9999)
    assert votes == []

def test_close_proposal_on_invalid_id_does_not_crash():
    try:
        dao_storage.close_proposal(9999)
    except Exception:
        pytest.fail("Boş ID'de close_proposal() hata vermemeli")

def test_delete_proposal_on_invalid_id_does_not_crash():
    try:
        dao_storage.delete_proposal(9999)
    except Exception:
        pytest.fail("Boş ID'de delete_proposal() hata vermemeli")

def test_get_proposal_class_method_empty_result():
    dao = dao_storage.DAOStorage()
    result = dao.get_proposal(99999)
    assert result == {}

def test_get_votes_returns_empty_list_if_no_votes():
    dao_storage.add_proposal(
        title="Boş Oy Testi",
        description="Henüz oy verilmedi",
        creator="user",
        symbol="BHRC",
        options=["A", "B"]
    )
    pid = dao_storage.list_proposals()[0]["id"]
    votes = dao_storage.get_votes_for_proposal(pid)
    assert votes == []

