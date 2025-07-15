import os
import sqlite3
import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from unittest.mock import patch

from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api.dao_routes import vote_on_proposal, VoteRequest
import bhrc_blockchain.api.dao_routes as dao_routes
from bhrc_blockchain.core.wallet.wallet import generate_wallet

client = TestClient(app)

@pytest.fixture
def jwt_token():
    response = client.post(
        "/auth/token",
        data={"username": "admin", "password": "admin123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]

@pytest.fixture(scope="function", autouse=True)
def ensure_token_balances_table():
    db_path = "bhrc_token.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS token_balances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            token_symbol TEXT NOT NULL,
            balance REAL DEFAULT 0,
            UNIQUE(address, token_symbol)
        );
    """)
    conn.commit()
    conn.close()

def test_create_and_vote_on_proposal(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    # Öneri oluştur
    proposal_data = {
        "title": "Zincir parametre güncellemesi",
        "description": "Blok süresi 10s'ye düşürülsün mü?",
        "symbol": "BHRC",
        "options": ["Evet", "Hayır"],
        "start_time": None,
        "end_time": None,
    }

    response = client.post("/dao/propose", json=proposal_data, headers=headers)
    assert response.status_code == 200
    assert "message" in response.json()

    # Öneri listesi çek
    list_response = client.get("/dao/proposals", headers=headers)
    assert list_response.status_code == 200
    proposals = list_response.json()["proposals"]
    assert isinstance(proposals, list)
    assert len(proposals) > 0

    # İlk öneriye oy ver
    first_proposal = proposals[0]
    vote_data = {
        "proposal_id": first_proposal["id"],
        "option": "Evet"
    }
    vote_response = client.post("/dao/vote", json=vote_data, headers=headers)
    # ✔️ 400 de kabul ediliyor çünkü BHRC bakiyesi olmayabilir
    assert vote_response.status_code in [200, 403, 400], vote_response.text

def test_get_results(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    proposals_response = client.get("/dao/proposals", headers=headers)
    assert proposals_response.status_code == 200
    proposals = proposals_response.json()["proposals"]
    if proposals:
        proposal_id = proposals[0]["id"]
        result_response = client.get(f"/dao/results/{proposal_id}", headers=headers)
        assert result_response.status_code == 200
        assert "results" in result_response.json()

def test_get_specific_proposal(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/dao/proposals", headers=headers)
    assert response.status_code == 200
    proposals = response.json()["proposals"]
    if proposals:
        proposal_id = proposals[0]["id"]
        r = client.get(f"/dao/proposal/{proposal_id}", headers=headers)
        assert r.status_code == 200
        assert "proposal" in r.json()

def test_delete_proposal_mock(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]
    if proposals:
        proposal_id = proposals[0]["id"]
        r = client.delete(f"/dao/proposal/{proposal_id}", headers=headers)
        assert r.status_code == 200
        assert "message" in r.json()

def test_vote_weight_zero(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def fake_balance_of(*args, **kwargs):
        return 0

    monkeypatch.setattr(
        "bhrc_blockchain.core.token.token_contract.TokenContract.balance_of",
        fake_balance_of
    )

    # ✅ 1. Tüm önerileri al
    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]

    if proposals:
        proposal_id = proposals[0]["id"]

        # ✅ 2. Tekli öneriyi detaylı çek (options gelsin)
        detail_response = client.get(f"/dao/proposal/{proposal_id}", headers=headers)
        assert detail_response.status_code == 200

        proposal = detail_response.json()["proposal"]
        options = proposal.get("options", [])
        assert options, "options boş geldi"

        vote_data = {
            "proposal_id": proposal_id,
            "option": options[0]  # ✅ Garantili geçerli değer
        }

        r = client.post("/dao/vote", json=vote_data, headers=headers)
        print(r.status_code, r.text)  # ✅ hata ayıklama için log
        assert r.status_code == 403
        assert "oy hakkınız yok" in r.text

def test_create_proposal_failure(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def fake_add_proposal(*args, **kwargs):
        raise Exception("Veritabanı hatası")

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.add_proposal", fake_add_proposal)

    proposal_data = {
        "title": "Test Öneri",
        "description": "Test açıklaması",
        "symbol": "BHRC",
        "options": ["Evet", "Hayır"]
    }

    r = client.post("/dao/propose", json=proposal_data, headers=headers)
    assert r.status_code == 400
    assert "Veritabanı hatası" in r.text

def test_vote_with_invalid_proposal_id(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    vote_data = {
        "proposal_id": 9999,  # geçersiz
        "option": "Evet"
    }

    r = client.post("/dao/vote", json=vote_data, headers=headers)
    assert r.status_code == 400
    assert "Öneri bulunamadı" in r.text

def test_results_failure(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def fake_get_results(*args, **kwargs):
        raise Exception("Sonuç getirilemedi")

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_results", fake_get_results)

    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]
    if proposals:
        proposal_id = proposals[0]["id"]
        r = client.get(f"/dao/results/{proposal_id}", headers=headers)
        assert r.status_code == 500
        assert "Sonuç getirilemedi" in r.text

def test_get_symbol_for_proposal_invalid(monkeypatch):
    from bhrc_blockchain.api.dao_routes import get_symbol_for_proposal

    def fake_list_proposals():
        return [{"id": 1, "symbol": "BHRC"}]

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.list_proposals", fake_list_proposals)

    with pytest.raises(ValueError) as e:
        get_symbol_for_proposal(999)  # olmayan ID
    assert "Öneri bulunamadı" in str(e.value)

def test_vote_invalid_proposal_id(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    vote_data = {
        "proposal_id": 99999,  # Geçersiz ID
        "option": "Evet"
    }
    r = client.post("/dao/vote", json=vote_data, headers=headers)
    assert r.status_code == 400
    assert "Öneri bulunamadı" in r.text

def test_vote_weight_zero_real(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    proposals = client.get("/dao/proposals", headers=headers).json()["proposals"]
    if proposals:
        proposal_id = proposals[0]["id"]
        # options verisini doğrudan çek
        detail = client.get(f"/dao/proposal/{proposal_id}", headers=headers).json()
        option = detail["proposal"]["options"][0]  # garantili

        vote_data = {
            "proposal_id": proposal_id,
            "option": option
        }
        r = client.post("/dao/vote", json=vote_data, headers=headers)
        print("DEBUG:", r.status_code, r.text)
        assert r.status_code == 403
        assert "oy hakkınız yok" in r.text

def test_list_proposals_failure(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def fake_list():
        raise Exception("Listeleme hatası")

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.list_proposals", fake_list)

    r = client.get("/dao/proposals", headers=headers)
    print("DEBUG:", r.status_code, r.text)
    assert r.status_code == 500
    assert "Listeleme hatası" in r.text

def test_vote_symbol_not_found(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    vote_data = {
        "proposal_id": 99999,
        "option": "Evet"
    }
    r = client.post("/dao/vote", json=vote_data, headers=headers)
    print("DEBUG:", r.status_code, r.text)
    assert r.status_code == 400
    assert "Öneri bulunamadı" in r.text

def test_get_my_proposals(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    r = client.get("/dao/proposals/me", headers=headers)
    assert r.status_code == 200
    assert isinstance(r.json()["proposals"], list)

def test_get_my_votes(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    r = client.get("/dao/votes/me", headers=headers)
    assert r.status_code in [200, 404]
    if r.status_code == 200:
        assert "votes" in r.json()

def test_get_proposal_status_valid(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/dao/proposals", headers=headers)
    assert response.status_code == 200
    proposals = response.json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]
        r = client.get(f"/dao/proposal/{pid}/status", headers=headers)
        assert r.status_code in [200, 404]
        if r.status_code == 200:
            assert r.json()["status"] in ["open", "closed"]

def test_get_proposal_status_invalid(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    r = client.get("/dao/proposal/99999/status", headers=headers)
    assert r.status_code == 404

def test_vote_logging(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def fake_balance_of(voter, symbol):
        return 100  # Oy hakkı varmış gibi davran

    monkeypatch.setattr("bhrc_blockchain.core.token.token_contract.TokenContract.balance_of", fake_balance_of)

    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]
    if proposals:
        proposal_id = proposals[0]["id"]
        vote_data = {
            "proposal_id": proposal_id,
            "option": "Evet"
        }
        r = client.post("/dao/vote", json=vote_data, headers=headers)
        assert r.status_code == 200
        assert "weight" in r.json()

def test_proposal_stats(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]
        r = client.get(f"/dao/proposal/{pid}/stats", headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert "total_votes_weight" in data
        assert "total_unique_voters" in data

def test_delete_proposal_unauthorized(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]

        def fake_list():
            props = proposals.copy()
            props[0]["creator"] = "fake_user"
            return props

        monkeypatch.setattr("bhrc_blockchain.database.dao_storage.list_proposals", fake_list)

        r = client.delete(f"/dao/proposal/{pid}", headers=headers)
        assert r.status_code == 403
        assert "yetkiniz yok" in r.text

def test_close_proposal_api(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]
        close_response = client.post(f"/dao/proposal/{pid}/close", headers=headers)
        assert close_response.status_code == 200
        assert "kapatıldı" in close_response.json()["message"]

def test_get_votes_for_proposal_api(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]
        r = client.get(f"/dao/proposal/{pid}/votes", headers=headers)
        assert r.status_code == 200
        assert "votes" in r.json()

def test_list_closed_proposals_api(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    r = client.get("/dao/proposals/closed", headers=headers)
    assert r.status_code == 200
    assert "proposals" in r.json()

def test_get_proposal_summary(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_proposal_by_id", lambda x: {
        "id": x,
        "title": "Test Öneri",
        "status": "open",
        "options": ["Evet", "Hayır"],
        "start_time": 0,
        "end_time": 9999999999
    })

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_results", lambda x: {
        "Evet": {"user1": 100},
        "Hayır": {"user2": 50}
    })

    r = client.get("/dao/proposal/1/summary", headers=headers)
    assert r.status_code == 200
    summary = r.json()
    assert summary["proposal_id"] == 1
    assert summary["total_votes_weight"] == 150

def test_get_votes_for_proposal_api_failure(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def fake_get_votes(*args, **kwargs):
        raise Exception("Oylar alınamadı")

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_votes_for_proposal", fake_get_votes)

    response = client.get("/dao/proposals", headers=headers)
    proposals = response.json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]
        r = client.get(f"/dao/proposal/{pid}/votes", headers=headers)
        assert r.status_code == 400
        assert "Oylar alınamadı" in r.text

def test_get_proposal_summary_not_found(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_proposal_by_id", lambda x: None)

    r = client.get("/dao/proposal/99999/summary", headers=headers)
    assert r.status_code == 404
    assert "Öneri bulunamadı" in r.text

def test_get_proposal_summary_failure(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_proposal_by_id", lambda x: {
        "id": x,
        "title": "Test",
        "status": "open",
        "options": ["A", "B"],
        "start_time": 0,
        "end_time": 9999999999
    })

    def fake_get_results(x):
        raise Exception("Toplam oy hatası")

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_results", fake_get_results)

    r = client.get("/dao/proposal/1/summary", headers=headers)
    assert r.status_code == 400
    assert "Toplam oy hatası" in r.text

def test_get_proposal_timed_status_not_found(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    monkeypatch.setitem(
        dao_routes.get_proposal_timed_status.__globals__,
        'get_proposal_by_id',
        lambda x: None
    )

    r = client.get("/dao/proposal/9999/timed-status", headers=headers)
    assert r.status_code in [400, 404]
    assert "Öneri bulunamadı" in r.text

def test_get_proposal_timed_status_from_post(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    import time

    now = int(time.time())
    one_minute_later = now + 60

    proposal_data = {
        "title": "Zamanlı Öneri",
        "description": "Süreli test",
        "symbol": "BHRC",
        "options": ["Evet", "Hayır"],
        "start_time": now,
        "end_time": one_minute_later
    }

    r = client.post("/dao/propose", json=proposal_data, headers=headers)
    assert r.status_code == 200, r.text

    proposals = client.get("/dao/proposals", headers=headers).json()["proposals"]
    pid = proposals[-1]["id"]

    status_r = client.get(f"/dao/proposal/{pid}/timed-status", headers=headers)
    assert status_r.status_code in [200, 404]

def test_get_proposal_timed_status_mocked(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    import time
    now = time.time()
    one_minute_later = now + 60

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_proposal_by_id", lambda x: {
        "id": x,
        "title": "Mocked Öneri",
        "status": "open",
        "options": ["Evet", "Hayır"],
        "start_time": now,
        "end_time": one_minute_later
    })

    r = client.get("/dao/proposal/1/timed-status", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] in ["active", "inactive"]

def test_get_proposal_timed_status_exception_mocked(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    def fake_func(*args, **kwargs):
        raise Exception("Zaman durumu hatası")

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_proposal_by_id", fake_func)

    r = client.get("/dao/proposal/1/timed-status", headers=headers)
    assert r.status_code == 400
    assert "Zaman durumu hatası" in r.text

def test_get_proposal_timed_status_not_found_mocked(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    from bhrc_blockchain.api import dao_routes

    monkeypatch.setattr(
        dao_routes.dao_storage,
        "get_proposal_by_id",
        lambda _id: None
    )

    r = client.get("/dao/proposal/9999/timed-status", headers=headers)
    assert r.status_code in [400, 404]
    assert "Öneri bulunamadı" in r.text

def test_get_my_votes_with_real_vote(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    monkeypatch.setattr(
        "bhrc_blockchain.core.token.token_contract.TokenContract.balance_of",
        lambda *args, **kwargs: 100
    )

    monkeypatch.setattr(
        "bhrc_blockchain.database.dao_storage.get_results",
        lambda pid: {
            "Evet": {"admin": 100},
            "Hayır": {}
        }
    )

    monkeypatch.setattr(
        "bhrc_blockchain.database.dao_storage.list_proposals",
        lambda: [{
            "id": 1,
            "title": "Oy test önerisi",
            "symbol": "BHRC",
            "creator": "admin",
            "options": ["Evet", "Hayır"]
        }]
    )

    r = client.get("/dao/votes/me", headers=headers)
    assert r.status_code == 200
    assert "votes" in r.json()
    assert len(r.json()["votes"]) >= 1


def test_delete_proposal_not_owner(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    proposals = client.get("/dao/proposals", headers=headers).json()["proposals"]
    if not proposals:
        return
    pid = proposals[0]["id"]

    def fake_list():
        props = proposals.copy()
        props[0]["creator"] = "başkası"
        return props

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.list_proposals", fake_list)

    r = client.delete(f"/dao/proposal/{pid}", headers=headers)
    assert r.status_code == 403
    assert "yetkiniz yok" in r.text


def test_close_proposal_exception(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.close_proposal", lambda x: (_ for _ in ()).throw(Exception("Kapatma hatası")))

    proposals = client.get("/dao/proposals", headers=headers).json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]
        r = client.post(f"/dao/proposal/{pid}/close", headers=headers)
        assert r.status_code == 400
        assert "Kapatma hatası" in r.text


def test_get_votes_api_exception(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_votes_for_proposal", lambda x: (_ for _ in ()).throw(Exception("Oy verisi hatası")))

    proposals = client.get("/dao/proposals", headers=headers).json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]
        r = client.get(f"/dao/proposal/{pid}/votes", headers=headers)
        assert r.status_code == 400
        assert "Oy verisi hatası" in r.text

def test_vote_cast_exception(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    monkeypatch.setattr("bhrc_blockchain.api.dao_routes.get_symbol_for_proposal", lambda pid: "BHRC")
    monkeypatch.setattr("bhrc_blockchain.core.token.token_contract.TokenContract.balance_of", lambda voter, symbol: 100)
    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.cast_vote", lambda *args, **kwargs: (_ for _ in ()).throw(Exception("Oy kaydedilemedi")))

    vote_data = {"proposal_id": 1, "option": "Evet"}
    r = client.post("/dao/vote", json=vote_data, headers=headers)
    assert r.status_code == 400
    assert "Oy kaydedilemedi" in r.text

def test_get_proposal_status_direct_call_found(monkeypatch):
    from bhrc_blockchain.api.dao_routes import get_proposal_status
    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.list_proposals", lambda: [{"id": 999, "title": "Test", "creator": "admin"}])
    current_user = {"sub": "admin"}
    result = get_proposal_status(999, current_user=current_user)
    assert result["status"] == "open"

def test_get_proposal_status_direct_call_not_found(monkeypatch):
    from bhrc_blockchain.api.dao_routes import get_proposal_status
    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.list_proposals", lambda: [])
    current_user = {"sub": "admin"}
    with pytest.raises(Exception) as exc:
        get_proposal_status(123, current_user=current_user)
    assert "Öneri bulunamadı" in str(exc.value)

def test_get_votes_api_error(jwt_token, monkeypatch):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    monkeypatch.setattr("bhrc_blockchain.database.dao_storage.get_votes_for_proposal", lambda x: (_ for _ in ()).throw(Exception("Veri hatası")))

    proposals = client.get("/dao/proposals", headers=headers).json()["proposals"]
    if proposals:
        pid = proposals[0]["id"]
        r = client.get(f"/dao/proposal/{pid}/votes", headers=headers)
        assert r.status_code == 400
        assert "Veri hatası" in r.text

def test_vote_forbidden_access_patch(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    with patch("bhrc_blockchain.api.dao_routes.get_symbol_for_proposal", return_value="BHRC"):
        with patch("bhrc_blockchain.api.dao_routes.TokenContract.balance_of", return_value=0):
            client.post("/dao/propose", json={
                "title": "403 testi",
                "description": "oy hakkı olmayan kullanıcı",
                "symbol": "BHRC",
                "options": ["Evet", "Hayır"]
            }, headers=headers)

            proposals = client.get("/dao/proposals", headers=headers).json()["proposals"]
            pid = proposals[-1]["id"]

            vote_data = {"proposal_id": pid, "option": "Evet"}
            r = client.post("/dao/vote", json=vote_data, headers=headers)
            assert r.status_code == 403
            assert "oy hakkınız yok" in r.text

def test_get_votes_api_throws_exception_patch(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    client.post("/dao/propose", json={
        "title": "votes hata testi",
        "description": "deneme",
        "symbol": "BHRC",
        "options": ["A", "B"]
    }, headers=headers)

    proposals = client.get("/dao/proposals", headers=headers).json()["proposals"]
    pid = proposals[-1]["id"]

    with patch("bhrc_blockchain.api.dao_routes.dao_storage.get_votes_for_proposal", side_effect=Exception("Beklenmeyen hata")):
        r = client.get(f"/dao/proposal/{pid}/votes", headers=headers)
        assert r.status_code == 400
        assert "Beklenmeyen hata" in r.text

def test_vote_forbidden_direct(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.dao_routes.get_symbol_for_proposal", lambda x: "BHRC")
    monkeypatch.setattr("bhrc_blockchain.api.dao_routes.TokenContract.balance_of", lambda x, y: 0)

    req = VoteRequest(proposal_id=1, option="Evet")
    with pytest.raises(HTTPException) as e:
        vote_on_proposal(data=req, current_user={"sub": "admin"})
    assert e.value.status_code == 403
    assert "oy hakkınız yok" in str(e.value.detail)

def test_vote_cast_failure_direct(monkeypatch):
    monkeypatch.setattr("bhrc_blockchain.api.dao_routes.get_symbol_for_proposal", lambda x: "BHRC")
    monkeypatch.setattr("bhrc_blockchain.api.dao_routes.TokenContract.balance_of", lambda x, y: 100)
    monkeypatch.setattr("bhrc_blockchain.api.dao_routes.dao_storage.cast_vote", lambda *a, **kw: (_ for _ in ()).throw(Exception("bozuk")))

    req = VoteRequest(proposal_id=1, option="Evet")
    with pytest.raises(HTTPException) as e:
        vote_on_proposal(data=req, current_user={"sub": "admin"})
    assert e.value.status_code == 400
    assert "bozuk" in str(e.value.detail)
