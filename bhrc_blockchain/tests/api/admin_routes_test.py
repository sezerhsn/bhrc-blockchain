import json
import pytest
import asyncio
from fastapi import Depends, HTTPException
from unittest.mock import patch
from pathlib import Path
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api.auth import create_access_token
from bhrc_blockchain.database.models import User
from bhrc_blockchain.database.database import Session
from bhrc_blockchain.api import admin_routes

client = TestClient(app)

def override_permission_required(permission: str):
    def dependency():
        user = override_get_current_admin()
        if permission not in user.get("permissions", []):
            raise HTTPException(status_code=403, detail="Yetersiz yetki")
        return user["sub"]
    return Depends(dependency)

def override_get_current_admin():
    return {
        "sub": "admin_user",
        "role": "admin",
        "permissions": []
    }

def override_get_admin_user():
    return {
        "sub": "admin_user",
        "role": "admin",
        "permissions": []
    }

def get_admin_token():
    from bhrc_blockchain.api.auth import create_access_token
    token = create_access_token({"sub": "admin_user", "role": "admin"})
    return f"Bearer {token}"

def get_token(role="admin"):
    token = create_access_token({"sub": "test_user", "role": role})
    return f"Bearer {token}"

@pytest.fixture
def admin_auth_header():
    return {"Authorization": get_token("admin")}

def test_add_fake_block(admin_auth_header):
    response = client.post("/admin/add-fake-block", headers=admin_auth_header)
    assert response.status_code == 200
    assert "Sahte blok eklendi" in response.json()["message"]

def test_clear_mempool(super_admin_auth_header):
    response = client.post("/admin/clear-mempool", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json()["message"] == "Mempool temizlendi."

def test_network_stats(admin_auth_header):
    response = client.get("/admin/network-stats", headers=admin_auth_header)
    assert response.status_code == 200
    data = response.json()
    assert "peers" in data
    assert "total_blocks" in data
    assert "difficulty" in data
    assert "mempool_size" in data
    assert "last_block_index" in data
    assert "avg_block_time" in data

def test_active_sessions(super_admin_auth_header):
    response = client.get("/admin/sessions", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_add_fake_block_restricted_in_mainnet(admin_auth_header):
    import importlib
    from bhrc_blockchain.config import config
    from bhrc_blockchain.api import admin_routes

    config.settings = config.Config(_env_file=None, NETWORK="mainnet")

    importlib.reload(admin_routes)

    response = client.post("/admin/add-fake-block", headers=admin_auth_header)
    assert response.status_code == 403
    assert response.json()["detail"] == "Bu işlem sadece testnet üzerinde yapılabilir."

def get_super_admin_token():
    from bhrc_blockchain.api.auth import create_access_token
    token = create_access_token({"sub": "test_super", "role": "super_admin"})
    return f"Bearer {token}"

@pytest.fixture
def super_admin_auth_header():
    return {"Authorization": get_token("super_admin")}

def test_reset_chain_requires_super_admin(super_admin_auth_header, monkeypatch):
    monkeypatch.delenv("BHRC_TEST_MODE", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    response = client.post("/admin/reset-chain", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert "Zincir genesis bloğa sıfırlandı" in response.json()["message"]

def test_network_stats_with_single_block(super_admin_auth_header, monkeypatch):
    from bhrc_blockchain.core.blockchain.blockchain import get_blockchain

    monkeypatch.delenv("BHRC_TEST_MODE", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    client.post("/admin/reset-chain", headers=super_admin_auth_header)

    blockchain = get_blockchain()
    assert len(blockchain.chain) == 1

    response = client.get("/admin/network-stats", headers=super_admin_auth_header)
    assert response.status_code == 200
    data = response.json()
    assert data["avg_block_time"] == 0

def test_avg_block_time_zero_via_api(super_admin_auth_header, monkeypatch):
    from bhrc_blockchain.core.blockchain.blockchain import get_blockchain
    from bhrc_blockchain.core.block import Block
    import time

    monkeypatch.delenv("BHRC_TEST_MODE", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    blockchain = get_blockchain()
    genesis_block = Block(
        index=0,
        previous_hash="0",
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="genesis",
        difficulty=blockchain.difficulty_prefix,
        events=["Genesis block"]
    )
    genesis_block.block_hash = genesis_block.calculate_hash()
    blockchain.chain = [genesis_block]
    blockchain.mempool.clear()

    assert len(blockchain.chain) == 1

    response = client.get("/admin/network-stats", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json()["avg_block_time"] == 0

def test_snapshot_rollback(super_admin_auth_header):
    reset_response = client.post("/admin/reset-chain", headers=super_admin_auth_header)
    assert reset_response.status_code == 200

    snapshot_response = client.post("/admin/snapshot", headers=super_admin_auth_header)
    assert snapshot_response.status_code == 200

    headers = {
        **super_admin_auth_header,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    rollback_response = client.post(
        "/snapshot-rollback",
        data={"rollback_id": "snapshot.json"},
        headers=headers
    )

    assert rollback_response.status_code == 200
    assert rollback_response.json()["rolled_back_to"] == "snapshot.json"

def test_deactivate_user_creates_undo(super_admin_auth_header):
    ensure_test_user()
    response = client.post("/admin/users/1/deactivate", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json()["deactivated"] is True
    assert "undo_id" in response.json()

def test_undo_already_reversed(super_admin_auth_header):
    ensure_test_user()

    deactivate = client.post("/admin/users/1/deactivate", headers=super_admin_auth_header)
    deactivate_json = deactivate.json()

    assert "undo_id" in deactivate_json, f"undo_id bekleniyordu ama response: {deactivate_json}"
    undo_id = deactivate_json["undo_id"]

    client.post(f"/admin/undo/{undo_id}", headers=super_admin_auth_header)
    repeat = client.post(f"/admin/undo/{undo_id}", headers=super_admin_auth_header)

    assert repeat.status_code == 400

def test_active_sessions_endpoint(super_admin_auth_header):
    response = client.get("/admin/sessions", headers=super_admin_auth_header)
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    if data:
        assert "username" in data[0]
        assert "ip_address" in data[0]
        assert "user_agent" in data[0]
        assert "login_time" in data[0]

def ensure_test_user():
    session = Session()
    user = session.query(User).filter_by(id=1).first()
    if user:
        user.status = True
    else:
        user = User(id=1, username="testuser", role="user", status=True)
        session.add(user)
    session.commit()

def test_clear_mempool_forbidden_for_admin_role():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from bhrc_blockchain.api.admin_routes import permission_required
    from bhrc_blockchain.api.auth import create_access_token

    test_app = FastAPI()

    @test_app.post("/test-protected")
    def test_route(_: str = permission_required("clear-mempool")):
        return {"message": "should not reach here"}

    test_client = TestClient(test_app)

    token = create_access_token({"sub": "test_admin", "role": "admin"})
    headers = {"Authorization": f"Bearer {token}"}

    response = test_client.post("/test-protected", headers=headers)

    assert response.status_code == 403
    assert response.json()["detail"] in ["yetkiniz yok", "Yetersiz yetki"]

def test_reset_chain_runtime_error(monkeypatch, super_admin_auth_header):
    def mock_create_task(*args, **kwargs):
        raise RuntimeError("Simüle edilmiş event loop hatası")

    monkeypatch.setattr(asyncio, "create_task", mock_create_task)

    response = client.post("/admin/reset-chain", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert "genesis" in response.json()["message"]

def test_network_stats_success(super_admin_auth_header):
    response = client.get("/admin/network-stats", headers=super_admin_auth_header)
    assert response.status_code == 200
    data = response.json()
    assert "total_blocks" in data
    assert "avg_block_time" in data

def test_network_stats_exception(monkeypatch, super_admin_auth_header):
    def broken_blockchain():
        raise Exception("Simüle hata")

    monkeypatch.setattr("bhrc_blockchain.api.admin_routes.get_blockchain", broken_blockchain)

    response = client.get("/admin/network-stats", headers=super_admin_auth_header)
    assert response.status_code == 500
    assert response.json()["detail"] == "Simüle hata"

def test_snapshot_rollback_success(super_admin_auth_header):
    client.post("/admin/reset-chain", headers=super_admin_auth_header)
    client.post("/admin/snapshot", headers=super_admin_auth_header)

    snapshot_files = list(Path(".").glob("*.json"))
    assert snapshot_files, "Snapshot dosyası bulunamadı"

    snapshot_name = snapshot_files[0].name
    headers = {
        **super_admin_auth_header,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = client.post(
        "/snapshot-rollback",
        data={"rollback_id": snapshot_name},
        headers=headers
    )

    assert response.status_code == 200
    assert response.json()["rolled_back_to"] == snapshot_name

def test_snapshot_rollback_bad_request(super_admin_auth_header):
    headers = {
        **super_admin_auth_header,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = client.post("/snapshot-rollback", headers=headers)

    assert response.status_code == 422

def test_snapshot_rollback_exception(monkeypatch, super_admin_auth_header):
    def mock_load_snapshot(sid):
        raise Exception("Rollback hata verdi")

    monkeypatch.setattr("bhrc_blockchain.api.admin_routes.load_snapshot", mock_load_snapshot)

    response = client.post(
        "/snapshot-rollback",
        data={"rollback_id": "invalid_snapshot"},
        headers=super_admin_auth_header
    )

    assert response.status_code == 500
    assert "Rollback hata verdi" in response.json()["detail"]

def test_undo_user_deactivation(super_admin_auth_header):
    ensure_test_user()
    deactivate = client.post("/admin/users/1/deactivate", headers=super_admin_auth_header)
    assert deactivate.status_code == 200
    undo_id = deactivate.json()["undo_id"]

    undo = client.post(f"/admin/undo/{undo_id}", headers=super_admin_auth_header)
    assert undo.status_code == 200
    assert undo.json()["status"] == "undo_applied"

def test_get_active_sessions(super_admin_auth_header):
    response = client.get("/admin/sessions", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_clear_mempool_as_superadmin(super_admin_auth_header):
    response = client.post("/admin/clear-mempool", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json() == {"message": "Mempool temizlendi."}

def test_reset_chain(super_admin_auth_header):
    response = client.post("/admin/reset-chain", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert "message" in response.json()
    assert "zincir genesis bloğa sıfırlandı" in response.json()["message"].lower()

def test_reset_chain_runtime_error(super_admin_auth_header):
    with patch("bhrc_blockchain.core.blockchain.blockchain.Blockchain.reset_chain", side_effect=RuntimeError("Zincir sıfırlanamadı")):
        response = client.post("/admin/reset-chain", headers=super_admin_auth_header)
        assert response.status_code == 500
        assert response.json()["detail"] == "Zincir sıfırlanamadı"

def test_network_stats_empty_chain(super_admin_auth_header):
    response = client.get("/admin/network-stats", headers=super_admin_auth_header)
    assert response.status_code == 200
    json_data = response.json()
    assert "total_blocks" in json_data
    assert json_data["total_blocks"] >= 0

def test_active_sessions_view_logs(super_admin_auth_header):
    response = client.get("/admin/sessions", headers=super_admin_auth_header)
    assert response.status_code == 200

def test_update_user_role(super_admin_auth_header):
    ensure_test_user()
    headers = {
        **super_admin_auth_header,
        "Content-Type": "application/json"
    }
    response = client.post(
        "/admin/users/1/update_role",
        data=json.dumps("observer"),
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["updated"] is True

def test_deactivate_user_already_inactive(super_admin_auth_header):
    ensure_test_user()
    client.post("/admin/users/1/deactivate", headers=super_admin_auth_header)
    response = client.post("/admin/users/1/deactivate", headers=super_admin_auth_header)
    assert response.status_code == 400
    assert "zaten pasif" in response.json()["detail"]

def test_list_undo_logs(super_admin_auth_header):
    response = client.get("/admin/undo", headers=super_admin_auth_header)
    assert response.status_code == 200

def test_list_users(super_admin_auth_header):
    response = client.get("/admin/users", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_admin_logs_file_missing(monkeypatch, super_admin_auth_header):
    import os
    log_path = "bhrc_blockchain/logs/admin.log"
    if os.path.exists(log_path):
        os.remove(log_path)

    response = client.get("/admin/logs", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json()["logs"] == []

def test_active_sessions_empty(monkeypatch, super_admin_auth_header):
    from bhrc_blockchain.database.models import SessionLog
    from bhrc_blockchain.database.database import SessionLocal

    session = SessionLocal()
    session.query(SessionLog).update({SessionLog.active: False})
    session.commit()

    response = client.get("/admin/sessions", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json() == []

def test_update_user_role_user_not_found(super_admin_auth_header):
    response = client.post(
        "/admin/users/9999/update_role",
        data=json.dumps("observer"),
        headers={**super_admin_auth_header, "Content-Type": "application/json"}
    )
    assert response.status_code == 404
    assert "Kullanıcı bulunamadı" in response.json()["detail"]

def test_undo_invalid_action_type(super_admin_auth_header):
    from bhrc_blockchain.database.models import UndoLog
    from bhrc_blockchain.database.database import SessionLocal

    session = SessionLocal()
    log = UndoLog(
        action_type="bilinmeyen_tip",
        snapshot_ref=None,
        meta_data=None,
        reversed=False
    )
    session.add(log)
    session.commit()

    response = client.post(f"/admin/undo/{log.id}", headers=super_admin_auth_header)
    assert response.status_code == 400
    assert "Bu tür işlem için undo tanımlı değil" in response.json()["detail"]

def test_list_users_empty(monkeypatch, super_admin_auth_header):
    from bhrc_blockchain.database.database import SessionLocal
    from bhrc_blockchain.database.models import User

    session = SessionLocal()
    session.query(User).delete()
    session.commit()

    response = client.get("/admin/users", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json() == []

def test_active_sessions_with_data(super_admin_auth_header):
    from bhrc_blockchain.database.models import SessionLog, User
    from bhrc_blockchain.database.database import SessionLocal
    import datetime

    session = SessionLocal()

    test_user = User(id=10, username="admin_user", role="admin", status=True)
    session.merge(test_user)
    session.commit()

    session_log = SessionLog(
        user_id=10,
        username="admin_user",
        ip_address="127.0.0.1",
        user_agent="pytest",
        login_time=datetime.datetime.now(),
        active=True
    )
    session.add(session_log)
    session.commit()

    response = client.get("/admin/sessions", headers=super_admin_auth_header)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(log["username"] == "admin_user" for log in data)

def test_update_user_role_twice(super_admin_auth_header):
    ensure_test_user()

    headers = {
        **super_admin_auth_header,
        "Content-Type": "application/json"
    }

    response1 = client.post(
        "/admin/users/1/update_role",
        data=json.dumps("observer"),
        headers=headers
    )
    assert response1.status_code == 200

    response2 = client.post(
        "/admin/users/1/update_role",
        data=json.dumps("admin"),
        headers=headers
    )
    assert response2.status_code == 200

def test_redeactivate_user_after_undo(super_admin_auth_header):
    ensure_test_user()

    deactivate = client.post("/admin/users/1/deactivate", headers=super_admin_auth_header)
    undo_id = deactivate.json()["undo_id"]

    client.post(f"/admin/undo/{undo_id}", headers=super_admin_auth_header)

    deactivate2 = client.post("/admin/users/1/deactivate", headers=super_admin_auth_header)
    assert deactivate2.status_code == 200

    response = client.post("/admin/users/1/deactivate", headers=super_admin_auth_header)
    assert response.status_code == 400
    assert "zaten pasif" in response.json()["detail"]

def test_list_users_with_data(super_admin_auth_header):
    ensure_test_user()
    response = client.get("/admin/users", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert any(u["username"] == "testuser" for u in response.json())

def test_active_sessions_multiple(monkeypatch, super_admin_auth_header):
    from bhrc_blockchain.database.models import SessionLog, User
    from bhrc_blockchain.database.database import SessionLocal
    import datetime

    session = SessionLocal()
    for uid, uname in [(11, "admin1"), (12, "admin2")]:
        user = User(id=uid, username=uname, role="admin", status=True)
        session.merge(user)
        log = SessionLog(
            user_id=uid,
            username=uname,
            ip_address="127.0.0.1",
            user_agent="pytest",
            login_time=datetime.datetime.now(),
            active=True
        )
        session.add(log)
    session.commit()

    response = client.get("/admin/sessions", headers=super_admin_auth_header)
    assert response.status_code == 200
    users = [entry["username"] for entry in response.json()]
    assert "admin1" in users and "admin2" in users

def test_update_user_role_same_role(super_admin_auth_header):
    ensure_test_user()

    headers = {
        **super_admin_auth_header,
        "Content-Type": "application/json"
    }

    response = client.post(
        "/admin/users/1/update_role",
        data=json.dumps("user"),
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["updated"] is True

def test_deactivate_already_inactive_user(super_admin_auth_header):
    from bhrc_blockchain.database.database import SessionLocal
    from bhrc_blockchain.database.models import User

    session = SessionLocal()
    user = User(id=20, username="inactive_user", role="admin", status=False)
    session.merge(user)
    session.commit()

    response = client.post("/admin/users/20/deactivate", headers=super_admin_auth_header)
    assert response.status_code == 400
    assert "zaten pasif" in response.json()["detail"]

def test_list_multiple_users(super_admin_auth_header):
    from bhrc_blockchain.database.database import SessionLocal
    from bhrc_blockchain.database.models import User

    session = SessionLocal()
    session.add_all([
        User(id=21, username="alpha", role="admin", status=True),
        User(id=22, username="beta", role="observer", status=True)
    ])
    session.commit()

    response = client.get("/admin/users", headers=super_admin_auth_header)
    assert response.status_code == 200
    usernames = [u["username"] for u in response.json()]
    assert "alpha" in usernames and "beta" in usernames

def test_permission_required_allowed():
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient
    from fastapi import HTTPException
    from bhrc_blockchain.api.auth import get_current_admin

    def custom_permission_required(permission: str):
        def dependency():
            user = {
                "sub": "admin",
                "role": "admin",
                "permissions": ["network_stats"]
            }
            if permission not in user["permissions"]:
                raise HTTPException(status_code=403, detail="yetkiniz yok")
            return user["sub"]
        return Depends(dependency)

    app = FastAPI()

    @app.get("/test-perm")
    def test_route(_: str = custom_permission_required("network_stats")):
        return {"status": "ok"}

    client = TestClient(app)
    response = client.get("/test-perm")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_permission_required_forbidden(monkeypatch):
    from fastapi import FastAPI
    from bhrc_blockchain.api.admin_routes import permission_required

    app = FastAPI()

    @app.get("/test-perm")
    def test_route(_: str = permission_required("deactivate_user")):
        return {"status": "ok"}

    client_ = TestClient(app)
    token = create_access_token({"sub": "admin", "role": "admin"})
    response = client_.get("/test-perm", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["detail"] in ["yetkiniz yok", "Yetersiz yetki"]

def test_update_role_user_not_found(super_admin_auth_header):
    response = client.post(
        "/admin/users/9999/update_role",
        data=json.dumps("admin"),
        headers={**super_admin_auth_header, "Content-Type": "application/json"}
    )
    assert response.status_code == 404

def test_undo_user_deactivation_missing_metadata(super_admin_auth_header):
    from bhrc_blockchain.database.models import UndoLog
    from bhrc_blockchain.database.database import SessionLocal

    session = SessionLocal()
    log = UndoLog(
        action_type="user_deactivation",
        snapshot_ref=None,
        meta_data=None,
        reversed=False
    )
    session.add(log)
    session.commit()

    response = client.post(f"/admin/undo/{log.id}", headers=super_admin_auth_header)
    assert response.status_code == 400

def test_list_users_none(monkeypatch, super_admin_auth_header):
    from bhrc_blockchain.database.models import User
    from bhrc_blockchain.database.database import SessionLocal

    session = SessionLocal()
    session.query(User).delete()
    session.commit()

    response = client.get("/admin/users", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json() == []

def test_active_sessions_none(super_admin_auth_header):
    from bhrc_blockchain.database.models import SessionLog
    from bhrc_blockchain.database.database import SessionLocal

    session = SessionLocal()
    session.query(SessionLog).delete()
    session.commit()

    response = client.get("/admin/sessions", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json() == []

def test_get_admin_logs_with_entries(super_admin_auth_header):
    import os
    import json
    from bhrc_blockchain.api.admin_routes import log_admin_action

    log_path = "bhrc_blockchain/logs/admin.log"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    log_admin_action("test-log", user="admin_log_test")

    response = client.get("/admin/logs", headers=super_admin_auth_header)
    assert response.status_code == 200
    logs = response.json()["logs"]
    assert any("test-log" in log["action"] for log in logs)

def test_update_user_role_multiple_transitions(super_admin_auth_header):
    ensure_test_user()
    headers = {
        **super_admin_auth_header,
        "Content-Type": "application/json"
    }

    res1 = client.post("/admin/users/1/update_role", data=json.dumps("admin"), headers=headers)
    assert res1.status_code == 200

    res2 = client.post("/admin/users/1/update_role", data=json.dumps("observer"), headers=headers)
    assert res2.status_code == 200

def test_undo_user_deactivation_user_not_found(super_admin_auth_header):
    from bhrc_blockchain.database.models import UndoLog
    from bhrc_blockchain.database.database import SessionLocal

    session = SessionLocal()
    log = UndoLog(
        action_type="user_deactivation",
        snapshot_ref=None,
        meta_data={"user_id": 9999},
        reversed=False
    )
    session.add(log)
    session.commit()

    response = client.post(f"/admin/undo/{log.id}", headers=super_admin_auth_header)
    assert response.status_code == 200
    assert response.json()["status"] == "undo_applied"

def test_update_role_user_does_not_exist(super_admin_auth_header):
    response = client.post(
        "/admin/users/9999/update_role",
        data=json.dumps("admin"),
        headers={**super_admin_auth_header, "Content-Type": "application/json"}
    )
    assert response.status_code == 404

def test_admin_logs_with_invalid_json(monkeypatch, super_admin_auth_header):
    import os

    log_path = "bhrc_blockchain/logs/admin.log"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    with open(log_path, "w") as f:
        f.write("BU GEÇERSİZ JSON SATIRI\n")

    response = client.get("/admin/logs", headers=super_admin_auth_header)
    assert response.status_code == 500
    assert "Log okunamadı" in response.json()["detail"]

