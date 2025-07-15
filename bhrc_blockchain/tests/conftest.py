import os
import pytest
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app
from fastapi import Depends, HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from bhrc_blockchain.database.models import Base
from bhrc_blockchain.api import (
    auth_routes,
    admin_routes,
    token_routes,
    panel_routes,
    dao_routes,
    nft_routes,
    multisig_routes,
    transaction_routes,
    export_routes,
)

def pytest_configure(config):
    os.environ["TESTING"] = "1"
    os.environ["BHRC_TEST_MODE"] = "1"

TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture(scope="function")
def db_session():
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(autouse=True)
def override_permission_required_fixture():
    def override_permission_required(permission: str):
        def dependency():
            user = {
                "sub": "admin_user",
                "role": "admin",
                "permissions": []
            }
            if permission not in user["permissions"]:
                raise HTTPException(status_code=403, detail="Yetersiz yetki")
            return user["sub"]
        return Depends(dependency)

    admin_routes.permission_required = override_permission_required

@pytest.fixture(autouse=True)
def override_dependencies():
    def mock_user():
        return {
            "sub": "admin",
            "role": "super_admin",
            "permissions": [
                "clear-mempool", "active-sessions", "snapshot", "rollback",
                "reset-chain", "update_role", "deactivate_user", "view_logs"
            ]
        }

    app.dependency_overrides[auth_routes.get_current_user] = mock_user
    app.dependency_overrides[auth_routes.get_current_admin] = mock_user
    app.dependency_overrides[token_routes.get_current_user] = mock_user
    app.dependency_overrides[panel_routes.get_current_user] = mock_user
    app.dependency_overrides[dao_routes.get_current_user] = mock_user
    app.dependency_overrides[nft_routes.get_current_user] = mock_user
    app.dependency_overrides[multisig_routes.get_current_user] = mock_user
    app.dependency_overrides[transaction_routes.get_current_user] = mock_user

    yield

    app.dependency_overrides = {}

