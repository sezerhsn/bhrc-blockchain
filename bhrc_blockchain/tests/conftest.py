import pytest
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api.auth import get_current_user

@pytest.fixture(autouse=True)
def override_auth_dependency():
    def mock_user():
        return {
            "username": "test_user",
            "sub": "test_user",
            "roles": ["admin"]
        }
    app.dependency_overrides[get_current_user] = mock_user

