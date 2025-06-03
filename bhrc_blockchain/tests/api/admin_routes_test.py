import pytest
from fastapi.testclient import TestClient
from bhrc_blockchain.api.api_server import app

client = TestClient(app)

def get_admin_token():
    # Burada sabit admin token'ı kullanılabilir veya dinamik olarak oluşturulabilir
    return "Bearer test-admin-token"

@pytest.fixture
def admin_auth_header():
    return {"Authorization": get_admin_token()}

def test_reset_chain(admin_auth_header):
    response = client.post("/admin/reset-chain", headers=admin_auth_header)
    assert response.status_code == 200
    assert "Zincir genesis bloğa sıfırlandı" in response.json()["message"]

def test_add_fake_block(admin_auth_header):
    response = client.post("/admin/add-fake-block", headers=admin_auth_header)
    assert response.status_code == 200
    assert "Sahte blok eklendi" in response.json()["message"]

def test_clear_mempool(admin_auth_header):
    response = client.post("/admin/clear-mempool", headers=admin_auth_header)
    assert response.status_code == 200
    assert response.json()["message"] == "Mempool temizlendi."

def test_network_stats(admin_auth_header):
    response = client.get("/admin/network-stats", headers=admin_auth_header)
    assert response.status_code == 200
    data = response.json()
    assert "peers" in data
    assert "total_blocks" in data
    assert "difficulty" in data

def test_active_sessions(admin_auth_header):
    response = client.get("/admin/sessions", headers=admin_auth_header)
    assert response.status_code == 200
    assert "Oturum yönetimi" in response.json()["message"]

