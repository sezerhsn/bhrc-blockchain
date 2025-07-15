import pytest
import zipfile
import io
from httpx import AsyncClient, ASGITransport
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.api import export_routes

class DummyLog:
    def __init__(self, id, created_at, action_type, message, user_id):
        self.id = id
        self.created_at = created_at
        self.action_type = action_type
        self.message = message
        self.user_id = user_id

@pytest.fixture(autouse=True)
def override_get_logs(monkeypatch):
    def mock_get_logs_from_db(db=None, user_id=None, action_type=None, date_from=None, date_to=None):
        logs = [
            DummyLog(1, "2025-06-11 15:00", "login", "Logged in", "user1"),
            DummyLog(2, "2025-06-11 15:30", "logout", "Logged out", "user2"),
            DummyLog(3, "2025-06-12 10:00", "transfer", "Sent 10 BHRC", "user1"),
        ]

        # Filtreleme
        if user_id:
            logs = [log for log in logs if log.user_id == user_id]
        if action_type:
            logs = [log for log in logs if log.action_type == action_type]
        return logs

    monkeypatch.setattr(export_routes, "get_logs_from_db", mock_get_logs_from_db)

@pytest.mark.asyncio
@pytest.mark.parametrize("format, content_type, extension", [
    ("csv", "text/csv", ".csv"),
    ("pdf", "application/pdf", ".pdf"),
    ("json", "application/json", ".json"),
    ("zip", "application/zip", ".zip"),
])
async def test_export_logs_formats(format, content_type, extension):
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get(f"/export/logs?format={format}")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert "filename=" in response.headers["content-disposition"]
        assert response.headers["content-disposition"].endswith(extension)
        assert len(response.content) > 50

        if format == "zip":
            import zipfile
            import io
            z = zipfile.ZipFile(io.BytesIO(response.content))
            names = z.namelist()
            assert any(name.endswith(".csv") or name.endswith(".pdf") or name.endswith(".json") for name in names)

@pytest.mark.asyncio
async def test_export_logs_with_user_id_filter():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&user_id=user1")
        assert response.status_code == 200
        assert b"user1" in response.content
        assert b"user2" not in response.content

@pytest.mark.asyncio
async def test_export_logs_with_action_type_filter():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&action_type=logout")
        assert response.status_code == 200
        assert b"logout" in response.content
        assert b"login" not in response.content

@pytest.mark.asyncio
async def test_export_logs_invalid_format_returns_400():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=exe")
        assert response.status_code == 400
        assert "Geçersiz format" in response.text

@pytest.mark.asyncio
async def test_export_logs_user2_login_filter():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&user_id=user2&action_type=logout")
        assert response.status_code == 200
        assert b"user2" in response.content
        assert b"user1" not in response.content

@pytest.mark.asyncio
async def test_export_logs_user2_only_filter():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&user_id=user2")
        assert response.status_code == 200
        assert b"user2" in response.content

@pytest.mark.asyncio
async def test_export_logs_login_only_filter():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&action_type=login")
        assert response.status_code == 200
        assert b"login" in response.content

@pytest.mark.asyncio
async def test_export_logs_user_filter_minimal():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&user_id=nonexistent_user")
        assert response.status_code == 200

@pytest.mark.asyncio
async def test_export_logs_action_filter_minimal():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&action_type=nonexistent_action")
        assert response.status_code == 200

@pytest.mark.asyncio
async def test_export_logs_user1_filter_hits():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&user_id=user1")
        assert response.status_code == 200
        assert b"user1" in response.content

@pytest.mark.asyncio
async def test_export_logs_action_login_hits():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=json&action_type=login")
        assert response.status_code == 200
        assert b"login" in response.content

@pytest.mark.asyncio
async def test_export_logs_format_all_zip_contains_all_formats():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/export/logs?format=all")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/zip")
        assert "filename=" in response.headers["content-disposition"]
        assert response.headers["content-disposition"].endswith("_all_formats.zip")
        assert len(response.content) > 100

        zip_file = zipfile.ZipFile(io.BytesIO(response.content))
        names = zip_file.namelist()
        assert "logs.csv" in names
        assert "logs.pdf" in names
        assert "logs.json" in names
