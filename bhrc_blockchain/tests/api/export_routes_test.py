import pytest
from httpx import AsyncClient, ASGITransport
from bhrc_blockchain.api.api_server import app

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

