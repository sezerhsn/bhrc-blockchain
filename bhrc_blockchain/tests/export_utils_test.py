import io
import pytest
import os
import tempfile
import json
from bhrc_blockchain.utils import export_utils
from unittest.mock import patch, MagicMock

class DummyLog:
    def __init__(self, id, user_id, action_type, created_at):
        self.id = id
        self.user_id = user_id
        self.action_type = action_type
        self.created_at = created_at

@pytest.fixture
def sample_logs():
    return [
        DummyLog(1, "user1", "login", "2025-06-11 15:00"),
        DummyLog(2, "user2", "logout", "2025-06-11 15:10")
    ]

def test_export_logs_to_csv(sample_logs):
    csv_output = export_utils.export_logs_to_csv(sample_logs)
    assert "ID,Kullanıcı,İşlem,Tarih" in csv_output
    assert "1,user1,login,2025-06-11 15:00" in csv_output
    assert "2,user2,logout,2025-06-11 15:10" in csv_output

def test_export_logs_to_pdf(sample_logs):
    pdf_output = export_utils.export_logs_to_pdf(sample_logs)
    assert isinstance(pdf_output, io.BytesIO)
    content = pdf_output.getvalue()
    assert len(content) > 100

def test_export_logs_to_csv_writes_file(sample_logs):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp_file:
        path = temp_file.name

    try:
        result_path = export_utils.export_logs_to_csv(sample_logs, output_path=path)
        assert os.path.exists(result_path)
        with open(result_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "Kullanıcı" in content
            assert "user1" in content
    finally:
        os.remove(path)

def test_export_logs_to_pdf_writes_file(sample_logs):
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_file:
        path = temp_file.name

    try:
        result_path = export_utils.export_logs_to_pdf(sample_logs, output_path=path)
        assert os.path.exists(result_path)
        with open(result_path, "rb") as f:
            content = f.read()
            assert content.startswith(b"%PDF")
            assert len(content) > 100
    finally:
        os.remove(path)

def test_export_logs_to_json_memory(sample_logs):
    json_output = export_utils.export_logs_to_json(sample_logs)
    data = json.loads(json_output)
    assert isinstance(data, list)
    assert data[0]["user_id"] == "user1"

def test_export_logs_to_json_file(sample_logs):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
        path = temp_file.name

    try:
        result_path = export_utils.export_logs_to_json(sample_logs, output_path=path)
        assert os.path.exists(result_path)
        with open(result_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert isinstance(data, list)
            assert data[1]["action_type"] == "logout"
    finally:
        os.remove(path)

def test_export_logs_as_zip_creates_zip_with_files(sample_logs):
    import zipfile
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as temp_file:
        path = temp_file.name

    try:
        result_path = export_utils.export_logs_as_zip(sample_logs, output_path=path)
        assert os.path.exists(result_path)

        with zipfile.ZipFile(result_path, 'r') as zipf:
            namelist = zipf.namelist()
            assert "logs.csv" in namelist
            assert "logs.pdf" in namelist

            with zipf.open("logs.csv") as f:
                content = f.read().decode("utf-8")
                assert "user1" in content

    finally:
        os.remove(path)

def test_export_logs_to_csv_with_filter(sample_logs):
    csv_output = export_utils.export_logs_to_csv(
        sample_logs,
        filter_fn=lambda log: log.user_id == "user2"
    )
    assert "user1" not in csv_output
    assert "user2" in csv_output

def test_export_logs_to_csv_with_sorting(sample_logs):
    sample_logs[0].created_at = "2025-06-11 16:00"
    sample_logs[1].created_at = "2025-06-11 15:00"

    csv_output = export_utils.export_logs_to_csv(
        sample_logs,
        sort_by="created_at"
    )

    first_data_line = csv_output.strip().split("\n")[1]
    assert "user2" in first_data_line

def test_export_logs_to_csv_with_custom_headers(sample_logs):
    custom_headers = ["Log ID", "User", "Action", "Timestamp"]
    csv_output = export_utils.export_logs_to_csv(
        sample_logs,
        headers=custom_headers
    )
    first_line = csv_output.strip().split("\n")[0]
    assert "Log ID" in first_line
    assert "User" in first_line
    assert "Kullanıcı" not in first_line

def test_send_export_via_email_mocks_smtp(sample_logs):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write("Deneme içeriği".encode("utf-8"))
        tmp_path = tmp.name

    try:
        with patch("smtplib.SMTP") as mock_smtp:
            mock_instance = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_instance

            success = export_utils.send_export_via_email(
                to_email="test@example.com",
                subject="BHRC Test Maili",
                body="Bu bir testtir.",
                attachment_path=tmp_path,
                smtp_server="localhost",
                smtp_port=25
            )

            assert success is True
            mock_instance.send_message.assert_called_once()
    finally:
        os.remove(tmp_path)

def test_export_logs_to_pdf_with_metadata(sample_logs):
    pdf_buffer = export_utils.export_logs_to_pdf(sample_logs, include_metadata=True)
    content = pdf_buffer.getvalue()
    assert isinstance(content, bytes)
    assert len(content) > 100

