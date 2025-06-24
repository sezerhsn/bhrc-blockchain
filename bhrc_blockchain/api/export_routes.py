from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from bhrc_blockchain.utils import export_utils
from datetime import datetime
import io

router = APIRouter()

class DummyLog:
    def __init__(self, id, user_id, action_type, created_at):
        self.id = id
        self.user_id = user_id
        self.action_type = action_type
        self.created_at = created_at

def get_dummy_logs():
    return [
        DummyLog(1, "user1", "login", "2025-06-11 15:00"),
        DummyLog(2, "user2", "logout", "2025-06-11 15:30")
    ]

@router.get("/logs")
def export_logs(format: str = Query(..., description="csv, pdf, json veya zip")):
    logs = get_dummy_logs()
    filename = f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M')}"

    if format == "csv":
        csv_data = export_utils.export_logs_to_csv(logs)
        return StreamingResponse(
            io.StringIO(csv_data),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"}
        )

    elif format == "pdf":
        pdf_data = export_utils.export_logs_to_pdf(logs)
        return StreamingResponse(
            pdf_data,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}.pdf"}
        )

    elif format == "json":
        json_data = export_utils.export_logs_to_json(logs)
        return StreamingResponse(
            io.StringIO(json_data),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}.json"}
        )

    elif format == "zip":
        zip_path = export_utils.export_logs_as_zip(logs, output_path=f"/tmp/{filename}.zip")
        zip_file = open(zip_path, "rb")
        return StreamingResponse(
            zip_file,
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename={filename}.zip"}
        )

    else:
        raise HTTPException(status_code=400, detail="Geçersiz format: csv, pdf, json, zip kullanılabilir.")

