# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import io
from fastapi import APIRouter, Query, HTTPException, Depends
from fastapi.responses import StreamingResponse
from bhrc_blockchain.utils import export_utils
from datetime import datetime
from bhrc_blockchain.database.models import LogModel
from bhrc_blockchain.database.database import SessionLocal, get_db
from sqlalchemy.orm import Session

router = APIRouter()

def get_logs_from_db(db, user_id=None, action_type=None, date_from=None, date_to=None):
    query = db.query(LogModel)

    if user_id:
        query = query.filter(LogModel.user_id == user_id)
    if action_type:
        query = query.filter(LogModel.action_type == action_type)
    if date_from:
        query = query.filter(LogModel.created_at >= date_from)
    if date_to:
        query = query.filter(LogModel.created_at <= date_to)

    return query.order_by(LogModel.created_at.desc()).all()

@router.get("/logs")
def export_logs(
    format: str = Query(..., description="csv, pdf, json veya zip"),
    user_id: str | None = Query(None),
    action_type: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: Session = Depends(get_db)
):
    logs = get_logs_from_db(
        db=db,
        user_id=user_id,
        action_type=action_type,
        date_from=date_from,
        date_to=date_to
    )

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

    elif format == "all":
        import tempfile
        import zipfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            # CSV
            csv_data = export_utils.export_logs_to_csv(logs)
            Path(f"{temp_dir}/logs.csv").write_text(csv_data)

            # PDF
            pdf_stream = export_utils.export_logs_to_pdf(logs)
            with open(f"{temp_dir}/logs.pdf", "wb") as f:
                f.write(pdf_stream.read())
                pdf_stream.seek(0)

            # JSON
            json_data = export_utils.export_logs_to_json(logs)
            Path(f"{temp_dir}/logs.json").write_text(json_data)

            # ZIP oluştur
            zip_path = f"/tmp/{filename}_all_formats.zip"
            with zipfile.ZipFile(zip_path, "w") as zipf:
                zipf.write(f"{temp_dir}/logs.csv", arcname="logs.csv")
                zipf.write(f"{temp_dir}/logs.pdf", arcname="logs.pdf")
                zipf.write(f"{temp_dir}/logs.json", arcname="logs.json")

        return StreamingResponse(
            open(zip_path, "rb"),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename={filename}_all_formats.zip"}
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

