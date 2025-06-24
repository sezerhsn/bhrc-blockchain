import csv
import io
import json
import zipfile
import smtplib
import mimetypes
from email.message import EmailMessage
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime

def export_logs_to_csv(logs, output_path=None, filter_fn=None, sort_by=None, headers=None):
    if filter_fn:
        logs = list(filter(filter_fn, logs))
    if sort_by:
        logs = sorted(logs, key=lambda log: getattr(log, sort_by, None))

    headers = headers or ["ID", "Kullanıcı", "İşlem", "Tarih"]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for log in logs:
        writer.writerow([log.id, log.user_id, log.action_type, log.created_at])

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output.getvalue())
        return output_path
    else:
        return output.getvalue()

def export_logs_to_pdf(logs, output_path=None, include_metadata=True):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()

    elements = [Paragraph("İşlem Logları", styles["Heading1"])]

    if not logs:
        elements.append(Paragraph("Kayıt bulunamadı.", styles["Normal"]))
    else:
        for log in logs:
            entry = f"{log.id} | {log.user_id} | {log.action_type} | {log.created_at}"
            elements.append(Paragraph(entry, styles["Normal"]))

    if include_metadata:
        elements.append(Paragraph(f"Toplam kayıt: {len(logs)}", styles["Italic"]))
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        elements.append(Paragraph(f"Export Tarihi: {now_str}", styles["Italic"]))
        elements.append(Paragraph("BHRC Log Export", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)

    if output_path:
        with open(output_path, "wb") as f:
            f.write(buffer.read())
        return output_path
    else:
        return buffer

def export_logs_to_json(logs, output_path=None):
    """
    Logları JSON formatında dışa aktarır.
    - Bellekte string döner (output_path verilmezse)
    - Diske yazılır (output_path verilirse)
    """
    data = [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action_type": log.action_type,
            "created_at": log.created_at,
        }
        for log in logs
    ]

    json_string = json.dumps(data, indent=4, ensure_ascii=False)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_string)
        return output_path
    else:
        return json_string

def export_logs_as_zip(logs, output_path="logs_export.zip"):
    csv_content = export_logs_to_csv(logs)
    pdf_buffer = export_logs_to_pdf(logs)

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("logs.csv", csv_content)
        pdf_buffer.seek(0)
        zipf.writestr("logs.pdf", pdf_buffer.read())

    return output_path

def send_export_via_email(to_email, subject, body, attachment_path, from_email="noreply@bhrc.io", smtp_server="localhost", smtp_port=25):
    """
    Basit e-posta gönderimi. attachment_path ile dosya eklenir.
    SMTP sunucusu varsayılan olarak localhost:25.
    """
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(body)

        with open(attachment_path, "rb") as f:
            data = f.read()
            maintype, subtype = mimetypes.guess_type(attachment_path)[0].split("/")
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=attachment_path.split("/")[-1])

        with smtplib.SMTP(smtp_server, smtp_port) as smtp:
            smtp.send_message(msg)

        return True

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

