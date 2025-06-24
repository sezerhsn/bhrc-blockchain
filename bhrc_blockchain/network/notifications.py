import asyncio
import json
from websockets import broadcast
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Set, List
from websockets.server import WebSocketServerProtocol, serve
from bhrc_blockchain.core.logger.logger import setup_logger

logger = setup_logger("Notifications")

connected_clients: Set[WebSocketServerProtocol] = set()
subscribed_clients: Dict[WebSocketServerProtocol, str] = {}  # ws: address eşleşmesi
websocket_connections: List[WebSocket] = []
connected_admins = set()

async def notification_handler(websocket: WebSocketServerProtocol):
    logger.info("🔔 Yeni WebSocket istemcisi bağlandı.")
    connected_clients.add(websocket)

    try:
        await websocket.send(json.dumps({"type": "welcome", "message": "WebSocket bağlantısı kuruldu"}))

        async for message in websocket:
            try:
                data = json.loads(message)
                if data.get("type") == "subscribe":
                    addr = data.get("address")
                    if addr:
                        subscribed_clients[websocket] = addr
                        await websocket.send(json.dumps({"type": "subscribed", "address": addr}))
                        logger.info(f"✅ {addr} adresi için abonelik alındı.")
            except Exception as e:
                logger.warning(f"📛 Geçersiz mesaj: {e}")

    except Exception as e:
        logger.warning(f"⚠️ WebSocket bağlantı hatası: {e}")
    finally:
        connected_clients.discard(websocket)
        subscribed_clients.pop(websocket, None)
        logger.info("🔌 WebSocket istemcisi bağlantıyı kesti.")

async def start_notification_server(host="0.0.0.0", port=8888):
    logger.info(f"📡 Bildirim WebSocket sunucusu başlatılıyor → {host}:{port}")
    async with serve(notification_handler, host, port):
        await asyncio.Future()

async def broadcast_block_notification(block_data: dict):
    if not connected_clients:
        return

    message = json.dumps({
        "type": "block",
        "index": block_data.get("index"),
        "hash": block_data.get("block_hash"),
        "event": "Yeni blok kazıldı"
    })
    for ws in list(connected_clients):
        if ws.open:
            try:
                await ws.send(message)
            except Exception as e:
                logger.debug(f"Blok bildirimi gönderilemedi: {e}")

    for tx in block_data.get("transactions", []):
        recipient = tx.get("recipient")
        if not recipient:
            continue
        for ws, sub_address in subscribed_clients.items():
            if recipient == sub_address and ws.open:
                try:
                    await ws.send(json.dumps({
                        "type": "incoming_tx",
                        "event": f"💸 Yeni transfer alındı",
                        "tx": tx
                    }))
                except Exception:
                    continue

async def emit_admin_alert(event_type: str, details: dict):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "details": details
    }
    write_to_log(log_entry)
    await broadcast_to_admin_websocket(log_entry)

def write_to_log(entry: dict):
    import os
    os.makedirs("logs", exist_ok=True)
    with open("logs/admin_events.log", "a") as f:
        f.write(json.dumps(entry) + "\n")

async def broadcast_to_admin_websocket(entry: dict):
    for websocket in websocket_connections[:]:
        try:
            await websocket.send_text(json.dumps(entry))
        except Exception:
            websocket_connections.remove(websocket)

async def notify_admin(data: dict):
    if websocket_connections:
        print(f"🔁 Bildirim gönderiliyor: {data}")
        print(f"🧩 Bağlı WebSocket sayısı: {len(websocket_connections)}")
        message = json.dumps(data)
        await asyncio.gather(*[ws.send_text(message) for ws in websocket_connections])

async def admin_event_ws(websocket: WebSocket):
    await websocket.accept()
    connected_admins.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_admins.remove(websocket)
