# notifications.py
import asyncio
import json
from typing import Dict, Set
from websockets.server import WebSocketServerProtocol, serve
from bhrc_blockchain.core.logger.logger import setup_logger

logger = setup_logger("Notifications")

connected_clients: Set[WebSocketServerProtocol] = set()
subscribed_clients: Dict[WebSocketServerProtocol, str] = {}  # ws: address eşleşmesi

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

    # 1. Herkese genel blok bildirimi
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
            except Exception:
                pass

    # 2. Kişisel adres eşleşmelerini bildir
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

