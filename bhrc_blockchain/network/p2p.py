import asyncio
import json
from typing import Set
from websockets.exceptions import ConnectionClosed
from websockets.server import WebSocketServerProtocol, serve
from websockets.client import connect
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.logger.logging_utils import setup_logger
from bhrc_blockchain.core.transaction.validation import validate_block_structure, ChainValidator
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.mempool.mempool import add_transaction_to_mempool, get_transaction_from_mempool

logger = setup_logger("P2P")

connected_peers: Set[WebSocketServerProtocol] = set()
local_blockchain: Blockchain = None
banned_peers: Set[str] = set()

router = APIRouter()

def chain_score(chain: list) -> int:
    return sum(block.get("index", 0) + block.get("nonce", 0) for block in chain)

async def handler(websocket: WebSocketServerProtocol, path):
    global local_blockchain

    peer_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
    if peer_ip in banned_peers:
        logger.warning(f"⛔ Bağlantı reddedildi (banlı peer): {peer_ip}")
        await websocket.close()
        return

    connected_peers.add(websocket)
    logger.info(f"🔌 Yeni peer bağlandı: {peer_ip}")

    try:
        async for message in websocket:
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                logger.warning(f"📛 Geçersiz JSON alındı: {message}")
                continue

            action = data.get("action")

            if action == "HELLO":
                peer_id = data.get("peer_id")
                pubkey = data.get("public_key")
                ts = data.get("timestamp")
                if not pubkey or not ts:
                    logger.warning("❌ Eksik handshake verisi")
                    await websocket.close()
                    return
                websocket.peer_id = peer_id
                websocket.public_key = pubkey
                logger.info(f"🤝 Peer kendini tanıttı: {peer_id} | PublicKey: {pubkey[:20]}... | TS: {ts}")
                continue

            elif action == "REQUEST_CHAIN":
                logger.info("🔗 Zincir talebi alındı. Zincir gönderiliyor...")
                chain_data = [block.to_dict() for block in local_blockchain.chain]
                await websocket.send(json.dumps({"action": "BLOCKCHAIN", "chain": chain_data}))

            elif action == "BLOCKCHAIN":
                received_chain = data.get("chain")
                if not received_chain:
                    logger.warning("❌ Zincir verisi alınamadı (None veya boş).")
                    return
                logger.info(f"🔁 Zincir senkronize ediliyor... Blok sayısı: {len(received_chain)}")

                if len(received_chain) > len(local_blockchain.chain):
                    if chain_score(received_chain) > chain_score([b.to_dict() for b in local_blockchain.chain]):
                        fake_holder = type("ChainHolder", (), {"chain": received_chain})
                        if ChainValidator.validate_chain(fake_holder):
                            try:
                                new_chain = [Block.from_dict(b) for b in received_chain]
                                local_blockchain.chain = new_chain
                                local_blockchain.save_chain()
                                logger.info("✅ Zincir zincir puanı üstünlüğüne göre güncellendi.")
                            except Exception as e:
                                logger.error(f"🚨 Zincir güncelleme hatası: {e}")
                        else:
                            logger.warning("❌ Gelen zincir geçersiz.")
                    else:
                        logger.info("ℹ️ Zincir puanı mevcut zincirden düşük — güncellenmedi.")
                else:
                    logger.info("ℹ️ Gelen zincir uzunluğu yetersiz — güncellenmedi.")

            elif action == "NEW_BLOCK":
                block_data = data.get("block")
                logger.info(f"📦 Yeni blok alındı: #{block_data.get('index')} → Doğrulanıyor...")

                try:
                    validate_block_structure(block_data)
                    new_block = Block.from_dict(block_data)
                except Exception as e:
                    logger.warning(f"❌ Geçersiz blok yapısı: {e}")
                    banned_peers.add(peer_ip)
                    await websocket.close()
                    return

                if local_blockchain.validate_chain():
                    local_blockchain.chain.append(new_block)
                    local_blockchain.save_chain()
                    logger.info(f"✅ Blok #{new_block.index} zincire eklendi.")
                else:
                    logger.warning(f"❌ Blok #{new_block.index} zincire eklenemedi. Zincir geçersiz.")

            elif action == "NEW_TX":
                tx = data.get("transaction")
                txid = tx.get("txid")

                if not get_transaction_from_mempool(txid):
                    logger.info(f"📨 Yeni işlem alındı ve mempool'a eklendi: {txid}")
                    add_transaction_to_mempool(tx)
                else:
                    logger.info(f"🔁 İşlem zaten mempool'da var: {txid}")

    except ConnectionClosed:
        logger.warning(f"⚠️ Peer bağlantısı kapatıldı: {peer_ip}")
    finally:
        connected_peers.discard(websocket)
        logger.info(f"🔌 Peer bağlantısı kesildi: {peer_ip}")

async def start_p2p_server(host="0.0.0.0", port=8765):
    logger.info(f"🌐 P2P sunucusu başlatılıyor → {host}:{port}")
    async with serve(handler, host, port):
        await asyncio.Future()

async def broadcast_new_block(block_data):
    message = json.dumps({"action": "NEW_BLOCK", "block": block_data})
    for peer in list(connected_peers):
        if peer.open:
            try:
                await peer.send(message)
            except Exception as e:
                logger.warning(f"🚨 Blok yayını peer'a iletilemedi: {e}")
    logger.info(f"📢 Yeni blok {block_data.get('index')} peer'lara yayınlandı.")

async def broadcast_new_transaction(tx: dict):
    message = json.dumps({"action": "NEW_TX", "transaction": tx})
    for peer in list(connected_peers):
        if peer.open:
            try:
                await peer.send(message)
            except Exception as e:
                logger.warning(f"🚨 İşlem yayını peer'a iletilemedi: {e}")
    logger.info(f"📢 İşlem yayınlandı: {tx.get('txid')}")

async def request_chain_from(peer_url):
    try:
        async with connect(peer_url) as websocket:
            await websocket.send(json.dumps({"action": "REQUEST_CHAIN"}))
            logger.info(f"📡 Zincir isteği gönderildi: {peer_url}")

            response = await websocket.recv()
            data = json.loads(response)
            if data.get("action") == "BLOCKCHAIN":
                return data.get("chain")
    except Exception as e:
        logger.error(f"🚨 Zincir isteği başarısız: {e}")
        return None

def get_connected_peers_info():
    """Aktif bağlı peer'ları IP ve varsa kimlik bilgileriyle döndürür."""
    peer_list = []
    for peer in connected_peers:
        try:
            peer_info = {
                "ip": peer.remote_address[0] if peer.remote_address else "unknown",
                "status": "Bağlı",
                "peer_id": getattr(peer, "peer_id", "Bilinmiyor"),
                "public_key": getattr(peer, "public_key", "")[:20] + "..."
            }
            peer_list.append(peer_info)
        except Exception:
            continue
    return peer_list

@router.get("/api/peers")
def api_peers():
    return JSONResponse(content={"peers": get_connected_peers_info()})

class P2PNode:
    def __init__(self):
        pass

    @property
    def peers(self):
        return get_connected_peers_info()

