import asyncio
import websockets
import json

connected_peers = set()
local_blockchain = None  # dışarıdan atanmalı

async def handler(websocket, path):
    connected_peers.add(websocket)
    try:
        async for message in websocket:
            data = json.loads(message)
            if data.get("type") == "chain_request":
                await websocket.send(json.dumps({
                    "type": "chain_response",
                    "chain": local_blockchain.chain
                }))
            elif data.get("type") == "new_block":
                print("🧱 Yeni blok alındı (P2P üzerinden)")
                new_block = data["block"]

                temp_chain = local_blockchain.chain.copy()
                temp_chain.append(new_block)

                # Geçici zincir ile test
                original_chain = local_blockchain.chain
                local_blockchain.chain = temp_chain

                if local_blockchain.validate_chain():
                    print("✅ Yeni blok doğrulandı ve zincire eklendi.")
                else:
                    print("❌ Yeni blok geçersiz, zincire eklenmedi.")
                    local_blockchain.chain = original_chain  # zinciri geri yükle

    finally:
        connected_peers.remove(websocket)

async def start_p2p_server(host="0.0.0.0", port=8765):
    async with websockets.serve(handler, host, port):
        print(f"🌐 P2P sunucusu dinleniyor: ws://{host}:{port}")
        await asyncio.Future()  # Sonsuz bekleme

async def broadcast_new_block(block):
    if connected_peers:
        message = json.dumps({
            "type": "new_block",
            "block": block
        })
        await asyncio.wait([peer.send(message) for peer in connected_peers])

async def request_chain_from(peer_url):
    try:
        async with websockets.connect(peer_url) as websocket:
            await websocket.send(json.dumps({"type": "chain_request"}))
            response = await websocket.recv()
            data = json.loads(response)
            return data.get("chain")
    except Exception as e: # pragma: no cover
        print("❌ DEBUG: except bloğuna girildi") # pragma: no cover
        print(f"❌ Zincir istenirken hata: {peer_url} → {e}") # pragma: no cover
        return None # pragma: no cover

