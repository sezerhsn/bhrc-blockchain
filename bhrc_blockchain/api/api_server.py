# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from bhrc_blockchain.network.notifications import websocket_connections
from bhrc_blockchain.api.token_routes import router as token_router
from bhrc_blockchain.api.chain_routes import router as chain_router
from bhrc_blockchain.api.wallet_routes import router as wallet_router
from bhrc_blockchain.api.auth_routes import router as auth_router
from bhrc_blockchain.api.transaction_routes import router as transaction_router
from bhrc_blockchain.api.dao_routes import router as dao_router
from bhrc_blockchain.api.nft_routes import router as nft_router
from bhrc_blockchain.api.multisig_routes import router as multisig_router
from bhrc_blockchain.api.panel_routes import router as panel_router
from bhrc_blockchain.api.contract_routes import router as contract_router
from bhrc_blockchain.api.admin_routes import router as admin_router
from bhrc_blockchain.api.state_routes import router as state_router
from bhrc_blockchain.api.consensus_routes import router as consensus_router
from bhrc_blockchain.api.export_routes import router as export_router

app = FastAPI(title="Behind The Random Coin API")

app.include_router(token_router, tags=["Token"])
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(chain_router, tags=["Blockchain"])
app.include_router(wallet_router, prefix="/wallet", tags=["Wallet"])
app.include_router(transaction_router, prefix="/transaction", tags=["Transaction"])
app.include_router(dao_router, prefix="/dao", tags=["DAO"])
app.include_router(nft_router, prefix="/nft", tags=["NFT"])
app.include_router(multisig_router, prefix="/multisig", tags=["Multisig"])
app.include_router(panel_router, tags=["Panel"])
app.include_router(contract_router, prefix="/contract", tags=["SmartContract"])
app.include_router(admin_router, tags=["Admin"])
app.include_router(state_router, prefix="/state", tags=["State"])
app.include_router(consensus_router, prefix="/consensus", tags=["Consensus"])
app.include_router(export_router, prefix="/export", tags=["Export"])

@app.get("/", tags=["Docs"])
def root():
    return {"message": "Behind The Random Coin API → Swagger: /docs"}

@app.websocket("/ws/admin-events")
async def admin_events_ws(websocket: WebSocket):
    await websocket.accept()
    if websocket not in websocket_connections:
        websocket_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in websocket_connections:
            websocket_connections.remove(websocket)

