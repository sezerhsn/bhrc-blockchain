# api_server.py (GÜNCELLENMİŞ)
import requests
import json
import re
import asyncio
from pydantic import BaseModel
from fastapi import FastAPI, Query
from typing import List
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.encoders import jsonable_encoder

from bhrc_blockchain.core.blockchain import Blockchain
from bhrc_blockchain.core.transaction import create_transaction
from bhrc_blockchain.core.token import TokenContract
from bhrc_blockchain.core.wallet import generate_wallet, MinerWallet
from bhrc_blockchain.core.mempool import add_transaction_to_mempool, mempool
from bhrc_blockchain.network.p2p import start_p2p_server, local_blockchain

nodes = set()
app = FastAPI(title="Behind The Random Coin API")
blockchain = Blockchain()
local_blockchain = blockchain

@app.post("/token/deploy")
def deploy_token(name: str, symbol: str, total_supply: float, decimals: int = 0, creator_private_key: str = Query(...)):
    try:
        creator = MinerWallet(private_key=creator_private_key).address
        token = TokenContract(name=name, symbol=symbol, total_supply=total_supply, decimals=decimals, creator=creator)
        tx = token.deploy(creator_private_key)
        tx["status"] = "ready"
        blockchain.current_transactions.append(tx)
        return {"message": f"{symbol} token'ı başarıyla deploy edildi.", "txid": tx["txid"]}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

class TokenTransferRequest(BaseModel):
    sender_private_key: str
    sender: str
    recipient: str
    symbol: str
    amount: float

@app.post("/token/transfer")
def transfer_token(data: TokenTransferRequest):
    try:
        tx = create_transaction(
            sender=data.sender,
            recipient=data.recipient,
            amount=data.amount,
            message="",
            note=data.symbol,
            tx_type="token_transfer",
            sender_private_key=data.sender_private_key
        )
        tx["status"] = "ready"
        blockchain.current_transactions.append(tx)
        return {"message": "Token transfer işlemi kuyruğa alındı", "txid": tx["txid"]}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.get("/token/balance")
def get_token_balance(address: str = Query(...), symbol: str = Query(...)):
    try:
        balance = TokenContract.balance_of(address, symbol)
        return {"address": address, "symbol": symbol, "balance": balance}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

