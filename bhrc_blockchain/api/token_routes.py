# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import os
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.core.token.token_contract import (
    create_token_transaction,
    create_token_transfer_transaction,
    get_token_balance,
    get_token_transfers,
    get_all_tokens,
    get_token_details,
)
from bhrc_blockchain.core.blockchain.blockchain import get_blockchain
from bhrc_blockchain.utils.utils import render_template
from bhrc_blockchain.tools.confirmation_watcher import watch_transaction_confirmation
from bhrc_blockchain.core.logger.logging_utils import setup_logger
from bhrc_blockchain.core.mempool.mempool import add_transaction_to_mempool, get_transaction_from_mempool

logger = setup_logger("TokenRoutes")
router = APIRouter()


@router.post("/token/deploy")
async def deploy_token(
    request: Request,
    name: str,
    symbol: str,
    total_supply: int,
    decimals: int,
    creator_address: str,
    message: str,
    signature: str,
    blockchain=Depends(get_blockchain),
    current_user=Depends(get_current_user),
):
    try:
        tx = create_token_transaction(name, symbol, total_supply, decimals, creator_address, message, signature, blockchain)
        if not get_transaction_from_mempool(tx["txid"]):
            add_transaction_to_mempool(tx)
        await watch_transaction_confirmation(tx["txid"], blockchain)
        return {"message": "Token oluşturma işlemi mempool'a eklendi", **tx}
    except Exception as e:
        logger.error(f"Token oluşturulamadı: {e}")
        return [{"detail": f"Token oluşturulamadı: {str(e)}"}, 400]


@router.post("/token/transfer")
async def transfer_token(
    request: Request,
    symbol: str,
    amount: int,
    sender_address: str,
    recipient_address: str,
    message: str,
    signature: str,
    blockchain=Depends(get_blockchain),
    current_user=Depends(get_current_user),
):
    try:
        tx = create_token_transfer_transaction(symbol, amount, sender_address, recipient_address, message, signature, blockchain)
        if not get_transaction_from_mempool(tx["txid"]):
            add_transaction_to_mempool(tx)
        await watch_transaction_confirmation(tx["txid"], blockchain)
        return {"message": "Token transfer işlemi mempool'a eklendi", **tx}
    except Exception as e:
        logger.error(f"Token transferi başarısız: {e}")
        return [{"detail": f"Token transferi başarısız: {str(e)}"}, 400]


@router.get("/token/balance")
async def read_token_balance(
    symbol: str,
    address: str,
    blockchain=Depends(get_blockchain),
    current_user=Depends(get_current_user),
):
    try:
        balance = get_token_balance(symbol, address, blockchain)
        return balance
    except Exception as e:
        logger.error(f"Bakiye alınamadı: {e}")
        return [{"detail": f"Bakiye alınamadı: {str(e)}"}, 400]


@router.get("/token/transfers")
async def read_token_transfers(
    symbol: str,
    address: str,
    blockchain=Depends(get_blockchain),
    current_user=Depends(get_current_user),
):
    try:
        transfers = get_token_transfers(symbol, address, blockchain)
        return transfers
    except Exception as e:
        logger.error(f"Transfer geçmişi alınamadı: {e}")
        return [{"detail": f"Transfer geçmişi alınamadı: {str(e)}"}, 400]


@router.get("/token/explorer", response_class=HTMLResponse)
async def token_explorer(request: Request, blockchain=Depends(get_blockchain)):
    try:
        tokens = get_all_tokens(blockchain)
        return render_template("panel/token.html", request, {"tokens": tokens})
    except Exception as e:
        logger.error(f"Token explorer hatası: {e}")
        return HTMLResponse(content="Hata oluştu", status_code=500)


@router.get("/token/details")
async def token_details(symbol: str, blockchain=Depends(get_blockchain)):
    try:
        return get_token_details(symbol, blockchain)
    except Exception as e:
        logger.error(f"Token detayları alınamadı: {e}")
        return [{"detail": f"Token detayları alınamadı: {str(e)}"}, 400]

@router.get("/token/all")
async def token_list(blockchain=Depends(get_blockchain)):
    return get_all_tokens(blockchain)

