import sqlite3
import os
from bhrc_blockchain.core.mempool.mempool import get_ready_transactions
from bhrc_blockchain.network.p2p import connected_peers
from fastapi import APIRouter, Request, Query, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, Dict
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from datetime import datetime
from collections import defaultdict
from bhrc_blockchain.core.block import Block

router = APIRouter()
templates = Jinja2Templates(directory="bhrc_blockchain/templates")
blockchain = Blockchain()

class APIResponse(BaseModel):
    message: str
    data: Optional[Dict] = None


@router.get(
    "/mine",
    summary="Yeni blok kaz",
    description="Onaylanmış işlemleri içeren yeni bir blok oluşturur ve madenciye ödül verir.",
    response_model=APIResponse,
    responses={
        201: {"description": "Blok başarıyla kazıldı."},
        204: {"description": "Kazılacak işlem yok."}
    }
)
async def mine_block():
    block = await blockchain.mine_block()
    if block:
        return JSONResponse(
            status_code=201,
            content={
                "message": f"Blok #{block.index} başarıyla kazıldı.",
                "data": {"index": block.index, "hash": block.block_hash}
            }
        )
    return JSONResponse(status_code=204, content={"message": "İşlem yok veya blok oluşturulamadı."})


@router.get(
    "/chain",
    summary="Zinciri getir",
    description="Tüm blok zincirini JSON formatında döndürür.",
    response_model=APIResponse,
    responses={
        200: {"description": "Zincir başarıyla getirildi."}
    }
)
def get_chain():
    chain_data = [block.to_dict() for block in blockchain.chain]
    return JSONResponse(
        status_code=200,
        content={
            "message": "Zincir başarıyla getirildi.",
            "data": {
                "length": len(chain_data),
                "chain": chain_data
            }
        }
    )


@router.get(
    "/explorer",
    response_class=HTMLResponse,
    summary="Zincir explorer (HTML)",
    description="Son blokları HTML formatında gösteren tarayıcı arayüzü."
)
def explorer(request: Request):
    chain_data = [block.to_dict() for block in blockchain.chain][-15:][::-1]
    return templates.TemplateResponse("explorer.html", {"request": request, "chain": chain_data})

@router.get("/explorer/search", summary="Blokzincir üzerinde arama yap")
def explorer_search(q: str = Query(..., description="txid, block_hash veya xBHR adres")):
    try:
        blockchain = Blockchain(autoload=True)

        # 1. İşlem araması (txid eşleşirse)
        for block in blockchain.chain:
            for tx in block.transactions:
                if tx.get("txid") == q:
                    return {
                        "query": q,
                        "type": "transaction",
                        "result": tx
                    }

        # 2. Blok araması
        for block in blockchain.chain:
            if block.block_hash == q:
                return {
                    "query": q,
                    "type": "block",
                    "result": block.to_dict()
                }

        # 3. Adres araması
        if q.startswith("xBHR"):
            related_txs = []
            for block in blockchain.chain:
                for tx in block.transactions:
                    if tx.get("sender") == q or tx.get("recipient") == q:
                        related_txs.append(tx)
            return {
                "query": q,
                "type": "address",
                "results": related_txs
            }

        # Hiçbir sonuç bulunamadı
        return {"query": q, "type": "unknown", "message": "Eşleşen veri bulunamadı."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Arama hatası: {str(e)}")

@router.get("/explorer/search/ui", response_class=HTMLResponse, summary="Zincir arama arayüzü")
def explorer_search_ui(request: Request):
    return templates.TemplateResponse("explorer_search.html", {"request": request})

@router.get("/dashboard", response_class=HTMLResponse, summary="Zincir dashboard arayüzü")
def dashboard_ui(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@router.get("/dashboard/data", summary="Zincir durumunu getir")
def dashboard_data():
    blockchain = Blockchain(autoload=True)
    mempool = get_ready_transactions()

    total_blocks = len(blockchain.chain)
    total_transactions = sum(len(block.transactions) for block in blockchain.chain)
    total_peers = len(connected_peers)

    nft_count = 0
    if os.path.exists("nft.db"):
        conn = sqlite3.connect("nft.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM nfts")
        nft_count = c.fetchone()[0]
        conn.close()

    token_count = 0
    if os.path.exists("bhrc_token.db"):
        conn = sqlite3.connect("bhrc_token.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM tokens")
        token_count = c.fetchone()[0]
        conn.close()

    return {
        "total_blocks": total_blocks,
        "total_transactions": total_transactions,
        "mempool_size": len(mempool),
        "active_peers": total_peers,
        "total_nfts": nft_count,
        "total_tokens": token_count
    }

@router.get("/notifications/test", response_class=HTMLResponse, summary="WebSocket bildirim test arayüzü")
def websocket_test(request: Request):
    return templates.TemplateResponse("notifications_test.html", {"request": request})

@router.get("/notifications/subscribe", response_class=HTMLResponse)
def websocket_subscriber_ui(request: Request):
    return templates.TemplateResponse("notifications_subscriber.html", {"request": request})

@router.get("/notifications/subscribe", response_class=HTMLResponse, summary="Kişisel adres bildirim arayüzü")
def websocket_subscriber_ui(request: Request):
    return templates.TemplateResponse("notifications_subscriber.html", {"request": request})

@router.get("/explorer/search/advanced", summary="Gelişmiş zincir araması")
def advanced_search(
    q: Optional[str] = Query(None, description="txid, adres veya block_hash"),
    tx_type: Optional[str] = Query(None, description="İşlem tipi (transfer, token_transfer vs.)"),
    start: Optional[float] = Query(None, description="Başlangıç zaman damgası (timestamp)"),
    end: Optional[float] = Query(None, description="Bitiş zaman damgası (timestamp)"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100)
):
    blockchain = Blockchain(autoload=True)
    all_txs = []

    for block in blockchain.chain:
        for tx in block.transactions:
            tx["block_index"] = block.index
            all_txs.append(tx)

    results = []

    for tx in all_txs:
        if q:
            if not (
                q in tx.get("txid", "") or
                q in tx.get("sender", "") or
                q in tx.get("recipient", "") or
                q in tx.get("note", "") or
                q in str(tx.get("amount", ""))
            ):
                continue
        if tx_type and tx.get("type") != tx_type:
            continue
        if start and tx.get("time", 0) < start:
            continue
        if end and tx.get("time", 0) > end:
            continue
        results.append(tx)

    total = len(results)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paged_results = results[start_idx:end_idx]

    return {
        "query": q,
        "total": total,
        "page": page,
        "limit": limit,
        "results": paged_results
    }

@router.get("/dashboard/data/graph", summary="Grafikler için zincir verileri")
def dashboard_graph_data():
    blockchain = Blockchain(autoload=True)
    blocks = blockchain.chain[-20:]  # son 20 blok üzerinden analiz

    tx_counts = []
    block_indices = []
    block_timestamps = []
    type_counter = defaultdict(int)

    for block in blocks:
        block_indices.append(block.index)
        block_timestamps.append(block.timestamp)
        tx_counts.append(len(block.transactions))
        for tx in block.transactions:
            type_counter[tx.get("type", "unknown")] += 1

    return {
        "block_indices": block_indices,
        "tx_counts": tx_counts,
        "block_timestamps": block_timestamps,
        "tx_type_counts": dict(type_counter)
    }

@router.post("/sync", summary="Zincir senkronizasyonu (başka node'dan zincir al)")
def sync_chain(request: Request, payload: Dict):
    try:
        incoming_chain_raw = payload.get("chain", [])
        incoming_chain = [Block.from_dict(b) for b in incoming_chain_raw]

        success = blockchain.replace_chain_if_better(incoming_chain)
        if success:
            return {"message": "✅ Zincir güncellendi."}
        return {"message": "⚖️ Zincir güncellenmedi. Daha ağır değil veya geçersiz."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Sync hatası: {str(e)}")
