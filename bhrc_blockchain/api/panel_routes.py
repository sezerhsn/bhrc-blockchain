from fastapi import APIRouter, Request, Depends, HTTPException, Response
from bhrc_blockchain.utils.export_utils import export_logs_to_csv, export_logs_to_pdf
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from bhrc_blockchain.api.auth import get_current_user, verify_token
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.mempool.mempool import get_ready_transactions
from bhrc_blockchain.database.dao_storage import DAOStorage
from bhrc_blockchain.database.nft_storage import NFTStorage
from bhrc_blockchain.network.p2p import P2PNode
from typing import Optional
from sqlalchemy.orm import Session
from bhrc_blockchain.database.models import LogModel, UndoLog
from bhrc_blockchain.database.database import SessionLocal

router = APIRouter()
templates = Jinja2Templates(directory="bhrc_blockchain/templates")

@router.get("/panel/login", response_class=HTMLResponse)
def panel_login(request: Request):
    return templates.TemplateResponse("panel/login.html", {"request": request})

@router.get("/panel/wallet", response_class=HTMLResponse)
def panel_wallet(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("panel/wallet.html", {"request": request})

@router.get("/panel/token", response_class=HTMLResponse)
def panel_token(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("panel/token.html", {"request": request})

@router.get("/panel/nft", response_class=HTMLResponse)
def panel_nft(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("panel/nft.html", {"request": request})

@router.get("/panel/explorer", response_class=HTMLResponse)
def panel_explorer(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("panel/explorer.html", {"request": request})

@router.get("/panel/overview", response_class=HTMLResponse)
def panel_overview(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("panel/overview.html", {"request": request})

@router.get("/panel/graph", response_class=HTMLResponse)
async def graph_page(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("panel/graph.html", {"request": request})

@router.get("/panel/status", response_class=HTMLResponse)
def panel_status(request: Request, current_user: dict = Depends(get_current_user)):
    blockchain = Blockchain()
    dao_storage = DAOStorage()
    nft_storage = NFTStorage()
    p2p = P2PNode()

    chain = blockchain.chain
    last_10_blocks = chain[-10:]
    block_labels = [f"Blok {i}" for i in range(len(chain) - len(last_10_blocks) + 1, len(chain) + 1)]
    block_sizes = [len(str(block.__dict__)) for block in last_10_blocks]
    block_tx_counts = [len(block.transactions) for block in last_10_blocks]

    return templates.TemplateResponse("panel/status.html", {
        "request": request,
        "total_blocks": len(chain),
        "total_transactions": sum(len(block.transactions) for block in chain),
        "mempool_size": len(get_ready_transactions()),
        "last_block_hash": chain[-1].block_hash if chain else "Yok",
        "block_labels": block_labels,
        "block_sizes": block_sizes,
        "block_tx_counts": block_tx_counts,
        "total_tokens": len(dao_storage.get_all_tokens()),
        "total_nfts": len(nft_storage.get_all_nfts()),
        "peer_count": len(p2p.peers)
    })

@router.get("/panel/status-data")
def get_panel_status_data(current_user: dict = Depends(get_current_user)):
    blockchain = Blockchain()
    dao_storage = DAOStorage()
    nft_storage = NFTStorage()
    p2p = P2PNode()
    chain = blockchain.chain

    last_10_blocks = chain[-10:]
    block_labels = [f"Blok {i}" for i in range(len(chain) - len(last_10_blocks) + 1, len(chain) + 1)]
    block_sizes = [len(str(block.__dict__)) for block in last_10_blocks]
    block_tx_counts = [len(block.transactions) for block in last_10_blocks]

    return {
        "total_blocks": len(chain),
        "total_transactions": sum(len(block.transactions) for block in chain),
        "mempool_size": len(get_ready_transactions()),
        "last_block_hash": chain[-1].block_hash if chain else "Yok",
        "total_tokens": len(dao_storage.get_all_tokens()),
        "total_nfts": len(nft_storage.get_all_nfts()),
        "peer_count": len(p2p.peers),
        "block_labels": block_labels,
        "block_sizes": block_sizes,
        "block_tx_counts": block_tx_counts,
        "latest_timestamp": chain[-1].timestamp if chain else None,
        "difficulty": blockchain.difficulty_prefix,
        "unique_addresses": len(set(
            tx["recipient"] for block in chain for tx in block.transactions
        )),
        "total_supply": sum(
            output["amount"]
            for block in chain
            for tx in block.transactions
            for output in tx.get("outputs", [])
        )
    }

@router.get("/panel/transfer", response_class=HTMLResponse)
async def transfer_form(request: Request):
    return templates.TemplateResponse("panel/transfer.html", {"request": request})

@router.get("/panel/history", response_class=HTMLResponse)
async def wallet_history(request: Request):
    return templates.TemplateResponse("panel/history.html", {"request": request})

@router.get("/panel/peers", response_class=HTMLResponse)
async def peer_page(request: Request):
    return templates.TemplateResponse("panel/peers.html", {"request": request})

@router.get("/panel/admin", response_class=HTMLResponse)
async def admin_page(request: Request, token_data=Depends(verify_token)):
    if token_data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Erişim reddedildi")
    return templates.TemplateResponse("panel/admin.html", {"request": request, "user": token_data})

@router.get("/panel/home", response_class=HTMLResponse)
async def panel_home(request: Request):
    return templates.TemplateResponse("panel/home.html", {"request": request})

@router.get("/panel/snapshot", summary="Zincir snapshot verisi (basitleştirilmiş)")
def get_chain_snapshot(current_user: dict = Depends(get_current_user)):
    blockchain = Blockchain()
    snapshot = []

    for block in blockchain.chain:
        snapshot.append({
            "index": block.index,
            "hash": block.block_hash,
            "tx_count": len(block.transactions),
            "miner": block.miner_address,
            "timestamp": block.timestamp,
            "size": block.virtual_size,
            "events": block.events
        })

    return {"length": len(snapshot), "chain": snapshot}

@router.get("/admin/history", response_class=HTMLResponse)
async def admin_history(
    request: Request,
    user_id: Optional[str] = None,
    sort: Optional[str] = "desc"
):
    session: Session = SessionLocal()
    query = session.query(LogModel)

    if user_id:
        query = query.filter(LogModel.user_id == user_id)

    if sort == "asc":
        query = query.order_by(LogModel.timestamp.asc())
    else:
        query = query.order_by(LogModel.timestamp.desc())

    logs = query.all()
    return templates.TemplateResponse("panel/history.html", {
        "request": request,
        "logs": logs
    })

@router.get("/admin/export_logs")
async def export_logs(format: str = "csv"):
    session = SessionLocal()
    logs = session.query(UndoLog).all()

    if format == "csv":
        csv_data = export_logs_to_csv(logs)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=logs.csv"}
        )
    elif format == "pdf":
        pdf_data = export_logs_to_pdf(logs)
        return Response(
            content=pdf_data.read(),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=logs.pdf"}
        )
    else:
        raise HTTPException(status_code=400, detail="Format desteklenmiyor. csv veya pdf kullanın.")

