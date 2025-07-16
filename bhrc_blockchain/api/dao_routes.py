# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.core.token.token_contract import TokenContract
from bhrc_blockchain.database import dao_storage

router = APIRouter()
dao_storage.init_dao_db()

# === Veri Modelleri ===

class ProposalRequest(BaseModel):
    title: str
    description: str
    symbol: str
    options: List[str]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

class VoteRequest(BaseModel):
    proposal_id: int
    option: str

# === API Endpoints ===

@router.post("/propose", summary="Yeni DAO önerisi oluştur")
def propose_dao(
    data: ProposalRequest,
    current_user: dict = Depends(get_current_user)
):
    creator = current_user["sub"]
    try:
        dao_storage.add_proposal(data.title, data.description, creator, data.symbol, data.options,
                                 start_time=data.start_time, end_time=data.end_time)

        return {"message": "Öneri başarıyla oluşturuldu."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/vote", summary="Bir DAO önerisine oy ver")
def vote_on_proposal(
    data: VoteRequest,
    current_user: dict = Depends(get_current_user)
):
    voter = current_user["sub"]
    try:
        symbol = get_symbol_for_proposal(data.proposal_id)
        weight = TokenContract.balance_of(voter, symbol)
        if weight <= 0:
            raise HTTPException(status_code=403, detail="Bu token ile oy hakkınız yok.")
        dao_storage.cast_vote(data.proposal_id, voter, data.option, weight)

        with open("audit.log", "a") as f:
            f.write(f"[{datetime.utcnow()}] VOTE → user={voter}, proposal={data.proposal_id}, option={data.option}, weight={weight}\n")

        return {"message": f"{data.option} için oy verildi.", "weight": weight}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/results/{proposal_id}", summary="Bir önerinin sonuçlarını getir")
def proposal_results(
    proposal_id: int,
    current_user: dict = Depends(get_current_user)
):
    try:
        results = dao_storage.get_results(proposal_id)
        return {"proposal_id": proposal_id, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/proposals", summary="Tüm DAO önerilerini getir")
def get_all_proposals(current_user: dict = Depends(get_current_user)):
    try:
        return {"proposals": dao_storage.list_proposals()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))  # ⬅️ BURAYA

# === Yardımcı ===
def get_symbol_for_proposal(proposal_id: int) -> str:
    proposals = dao_storage.list_proposals()
    for prop in proposals:
        if prop["id"] == proposal_id:
            return prop["symbol"]
    raise ValueError("Öneri bulunamadı.")

@router.get("/proposal/{proposal_id}", summary="Tek bir DAO önerisini getir")
def get_proposal_by_id(proposal_id: int, current_user: dict = Depends(get_current_user)):
    proposals = dao_storage.list_proposals()
    for prop in proposals:
        if prop["id"] == proposal_id:
            return {"proposal": prop}
    raise HTTPException(status_code=404, detail="Öneri bulunamadı.")

@router.delete("/proposal/{proposal_id}", summary="DAO önerisini sil (mock)")
def delete_proposal(proposal_id: int, current_user: dict = Depends(get_current_user)):
    proposals = dao_storage.list_proposals()
    for prop in proposals:
        if prop["id"] == proposal_id:
            if prop.get("creator") != current_user["sub"]:
                raise HTTPException(status_code=403, detail="Bu öneriyi silme yetkiniz yok.")
            return {"message": f"Öneri (id={proposal_id}) silinmiş varsayılıyor."}
    raise HTTPException(status_code=404, detail="Silinecek öneri bulunamadı.")

@router.get("/proposals/me", summary="Kullanıcının oluşturduğu DAO önerilerini getir")
def get_my_proposals(current_user: dict = Depends(get_current_user)):
    user = current_user["sub"]
    proposals = dao_storage.list_proposals()
    my_props = [p for p in proposals if p.get("creator") == user]
    return {"proposals": my_props}

def get_my_votes(current_user: dict = Depends(get_current_user)):
    user = current_user["sub"]
    all_proposals = dao_storage.list_proposals()
    my_votes = []

    for prop in all_proposals:
        results = dao_storage.get_results(prop["id"])
        for option, vote_data in results.items():
            if isinstance(vote_data, dict):
                for voter, weight in vote_data.items():
                    if voter == user:
                        my_votes.append({
                            "proposal_id": prop["id"],
                            "title": prop["title"],
                            "option": option,
                            "weight": weight
                        })
    return {"votes": my_votes}

@router.get("/votes/me", summary="Kullanıcının verdiği tüm oyları getir")
def get_my_votes_api(current_user: dict = Depends(get_current_user)):
    return get_my_votes(current_user)

def get_proposal_status(proposal_id: int, current_user: dict = Depends(get_current_user)):
    proposals = dao_storage.list_proposals()
    for prop in proposals:
        if prop["id"] == proposal_id:
            return {"proposal_id": proposal_id, "status": "open"}
    raise HTTPException(status_code=404, detail="Öneri bulunamadı.")

@router.get("/proposal/{proposal_id}/stats", summary="Öneri oylama istatistiklerini getir")
def proposal_stats(proposal_id: int, current_user: dict = Depends(get_current_user)):
    try:
        results = dao_storage.get_results(proposal_id)
        total_votes = sum(
            sum(option_votes.values()) for option_votes in results.values() if isinstance(option_votes, dict)
        )
        total_voters = len(
            set(voter for option in results.values() if isinstance(option, dict) for voter in option.keys())
        )
        return {
            "proposal_id": proposal_id,
            "total_votes_weight": total_votes,
            "total_unique_voters": total_voters
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/proposal/{proposal_id}/close", summary="Bir öneriyi kapat")
def close_proposal_api(proposal_id: int, current_user: dict = Depends(get_current_user)):
    from bhrc_blockchain.database.dao_storage import close_proposal
    try:
        dao_storage.close_proposal(proposal_id)
        return {"message": f"Öneri (id={proposal_id}) kapatıldı."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/proposal/{proposal_id}/votes", summary="Öneriye ait tüm oyları getir")
def get_votes_api(proposal_id: int, current_user: dict = Depends(get_current_user)):
    from bhrc_blockchain.database.dao_storage import get_votes_for_proposal
    try:
        votes = dao_storage.get_votes_for_proposal(proposal_id)
        return {"proposal_id": proposal_id, "votes": votes}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/proposals/closed", summary="Kapalı DAO önerilerini getir")
def get_closed_proposals_api(current_user: dict = Depends(get_current_user)):
    from bhrc_blockchain.database.dao_storage import list_closed_proposals
    try:
        return {"proposals": dao_storage.list_closed_proposals()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/proposal/{proposal_id}/summary", summary="Öneri özeti")
def get_proposal_summary(proposal_id: int, current_user: dict = Depends(get_current_user)):
    try:
        prop = dao_storage.get_proposal_by_id(proposal_id)
        if not prop or "id" not in prop:
            raise HTTPException(status_code=404, detail="Öneri bulunamadı")

        results = dao_storage.get_results(proposal_id)

        total_weight = sum(
            sum(option_votes.values())
            for option_votes in results.values()
            if isinstance(option_votes, dict)
        )

        return {
            "proposal_id": prop["id"],
            "title": prop["title"],
            "status": prop["status"],
            "options": prop["options"],
            "total_votes_weight": total_weight
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/proposal/{proposal_id}/timed-status", summary="Önerinin zamanlamaya göre durumunu getir")
def get_proposal_timed_status(proposal_id: int, current_user: dict = Depends(get_current_user)):
    try:
        prop = dao_storage.get_proposal_by_id(proposal_id)
        if not prop or "id" not in prop:
            raise HTTPException(status_code=404, detail="Öneri bulunamadı")

        now = datetime.utcnow().timestamp()
        start = prop.get("start_time") or 0
        end = prop.get("end_time")

        if end is None:
            end = now + 100 * 365 * 24 * 60 * 60

        status = "active" if start <= now <= end else "inactive"

        return {
            "proposal_id": prop["id"],
            "status": status,
            "start_time": int(start),
            "end_time": int(end)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

