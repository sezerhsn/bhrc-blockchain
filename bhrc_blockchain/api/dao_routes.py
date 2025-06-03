from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Dict

from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.core.token.token_contract import TokenContract
from bhrc_blockchain.database.dao_storage import (
    init_dao_db, add_proposal, list_proposals,
    cast_vote, get_results
)

router = APIRouter()
init_dao_db()  # Uygulama başında bir kez çağrılır

# === Veri Modelleri ===

class ProposalRequest(BaseModel):
    title: str
    description: str
    symbol: str
    options: List[str]

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
        add_proposal(data.title, data.description, creator, data.symbol, data.options)
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
        cast_vote(data.proposal_id, voter, data.option, weight)
        return {"message": f"{data.option} için oy verildi.", "weight": weight}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/results/{proposal_id}", summary="Bir önerinin sonuçlarını getir")
def proposal_results(
    proposal_id: int,
    current_user: dict = Depends(get_current_user)
):
    try:
        results = get_results(proposal_id)
        return {"proposal_id": proposal_id, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/proposals", summary="Tüm DAO önerilerini getir")
def get_all_proposals(current_user: dict = Depends(get_current_user)):
    return {"proposals": list_proposals()}

# === Yardımcı ===
def get_symbol_for_proposal(proposal_id: int) -> str:
    proposals = list_proposals()
    for prop in proposals:
        if prop["id"] == proposal_id:
            return prop["symbol"]
    raise ValueError("Öneri bulunamadı.")

