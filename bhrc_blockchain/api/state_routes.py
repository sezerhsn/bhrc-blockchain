from fastapi import APIRouter
from bhrc_blockchain.core.state.state_manager import StateManager

router = APIRouter(tags=["State"])
state = StateManager()

@router.get("/balance/{address}")
def get_balance(address: str):
    balance = state.get_balance(address)
    return {"address": address, "balance": balance}

@router.get("/all")
def get_all_balances():
    return {"state": state.state}

@router.get("/stats/{address}")
def get_address_stats(address: str):
    incoming = 0
    outgoing = 0
    net_gain = 0.0

    from bhrc_blockchain.core.blockchain.blockchain import get_blockchain
    blockchain = get_blockchain()

    for block in blockchain.chain:
        for tx in block.transactions:
            # Giden işlemler
            if tx.get("sender") == address:
                outgoing += 1
                net_gain -= tx.get("amount", 0)

            # Gelen işlemler
            recipient_direct = tx.get("recipient")
            if recipient_direct == address:
                incoming += 1
                net_gain += tx.get("amount", 0)

            # 🔍 outputs içindeki tüm adresleri tara
            for output in tx.get("outputs", []):
                if output.get("recipient") == address or output.get("address") == address:
                    incoming += 1
                    net_gain += output.get("amount", 0)

    return {
        "address": address,
        "balance": state.get_balance(address),
        "incoming_tx_count": incoming,
        "outgoing_tx_count": outgoing,
        "net_gain": net_gain
    }

