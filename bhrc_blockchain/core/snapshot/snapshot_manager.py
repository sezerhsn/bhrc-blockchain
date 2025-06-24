import json
import os
import time
from typing import List
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.network.notifications import emit_admin_alert

def save_snapshot(blockchain, path: str = "snapshot.json", current_admin: str = "unknown") -> None:
    chain_data = [block.to_dict() for block in blockchain.chain]
    with open(path, "w") as f:
        json.dump(chain_data, f, indent=4)
    print(f"[Snapshot] ✅ Zincir başarıyla kaydedildi: {path}")

    emit_admin_alert("snapshot_created", {
        "by": current_admin,
        "timestamp": time.time()
    })

def load_snapshot(path: str = "snapshot.json") -> List[Block]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Snapshot dosyası bulunamadı: {path}")
    with open(path, "r") as f:
        chain_data = json.load(f)
    return [Block.from_dict(block_data) for block_data in chain_data]

