from typing import List, Dict, Any
from bhrc_blockchain.core.block import Block


class ChainValidator:
    @staticmethod
    def validate_chain(chain_holder: Any) -> bool:
        if not chain_holder.chain:
            print("❌ Zincir boş olamaz.")
            return False

        temp_utxos: Dict[tuple, dict] = {}
        for i in range(len(chain_holder.chain)):
            current = chain_holder.chain[i]

            if i > 0:
                previous = chain_holder.chain[i - 1]
                if current["previous_hash"] != previous["block_hash"]:
                    print(f"❌ Hata: Blok #{i} önceki hash uyuşmuyor.")
                    return False

            temp_block = Block(
                index=current["index"],
                previous_hash=current["previous_hash"],
                transactions=current["transactions"],
                miner_address=current["miner_address"],
                nonce=current["nonce"],
                version=current["version"],
                timestamp=current["timestamp"]
            )

            if current["merkle_root"] != temp_block.merkle_root:
                print(f"❌ Hata: Blok #{i} Merkle Root geçersiz.")
                return False

            if current["block_hash"] != temp_block.block_hash:
                print(f"❌ Hata: Blok #{i} hash yanlış hesaplanmış.")
                return False

            for tx in current["transactions"]:
                if tx["type"] == "coinbase":
                    for idx, out in enumerate(tx["outputs"]):
                        key = (tx["txid"], idx)
                        temp_utxos[key] = out
                    continue

                for txin in tx.get("inputs", []):
                    key = (txin["txid"], txin["output_index"])
                    if key not in temp_utxos:
                        print(f"❌ Hata: Blok #{i} içinde geçersiz veya harcanmış input: {key}")
                        return False
                    del temp_utxos[key]

                for idx, out in enumerate(tx.get("outputs", [])):
                    key = (tx["txid"], idx)
                    temp_utxos[key] = out

        print("✅ Zincir geçerli.")
        return True


def validate_block_structure(block: Dict[str, Any]) -> bool:
    required_fields = {
        "index", "block_hash", "previous_hash", "timestamp",
        "miner_address", "merkle_root", "nonce", "version",
        "virtual_size", "transactions"
    }

    if not required_fields.issubset(block):
        raise ValueError("Block sözleşmesi eksik alanlar içeriyor.")

    miner_addr = block.get("miner_address", "")
    if not isinstance(miner_addr, str) or not miner_addr.startswith("xBHR") or len(miner_addr) != 64:
        raise ValueError("Blok içindeki miner_address biçimi geçersiz.")

    for tx in block["transactions"]:
        tx_required = {"txid", "sender", "recipient", "amount", "fee", "message", "note", "type", "locktime", "time"}
        if not tx_required.issubset(tx):
            raise ValueError("İşlem sözleşmesi eksik alanlar içeriyor.")

        if tx["type"] != "coinbase":
            if "script_sig" not in tx or "public_key" not in tx:
                raise ValueError("İmza verisi eksik.")

    return True


def validate_block_transactions(transactions: List[dict]) -> List[dict]:
    return [tx for tx in transactions if tx.get("status") == "ready"]

