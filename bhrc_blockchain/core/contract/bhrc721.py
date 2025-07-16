# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

class BHRC721Contract:
    def __init__(self, name: str, symbol: str):
        self.name = name
        self.symbol = symbol
        self.tokens = {}  # token_id -> owner
        self.token_metadata = {}  # token_id -> metadata

    def mint(self, token_id: int, to_addr: str, metadata: dict = None) -> bool:
        if token_id in self.tokens:
            return False  # already minted
        self.tokens[token_id] = to_addr
        self.token_metadata[token_id] = metadata or {}
        return True

    def owner_of(self, token_id: int) -> str:
        return self.tokens.get(token_id, None)

    def transfer(self, token_id: int, from_addr: str, to_addr: str) -> bool:
        owner = self.tokens.get(token_id)
        if owner != from_addr:
            return False
        self.tokens[token_id] = to_addr
        return True

    def burn(self, token_id: int) -> bool:
        if token_id not in self.tokens:
            return False
        del self.tokens[token_id]
        del self.token_metadata[token_id]
        return True

    def metadata(self):
        return {
            "name": self.name,
            "symbol": self.symbol,
            "total_supply": len(self.tokens)
        }

    def get_abi(self):
        return {
            "name": self.name,
            "symbol": self.symbol,
            "total_supply": len(self.tokens),
            "methods": [
                "mint",
                "transfer",
                "owner_of",
                "burn",
                "metadata"
            ]
        }

