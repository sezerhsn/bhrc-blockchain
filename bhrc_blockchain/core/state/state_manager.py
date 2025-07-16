# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import json
import os

class StateManager:
    def __init__(self, state_file: str = "state.json"):
        self.state_file = state_file
        self.state = self.load_state()

    def load_state(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, "r") as f:
                return json.load(f)
        return {}

    def save_state(self):
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=4)

    def apply_transactions(self, transactions):
        for tx in transactions:
            sender = tx.get("sender")
            recipient = tx.get("recipient")
            amount = tx.get("amount", 0)

            # CoinBase işlemi: sender = SYSTEM
            if sender != "SYSTEM":
                self.state[sender] = self.state.get(sender, 0) - amount
            self.state[recipient] = self.state.get(recipient, 0) + amount

        self.save_state()

    def get_balance(self, address: str) -> float:
        return self.state.get(address, 0.0)

    def init_genesis_state(self, recipient: str, amount: float):
        self.state[recipient] = amount
        self.save_state()

