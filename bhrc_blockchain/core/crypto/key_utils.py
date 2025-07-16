# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from ecdsa import SigningKey, SECP256k1
import json
import os

def generate_keypair():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key.to_string().hex(), public_key.to_string().hex()

def save_wallet(wallet_path, wallet_data):
    os.makedirs(os.path.dirname(wallet_path), exist_ok=True)
    with open(wallet_path, 'w') as f:
        json.dump(wallet_data, f, indent=4)

