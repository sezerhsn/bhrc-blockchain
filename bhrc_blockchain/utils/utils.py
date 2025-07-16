# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import os
import hashlib
import time
import random
from datetime import datetime
from fastapi.templating import Jinja2Templates

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

def get_readable_time(timestamp=None):
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp).strftime('%d-%m-%Y %H:%M:%S')

def get_random_quote():
    quotes = [
        "Coin'ler geçer, kod kalır.",
        "Blockchain, güvenin yeni adıdır.",
        "Gelecek, kodla yazılmıştır.",
        "Her blok bir hikayedir.",
        "Gerçek özgürlük, merkeziyetsizliktir.",
        "Rastgelelik, evrenin temel yasasıdır.",
    ]
    return random.choice(quotes)

def generate_address(public_key: str) -> str:
    prefix = "xBHR"
    hashed = hashlib.sha256(public_key.encode()).hexdigest()
    return prefix + hashed[:60]

generate_address_from_public_key = generate_address

def render_template(template_name: str, request, context: dict):
    return templates.TemplateResponse(template_name, {"request": request, **context})

