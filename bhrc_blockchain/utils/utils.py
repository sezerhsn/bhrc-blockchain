# utils.py
import time
import random
from datetime import datetime

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
    import hashlib
    prefix = "xBHR"
    hashed = hashlib.sha256(public_key.encode()).hexdigest()
    return prefix + hashed[:60]

