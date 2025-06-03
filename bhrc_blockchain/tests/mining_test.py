import pytest
from bhrc_blockchain.core.blockchain import mining

class Block:
    def __init__(self, timestamp):
        self.timestamp = timestamp

class BlockchainMock:
    def __init__(self, timestamps, prefix="00"):
        self.chain = [Block(ts) for ts in timestamps]
        self.adjustment_interval = 5
        self.target_block_time = 60  # saniye
        self.difficulty_prefix = prefix

    def adjust_difficulty(self):
        return mining.adjust_difficulty(self)

def test_adjust_difficulty_increase():
    # Bloklar hedef süreden hızlı üretildi → zorluk artmalı
    timestamps = [0, 50, 100, 150, 200, 240]  # ortalama 48s
    blockchain = BlockchainMock(timestamps, prefix="00")
    blockchain.adjust_difficulty()
    assert len(blockchain.difficulty_prefix) == 3  # "000"

def test_adjust_difficulty_decrease():
    # Bloklar hedef süreden yavaş üretildi → zorluk azalmalı
    timestamps = [0, 70, 140, 210, 280, 400]  # ortalama 80s
    blockchain = BlockchainMock(timestamps, prefix="0000")
    blockchain.adjust_difficulty()
    assert len(blockchain.difficulty_prefix) == 3  # "000"

def test_adjust_difficulty_no_change():
    # Hedef sürede üretim → zorluk değişmemeli
    timestamps = [0, 60, 120, 180, 240, 300]  # tam 60s
    blockchain = BlockchainMock(timestamps, prefix="0000")
    blockchain.adjust_difficulty()
    assert len(blockchain.difficulty_prefix) == 4  # aynı kaldı

