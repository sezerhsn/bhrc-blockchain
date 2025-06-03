# tests/confirmation_watcher_test.py
import pytest
import asyncio
from unittest.mock import AsyncMock
from bhrc_blockchain.tools.confirmation_watcher import watch_transaction_confirmation

class DummyBlock:
    def __init__(self, index, txs):
        self.index = index
        self.transactions = txs

class DummyChain:
    def __init__(self, chain):
        self.chain = chain

@pytest.mark.asyncio
async def test_watch_transaction_confirmation_found():
    txid = "tx123"
    mock_tx = {"txid": txid, "type": "transfer", "outputs": []}
    blockchain = DummyChain([
        DummyBlock(0, []),
        DummyBlock(1, [mock_tx])
    ])

    result = await watch_transaction_confirmation(txid, blockchain, timeout=3)
    assert result is True

@pytest.mark.asyncio
async def test_watch_transaction_confirmation_timeout():
    txid = "tx_not_found"
    blockchain = DummyChain([
        DummyBlock(0, []),
        DummyBlock(1, [])
    ])

    result = await watch_transaction_confirmation(txid, blockchain, timeout=2)
    assert result is False

