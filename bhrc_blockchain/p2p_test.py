# p2p_test.py
import json
import asyncio
import pytest

from unittest.mock import AsyncMock, patch, MagicMock
from bhrc_blockchain.network import p2p
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.blockchain import Blockchain

@pytest.fixture
def fake_blockchain():
    class FakeBlockchain:
        def __init__(self):
            self.chain = [{"index": 0, "block_hash": "abc", "previous_hash": "0", "transactions": []}]
        def validate_chain(self):
            return False
    return FakeBlockchain()

@pytest.mark.asyncio
async def test_chain_request_handler(fake_blockchain):
    mock_ws = AsyncMock()
    p2p.local_blockchain = fake_blockchain
    await p2p.handler(mock_ws, "/")
    mock_ws.send.assert_not_called()

@pytest.mark.asyncio
async def test_new_block_validation(fake_blockchain):
    p2p.local_blockchain = fake_blockchain
    fake_block = {"index": 1, "block_hash": "bad", "previous_hash": "abc", "transactions": []}
    ws = AsyncMock()
    ws.__aiter__.return_value = iter([
        '{"type": "new_block", "block": {"index": 1, "block_hash": "bad", "previous_hash": "abc", "transactions": []}}'
    ])
    await p2p.handler(ws, "/")
    assert fake_blockchain.chain[0]["block_hash"] == "abc"

@pytest.mark.asyncio
async def test_request_chain_from_peer():
    with patch("websockets.connect") as mock_connect:
        mock_ws = AsyncMock()
        mock_ws.recv.return_value = '{"type": "chain_response", "chain": [{"index":0}]}'
        mock_connect.return_value.__aenter__.return_value = mock_ws
        result = await p2p.request_chain_from("ws://fake-peer")
        assert isinstance(result, list)
        assert result[0]["index"] == 0

@pytest.mark.asyncio
async def test_broadcast_new_block_sends_to_all_peers():
    mock_ws1 = AsyncMock()
    mock_ws2 = AsyncMock()
    p2p.connected_peers.clear()
    p2p.connected_peers.update({mock_ws1, mock_ws2})
    test_block = {"index": 1, "data": "dummy"}
    await p2p.broadcast_new_block(test_block)
    expected_message = json.dumps({"type": "new_block", "block": test_block})
    mock_ws1.send.assert_awaited_with(expected_message)
    mock_ws2.send.assert_awaited_with(expected_message)

@pytest.mark.asyncio
async def test_request_chain_from_handles_error():
    with patch("websockets.connect", side_effect=Exception("Bağlantı hatası")):
        chain = await p2p.request_chain_from("ws://fake-peer")
        assert chain is None

@pytest.mark.asyncio
async def test_handler_chain_request():
    fake_chain = [{"index": 0, "previous_hash": "0", "transactions": [], "nonce": 0, "miner_address": "abc"}]
    mock_ws = AsyncMock()
    mock_ws.__aiter__.return_value = iter([json.dumps({"type": "chain_request"})])
    mock_ws.send = AsyncMock()
    class DummyBlockchain:
        chain = fake_chain
        def validate_chain(self): return True
    p2p.local_blockchain = DummyBlockchain()
    await p2p.handler(mock_ws, "/dummy-path")
    mock_ws.send.assert_awaited_once()
    sent_data = json.loads(mock_ws.send.call_args[0][0])
    assert sent_data["type"] == "chain_response"
    assert sent_data["chain"] == fake_chain

@pytest.mark.asyncio
async def test_handler_new_block_valid_chain():
    blockchain = Blockchain()
    blockchain.validate_chain = lambda: True
    blockchain.chain = [{"index": 0, "block_hash": "0", "previous_hash": "0", "transactions": []}]
    p2p.local_blockchain = blockchain
    new_block = {"index": 1, "block_hash": "1", "previous_hash": "0", "transactions": []}
    websocket = AsyncMock()
    websocket.__aiter__.return_value = [json.dumps({"type": "new_block", "block": new_block})]
    await p2p.handler(websocket, "/")
    assert p2p.local_blockchain.chain[-1] == new_block

@pytest.mark.asyncio
async def test_handler_new_block_invalid_chain():
    blockchain = Blockchain()
    blockchain.validate_chain = lambda: False
    blockchain.chain = [{"index": 0, "block_hash": "0", "previous_hash": "0", "transactions": []}]
    p2p.local_blockchain = blockchain
    new_block = {"index": 1, "block_hash": "1", "previous_hash": "0", "transactions": []}
    websocket = AsyncMock()
    websocket.__aiter__.return_value = [json.dumps({"type": "new_block", "block": new_block})]
    await p2p.handler(websocket, "/")
    assert len(p2p.local_blockchain.chain) == 1

