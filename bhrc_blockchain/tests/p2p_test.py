import pytest
import asyncio
import json
import threading
import time
from unittest.mock import AsyncMock, patch, MagicMock
from bhrc_blockchain.network import p2p
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.blockchain.blockchain import Blockchain

@pytest.fixture(autouse=True)
def reset_blockchain():
    p2p.local_blockchain = MagicMock()
    genesis = Block(index=0, previous_hash="0", transactions=[], timestamp=time.time(), nonce=0, miner_address="xBHR" + "0" * 60)
    p2p.local_blockchain.chain = [genesis]
    p2p.local_blockchain.save_chain = MagicMock()
    p2p.local_blockchain.validate_chain = MagicMock(return_value=True)

@pytest.mark.asyncio
async def test_handler_chain_request():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)
    ws.__aiter__.return_value = iter([json.dumps({"action": "REQUEST_CHAIN"})])
    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)
    ws.send.assert_awaited_once()

@pytest.mark.asyncio
async def test_handler_hello():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)
    ws.__aiter__.return_value = iter([json.dumps({
        "action": "HELLO", "peer_id": "peer1", "public_key": "pub", "timestamp": "123"
    })])
    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)
    ws.close.assert_not_called()

@pytest.mark.asyncio
async def test_handler_invalid_json():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)
    ws.__aiter__.return_value = iter(["NOT_JSON"])
    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
async def test_handler_rejects_banned_peer():
    ws = AsyncMock()
    ws.remote_address = ("192.168.1.1", 1234)
    p2p.banned_peers.add("192.168.1.1")
    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)
    ws.close.assert_awaited()
    p2p.banned_peers.clear()

@pytest.mark.asyncio
async def test_broadcast_new_block():
    ws = AsyncMock()
    ws.open = True
    p2p.connected_peers.clear()
    p2p.connected_peers.add(ws)
    await p2p.broadcast_new_block({"index": 1})
    ws.send.assert_called_once()

@pytest.mark.asyncio
async def test_broadcast_new_transaction():
    tx = {"txid": "tx999"}
    ws = AsyncMock()
    ws.open = True
    p2p.connected_peers.clear()
    p2p.connected_peers.add(ws)
    await p2p.broadcast_new_transaction(tx)
    ws.send.assert_called_once()

def test_chain_score():
    chain = [{"index": 2, "nonce": 3}, {"index": 1, "nonce": 4}]
    assert p2p.chain_score(chain) == 10

def test_get_connected_peers_info():
    peer = MagicMock()
    peer.remote_address = ("10.0.0.1", 9000)
    peer.peer_id = "peer1"
    peer.public_key = "pub123"
    p2p.connected_peers.clear()
    p2p.connected_peers.add(peer)
    result = p2p.get_connected_peers_info()
    assert result[0]["ip"] == "10.0.0.1"
    assert result[0]["peer_id"] == "peer1"

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.connect")
async def test_request_chain_success(mock_connect):
    dummy = [{"index": 0}, {"index": 1}]
    ws = AsyncMock()
    ws.recv.return_value = json.dumps({"action": "BLOCKCHAIN", "chain": dummy})
    mock_connect.return_value.__aenter__.return_value = ws
    chain = await p2p.request_chain_from("ws://dummy")
    assert isinstance(chain, list)
    assert chain == dummy

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.ChainValidator.validate_chain", return_value=True)
@patch("bhrc_blockchain.network.p2p.Block.from_dict", return_value=MagicMock())
async def test_handler_blockchain_updates_chain(mock_from_dict, mock_validate):
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    # Zincir simülasyonu
    block_dicts = []
    for i in range(3):
        blk = Block(
            index=i,
            previous_hash="0" if i == 0 else f"hash{i-1}",
            transactions=[],
            timestamp=time.time(),
            nonce=0,
            miner_address="xBHR" + "0" * 60
        )
        block_dicts.append(blk.to_dict())

    ws.__aiter__.return_value = iter([json.dumps({"action": "BLOCKCHAIN", "chain": block_dicts})])
    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

    assert mock_validate.called
    assert mock_from_dict.call_count == 3

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.Block.from_dict")
@patch("bhrc_blockchain.network.p2p.validate_block_structure")
async def test_handler_new_block_valid_block_added(mock_validate_structure, mock_from_dict):
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    blk = Block(
        index=1,
        previous_hash="0",
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="xBHR" + "0" * 60
    )
    new_block_dict = blk.to_dict()
    ws.__aiter__.return_value = iter([json.dumps({"action": "NEW_BLOCK", "block": new_block_dict})])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

    mock_validate_structure.assert_called_once()
    mock_from_dict.assert_called_once()

