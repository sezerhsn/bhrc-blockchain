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

@pytest.mark.asyncio
async def test_handler_blockchain_score_too_low():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    low_score_chain = [{"index": 0, "nonce": 0}]
    ws.__aiter__.return_value = iter([json.dumps({"action": "BLOCKCHAIN", "chain": low_score_chain})])

    p2p.local_blockchain.chain = [MagicMock(index=1, nonce=1)]
    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.Block.from_dict", side_effect=Exception("invalid"))
@patch("bhrc_blockchain.network.p2p.validate_block_structure", side_effect=Exception("invalid"))
async def test_handler_new_block_invalid_structure(mock_validate, mock_from_dict):
    ws = AsyncMock()
    ws.remote_address = ("11.22.33.44", 1234)

    blk = Block(index=1, previous_hash="0", transactions=[], timestamp=time.time(), nonce=0, miner_address="xBHR" + "0" * 60)
    block_dict = blk.to_dict()

    ws.__aiter__.return_value = iter([json.dumps({"action": "NEW_BLOCK", "block": block_dict})])
    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

    assert "11.22.33.44" in p2p.banned_peers

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.add_transaction_to_mempool")
async def test_handler_new_tx_already_in_mempool(mock_add_tx):
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    with patch("bhrc_blockchain.network.p2p.any", return_value=True):
        ws.__aiter__.return_value = iter([
            json.dumps({"action": "NEW_TX", "transaction": {"txid": "dupe_tx"}})
        ])
        await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=1.0)

    mock_add_tx.assert_not_called()

@pytest.mark.asyncio
async def test_broadcast_new_block_send_fails():
    peer = AsyncMock()
    peer.open = True
    peer.send.side_effect = Exception("send failed")

    p2p.connected_peers.clear()
    p2p.connected_peers.add(peer)

    await p2p.broadcast_new_block({"index": 5})

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.connect", side_effect=Exception("connection error"))
async def test_request_chain_from_connection_error(mock_connect):
    result = await p2p.request_chain_from("ws://fake-peer")
    assert result is None

@pytest.mark.asyncio
async def test_handler_new_block_missing_index():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)
    bad_block = {"nonce": 1}

    ws.__aiter__.return_value = iter([
        json.dumps({"action": "NEW_BLOCK", "block": bad_block})
    ])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.Block.from_dict", return_value=MagicMock(index=999))
@patch("bhrc_blockchain.network.p2p.validate_block_structure")
async def test_handler_new_block_invalid_chain(mock_validate_structure, mock_from_dict):
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    block_data = Block(index=999, previous_hash="0", transactions=[], timestamp=time.time(), nonce=0, miner_address="xBHR" + "0" * 60).to_dict()
    ws.__aiter__.return_value = iter([
        json.dumps({"action": "NEW_BLOCK", "block": block_data})
    ])

    p2p.local_blockchain.validate_chain.return_value = False

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
async def test_broadcast_new_transaction_send_fails():
    ws = AsyncMock()
    ws.open = True
    ws.send.side_effect = Exception("fail")

    p2p.connected_peers.clear()
    p2p.connected_peers.add(ws)

    await p2p.broadcast_new_transaction({"txid": "fail_tx"})

def test_get_connected_peers_info_with_exception():
    peer = MagicMock()
    peer.remote_address = None
    del peer.remote_address
    p2p.connected_peers.clear()
    p2p.connected_peers.add(peer)

    result = p2p.get_connected_peers_info()
    assert isinstance(result, list)

@pytest.mark.asyncio
async def test_handler_banned_peer_rejected_immediately():
    ws = AsyncMock()
    ws.remote_address = ("192.168.1.100", 9999)
    p2p.banned_peers.add("192.168.1.100")

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)
    ws.close.assert_awaited()
    p2p.banned_peers.clear()

@pytest.mark.asyncio
async def test_handler_hello_missing_fields():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    hello_msg = {
        "action": "HELLO",
        "peer_id": "peer123",
        "public_key": None,
        "timestamp": None
    }
    ws.__aiter__.return_value = iter([json.dumps(hello_msg)])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)
    ws.close.assert_awaited()

@pytest.mark.asyncio
async def test_broadcast_new_transaction_with_no_peers():
    p2p.connected_peers.clear()
    tx = {"txid": "test_txid_no_peers"}
    await p2p.broadcast_new_transaction(tx)

@pytest.mark.asyncio
async def test_handler_blockchain_with_none_chain():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    ws.__aiter__.return_value = iter([
        json.dumps({"action": "BLOCKCHAIN", "chain": None})
    ])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.Block.from_dict", side_effect=Exception("deserialize fail"))
@patch("bhrc_blockchain.network.p2p.ChainValidator.validate_chain", return_value=True)
async def test_handler_blockchain_from_dict_failure(mock_validate, mock_from_dict):
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    blk = Block(index=1, previous_hash="0", transactions=[], timestamp=time.time(), nonce=0, miner_address="xBHR" + "0" * 60)
    block_dicts = [blk.to_dict()]
    ws.__aiter__.return_value = iter([
        json.dumps({"action": "BLOCKCHAIN", "chain": block_dicts})
    ])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
async def test_handler_hello_missing_pubkey_and_timestamp():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    hello_msg = {
        "action": "HELLO",
        "peer_id": "peer123"
    }
    ws.__aiter__.return_value = iter([json.dumps(hello_msg)])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)
    ws.close.assert_awaited()

@pytest.mark.asyncio
async def test_broadcast_new_transaction_with_closed_peer():
    ws = AsyncMock()
    ws.open = False

    p2p.connected_peers.clear()
    p2p.connected_peers.add(ws)

    tx = {"txid": "tx_closed_peer"}
    await p2p.broadcast_new_transaction(tx)
    ws.send.assert_not_called()

@pytest.mark.asyncio
async def test_handler_blockchain_score_too_low_no_update():
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    received_chain = [
        {"index": 0, "nonce": 0},
        {"index": 1, "nonce": 0}
    ]

    from bhrc_blockchain.core.block import Block
    b1 = Block(index=0, previous_hash="0", transactions=[], timestamp=time.time(), nonce=5, miner_address="xBHR" + "0" * 60)
    b2 = Block(index=1, previous_hash="hash0", transactions=[], timestamp=time.time(), nonce=5, miner_address="xBHR" + "0" * 60)
    p2p.local_blockchain.chain = [b1, b2]

    ws.__aiter__.return_value = iter([
        json.dumps({"action": "BLOCKCHAIN", "chain": received_chain})
    ])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.Block.from_dict", side_effect=lambda x: MagicMock(index=2))
@patch("bhrc_blockchain.network.p2p.ChainValidator.validate_chain", return_value=True)
async def test_handler_blockchain_valid_but_already_up_to_date(mock_validate, mock_from_dict):
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    block = Block(index=2, previous_hash="x", transactions=[], timestamp=time.time(), nonce=0, miner_address="xBHR" + "0" * 60).to_dict()
    p2p.local_blockchain.chain = [MagicMock(index=1, nonce=0), MagicMock(index=2, nonce=0)]
    ws.__aiter__.return_value = iter([json.dumps({"action": "BLOCKCHAIN", "chain": [block]})])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
async def test_handler_blockchain_score_lower_than_current(monkeypatch):
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    received_chain = [
        {"index": 0, "nonce": 0},
        {"index": 1, "nonce": 0}
    ]

    from bhrc_blockchain.core.block import Block
    local_block = Block(index=0, previous_hash="0", transactions=[], timestamp=time.time(), nonce=5, miner_address="xBHR" + "0" * 60)
    p2p.local_blockchain.chain = [local_block]

    ws.__aiter__.return_value = iter([
        json.dumps({"action": "BLOCKCHAIN", "chain": received_chain})
    ])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
@patch("bhrc_blockchain.network.p2p.ChainValidator.validate_chain", return_value=False)
async def test_handler_blockchain_invalid_chain_rejected(mock_validate):
    ws = AsyncMock()
    ws.remote_address = ("127.0.0.1", 1234)

    blk = Block(index=0, previous_hash="0", transactions=[], timestamp=time.time(), nonce=0, miner_address="xBHR" + "0" * 60)
    chain = [blk.to_dict()]

    ws.__aiter__.return_value = iter([
        json.dumps({"action": "BLOCKCHAIN", "chain": chain})
    ])

    await asyncio.wait_for(p2p.handler(ws, path="/"), timeout=0.5)

@pytest.mark.asyncio
async def test_broadcast_new_transaction_send_raises():
    ws = AsyncMock()
    ws.open = True
    ws.send.side_effect = Exception("send fail")

    p2p.connected_peers.clear()
    p2p.connected_peers.add(ws)

    tx = {"txid": "fail_txid"}
    await p2p.broadcast_new_transaction(tx)

