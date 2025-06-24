import pytest
import asyncio
import json
from bhrc_blockchain.network import notifications
from unittest.mock import patch

class MockWebSocket:
    def __init__(self):
        self.sent_messages = []
        self.received_messages = asyncio.Queue()
        self.open = True

    async def send(self, message):
        self.sent_messages.append(message)

    def queue_message(self, msg_dict):
        self.received_messages.put_nowait(json.dumps(msg_dict))

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.received_messages.empty():
            raise StopAsyncIteration
        return await self.received_messages.get()

@pytest.mark.asyncio
async def test_notification_handler_subscription():
    ws = MockWebSocket()
    notifications.connected_clients.clear()
    notifications.subscribed_clients.clear()

    ws.queue_message({"type": "subscribe", "address": "addr123"})
    await notifications.notification_handler(ws)

    sent = [json.loads(msg) for msg in ws.sent_messages]
    subscribed_msgs = [m for m in sent if m.get("type") == "subscribed"]

    assert len(subscribed_msgs) == 1
    assert subscribed_msgs[0]["address"] == "addr123"

@pytest.mark.asyncio
async def test_broadcast_block_notification():
    ws = MockWebSocket()
    ws.open = True
    notifications.connected_clients.clear()
    notifications.subscribed_clients.clear()

    notifications.connected_clients.add(ws)
    notifications.subscribed_clients[ws] = "receiver1"

    dummy_block = {
        "index": 5,
        "block_hash": "abc123",
        "transactions": [
            {"recipient": "receiver1", "amount": 100},
            {"recipient": "other", "amount": 50}
        ]
    }

    await notifications.broadcast_block_notification(dummy_block)

    sent_jsons = [json.loads(m) for m in ws.sent_messages]
    types = [m["type"] for m in sent_jsons]

    assert "block" in types
    assert "incoming_tx" in types

@pytest.mark.asyncio
async def test_notification_handler_invalid_json():
    ws = MockWebSocket()
    notifications.connected_clients.clear()
    notifications.subscribed_clients.clear()

    ws.received_messages.put_nowait("not-a-json")
    await notifications.notification_handler(ws)

    assert any("welcome" in m for m in ws.sent_messages)

@pytest.mark.asyncio
async def test_notification_handler_connection_exception():
    class FailingWebSocket(MockWebSocket):
        async def send(self, message):
            raise Exception("Connection lost")

    ws = FailingWebSocket()
    ws.queue_message({"type": "subscribe", "address": "testaddr"})

    await notifications.notification_handler(ws)

    assert True

@pytest.mark.asyncio
async def test_broadcast_block_notification_with_send_error():
    class FailingWebSocket(MockWebSocket):
        async def send(self, message):
            raise Exception("Send failed")

    ws = FailingWebSocket()
    ws.open = True

    notifications.connected_clients.clear()
    notifications.subscribed_clients.clear()

    notifications.connected_clients.add(ws)
    notifications.subscribed_clients[ws] = "receiverX"

    dummy_block = {
        "index": 9,
        "block_hash": "fakehash",
        "transactions": [
            {"recipient": "receiverX", "amount": 100}
        ]
    }

    await notifications.broadcast_block_notification(dummy_block)

    assert True

@pytest.mark.asyncio
async def test_emit_admin_alert_writes_log(monkeypatch):
    called = {}

    def mock_write_to_log(entry):
        called["log"] = entry

    async def mock_broadcast(entry):
        called["broadcast"] = entry

    monkeypatch.setattr(notifications, "write_to_log", mock_write_to_log)
    monkeypatch.setattr(notifications, "broadcast_to_admin_websocket", mock_broadcast)

    await notifications.emit_admin_alert("test_event", {"info": "test"})

    assert "log" in called
    assert "broadcast" in called

def test_write_to_log_creates_file():
    import os
    import tempfile
    import shutil

    temp_dir = tempfile.mkdtemp()
    log_path = os.path.join(temp_dir, "logs")
    os.makedirs(log_path, exist_ok=True)

    try:
        test_entry = {"event_type": "test", "details": {"a": 1}}
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        notifications.write_to_log(test_entry)
        os.chdir(original_dir)

        log_file = os.path.join(log_path, "admin_events.log")
        assert os.path.exists(log_file)

        with open(log_file) as f:
            content = f.read()
            assert "event_type" in content
    finally:
        shutil.rmtree(temp_dir)

@pytest.mark.asyncio
async def test_broadcast_to_admin_websocket_failure():
    class FailingAdminWS:
        async def send_text(self, message):
            raise Exception("WebSocket Error")

    ws = FailingAdminWS()
    notifications.websocket_connections.clear()
    notifications.websocket_connections.append(ws)

    await notifications.broadcast_to_admin_websocket({"test": "data"})
    assert ws not in notifications.websocket_connections

@pytest.mark.asyncio
async def test_notify_admin_gather_called():
    class DummyWS:
        def __init__(self):
            self.sent = []
        async def send_text(self, msg):
            self.sent.append(msg)

    ws = DummyWS()
    notifications.websocket_connections.clear()
    notifications.websocket_connections.append(ws)

    data = {"msg": "hello"}
    await notifications.notify_admin(data)

    assert json.dumps(data) in ws.sent

@pytest.mark.asyncio
async def test_admin_event_ws_disconnect():
    class MockAdminWS:
        async def accept(self):
            pass
        async def receive_text(self):
            raise notifications.WebSocketDisconnect()

    ws = MockAdminWS()
    notifications.connected_admins.clear()
    await notifications.admin_event_ws(ws)
    assert ws not in notifications.connected_admins

@pytest.mark.asyncio
async def test_broadcast_block_notification_general_send_fails():
    class FailingSendWS(MockWebSocket):
        async def send(self, message):
            raise Exception("send failed")

    ws = FailingSendWS()
    ws.open = True

    notifications.connected_clients.clear()
    notifications.connected_clients.add(ws)

    block_data = {
        "index": 3,
        "block_hash": "failhash",
        "transactions": []
    }

    await notifications.broadcast_block_notification(block_data)
    assert True

@pytest.mark.asyncio
async def test_broadcast_block_notification_skips_invalid_tx():
    ws = MockWebSocket()
    ws.open = True

    notifications.connected_clients.clear()
    notifications.subscribed_clients.clear()

    notifications.connected_clients.add(ws)
    notifications.subscribed_clients[ws] = "abc"

    block_data = {
        "index": 6,
        "block_hash": "zzz",
        "transactions": [
            {"amount": 999}
        ]
    }

    await notifications.broadcast_block_notification(block_data)
    assert True

@pytest.mark.asyncio
async def test_broadcast_block_notification_general_send_exception():
    class FailingWS(MockWebSocket):
        async def send(self, message):
            raise Exception("send fail")

    ws = FailingWS()
    ws.open = True

    notifications.connected_clients.clear()
    notifications.connected_clients.add(ws)

    block_data = {
        "index": 99,
        "block_hash": "xxx",
        "transactions": []
    }

    await notifications.broadcast_block_notification(block_data)
    assert True

@pytest.mark.asyncio
async def test_broadcast_block_notification_general_send_exception_precise():
    class DummyWS:
        def __init__(self):
            self.open = True
        async def send(self, msg):
            raise Exception("GENERIC SEND FAILURE")

    notifications.connected_clients.clear()
    notifications.connected_clients.add(DummyWS())

    await notifications.broadcast_block_notification({
        "index": 1,
        "block_hash": "hash999",
        "transactions": []
    })

    assert True

@pytest.mark.asyncio
async def test_broadcast_block_notification_general_send_exception_tracked():
    class FailingWS:
        def __init__(self):
            self.open = True
        async def send(self, message):
            raise Exception("simulated send failure")

    ws = FailingWS()
    notifications.connected_clients.clear()
    notifications.connected_clients.add(ws)

    block_data = {
        "index": 42,
        "block_hash": "hash-fail",
        "transactions": []
    }

    with patch.object(notifications.logger, "debug") as mock_log:
        await notifications.broadcast_block_notification(block_data)
        mock_log.assert_called_once()
        assert "gönderilemedi" in mock_log.call_args[0][0]
