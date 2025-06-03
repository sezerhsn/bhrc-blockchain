import pytest
import asyncio
import json
from bhrc_blockchain.network import notifications

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

