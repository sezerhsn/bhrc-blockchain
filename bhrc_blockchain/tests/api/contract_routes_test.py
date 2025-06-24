import pytest
import uuid
import hashlib
from fastapi.testclient import TestClient
from bhrc_blockchain.api.auth import get_current_user
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.core.wallet.wallet import generate_wallet, sign_message
from bhrc_blockchain.api.contract_routes import contract_engine

client = TestClient(app)

class DummyDB:
    def get_unspent_utxos(self, address):
        return [
            ("mock_txid", "mock_txid", 0, None, 999999.0)
        ]

@pytest.fixture
def jwt_token():
    response = client.post(
        "/auth/token",
        data={"username": "admin", "password": "admin123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]

@pytest.fixture(autouse=True)
def reset_contract_registry():
    contract_engine.contracts.clear()

def test_submit_contract(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = True"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Test contract execution",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    print("PAYLOAD:", payload)

    response = client.post("/contract/submit", json=payload, headers=headers)
    assert response.status_code in [200, 400], response.text

    data = response.json()
    if response.status_code == 200:
        assert "txid" in data
        assert data["message"].startswith("Contract işlemi mempool")
        assert "execution_result" in data
        assert data["execution_result"]["status"] == "success"
    else:
        assert "detail" in data

    app.dependency_overrides = {}

def test_simulate_contract(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = True"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Test contract execution",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    print("SIMULATE PAYLOAD:", payload)

    response = client.post("/contract/simulate", json=payload, headers=headers)
    assert response.status_code in [200, 400], response.text

    data = response.json()
    if response.status_code == 200:
        assert "execution_result" in data
        assert data["execution_result"]["status"] == "success"
        assert data["execution_result"]["result"] is True
    else:
        assert "detail" in data

    app.dependency_overrides = {}

def test_get_contract_status(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = True"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 0.0,
        "fee": 0.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Test contract execution",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    submit_resp = client.post("/contract/submit", json=payload, headers=headers)
    assert submit_resp.status_code == 200, submit_resp.text
    submit_data = submit_resp.json()
    txid = submit_data["txid"]

    status_resp = client.get(f"/contract/tx/{txid}")
    assert status_resp.status_code == 200, status_resp.text
    status_data = status_resp.json()

    assert status_data["txid"] == txid
    assert status_data["executed"] is True
    assert status_data["execution_result"]["status"] == "success"
    assert status_data["execution_result"]["result"] is True
    assert "contract_result" in status_data["tx"]
    assert status_data["tx"]["contract_result"]["status"] == "success"

    app.dependency_overrides = {}

def test_deploy_contract(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = 42"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    payload = {
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "sender_private_key": private_key
    }

    response = client.post("/contract/deploy", json=payload, headers=headers)
    assert response.status_code == 200, response.text

    data = response.json()
    assert "contract_address" in data
    assert data["message"].startswith("Contract deployed")

    app.dependency_overrides = {}

def test_call_contract(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = value * 2"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    deploy_payload = {
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "sender_private_key": private_key
    }

    deploy_resp = client.post("/contract/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200, deploy_resp.text

    deploy_data = deploy_resp.json()
    contract_address = deploy_data["contract_address"]

    call_payload = {
        "contract_address": contract_address,
        "params": {"value": 7}
    }

    call_resp = client.post("/contract/call", json=call_payload, headers=headers)
    assert call_resp.status_code == 200, call_resp.text

    call_data = call_resp.json()
    assert call_data["contract_address"] == contract_address
    assert call_data["execution_result"]["status"] == "success"
    assert call_data["execution_result"]["result"] == 14

    app.dependency_overrides = {}

def test_invalid_script_hash(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = True"
    script_hash = "invalidhash123"
    signature = sign_message(private_key, script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Invalid hash test",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    response = client.post("/contract/submit", json=payload, headers=headers)
    assert response.status_code == 400
    assert "Script hash doğrulaması başarısız" in response.json()["detail"]

    app.dependency_overrides = {}

def test_invalid_signature(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)
    wrong_wallet = generate_wallet(password="wrong", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}

    script_content = "result = True"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()

    signature = sign_message(wrong_wallet["private_key"], script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Invalid signature test",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": recipient_wallet["private_key"]
    }

    response = client.post("/contract/submit", json=payload, headers=headers)
    assert response.status_code == 400
    assert "Script imzası geçersiz" in response.json()["detail"]

    app.dependency_overrides = {}

def test_missing_parameters(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = True"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": script_hash,
        "type": "BHRC-Logic-1.0",
        "message": "Missing parameter test",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    response = client.post("/contract/submit", json=payload, headers=headers)
    assert response.status_code == 422

    app.dependency_overrides = {}

def test_invalid_script_content(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result == True"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Invalid script content test",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    response = client.post("/contract/submit", json=payload, headers=headers)
    assert response.status_code == 400
    assert "Contract yürütme hatası" in response.json()["detail"]

    app.dependency_overrides = {}

def test_script_timeout(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}

    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "while True: pass"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Timeout test",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    response = client.post("/contract/submit", json=payload, headers=headers)

    assert response.status_code == 400
    assert "Contract yürütme hatası" in response.json()["detail"]

    app.dependency_overrides = {}

def test_deploy_contract_invalid_hash(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)
    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}
    headers = {"Authorization": f"Bearer {jwt_token}"}

    private_key = recipient_wallet["private_key"]
    script_content = "result = 42"
    invalid_hash = "invalidhash123"
    signature = sign_message(private_key, invalid_hash)

    payload = {
        "script": script_content,
        "script_hash": invalid_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "sender_private_key": private_key
    }

    response = client.post("/contract/deploy", json=payload, headers=headers)
    assert response.status_code == 400
    assert "Script hash doğrulaması başarısız" in response.json()["detail"]

    app.dependency_overrides = {}

def test_deploy_contract_duplicate(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)
    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}
    headers = {"Authorization": f"Bearer {jwt_token}"}

    private_key = recipient_wallet["private_key"]

    dummy_script = "result = 99"
    dummy_hash = hashlib.sha256(dummy_script.encode()).hexdigest()
    dummy_signature = sign_message(private_key, dummy_hash)
    dummy_payload = {
        "script": dummy_script,
        "script_hash": dummy_hash,
        "signature": dummy_signature,
        "type": "BHRC-Logic-1.0",
        "sender_private_key": private_key
    }
    client.post("/contract/deploy", json=dummy_payload, headers=headers)

    script_content = f"result = {uuid.uuid4().int % 100}"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    payload = {
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "sender_private_key": private_key
    }

    response1 = client.post("/contract/deploy", json=payload, headers=headers)
    assert response1.status_code == 200

    response2 = client.post("/contract/deploy", json=payload, headers=headers)
    print("DUPLICATE RESPONSE:", response2.status_code, response2.json())
    assert response2.status_code == 400
    assert "zaten deploy edilmiş" in response2.json()["detail"]

    app.dependency_overrides = {}

def test_call_contract_invalid_address(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)
    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}
    headers = {"Authorization": f"Bearer {jwt_token}"}

    call_payload = {
        "contract_address": "invalid_contract_address",
        "params": {"value": 5}
    }

    response = client.post("/contract/call", json=call_payload, headers=headers)
    assert response.status_code == 400
    assert "Contract çağırma hatası" in response.json()["detail"]

    app.dependency_overrides = {}

def test_get_contract_status_invalid_txid(jwt_token):
    invalid_txid = "nonexistent_txid_123"

    response = client.get(f"/contract/tx/{invalid_txid}")
    assert response.status_code in [400, 404]
    assert "Transaction bulunamadı" in response.json()["detail"]

def test_simulate_contract_invalid_hash(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)
    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}
    headers = {"Authorization": f"Bearer {jwt_token}"}

    private_key = recipient_wallet["private_key"]
    script_content = "result = True"
    invalid_hash = "invalidhash123"
    signature = sign_message(private_key, invalid_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": invalid_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Invalid simulate hash",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    response = client.post("/contract/simulate", json=payload, headers=headers)
    assert response.status_code == 400
    assert "Script hash doğrulaması başarısız" in response.json()["detail"]

    app.dependency_overrides = {}

def test_simulate_contract_invalid_signature(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)
    wrong_wallet = generate_wallet(password="wrong", force_new=True)
    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}
    headers = {"Authorization": f"Bearer {jwt_token}"}

    script_content = "result = True"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(wrong_wallet["private_key"], script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 5.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Invalid simulate signature",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": recipient_wallet["private_key"]
    }

    response = client.post("/contract/simulate", json=payload, headers=headers)
    assert response.status_code == 400
    assert "Script imzası geçersiz" in response.json()["detail"]

    app.dependency_overrides = {}

def test_get_contract_status_logs(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)

    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}
    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = True"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    payload = {
        "recipient": recipient_wallet["address"],
        "amount": 0.0,
        "fee": 0.0,
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "message": "Test log capture",
        "note": f"test-{uuid.uuid4().hex[:6]}",
        "sender_private_key": private_key
    }

    submit_resp = client.post("/contract/submit", json=payload, headers=headers)
    assert submit_resp.status_code == 200, submit_resp.text
    submit_data = submit_resp.json()
    txid = submit_data["txid"]

    status_resp = client.get(f"/contract/tx/{txid}")
    assert status_resp.status_code == 200, status_resp.text
    status_data = status_resp.json()

    assert "logs" in status_data
    assert isinstance(status_data["logs"], list)
    assert len(status_data["logs"]) > 0
    assert "safe mode" in status_data["logs"][0].lower()

    app.dependency_overrides = {}

def test_call_contract_with_logs(jwt_token):
    recipient_wallet = generate_wallet(password="receiver", force_new=True)
    app.dependency_overrides[get_current_user] = lambda: {"sub": recipient_wallet["address"]}
    headers = {"Authorization": f"Bearer {jwt_token}"}
    private_key = recipient_wallet["private_key"]

    script_content = "result = value + 1"
    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
    signature = sign_message(private_key, script_hash)

    deploy_payload = {
        "script": script_content,
        "script_hash": script_hash,
        "signature": signature,
        "type": "BHRC-Logic-1.0",
        "sender_private_key": private_key
    }

    deploy_resp = client.post("/contract/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200
    contract_address = deploy_resp.json()["contract_address"]

    call_payload = {
        "contract_address": contract_address,
        "params": {"value": 10}
    }

    call_resp = client.post("/contract/call", json=call_payload, headers=headers)
    assert call_resp.status_code == 200
    call_data = call_resp.json()

    assert "logs" in call_data["execution_result"]
    assert isinstance(call_data["execution_result"]["logs"], list)
    assert len(call_data["execution_result"]["logs"]) > 0
    assert "safe mode" in call_data["execution_result"]["logs"][0].lower()

    app.dependency_overrides = {}

def test_contracts_call_bhrc20_transfer(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    deploy_payload = {
        "template": "BHRC20",
        "contract_address": "xTOKEN_TEST_01",
        "name": "TestTokenAPI",
        "symbol": "TTKAPI",
        "total_supply": 1000,
        "owner": "xOWNER"
    }

    deploy_resp = client.post("/contract/contracts/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200, deploy_resp.text

    call_payload = {
        "contract_address": "xTOKEN_TEST_01",
        "method": "transfer",
        "args": {
            "from_addr": "xOWNER",
            "to_addr": "xRECIPIENT",
            "amount": 300
        }
    }

    call_resp = client.post("/contract/contracts/call", json=call_payload, headers=headers)
    assert call_resp.status_code == 200, call_resp.text

    call_data = call_resp.json()
    assert call_data["status"] == "success"
    assert call_data["method"] == "transfer"
    assert call_data["result"] is True

def test_contracts_call_bhrc721_mint_and_transfer(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    deploy_payload = {
        "template": "BHRC721",
        "contract_address": "xNFT_TEST_01",
        "name": "TestNFTAPI",
        "symbol": "TNFTAPI"
    }

    deploy_resp = client.post("/contract/contracts/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200, deploy_resp.text

    mint_payload = {
        "contract_address": "xNFT_TEST_01",
        "method": "mint",
        "args": {
            "token_id": 1001,
            "to_addr": "xOWNER",
            "metadata": {"name": "NFT #1001", "attr": "legendary"}
        }
    }

    mint_resp = client.post("/contract/contracts/call", json=mint_payload, headers=headers)
    assert mint_resp.status_code == 200, mint_resp.text

    mint_data = mint_resp.json()
    assert mint_data["status"] == "success"
    assert mint_data["method"] == "mint"
    assert mint_data["result"] is True

    transfer_payload = {
        "contract_address": "xNFT_TEST_01",
        "method": "transfer",
        "args": {
            "token_id": 1001,
            "from_addr": "xOWNER",
            "to_addr": "xRECIPIENT"
        }
    }

    transfer_resp = client.post("/contract/contracts/call", json=transfer_payload, headers=headers)
    assert transfer_resp.status_code == 200, transfer_resp.text

    transfer_data = transfer_resp.json()
    assert transfer_data["status"] == "success"
    assert transfer_data["method"] == "transfer"
    assert transfer_data["result"] is True

def test_contracts_reset(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    deploy_payload = {
        "template": "BHRC20",
        "contract_address": "xTOKEN_RESET_TEST",
        "name": "ResetToken",
        "symbol": "RST",
        "total_supply": 500,
        "owner": "xOWNER"
    }

    deploy_resp = client.post("/contract/contracts/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200

    list_resp = client.get("/contract/contracts/list", headers=headers)
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["count"] >= 1

    reset_resp = client.post("/contract/contracts/reset", headers=headers)
    assert reset_resp.status_code == 200
    reset_data = reset_resp.json()
    assert reset_data["status"] == "success"
    assert reset_data["cleared"] >= 1

    list_resp2 = client.get("/contract/contracts/list", headers=headers)
    assert list_resp2.status_code == 200
    list_data2 = list_resp2.json()
    assert list_data2["count"] == 0

def test_contracts_simulate_call_bhrc20_transfer(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    deploy_payload = {
        "template": "BHRC20",
        "contract_address": "xTOKEN_SIM_TEST",
        "name": "SimToken",
        "symbol": "SIMTK",
        "total_supply": 1000,
        "owner": "xOWNER"
    }

    deploy_resp = client.post("/contract/contracts/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200

    simulate_payload = {
        "contract_address": "xTOKEN_SIM_TEST",
        "method": "transfer",
        "args": {
            "from_addr": "xOWNER",
            "to_addr": "xRECIPIENT",
            "amount": 500
        }
    }

    simulate_resp = client.post("/contract/contracts/simulate_call", json=simulate_payload, headers=headers)
    assert simulate_resp.status_code == 200
    simulate_data = simulate_resp.json()

    assert simulate_data["status"] == "success"
    assert simulate_data["method"] == "transfer"
    assert simulate_data["simulated_result"] is True

def test_contracts_simulate_call_bhrc721_mint(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    deploy_payload = {
        "template": "BHRC721",
        "contract_address": "xNFT_SIM_TEST",
        "name": "SimNFT",
        "symbol": "SIMNFT"
    }

    deploy_resp = client.post("/contract/contracts/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200

    simulate_payload = {
        "contract_address": "xNFT_SIM_TEST",
        "method": "mint",
        "args": {
            "token_id": 999,
            "to_addr": "xOWNER",
            "metadata": {"name": "NFT #999", "attr": "rare"}
        }
    }

    simulate_resp = client.post("/contract/contracts/simulate_call", json=simulate_payload, headers=headers)
    assert simulate_resp.status_code == 200
    simulate_data = simulate_resp.json()

    assert simulate_data["status"] == "success"
    assert simulate_data["method"] == "mint"
    assert simulate_data["simulated_result"] is True

def test_contracts_events(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    deploy_payload = {
        "template": "BHRC20",
        "contract_address": "xTOKEN_EVENT_TEST",
        "name": "EventToken",
        "symbol": "EVT",
        "total_supply": 1000,
        "owner": "xOWNER"
    }

    deploy_resp = client.post("/contract/contracts/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200

    call_payload = {
        "contract_address": "xTOKEN_EVENT_TEST",
        "method": "transfer",
        "args": {
            "from_addr": "xOWNER",
            "to_addr": "xRECIPIENT",
            "amount": 100
        }
    }

    call_resp = client.post("/contract/contracts/call", json=call_payload, headers=headers)
    assert call_resp.status_code == 200

    events_resp = client.get("/contract/contracts/events", headers=headers)
    assert events_resp.status_code == 200
    events_data = events_resp.json()

    assert events_data["count"] >= 1
    assert any(e["method"] == "transfer" for e in events_data["events"])

def test_contracts_version_field(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}

    deploy_payload = {
        "template": "BHRC20",
        "contract_address": "xTOKEN_VERSION_TEST",
        "name": "VersionToken",
        "symbol": "VER",
        "total_supply": 500,
        "owner": "xOWNER"
    }

    deploy_resp = client.post("/contract/contracts/deploy", json=deploy_payload, headers=headers)
    assert deploy_resp.status_code == 200

    list_resp = client.get("/contract/contracts/list", headers=headers)
    assert list_resp.status_code == 200
    list_data = list_resp.json()

    contract = next((c for c in list_data["contracts"] if c["contract_address"] == "xTOKEN_VERSION_TEST"), None)
    assert contract is not None
    assert contract["version"] == "v1.0.0"

