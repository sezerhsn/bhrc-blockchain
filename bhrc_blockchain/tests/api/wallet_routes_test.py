import pytest
from fastapi.testclient import TestClient
from bhrc_blockchain.api.wallet_routes import router
from bhrc_blockchain.api.api_server import app
from bhrc_blockchain.core.wallet.wallet import generate_wallet, generate_mnemonic, generate_child_wallet

client = TestClient(app)

@pytest.fixture
def jwt_token():
    response = client.post(
        "/auth/token",
        data={"username": "admin", "password": "admin123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]

def test_wallet_create(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.post("/wallet/create", json={"password": "testpass"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "address" in data
    assert "private_key" in data
    assert "public_key" in data

def test_wallet_address(jwt_token):
    wallet = generate_wallet(password="abc123")
    private_key = wallet["private_key"]
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/wallet/address", params={"private_key": private_key}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["address"].startswith("xBHR")

def test_wallet_generate(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/wallet/generate", params={"password": "testpass"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "address" in data
    assert "private_key" in data
    assert "public_key" in data

def test_wallet_create_invalid(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.post("/wallet/create", json={"password": None}, headers=headers)
    assert response.status_code == 422

def test_wallet_address_invalid_key(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/wallet/address", params={"private_key": "geçersiz_key"}, headers=headers)
    assert response.status_code == 400
    assert "detail" in response.json()

def test_wallet_address_exception_trigger(jwt_token):
    import bhrc_blockchain.api.wallet_routes as wr

    def mock_fail(private_key):
        raise Exception("mocked failure")

    original = wr.get_address_from_private_key
    wr.get_address_from_private_key = mock_fail

    try:
        headers = {"Authorization": f"Bearer {jwt_token}"}
        response = client.get("/wallet/address", params={"private_key": "any"}, headers=headers)
        assert response.status_code == 400
        assert "mocked failure" in response.text
    finally:
        wr.get_address_from_private_key = original

def test_wallet_address_force_exception(jwt_token):
    import bhrc_blockchain.api.wallet_routes as wr

    def fail(_): raise Exception("fail in address")
    original_get_address = wr.get_address_from_private_key
    original_get_pub = wr.get_public_key_from_private_key

    wr.get_address_from_private_key = fail
    wr.get_public_key_from_private_key = fail

    try:
        headers = {"Authorization": f"Bearer {jwt_token}"}
        response = client.get("/wallet/address", params={"private_key": "any"}, headers=headers)
        assert response.status_code == 400
        assert "fail in address" in response.text  # ⬅️ Bu satır sayesinde coverage sayılır
    finally:
        wr.get_address_from_private_key = original_get_address
        wr.get_public_key_from_private_key = original_get_pub

def test_verify_wallet_integrity_api_success():
    phrase = generate_mnemonic()
    wallet_data = generate_child_wallet(phrase, index=0)

    payload = {
        "private_key": wallet_data["private_key"],
        "public_key": wallet_data["public_key"],
        "address": wallet_data["address"],
        "mnemonic": wallet_data["mnemonic"],
        "password": ""  # çünkü generate_child_wallet'da parola boş
    }

    response = client.post("/wallet/verify_integrity", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_verify_wallet_integrity_api_failure_invalid_pubkey():
    phrase = generate_mnemonic()
    wallet_data = generate_child_wallet(phrase, index=0)

    wallet_data["public_key"] = "00" * 64  # sahte key

    response = client.post("/wallet/verify_integrity", json=wallet_data)
    assert response.status_code == 400
    assert "bütünlüğü doğrulanamadı" in response.json()["detail"]

def test_from_hardware_wallet_returns_valid_data():
    response = client.get("/wallet/from_hardware?index=1")
    assert response.status_code == 200

    data = response.json()
    assert "address" in data
    assert "public_key" in data
    assert data["index"] == 1
    assert data["address"].startswith("xBHR")

def test_sign_message_endpoint_returns_signature():
    from bhrc_blockchain.core.wallet.wallet import generate_private_key

    private_key = generate_private_key()
    message = "The quick brown fox jumps over the lazy cowboy"

    response = client.post("/wallet/sign_message", json={
        "private_key": private_key,
        "message": message
    })

    assert response.status_code == 200
    data = response.json()
    assert "signature" in data
    assert isinstance(data["signature"], str)
    assert len(data["signature"]) > 20  # Muhtemel base64 imza

def test_verify_signature_endpoint_validates_signature_correctly():
    from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_public_key_from_private_key, sign_message

    message = "Ride fast, shoot straight 🤠"
    private_key = generate_private_key()
    public_key = get_public_key_from_private_key(private_key)
    signature = sign_message(private_key, message)

    response = client.post("/wallet/verify_signature", json={
        "public_key": public_key,
        "message": message,
        "signature": signature
    })

    assert response.status_code == 200
    data = response.json()
    assert "valid" in data
    assert data["valid"] is True

def test_get_foundation_address_endpoint_returns_valid_address():
    response = client.get("/wallet/foundation_address")
    assert response.status_code == 200

    data = response.json()
    assert "foundation_address" in data
    assert isinstance(data["foundation_address"], str)
    assert data["foundation_address"].startswith("xBHR")
    assert len(data["foundation_address"]) > 30

def test_import_mnemonic_endpoint_restores_wallet_correctly():
    from bhrc_blockchain.core.wallet.wallet import generate_child_wallet

    mnemonic = "kiss craft slush human fatigue clown train trust sport about bridge news"
    original = generate_child_wallet(mnemonic, index=0)

    response = client.post("/wallet/import_mnemonic", json={
        "mnemonic": mnemonic,
        "password": ""
    })

    assert response.status_code == 200
    data = response.json()
    assert data["address"] == original["address"]
    assert data["public_key"] == original["public_key"]
    assert data["private_key"] == original["private_key"]
    assert data["mnemonic"] == mnemonic

def test_import_private_key_endpoint_rebuilds_wallet_correctly():
    from bhrc_blockchain.core.wallet.wallet import generate_private_key, import_wallet_from_private_key

    private_key = generate_private_key()
    expected = import_wallet_from_private_key(private_key)

    response = client.post("/wallet/import_private_key", json={
        "private_key": private_key
    })

    assert response.status_code == 200
    data = response.json()
    assert data["private_key"] == private_key
    assert data["public_key"] == expected["public_key"]
    assert data["address"] == expected["address"]

def test_is_valid_address_endpoint_behaves_correctly():
    from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_address_from_private_key

    valid_address = get_address_from_private_key(generate_private_key())
    invalid_address = "invalid_bhrc_address_123"

    # Geçerli adres testi
    response_valid = client.get(f"/wallet/is_valid_address?address={valid_address}")
    assert response_valid.status_code == 200
    assert response_valid.json() == {"valid": True}

    # Geçersiz adres testi
    response_invalid = client.get(f"/wallet/is_valid_address?address={invalid_address}")
    assert response_invalid.status_code == 200
    assert response_invalid.json() == {"valid": False}

def test_verify_address_from_key_endpoint_behaves_correctly():
    from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_address_from_private_key

    private_key = generate_private_key()
    correct_address = get_address_from_private_key(private_key)
    wrong_address = get_address_from_private_key(generate_private_key())

    # Geçerli eşleşme
    response_match = client.post("/wallet/verify_address_from_key", json={
        "private_key": private_key,
        "address": correct_address
    })
    assert response_match.status_code == 200
    assert response_match.json() == {"match": True}

    # Geçersiz eşleşme
    response_mismatch = client.post("/wallet/verify_address_from_key", json={
        "private_key": private_key,
        "address": wrong_address
    })
    assert response_mismatch.status_code == 200
    assert response_mismatch.json() == {"match": False}

