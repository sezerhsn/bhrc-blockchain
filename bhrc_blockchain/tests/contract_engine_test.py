import pytest
import time
from bhrc_blockchain.core.contract.contract_engine import SmartContractEngine
from bhrc_blockchain.core.contract.evaluator import evaluate_contract

def test_valid_contract_passes():
    future_time = int(time.time()) - 10  # geçmiş zaman
    tx = {"script": f"if now > {future_time} then allow"}
    assert evaluate_contract(tx) is True

def test_locked_contract_fails():
    future_time = int(time.time()) + 9999  # henüz erişilememiş
    tx = {"script": f"if now > {future_time} then allow"}
    assert evaluate_contract(tx) is False

def test_empty_script_returns_false():
    tx = {"script": ""}
    assert evaluate_contract(tx) is False

def test_invalid_script_returns_false():
    tx = {"script": "do something now please"}
    assert evaluate_contract(tx) is False

def test_contract_deploy_and_call():
    engine = SmartContractEngine()

    contract_address = "xCONTRACT1"
    code = "simple_counter"
    initial_state = {"counter": 0}

    # 1. Dağıtım
    success = engine.deploy_contract(contract_address, code, initial_state)
    assert success is True
    assert engine.get_contract(contract_address)["state"]["counter"] == 0

    # 2. Çağrı: increment
    result = engine.call_contract_method(contract_address, "increment")
    assert result == 1

    # 3. Çağrı: get
    state = engine.call_contract_method(contract_address, "get")
    assert state["counter"] == 1

    # 4. Tekrar dağıtmayı engelle
    repeat = engine.deploy_contract(contract_address, code, {"counter": 99})
    assert repeat is False
