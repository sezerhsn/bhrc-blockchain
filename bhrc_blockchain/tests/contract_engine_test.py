import pytest
import time
import json
import multiprocessing
import ast
from bhrc_blockchain.core.contract.evaluator import evaluate_contract
from bhrc_blockchain.core.contract.contract_state_storage import load_contract_state
from bhrc_blockchain.core.contract.contract_engine import (
    SmartContractEngine,
    safe_execute_script,
    execute_script,
    execute_script_in_subprocess,
    ContractRegistry,
    ENGINE_REGISTRY,
)

def test_valid_contract_passes():
    future_time = int(time.time()) - 10
    tx = {"script": f"if now > {future_time} then allow"}
    assert evaluate_contract(tx) is True

def test_locked_contract_fails():
    future_time = int(time.time()) + 9999
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

    success = engine.deploy_contract(contract_address, code, initial_state)
    assert success is True
    assert engine.get_contract(contract_address)["state"]["counter"] == 0

    result = engine.call_contract_method(contract_address, "increment")
    assert result == 1

    state = engine.call_contract_method(contract_address, "get")
    assert state["counter"] == 1

    repeat = engine.deploy_contract(contract_address, code, {"counter": 99})
    assert repeat is False

def test_call_contract_with_state():
    engine = SmartContractEngine()

    contract_address = "xCONTRACT2"
    code = "result = 123; state['value'] = 999"

    engine.deploy_contract(contract_address, code, {"value": 0})

    result = engine.call_contract_with_state(
        contract_address,
        params={"dummy": "test"}
    )
    assert result["status"] == "success"
    assert result["result"] == 123

def test_safe_execute_script_success():
    script = "result = 42\nstate['counter'] = state.get('counter', 0) + 1"
    context = {"state": {"counter": 0}}

    output = safe_execute_script(script, context)

    assert output["status"] == "success"
    assert output["result"] == 42
    assert context["state"]["counter"] == 1

def test_safe_execute_script_invalid():
    script = "import os\nos.system('echo hacked')"
    context = {"state": {}}

    output = safe_execute_script(script, context)

    assert output["status"] == "error"
    assert "Import" in output["error"]

def test_execute_script_in_subprocess_timeout():
    script = "while True: pass"
    context = {"state": {}}

    output = execute_script_in_subprocess(script, context, timeout_seconds=1)

    assert output["status"] == "error"
    assert "timeout" in output["error"].lower() or "exceed" in output["error"].lower()

def test_contract_registry_deploy_and_get():
    registry = ContractRegistry()
    code = "result = 77"

    deployed = registry.deploy("hash123", code)
    assert deployed is True

    duplicate = registry.deploy("hash123", code)
    assert duplicate is False

    retrieved = registry.get("hash123")
    assert retrieved == code

    missing = registry.get("nonexistent")
    assert missing is None

def test_execute_script_dispatch():
    script = "result = 100"
    context = {"state": {}}

    result = execute_script("BHRC-Logic-1.0", script, context)
    assert result["status"] == "success"
    assert result["result"] == 100

def test_bcl_interpreter_basic():
    from bhrc_blockchain.core.contract.contract_engine import ENGINE_REGISTRY
    script = "state['counter'] = state.get('counter', 0) + 1"
    context = {"state": {}}

    result = ENGINE_REGISTRY["BCL-1.0"](script, context)

    assert result["status"] == "success"
    assert context["state"]["counter"] == 1

def test_bcl_interpreter_args():
    from bhrc_blockchain.core.contract.contract_engine import ENGINE_REGISTRY
    script = "state['counter'] = args.get('delta', 1)"
    context = {"state": {}}

    result = ENGINE_REGISTRY["BCL-1.0"](script, context, {"delta": 5})

    assert result["status"] == "success"
    assert context["state"]["counter"] == 5

def test_bcl_interpreter_for_loop():
    from bhrc_blockchain.core.contract.contract_engine import ENGINE_REGISTRY
    script = """
state['total'] = 0
for i in range(5):
    state['total'] += i
"""
    context = {"state": {}}

    result = ENGINE_REGISTRY["BCL-1.0"](script, context)

    assert result["status"] == "success"
    assert context["state"]["total"] == 10

def test_bcl_interpreter_if_else():
    from bhrc_blockchain.core.contract.contract_engine import ENGINE_REGISTRY
    script = """
if args.get('flag'):
    state['value'] = 100
else:
    state['value'] = 0
"""
    context = {"state": {}}

    result = ENGINE_REGISTRY["BCL-1.0"](script, context, {"flag": True})

    assert result["status"] == "success"
    assert context["state"]["value"] == 100

def test_bhrc20_transfer():
    from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract

    token = BHRC20Contract(name="TestToken", symbol="TTK", total_supply=1000, owner="xOWNER")

    assert token.balance_of("xOWNER") == 1000
    assert token.balance_of("xRECIPIENT") == 0

    success = token.transfer("xOWNER", "xRECIPIENT", 200)

    assert success is True
    assert token.balance_of("xOWNER") == 800
    assert token.balance_of("xRECIPIENT") == 200

def test_bhrc20_mint():
    from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract

    token = BHRC20Contract(name="TestToken", symbol="TTK", total_supply=1000, owner="xOWNER")

    assert token.balance_of("xOWNER") == 1000

    token.mint("xOWNER", 500)

    assert token.balance_of("xOWNER") == 1500
    assert token.total_supply == 1500

def test_bhrc20_burn():
    from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract

    token = BHRC20Contract(name="TestToken", symbol="TTK", total_supply=1000, owner="xOWNER")

    assert token.balance_of("xOWNER") == 1000

    success = token.burn("xOWNER", 300)

    assert success is True
    assert token.balance_of("xOWNER") == 700
    assert token.total_supply == 700

def test_bhrc20_approve_and_allowance():
    from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract

    token = BHRC20Contract(name="TestToken", symbol="TTK", total_supply=1000, owner="xOWNER")

    token.approve("xOWNER", "xSPENDER", 400)

    assert token.allowance("xOWNER", "xSPENDER") == 400

    token.approve("xOWNER", "xSPENDER", 250)

    assert token.allowance("xOWNER", "xSPENDER") == 250

def test_bhrc20_transfer_from():
    from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract

    token = BHRC20Contract(name="TestToken", symbol="TTK", total_supply=1000, owner="xOWNER")

    token.approve("xOWNER", "xSPENDER", 300)

    assert token.allowance("xOWNER", "xSPENDER") == 300

    success = token.transfer_from("xSPENDER", "xOWNER", "xRECIPIENT", 200)

    assert success is True
    assert token.balance_of("xOWNER") == 800
    assert token.balance_of("xRECIPIENT") == 200
    assert token.allowance("xOWNER", "xSPENDER") == 100

def test_bhrc20_metadata():
    from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract

    token = BHRC20Contract(name="MetaToken", symbol="MTK", total_supply=5000, owner="xOWNER")

    meta = token.metadata()

    assert meta["name"] == "MetaToken"
    assert meta["symbol"] == "MTK"
    assert meta["total_supply"] == 5000

def test_bhrc20_abi():
    from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract

    token = BHRC20Contract(name="AbiToken", symbol="ABI", total_supply=12345, owner="xOWNER")

    abi = token.get_abi()

    assert abi["name"] == "AbiToken"
    assert abi["symbol"] == "ABI"
    assert abi["total_supply"] == 12345
    assert "transfer" in abi["methods"]
    assert "metadata" in abi["methods"]

def test_bhrc721_mint_and_owner():
    from bhrc_blockchain.core.contract.bhrc721 import BHRC721Contract

    nft = BHRC721Contract(name="TestNFT", symbol="TNFT")

    success = nft.mint(1, "xOWNER", {"attr": "cool"})
    assert success is True
    assert nft.owner_of(1) == "xOWNER"

    duplicate = nft.mint(1, "xOTHER")
    assert duplicate is False

def test_bhrc721_transfer():
    from bhrc_blockchain.core.contract.bhrc721 import BHRC721Contract

    nft = BHRC721Contract(name="TestNFT", symbol="TNFT")
    nft.mint(2, "xOWNER")

    success = nft.transfer(2, "xOWNER", "xRECIPIENT")
    assert success is True
    assert nft.owner_of(2) == "xRECIPIENT"

    fail = nft.transfer(2, "xOWNER", "xHACKER")
    assert fail is False

def test_bhrc721_burn():
    from bhrc_blockchain.core.contract.bhrc721 import BHRC721Contract

    nft = BHRC721Contract(name="TestNFT", symbol="TNFT")
    nft.mint(3, "xOWNER")

    success = nft.burn(3)
    assert success is True
    assert nft.owner_of(3) is None

    fail = nft.burn(3)
    assert fail is False

def test_bhrc721_metadata():
    from bhrc_blockchain.core.contract.bhrc721 import BHRC721Contract

    nft = BHRC721Contract(name="MetaNFT", symbol="MNFT")
    nft.mint(10, "xOWNER")

    meta = nft.metadata()

    assert meta["name"] == "MetaNFT"
    assert meta["symbol"] == "MNFT"
    assert meta["total_supply"] == 1

def test_bhrc721_abi():
    from bhrc_blockchain.core.contract.bhrc721 import BHRC721Contract

    nft = BHRC721Contract(name="AbiNFT", symbol="ANFT")
    nft.mint(99, "xOWNER")

    abi = nft.get_abi()

    assert abi["name"] == "AbiNFT"
    assert abi["symbol"] == "ANFT"
    assert abi["total_supply"] == 1
    assert "mint" in abi["methods"]
    assert "metadata" in abi["methods"]

def test_deploy_template_bhrc20():
    engine = SmartContractEngine()
    addr = "xTOKEN1"

    success = engine.deploy_template(
        "BHRC20", addr, name="MyToken", symbol="MTK", total_supply=1000, owner="xOWNER"
    )
    assert success is True

    contract = engine.contracts[addr]["object"]
    meta = contract.metadata()

    assert meta["name"] == "MyToken"
    assert meta["symbol"] == "MTK"
    assert meta["total_supply"] == 1000

def test_deploy_template_bhrc721():
    engine = SmartContractEngine()
    addr = "xNFT1"

    success = engine.deploy_template(
        "BHRC721", addr, name="MyNFT", symbol="MNFT"
    )
    assert success is True

    contract = engine.contracts[addr]["object"]
    meta = contract.metadata()

    assert meta["name"] == "MyNFT"
    assert meta["symbol"] == "MNFT"
    assert meta["total_supply"] == 0

def test_call_template_method_bhrc20_transfer():
    engine = SmartContractEngine()
    addr = "xTOKEN_TEST"

    engine.deploy_template(
        "BHRC20", addr, name="CallToken", symbol="CTK", total_supply=500, owner="xOWNER"
    )

    contract = engine.contracts[addr]["object"]

    assert contract.balance_of("xOWNER") == 500
    assert contract.balance_of("xRECIPIENT") == 0

    result = contract.transfer(from_addr="xOWNER", to_addr="xRECIPIENT", amount=200)
    assert result is True

    assert contract.balance_of("xOWNER") == 300
    assert contract.balance_of("xRECIPIENT") == 200

def test_call_template_method_bhrc721_mint_and_transfer():
    engine = SmartContractEngine()
    addr = "xNFT_TEST"

    engine.deploy_template(
        "BHRC721", addr, name="CallNFT", symbol="CNFT"
    )

    contract = engine.contracts[addr]["object"]

    success = contract.mint(token_id=100, to_addr="xOWNER", metadata={"name": "NFT100"})
    assert success is True
    assert contract.owner_of(100) == "xOWNER"

    success = contract.transfer(token_id=100, from_addr="xOWNER", to_addr="xRECIPIENT")
    assert success is True
    assert contract.owner_of(100) == "xRECIPIENT"

def test_contract_state_persistence_across_engine_restart():
    from bhrc_blockchain.core.contract.contract_engine import SmartContractEngine
    from bhrc_blockchain.core.contract.contract_state_storage import reset_all_contract_states

    reset_all_contract_states()

    addr = "xSTATE_TEST"
    code = "state['counter'] = state.get('counter', 0) + 10"

    engine1 = SmartContractEngine()
    engine1.deploy_contract(addr, code, {"counter": 0})

    result1 = engine1.call_contract_with_state(addr, {})
    assert result1["status"] == "success"
    assert result1["state"]["counter"] == 10

    engine2 = SmartContractEngine()
    engine2.load_all_from_db()

    contract2 = engine2.get_contract(addr)
    assert contract2 is not None
    assert contract2["state"]["counter"] == 10

    result2 = engine2.call_contract_with_state(addr, {})
    assert result2["status"] == "success"
    assert result2["state"]["counter"] == 20

def test_reset_contracts_clears_db_and_ram():
    from bhrc_blockchain.core.contract.contract_engine import SmartContractEngine

    addr = "xRESET_TEST"
    code = "state['value'] = 123"

    engine = SmartContractEngine()
    engine.deploy_contract(addr, code, {})

    assert addr in engine.contracts

    loaded = load_contract_state(addr)
    assert loaded is not None

    engine.reset_contracts()

    assert addr not in engine.contracts

    loaded_after = load_contract_state(addr)
    assert loaded_after is None

def test_manifest_hash_computation():
    from bhrc_blockchain.api.contract_routes import compute_manifest_hash

    script = "result = 42"
    timestamp = int(time.time())
    nonce = 123456

    manifest_hash = compute_manifest_hash(script, timestamp, nonce)

    assert len(manifest_hash) == 64
    print(f"Manifest Hash: {manifest_hash}")

def test_safe_execute_script_with_version():
    from bhrc_blockchain.core.contract.contract_engine import safe_execute_script

    script = "result = 77"
    context = {"state": {}}

    output = safe_execute_script(script, context, version="1.1")

    assert output["status"] == "success"
    assert output["result"] == 77
    print(f"Versioned Script Output: {output}")
