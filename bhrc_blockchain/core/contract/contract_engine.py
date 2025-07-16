# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

import multiprocessing
import json
import ast
import time
from typing import Dict, Any
from bhrc_blockchain.core.logger.logger import setup_logger
from bhrc_blockchain.core.contract.evaluator import evaluate_contract
from .contract_state_storage import (
    save_contract_state,
    load_contract_state,
    delete_contract_state,
    reset_all_contract_states
)

logger = setup_logger("ContractEngine")


class SmartContractEngine:
    def __init__(self):
        self.contracts: Dict[str, Dict[str, Any]] = {}
        self.load_all_from_db()

    def load_all_from_db(self):
        logger.info("🔄 Contract state DB yükleniyor...")
        from .contract_state_storage import list_all_contracts

        all_contracts = list_all_contracts()
        for item in all_contracts:
            addr = item["contract_address"]
            loaded = load_contract_state(addr)
            if loaded:
                code, state = loaded
                self.contracts[addr] = {
                    "code": code,
                    "state": state,
                    "events": [],
                }
        logger.info(f"✅ {len(self.contracts)} sözleşme RAM'e yüklendi.")

    def deploy_contract(self, contract_address: str, code: str, initial_state: Dict = None) -> bool:
        if contract_address in self.contracts:
            logger.warning(f"⚠️ Bu adreste zaten bir sözleşme var: {contract_address}")
            return False

        self.contracts[contract_address] = {
            "code": code,
            "state": initial_state or {},
            "events": [],
        }
        logger.info(f"✅ Yeni sözleşme dağıtıldı: {contract_address}")

        save_contract_state(contract_address, code, initial_state or {})

        return True

    def call_contract_method(self, contract_address: str, method: str, args: Dict = None) -> Any:
        contract = self.contracts.get(contract_address)
        if not contract:
            logger.warning(f"⛔ Sözleşme bulunamadı: {contract_address}")
            return None

        state = contract["state"]
        if method == "increment":
            state["counter"] = state.get("counter", 0) + 1
            return state["counter"]

        elif method == "get":
            return state

        logger.warning(f"❌ Desteklenmeyen method: {method}")
        return None

    def get_contract(self, contract_address: str) -> Dict[str, Any]:
        return self.contracts.get(contract_address, {})

    def call_contract_with_state(self, contract_address: str, params: dict) -> dict:
        contract = self.contracts.get(contract_address)
        if not contract:
            raise ValueError("Sözleşme bulunamadı.")

        code = contract["code"]
        state = contract["state"]

        context = {"state": state.copy(), **params}

        result = execute_script("BHRC-Logic-1.0", code, context, params)

        new_state = result.get("state", state)
        contract["state"] = new_state

        save_contract_state(contract_address, code, new_state)

        return {
            "status": result.get("status"),
            "result": result.get("result"),
            "state": new_state,
            "logs": result.get("logs", []),
            "gas_used": result.get("gas_used", 0)
        }

    def deploy_template(self, template_name: str, contract_address: str, **kwargs) -> bool:
        if contract_address in self.contracts:
            logger.warning(f"⚠️ Bu adreste zaten bir sözleşme var: {contract_address}")
            return False

        if template_name == "BHRC20":
            from bhrc_blockchain.core.contract.bhrc20 import BHRC20Contract
            contract = BHRC20Contract(
                name=kwargs.get("name", "Token"),
                symbol=kwargs.get("symbol", "TKN"),
                total_supply=kwargs.get("total_supply", 0),
                owner=kwargs.get("owner", "xOWNER")
            )
        elif template_name == "BHRC721":
            from bhrc_blockchain.core.contract.bhrc721 import BHRC721Contract
            contract = BHRC721Contract(
                name=kwargs.get("name", "NFT"),
                symbol=kwargs.get("symbol", "NFT")
            )
        else:
            logger.error(f"⛔ Bilinmeyen template: {template_name}")
            return False

        self.contracts[contract_address] = {
            "template": template_name,
            "object": contract,
            "events": [],
            "version": "v1.0.0",
        }
        logger.info(f"✅ Template sözleşme deploy edildi: {contract_address} ({template_name})")
        return True

    def reset_contracts(self):
        count = len(self.contracts)
        self.contracts.clear()
        reset_all_contract_states()
        logger.info(f"🗑️ Tüm {count} sözleşme RAM ve DB'den temizlendi.")

def execute_script(script_type: str, script: str, context: dict, params: dict = None, timeout_seconds: int = 2) -> dict:
    engine_func = ENGINE_REGISTRY.get(script_type)
    if not engine_func:
        raise ValueError(f"Bilinmeyen script türü: {script_type}")

    return engine_func(script, context, params, timeout_seconds)

def safe_execute_script(script: str, context: dict, params: dict = None, version: str = "1.0") -> dict:
    try:
        parsed_ast = ast.parse(script, mode='exec')

        allowed_nodes = (
            ast.Module, ast.Assign, ast.Expr, ast.If, ast.Compare, ast.BinOp,
            ast.UnaryOp, ast.BoolOp, ast.Name, ast.Load, ast.Store, ast.Constant,
            ast.Return, ast.Call,
            ast.Add, ast.Sub, ast.Mult, ast.Div,
            ast.Subscript,
            ast.While,
            ast.Pass,
            ast.Attribute,
            ast.For,
        )

        for node in ast.walk(parsed_ast):
            if not isinstance(node, allowed_nodes):
                raise ValueError(f"Script içinde izin verilmeyen kod tespit edildi: {type(node).__name__}")

        local_context = {}
        if params:
            local_context.update(params)
        local_context.update(context)

        logger.info(f"[DEBUG] Script version: {version}")
        logger.info(f"[DEBUG] With local_context: {local_context}")

        exec(compile(parsed_ast, filename="<safe_script>", mode="exec"), {}, local_context)

        result = local_context.get("result", None)

        context["state"] = local_context.get("state", context.get("state", {}))

        return {
            "status": "success",
            "result": result,
            "state": local_context.get("state", {}),
            "logs": ["Contract executed in safe mode."],
            "gas_used": 10
        }

    except Exception as e:
        logger.error(f"[ERROR] Exception during execution: {e}")
        return {
            "status": "error",
            "error": str(e),
            "logs": ["Execution failed."],
            "gas_used": 0
        }

class ContractRegistry:
    def __init__(self):
        self.registry = {}

    def deploy(self, contract_hash: str, code: str) -> bool:
        if contract_hash in self.registry:
            return False
        self.registry[contract_hash] = code
        return True

    def get(self, contract_hash: str) -> str:
        return self.registry.get(contract_hash)

contract_engine = SmartContractEngine()
contract_registry = contract_engine

def execute_script_in_subprocess(script: str, context: dict, params: dict = None, timeout_seconds: int = 2) -> dict:
    def target_func(q, script, context, params):
        result = safe_execute_script(script, context, params)
        q.put(json.dumps(result))

    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=target_func, args=(q, script, context, params))

    p.start()
    p.join(timeout_seconds)

    if p.is_alive():
        logger.error(f"[ERROR] Script execution timed out after {timeout_seconds} seconds.")
        p.terminate()
        p.join()
        return {
            "status": "error",
            "error": "Timeout: script execution exceeded time limit.",
            "logs": ["Execution timed out."],
            "gas_used": 0
        }

    if not q.empty():
        result_json = q.get()
        return json.loads(result_json)
    else:
        logger.error("[ERROR] Script execution failed: no result returned.")
        return {
            "status": "error",
            "error": "Execution failed: no result.",
            "logs": ["Execution failed."],
            "gas_used": 0
        }

class BCLInterpreter:
    def execute(self, script: str, context: dict, params: dict = None, timeout_seconds: int = 2):
        local_context = {
            "state": context.get("state", {}),
            "args": params or {},
            "now": int(time.time()),
            "__builtins__": {
                "len": len, "min": min, "max": max, "int": int, "float": float, "str": str,
                "range": range,
            }
        }

        try:
            parsed_ast = ast.parse(script, mode="exec")

            allowed_nodes = (
                ast.Module, ast.Assign, ast.Expr, ast.If, ast.Compare, ast.BinOp,
                ast.UnaryOp, ast.BoolOp, ast.Name, ast.Load, ast.Store, ast.Constant,
                ast.Return, ast.Call,
                ast.Add, ast.Sub, ast.Mult, ast.Div,
                ast.Subscript, ast.While, ast.Pass, ast.Attribute,
                ast.For,
                ast.AugAssign,
                ast.Eq, ast.Gt, ast.Lt, ast.GtE, ast.LtE, ast.NotEq
            )

            for node in ast.walk(parsed_ast):
                if not isinstance(node, allowed_nodes):
                    raise ValueError(f"BCL içinde izin verilmeyen kod tespit edildi: {type(node).__name__}")

            exec(compile(parsed_ast, filename="<bcl_script>", mode="exec"), {}, local_context)

            context["state"] = local_context["state"]

            return {
                "status": "success",
                "result": local_context.get("result"),
                "logs": ["BCL executed."],
                "gas_used": 10
            }
        except Exception as e:
            logger.error(f"[BCL ERROR] {e}")
            return {
                "status": "error",
                "error": str(e),
                "logs": ["BCL execution failed."],
                "gas_used": 0
            }

ENGINE_REGISTRY = {
    "BHRC-Logic-1.0": execute_script_in_subprocess,
    "BHRC-Logic-1.1": lambda script, context, params=None, timeout_seconds=2: safe_execute_script(script, context, params, version="1.1"),
    "BCL-1.0": BCLInterpreter().execute
}

