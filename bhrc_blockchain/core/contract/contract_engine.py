import time
from typing import Dict, Any
from bhrc_blockchain.core.logger.logger import setup_logger
from bhrc_blockchain.core.contract.evaluator import evaluate_contract

logger = setup_logger("ContractEngine")


class SmartContractEngine:
    def __init__(self):
        self.contracts: Dict[str, Dict[str, Any]] = {}  # {contract_address: {code, state}}

    def deploy_contract(self, contract_address: str, code: str, initial_state: Dict = None) -> bool:
        if contract_address in self.contracts:
            logger.warning(f"⚠️ Bu adreste zaten bir sözleşme var: {contract_address}")
            return False

        self.contracts[contract_address] = {
            "code": code,
            "state": initial_state or {}
        }
        logger.info(f"✅ Yeni sözleşme dağıtıldı: {contract_address}")
        return True

    def call_contract_method(self, contract_address: str, method: str, args: Dict = None) -> Any:
        contract = self.contracts.get(contract_address)
        if not contract:
            logger.warning(f"⛔ Sözleşme bulunamadı: {contract_address}")
            return None

        # Basit bir method çağırıcı
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

