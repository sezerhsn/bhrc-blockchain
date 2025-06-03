class UTXOManager:
    def __init__(self):
        self.utxos = {}  # { txid_output_index: utxo_dict }

    def add_utxos(self, txid: str, outputs: list):
        for i, output in enumerate(outputs):
            key = f"{txid}_{i}"
            self.utxos[key] = output

    def remove_utxos(self, inputs: list):
        for tx_input in inputs:
            key = f"{tx_input['txid']}_{tx_input['index']}"
            self.utxos.pop(key, None)

    def get_utxo(self, txid: str, index: int):
        return self.utxos.get(f"{txid}_{index}")

    def validate_input(self, tx_input: dict, sender: str) -> bool:
        utxo = self.get_utxo(tx_input["txid"], tx_input["index"])
        return utxo and utxo["recipient"] == sender

    def apply_transaction(self, tx: dict):
        self.remove_utxos(tx.get("inputs", []))
        self.add_utxos(tx["txid"], tx.get("outputs", []))

    def reset(self):
        self.utxos = {}

    def is_utxo_owner(self, inputs, address):
        for inp in inputs:
            utxo = self.get_utxo(inp["txid"], inp["index"])
            if not utxo:
                return False
            if utxo.get("address") != address and utxo.get("recipient") != address:
                return False
        return True

    def update_with_transaction(self, transaction):
        self.remove_utxos(transaction.get("inputs", []))
        self.add_utxos(transaction["txid"], transaction.get("outputs", []))

