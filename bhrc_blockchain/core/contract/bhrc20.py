class BHRC20Contract:
    def __init__(self, name: str, symbol: str, total_supply: int, owner: str):
        self.name = name
        self.symbol = symbol
        self.total_supply = total_supply
        self.balances = {owner: total_supply}

    def transfer(self, from_addr: str, to_addr: str, amount: int) -> bool:
        if self.balances.get(from_addr, 0) >= amount:
            self.balances[from_addr] -= amount
            self.balances[to_addr] = self.balances.get(to_addr, 0) + amount
            return True
        return False

    def balance_of(self, addr: str) -> int:
        return self.balances.get(addr, 0)

    def mint(self, to_addr: str, amount: int):
        self.total_supply += amount
        self.balances[to_addr] = self.balances.get(to_addr, 0) + amount

    def burn(self, from_addr: str, amount: int) -> bool:
        if self.balances.get(from_addr, 0) >= amount:
            self.balances[from_addr] -= amount
            self.total_supply -= amount
            return True
        return False

    def approve(self, owner_addr: str, spender_addr: str, amount: int):
        if not hasattr(self, "allowances"):
            self.allowances = {}

        if owner_addr not in self.allowances:
            self.allowances[owner_addr] = {}

        self.allowances[owner_addr][spender_addr] = amount

    def allowance(self, owner_addr: str, spender_addr: str) -> int:
        if not hasattr(self, "allowances"):
            self.allowances = {}

        return self.allowances.get(owner_addr, {}).get(spender_addr, 0)

    def transfer_from(self, spender_addr: str, owner_addr: str, to_addr: str, amount: int) -> bool:
        if not hasattr(self, "allowances"):
            self.allowances = {}

        allowed = self.allowances.get(owner_addr, {}).get(spender_addr, 0)
        if allowed >= amount and self.balances.get(owner_addr, 0) >= amount:
            self.balances[owner_addr] -= amount
            self.balances[to_addr] = self.balances.get(to_addr, 0) + amount
            self.allowances[owner_addr][spender_addr] -= amount
            return True
        return False

    def metadata(self):
        return {
            "name": self.name,
            "symbol": self.symbol,
            "total_supply": self.total_supply
        }

    def get_abi(self):
        return {
            "name": self.name,
            "symbol": self.symbol,
            "total_supply": self.total_supply,
            "methods": [
                "transfer",
                "mint",
                "burn",
                "approve",
                "transfer_from",
                "balance_of",
                "allowance",
                "metadata"
            ]
        }

