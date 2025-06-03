from typing import Any

class StateDB:
    def __init__(self):
        self.state = {}

    def set(self, key: str, value: Any):
        self.state[key] = value

    def get(self, key: str) -> Any:
        return self.state.get(key)

    def delete(self, key: str):
        self.state.pop(key, None)

    def all(self) -> dict:
        return self.state.copy()

    def reset(self):
        self.state = {}

