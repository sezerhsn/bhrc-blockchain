from bhrc_blockchain.core.state.state_db import StateDB

def test_state_db_operations():
    db = StateDB()

    # 1. set ve get
    db.set("x123", {"balance": 100})
    assert db.get("x123") == {"balance": 100}

    # 2. update
    db.set("x123", {"balance": 200})
    assert db.get("x123")["balance"] == 200

    # 3. delete
    db.delete("x123")
    assert db.get("x123") is None

    # 4. all() ve reset()
    db.set("a", 1)
    db.set("b", 2)
    state = db.all()
    assert state == {"a": 1, "b": 2}

    db.reset()
    assert db.all() == {}

