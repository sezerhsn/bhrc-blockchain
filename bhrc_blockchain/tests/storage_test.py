import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from bhrc_blockchain.database.models import Base, BlockModel, UTXOModel
from bhrc_blockchain.database.orm_storage import (
    save_block,
    save_utxos,
    spend_utxos,
    get_unspent_utxos,
    apply_utxo_changes
)

TEST_DB = "sqlite:///test_bhrc_blockchain.db"

@pytest.fixture(scope="function")
def session():
    engine = create_engine(TEST_DB)
    Session = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    s = Session()
    yield s
    s.close()
    os.remove("test_bhrc_blockchain.db")


def test_save_block_and_read_back(session):
    block = {
        "index": 1,
        "block_hash": "abc123",
        "previous_hash": "000000",
        "timestamp": 1234567890.0,
        "miner_address": "xBHR" + "A" * 60,
        "merkle_root": "merkle123",
        "nonce": 0,
        "version": "0x01",
        "virtual_size": 1024,
        "transactions": []
    }
    save_block(block, session=session)
    result = session.query(BlockModel).filter_by(block_hash="abc123").first()
    assert result is not None
    assert result.block_index == 1


def test_utxo_save_and_spend(session):
    txid = "txABC"
    outputs = [{"address": "xBHR" + "D" * 60, "amount": 20.0}]
    save_utxos(txid, outputs, session=session)

    utxos = get_unspent_utxos(outputs[0]["address"], session=session)
    assert len(utxos) == 1
    assert utxos[0].amount == 20.0

    spend_utxos([{"txid": txid, "output_index": 0}], session=session)
    remaining = get_unspent_utxos(outputs[0]["address"], session=session)
    assert len(remaining) == 0


def test_apply_utxo_changes_with_coinbase_and_transfer(session):
    txs = [
        {
            "type": "coinbase",
            "txid": "coinbase1",
            "outputs": [{"recipient": "xBHR" + "C" * 60, "amount": 50.0}]
        },
        {
            "type": "transfer",
            "txid": "tx123",
            "inputs": [{"txid": "coinbase1", "output_index": 0}],
            "outputs": [{"recipient": "xBHR" + "Z" * 60, "amount": 30.0}]
        }
    ]

    apply_utxo_changes(txs, session=session)

    spent = get_unspent_utxos("xBHR" + "C" * 60, session=session)
    assert len(spent) == 0

    new_utxo = get_unspent_utxos("xBHR" + "Z" * 60, session=session)
    assert len(new_utxo) == 1
    assert new_utxo[0].amount == 30.0

