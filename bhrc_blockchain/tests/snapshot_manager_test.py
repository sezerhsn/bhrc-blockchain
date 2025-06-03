import os
import time
import pytest
from bhrc_blockchain.core.snapshot.snapshot_manager import save_snapshot, load_snapshot
from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.wallet.wallet import generate_private_key, get_public_key_from_private_key, sign_block

@pytest.fixture
def snapshot_chain():
    bc = Blockchain(autoload=False)
    bc.reset_chain()

    priv = generate_private_key()
    pub = get_public_key_from_private_key(priv)

    last_block = bc.get_last_block()
    new_block = Block(
        index=1,
        previous_hash=last_block.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="xSNAP",
        producer_id=pub,
    )
    new_block.block_hash = new_block.calculate_hash()
    new_block.block_signature = sign_block(new_block, priv)

    bc.add_block(new_block)
    return bc

def test_snapshot_cycle(snapshot_chain):
    path = "test_snapshot.json"
    save_snapshot(snapshot_chain, path)
    assert os.path.exists(path)
    loaded_chain = load_snapshot(path)
    assert isinstance(loaded_chain, list)
    assert len(loaded_chain) >= 2
    assert loaded_chain[0].index == 0
    os.remove(path)

