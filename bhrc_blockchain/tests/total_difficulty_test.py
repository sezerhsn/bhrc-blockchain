from bhrc_blockchain.core.blockchain.blockchain import get_blockchain

def test_total_difficulty():
    chain = get_blockchain()
    total = chain.get_total_difficulty()
    assert isinstance(total, int)
    assert total >= 1

