from bhrc_blockchain.core.blockchain.blockchain import Blockchain
from bhrc_blockchain.core.block import Block
from bhrc_blockchain.core.wallet.wallet import generate_private_key, sign_block
import time

def test_invalid_block_signature_rejected():
    blockchain = Blockchain(autoload=False)
    last_block = blockchain.get_last_block()

    # Sahte blok üret (geçerli hash, geçersiz imza)
    fake_block = Block(
        index=last_block.index + 1,
        previous_hash=last_block.block_hash,
        transactions=[],
        timestamp=time.time(),
        nonce=0,
        miner_address="xFAKE",
        difficulty=blockchain.difficulty_prefix,
        events=["⚠️ Sahte imzalı blok eklendi."]
    )
    fake_block.mine()

    # Yanlış private key ile imzala
    fake_private_key = generate_private_key()
    fake_block.block_signature = sign_block(fake_block, fake_private_key)
    fake_block.producer_id = "xBHR_NOT_MATCHING"

    # Zincire eklenmeye çalışılsın
    result = blockchain.add_block(fake_block)

    assert result is False, "Geçersiz imzalı blok zincire eklenmemeliydi!"

