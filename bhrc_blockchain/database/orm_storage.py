from sqlalchemy.orm import sessionmaker
from bhrc_blockchain.database.models import Base, BlockModel, UTXOModel
from bhrc_blockchain.database.database import engine
from bhrc_blockchain.core.logger.logging_utils import setup_logger

logger = setup_logger("ORM")

Session = sessionmaker(bind=engine)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

def get_session():
    return Session()

def save_block(block_dict, session=None):
    import json

    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    try:
        block = BlockModel(
            index=block_dict["index"],
            block_hash=block_dict["block_hash"],
            previous_hash=block_dict["previous_hash"],
            timestamp=block_dict["timestamp"],
            miner_address=block_dict["miner_address"],
            merkle_root=block_dict["merkle_root"],
            nonce=block_dict["nonce"],
            version=block_dict["version"],
            virtual_size=block_dict["virtual_size"],
            transactions=json.dumps(block_dict["transactions"])
        )

        session.add(block)

        if own_session:
            session.commit()
            session.close()

        logger.info(f"✅ Block {block_dict['index']} başarıyla kaydedildi.")
    except Exception as e:
        logger.error(f"🚨 Block kaydedilemedi: {e}")
        if own_session:
            session.rollback()

def save_utxos(txid, outputs, session=None):
    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    for idx, out in enumerate(outputs):
        utxo = UTXOModel(
            txid=txid,
            output_index=idx,
            address=out.get("address", out.get("recipient")),
            amount=out["amount"],
            spent=0
        )
        session.add(utxo)
    if own_session:
        session.commit()
        session.close()

def spend_utxos(txid_inputs, session=None):
    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    for utxo in txid_inputs:
        session.query(UTXOModel).filter_by(
            txid=utxo["txid"],
            output_index=utxo["output_index"]
        ).update({"spent": 1})
    if own_session:
        session.commit()
        session.close()

def get_unspent_utxos(address, session=None):
    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    rows = session.query(UTXOModel).filter_by(address=address, spent=0).all()
    result = [row for row in rows if not row.txid.startswith("GENESIS_TXID")]

    if own_session:
        session.close()
    return result

def apply_utxo_changes(transactions, session=None):
    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    for tx in transactions:
        if tx["type"] != "coinbase":
            for utxo in tx.get("inputs", []):
                session.query(UTXOModel).filter_by(
                    txid=utxo["txid"],
                    output_index=utxo["output_index"]
                ).update({"spent": 1})

        for idx, out in enumerate(tx.get("outputs", [])):
            new_utxo = UTXOModel(
                txid=tx["txid"],
                output_index=idx,
                address=out["recipient"],
                amount=out["amount"],
                spent=0
            )
            session.add(new_utxo)

    if own_session:
        session.commit()
        session.close()

def clear_all_blocks(session=None):
    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    try:
        session.query(BlockModel).delete()
        session.commit()
        logger.info("✅ Tüm bloklar başarıyla silindi.")
    except Exception as e:
        logger.error(f"🚨 Bloklar silinemedi: {e}")
        session.rollback()
    finally:
        if own_session:
            session.close()

def clear_all_utxos(session=None):
    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    try:
        session.query(UTXOModel).delete()
        session.commit()
        logger.info("✅ Tüm UTXO'lar başarıyla silindi.")
    except Exception as e:
        logger.error(f"🚨 UTXO'lar silinemedi: {e}")
        session.rollback()
    finally:
        if own_session:
            session.close()

def clear_all_data(session=None):
    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    session.query(BlockModel).delete()
    session.query(UTXOModel).delete()
    session.commit()
    logger.info("🧹 ORM | Blok ve UTXO verileri temizlendi.")

    if own_session:
        session.close()

