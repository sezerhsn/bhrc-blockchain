import os
import sys
import argparse
import json
import logging
from typing import Dict, Optional, List, Union
from bhrc_blockchain.core.wallet.wallet import (
    generate_wallet,
    MinerWallet,
    verify_address_from_key,
    generate_mnemonic,
    get_wallet_from_mnemonic,
    export_wallet,
    import_wallet_from_mnemonic,
    import_wallet_from_private_key,
    generate_child_wallet,
)
from bhrc_blockchain.core.logger.logger import setup_logger

logger = setup_logger("WalletCLI")

# ────────── YARDIMCI ÇIKIŞ FONKSİYONLARI ──────────

def output_success(data: dict):
    print(json.dumps({"status": "success", "data": data}, indent=2))
    sys.exit(0) # pragma: no cover

def output_error(message: str):
    print(json.dumps({"status": "error", "message": message}, indent=2))
    sys.exit(1) # pragma: no cover


# ────────── READ-ONLY KOMUTLAR ──────────

def load_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)

    wallet = MinerWallet(wallet_path=args["path"], password=args["password"])
    return {
        "private_key": wallet.private_key.hex() if isinstance(wallet.private_key, bytes) else wallet.private_key,
        "public_key": wallet.public_key.hex() if isinstance(wallet.public_key, bytes) else wallet.public_key,
        "address": wallet.address
    }

def show_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)

    wallet = MinerWallet(wallet_path=args["path"], password=args["password"], persist=False)
    return {
        "private_key": wallet.private_key,
        "public_key": wallet.public_key,
        "address": wallet.address
    }

def summary_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)
    wallet = MinerWallet(wallet_path=args["path"], password=args["password"])
    return {
        "address": wallet.address,
        "public_key": wallet.public_key
    }

def info_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)
    wallet = MinerWallet(wallet_path=args["path"], password=args["password"], persist=False)
    return {"address": wallet.address}

def verify_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)
    return verify_address_from_key(args["private_key"], args["address"])

def verify_mnemonic_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.wallet.wallet import is_valid_address
    args = args if isinstance(args, dict) else vars(args)

    data = get_wallet_from_mnemonic(args["mnemonic"])
    valid = is_valid_address(data["address"])
    return {
        "address": data["address"],
        "valid": valid
    }

def verify_integrity_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.wallet.wallet import verify_wallet_integrity
    args = args if isinstance(args, dict) else vars(args)

    wallet = {
        "private_key": args["private_key"],
        "public_key": args["public_key"],
        "address": args["address"],
        "mnemonic": args.get("mnemonic")
    }
    return verify_wallet_integrity(wallet, password=args.get("password", ""))

def get_pubkey_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.wallet.wallet import get_public_key_from_private_key
    args = args if isinstance(args, dict) else vars(args)

    pubkey = get_public_key_from_private_key(args["private_key"])
    return {"public_key": pubkey}

def get_address_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.wallet.wallet import (
        get_public_key_from_private_key,
        get_address_from_private_key
    )
    args = args if isinstance(args, dict) else vars(args)

    public_key = get_public_key_from_private_key(args["private_key"])
    address = get_address_from_private_key(args["private_key"])
    return {
        "public_key": public_key,
        "address": address
    }


# ────────── WALLET LIFECYCLE KOMUTLARI ──────────

def create_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)

    if not args.get("path"):
        raise ValueError("Cüzdan dosya yolu (--path) belirtilmeli.")

    mnemonic_str = None
    if args.get("mnemonic"):
        m = args["mnemonic"]
        mnemonic_str = " ".join(m) if isinstance(m, list) else m

    return generate_wallet(wallet_path=args["path"], password=args.get("password"), mnemonic=mnemonic_str)

def generate_mnemonic_cli():
    return generate_mnemonic()

def import_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)

    if args.get("mnemonic"):
        wallet_data = generate_child_wallet(args["mnemonic"], index=args.get("index", 0))
        wallet = MinerWallet(
            wallet_path=args["path"],
            password=args["password"],
            private_key=wallet_data["private_key"],
            persist=True
        )
    elif args.get("private_key"):
        wallet = MinerWallet(
            wallet_path=args["path"],
            password=args["password"],
            private_key=args.get("private_key"),
            persist=True
        )
    else:
        raise ValueError("⚠️ Import için mnemonic veya private_key gereklidir.")

    wallet.save_to_file()
    return wallet.to_dict()

def export_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)
    return export_wallet(
        args["path"],
        args["password"],
        include_mnemonic=args.get("mnemonic", False),
        only_address=args.get("only_address", False)
    )

def delete_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)

    if not os.path.exists(args["path"]):
        raise FileNotFoundError("❌ Belirtilen cüzdan dosyası bulunamadı.")

    os.remove(args["path"])
    return {"deleted": True, "path": args["path"]}

def rename_wallet_cli(args: Union[argparse.Namespace, dict]):
    args = args if isinstance(args, dict) else vars(args)

    wallet = MinerWallet(wallet_path=args["path"], password=args["password"])
    wallet.rename_wallet_file(args["new_path"])
    return {"renamed_to": args["new_path"]}

def from_hardware_wallet_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.wallet.wallet import from_hardware_wallet
    args = args if isinstance(args, dict) else vars(args)

    return from_hardware_wallet(index=args.get("index", 0))

def generate_child_wallet_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.wallet.wallet import generate_child_wallet
    args = args if isinstance(args, dict) else vars(args)

    child = generate_child_wallet(args["mnemonic"], args["index"])
    return {
        "private_key": child["private_key"],
        "public_key": child["public_key"],
        "address": child["address"]
    }


# ────────── TRANSACTIONAL KOMUTLAR ──────────

def send_transaction_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.transaction.transaction import create_transaction, validate_transaction
    from bhrc_blockchain.core.mempool.mempool import add_transaction_to_mempool

    args = args if isinstance(args, dict) else vars(args)
    wallet = MinerWallet(wallet_path=args["path"], password=args["password"])

    tx = create_transaction(
        sender=wallet.address,
        recipient=args["recipient"],
        amount=args["amount"],
        message=args.get("message", "") or "",
        note=args.get("note", "") or "",
        sender_private_key=wallet.private_key,
        fee=args.get("fee")
    )

    validate_transaction(tx)
    add_transaction_to_mempool(tx)
    return tx

def sign_message_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.wallet.wallet import sign_message
    args = args if isinstance(args, dict) else vars(args)

    signature = sign_message(args["private_key"], args["message"])
    return {"signature": signature}

def verify_signature_cli(args: Union[argparse.Namespace, dict]):
    from bhrc_blockchain.core.wallet.wallet import verify_signature
    args = args if isinstance(args, dict) else vars(args)

    is_valid = verify_signature(args["public_key"], args["message"], args["signature"])
    return {"valid": is_valid}

# ────────── ARGPARSE YENİ GRUPLU YAPI ──────────

def build_parser():
    parser = argparse.ArgumentParser(description="💼 BHRC Wallet CLI Aracı")
    subparsers = parser.add_subparsers(dest="group", required=True)

    # READ GROUP
    read_parser = subparsers.add_parser("read", help="Cüzdanı okuma işlemleri")
    read_sub = read_parser.add_subparsers(dest="command", required=True)

    read_info = read_sub.add_parser("info")
    read_info.add_argument("--path", required=True)
    read_info.add_argument("--password", required=True)

    read_summary = read_sub.add_parser("summary")
    read_summary.add_argument("--path", required=True)
    read_summary.add_argument("--password", required=True)

    read_show = read_sub.add_parser("show")
    read_show.add_argument("--path", required=True)
    read_show.add_argument("--password", required=True)

    read_load = read_sub.add_parser("load")
    read_load.add_argument("--path", required=True)
    read_load.add_argument("--password", required=True)

    read_verify = read_sub.add_parser("verify")
    read_verify.add_argument("--private_key", required=True)
    read_verify.add_argument("--address", required=True)

    read_verify_mnemonic = read_sub.add_parser("verify-mnemonic")
    read_verify_mnemonic.add_argument("--mnemonic", required=True)

    read_integrity = read_sub.add_parser("verify-integrity")
    read_integrity.add_argument("--private_key", required=True)
    read_integrity.add_argument("--public_key", required=True)
    read_integrity.add_argument("--address", required=True)
    read_integrity.add_argument("--mnemonic")
    read_integrity.add_argument("--password")

    read_pubkey = read_sub.add_parser("get-pubkey")
    read_pubkey.add_argument("--private_key", required=True)

    read_address = read_sub.add_parser("get-address")
    read_address.add_argument("--private_key", required=True)

    # WALLET GROUP
    wallet_parser = subparsers.add_parser("wallet", help="Cüzdan yaşam döngüsü işlemleri")
    wallet_sub = wallet_parser.add_subparsers(dest="command", required=True)

    w_create = wallet_sub.add_parser("create")
    w_create.add_argument("--path")
    w_create.add_argument("--password")
    w_create.add_argument("--mnemonic", nargs="+")

    w_import = wallet_sub.add_parser("import")
    w_import.add_argument("--mnemonic")
    w_import.add_argument("--private_key")
    w_import.add_argument("--password", required=True)
    w_import.add_argument("--path")

    w_export = wallet_sub.add_parser("export")
    w_export.add_argument("--path", required=True)
    w_export.add_argument("--password", required=True)
    w_export.add_argument("--mnemonic", action="store_true")
    w_export.add_argument("--only-address", action="store_true")

    w_delete = wallet_sub.add_parser("delete")
    w_delete.add_argument("--path", required=True)

    w_rename = wallet_sub.add_parser("rename")
    w_rename.add_argument("--path", required=True)
    w_rename.add_argument("--new_path", required=True)
    w_rename.add_argument("--password", required=True)

    w_mnemonic = wallet_sub.add_parser("mnemonic")

    w_child = wallet_sub.add_parser("child-wallet")
    w_child.add_argument("--mnemonic", required=True)
    w_child.add_argument("--index", type=int, required=True)

    w_hw = wallet_sub.add_parser("from-hardware")
    w_hw.add_argument("--index", type=int, default=0)

    # TX GROUP
    tx_parser = subparsers.add_parser("tx", help="İşlemsel komutlar")
    tx_sub = tx_parser.add_subparsers(dest="command", required=True)

    tx_send = tx_sub.add_parser("send")
    tx_send.add_argument("--path", required=True)
    tx_send.add_argument("--password", required=True)
    tx_send.add_argument("--recipient", required=True)
    tx_send.add_argument("--amount", type=float, required=True)
    tx_send.add_argument("--fee", type=float)
    tx_send.add_argument("--message")
    tx_send.add_argument("--note")

    tx_sign = tx_sub.add_parser("sign")
    tx_sign.add_argument("--private_key", required=True)
    tx_sign.add_argument("--message", required=True)

    tx_verify = tx_sub.add_parser("verify-signature")
    tx_verify.add_argument("--public_key", required=True)
    tx_verify.add_argument("--message", required=True)
    tx_verify.add_argument("--signature", required=True)

    return parser

# ────────── ANA ÇALIŞTIRICI ──────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        # Komut eşleşme yapısı
        dispatch = {
            "read": {
                "info": info_wallet_cli,
                "summary": summary_wallet_cli,
                "show": show_wallet_cli,
                "load": load_wallet_cli,
                "verify": verify_wallet_cli,
                "verify-mnemonic": verify_mnemonic_cli,
                "verify-integrity": verify_integrity_cli,
                "get-pubkey": get_pubkey_cli,
                "get-address": get_address_cli
            },
            "wallet": {
                "create": create_wallet_cli,
                "import": import_wallet_cli,
                "export": export_wallet_cli,
                "delete": delete_wallet_cli,
                "rename": rename_wallet_cli,
                "mnemonic": lambda args: {"mnemonic": generate_mnemonic_cli()},
                "child-wallet": generate_child_wallet_cli,
                "from-hardware": from_hardware_wallet_cli
            },
            "tx": {
                "send": send_transaction_cli,
                "sign": sign_message_cli,
                "verify-signature": verify_signature_cli
            }
        }

        group_cmds = dispatch.get(args.group)
        if not group_cmds:
            raise ValueError(f"❌ Tanımsız grup: {args.group}")

        func = group_cmds.get(args.command)
        if not func:
            raise ValueError(f"❌ Tanımsız komut: {args.command}")

        result = func(args)

        # Bazı komutlara özel çıktı biçimi
        if args.group == "read" and args.command == "verify":
            logger.info("🔍 Doğrulama sonucu: %s", "Geçerli" if result else "Geçersiz")
            output_success({"valid": result})

        elif args.group == "wallet" and args.command == "export":
            if getattr(args, "only_address", False):
                logger.info("📤 Adres dışa aktarıldı: %s", result["address"])
                output_success({"address": result["address"]})
            else:
                logger.info("📤 Cüzdan dışa aktarıldı: %s", result["address"])
                output_success(result)

        elif args.group == "read" and args.command == "verify-integrity":
            logger.info("🧩 Cüzdan bütünlüğü doğrulandı mı? %s", "Evet" if result else "Hayır")
            output_success({"valid": result})

        elif args.group == "tx" and args.command == "send":
            logger.info("📨 İşlem gönderildi: %s", result["txid"])
            print(f"✅ Gönderilen işlem kimliği: {result['txid']}")
            output_success(result)

        else:
            logger.info("✅ Komut: %s/%s → %s", args.group, args.command, result.get("address", result))
            output_success(result)

    except Exception as e:
        logger.error("❌ Hata: %s", e)
        output_error(str(e))


if __name__ == "__main__":
    main()

