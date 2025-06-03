import sys
import argparse
import json
import logging
from bhrc_blockchain.core.wallet.wallet import (
    generate_wallet,
    MinerWallet,
    verify_address_from_key,
    generate_mnemonic,
    get_wallet_from_mnemonic
)
from bhrc_blockchain.core.logger.logger import setup_logger

logger = setup_logger("WalletCLI")


def create_wallet_cli(args):
    if args.password and args.password.startswith("mnemonic:"):
        mnemonic_phrase = args.password.replace("mnemonic:", "")
        result = get_wallet_from_mnemonic(mnemonic_phrase)
        logger.info("🧠 Mnemonic ile oluşturulan cüzdan:")
        return result
    else:
        result = generate_wallet(wallet_path=args.path, password=args.password)
        logger.info("🪙 Yeni cüzdan oluşturuldu:")
        return result


def load_wallet_cli(args):
    try:
        wallet = MinerWallet(wallet_path=args.path, password=args.password)
        logger.info("🔓 Cüzdan yüklendi:")
        return {
            "private_key": wallet.private_key.hex() if isinstance(wallet.private_key, bytes) else wallet.private_key,
            "public_key": wallet.public_key.hex() if isinstance(wallet.public_key, bytes) else wallet.public_key,
            "address": wallet.address
        }
    except Exception as e:
        logger.error(f"❌ Yükleme hatası: {e}")
        raise


def verify_wallet_cli(args):
    is_valid = verify_address_from_key(args.private_key, args.address)
    return is_valid


def generate_mnemonic_cli():
    phrase = generate_mnemonic()
    logger.info("🧠 Yeni mnemonic oluşturuldu:")
    return phrase


def parse_arguments():
    parser = argparse.ArgumentParser(description="💼 BHRC Wallet CLI Aracı")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="Yeni bir cüzdan oluştur")
    create_parser.add_argument("--path", type=str, help="Cüzdanın kaydedileceği yol (örnek: wallets/w1.json)")
    create_parser.add_argument("--password", type=str, help="Opsiyonel parola veya mnemonic:...")

    load_parser = subparsers.add_parser("load", help="Mevcut bir cüzdanı şifreyle yükle")
    load_parser.add_argument("--path", type=str, required=True, help="Cüzdan dosyasının yolu")
    load_parser.add_argument("--password", type=str, required=True, help="Cüzdan şifresi")

    verify_parser = subparsers.add_parser("verify", help="Private key ile adres eşleşmesini doğrula")
    verify_parser.add_argument("--private_key", type=str, required=True, help="Private key (hex)")
    verify_parser.add_argument("--address", type=str, required=True, help="Beklenen adres")

    subparsers.add_parser("mnemonic", help="Yeni mnemonic üret")

    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.command == "create":
        result = create_wallet_cli(args)
        print(json.dumps(result, indent=2))

    elif args.command == "load":
        result = load_wallet_cli(args)
        print(json.dumps(result, indent=2))

    elif args.command == "verify":
        try:
            is_valid = verify_wallet_cli(args)
        except Exception as e:
            logger.error(f"Doğrulama hatası: {e}")
            is_valid = False
        sys.stdout.write("true\n" if is_valid else "false\n")
        sys.stdout.flush()
        sys.exit(0 if is_valid else 1)

    elif args.command == "mnemonic":
        phrase = generate_mnemonic_cli()
        print(phrase)


if __name__ == "__main__":
    main()

