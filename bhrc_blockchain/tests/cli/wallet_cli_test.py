import os
import subprocess
import json
import pytest
import shlex
from unittest.mock import patch
from bhrc_blockchain import wallet_cli
from types import SimpleNamespace
from bhrc_blockchain.core.wallet.wallet import MinerWallet as Wallet
from bhrc_blockchain.wallet_cli import (
    create_wallet_cli,
    load_wallet_cli,
    verify_wallet_cli,
    generate_mnemonic_cli
)

CLI_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../wallet_cli.py"))

def test_main_cli_verify_valid(tmp_path):
    path = tmp_path / "wallet_verify.json"
    create = subprocess.run(
        ["python3", CLI_PATH, "wallet", "create", "--path", str(path), "--password", "abc"],
        capture_output=True,
        text=True
    )
    assert create.returncode == 0
    data = json.loads(create.stdout)["data"]
    private_key = data["private_key"]
    address = data["address"]

    result = subprocess.run(
        ["python3", CLI_PATH, "read", "verify", "--private_key", private_key, "--address", address],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["status"] == "success"
    assert output["data"]["valid"] is True


def test_main_cli_verify_invalid():
    result = subprocess.run(
        ["python3", CLI_PATH, "read", "verify", "--private_key", "invalid", "--address", "fake"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 1
    output = json.loads(result.stdout)
    assert output["status"] == "error"
    assert "message" in output


def test_cli_verify(monkeypatch):
    from bhrc_blockchain.core.wallet.wallet import MinerWallet
    wallet = MinerWallet(password="abc")
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify",
        "--private_key", wallet.private_key,
        "--address", wallet.address
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            wallet_cli.main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["valid"] is True
        assert e.value.code == 0

def test_cli_verify_fail(monkeypatch):
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify",
        "--private_key", "deadbeef" * 8,
        "--address", "xBHR" + "F" * 60
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            wallet_cli.main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["valid"] is False
        assert e.value.code == 0

def test_cli_verify_mnemonic(monkeypatch):
    from bhrc_blockchain.wallet_cli import main, generate_mnemonic_cli
    mnemonic = generate_mnemonic_cli()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify-mnemonic",
        "--mnemonic", mnemonic
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["valid"] is True
        assert "address" in output["data"]


def test_cli_main_verify_integrity_valid_logger(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, generate_child_wallet

    mnemonic = generate_mnemonic()
    child = generate_child_wallet(mnemonic, 0)

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify-integrity",
        "--private_key", child["private_key"],
        "--public_key", child["public_key"],
        "--address", child["address"],
        "--mnemonic", mnemonic,
        "--password", ""
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["valid"] is True
        assert e.value.code == 0


def test_cli_verify_integrity_valid(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, generate_child_wallet

    mnemonic = generate_mnemonic()
    wallet = generate_child_wallet(mnemonic, index=0)

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify-integrity",
        "--private_key", wallet["private_key"],
        "--public_key", wallet["public_key"],
        "--address", wallet["address"],
        "--mnemonic", mnemonic,
        "--password", ""
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["valid"] is True
        assert e.value.code == 0


def test_cli_verify_integrity_invalid(monkeypatch):
    from bhrc_blockchain.wallet_cli import main

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify-integrity",
        "--private_key", "00" * 32,
        "--public_key", "00" * 64,
        "--address", "xBHR" + "F" * 60
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["valid"] is False
        assert e.value.code == 0

def test_cli_get_pubkey(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    wallet = MinerWallet(password="abc123")

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "get-pubkey",
        "--private_key", wallet.private_key
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert "public_key" in output["data"]
        assert e.value.code == 0


def test_cli_get_address(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    wallet = MinerWallet(password="def456")

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "get-address",
        "--private_key", wallet.private_key
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert "address" in output["data"]
        assert "public_key" in output["data"]
        assert e.value.code == 0

def test_cli_summary(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    wallet_path = tmp_path / "wallet_summary.json"
    wallet = MinerWallet(password="abc123", wallet_path=str(wallet_path))
    wallet.save_to_file()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "summary",
        "--path", str(wallet_path),
        "--password", "abc123"
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert "address" in output["data"]
        assert "public_key" in output["data"]
        assert e.value.code == 0


def test_cli_info_wallet(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    wallet_path = tmp_path / "info_wallet.json"
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(wallet_path),
        "--password", "info123"
    ])
    with patch("builtins.print"):
        with pytest.raises(SystemExit):
            main()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "info",
        "--path", str(wallet_path),
        "--password", "info123"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert "address" in output["data"]
        assert e.value.code == 0


def test_cli_output_success_exit():
    from bhrc_blockchain.wallet_cli import output_success
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            output_success({"foo": "bar"})
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["foo"] == "bar"
        assert e.value.code == 0


def test_cli_no_command(monkeypatch):
    monkeypatch.setattr("sys.argv", ["wallet_cli.py"])
    with pytest.raises(SystemExit) as e:
        wallet_cli.main()
    assert e.value.code != 0

def test_main_cli_create(tmp_path):
    path = tmp_path / "maincli_wallet.json"
    result = subprocess.run(
        ["python3", CLI_PATH, "wallet", "create", "--path", str(path), "--password", "abc"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert "address" in output["data"]
    assert os.path.exists(path)


def test_main_cli_mnemonic():
    result = subprocess.run(
        ["python3", CLI_PATH, "wallet", "mnemonic"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    words = result.stdout.strip().split()
    assert len(words) >= 12


def test_cli_create(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    path = tmp_path / "cli_wallet.json"
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(path), "--password", "mypw"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        out = json.loads(mock_print.call_args[0][0])
        assert "address" in out["data"]
        assert e.value.code == 0
    assert path.exists()


def test_cli_create_error(monkeypatch):
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create", "--path", "wallets/x.json"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            wallet_cli.main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "error"
        assert "parola" in output["message"].lower()
        assert e.value.code == 1


def test_cli_create_missing_password(monkeypatch):
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create", "--path", "wallets/temp.json"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            wallet_cli.main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "error"
        assert "parola" in output["message"].lower()
        assert e.value.code == 1


def test_cli_mnemonic(monkeypatch):
    monkeypatch.setattr("sys.argv", ["wallet_cli.py", "wallet", "mnemonic"])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            wallet_cli.main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert isinstance(output["data"]["mnemonic"], str)
        assert len(output["data"]["mnemonic"].split()) >= 12
        assert e.value.code == 0

def test_main_cli_export_wallet_full(tmp_path):
    path = tmp_path / "wallet_export.json"
    subprocess.run([
        "python3", CLI_PATH, "wallet", "create",
        "--path", str(path), "--password", "export123"
    ], check=True)

    result = subprocess.run([
        "python3", CLI_PATH, "wallet", "export",
        "--path", str(path), "--password", "export123"
    ], capture_output=True, text=True)

    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert "private_key" in output["data"]
    assert "mnemonic" in output["data"]
    assert "address" in output["data"]


def test_cli_export_wallet_only_address(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    path = tmp_path / "wallet_onlyaddr.json"
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(path), "--password", "pw123"
    ])
    with patch("builtins.print"):
        with pytest.raises(SystemExit):
            main()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "export",
        "--path", str(path), "--password", "pw123", "--only-address"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert "address" in output["data"]
        assert "private_key" not in output["data"]
        assert "mnemonic" not in output["data"]
        assert e.value.code == 0


def test_cli_load_success(monkeypatch, tmp_path):
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    path = tmp_path / "wallet_load.json"
    MinerWallet(password="abc123", wallet_path=str(path)).save_to_file()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "load",
        "--path", str(path), "--password", "abc123"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            wallet_cli.main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert "address" in output["data"]
        assert e.value.code == 0


def test_cli_load_corrupt_json(monkeypatch, tmp_path):
    path = tmp_path / "corrupt.json"
    path.write_text("{ this is not valid JSON ")

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "load",
        "--path", str(path), "--password", "123"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            wallet_cli.main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "error"
        assert "yüklenemedi" in output["message"].lower()
        assert e.value.code == 1

def test_cli_delete_wallet(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    path = tmp_path / "wallet_delete.json"
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(path), "--password", "del123"
    ])
    with patch("builtins.print"):
        with pytest.raises(SystemExit):
            main()
    assert path.exists()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "delete", "--path", str(path)
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["data"]["deleted"] is True
        assert e.value.code == 0
    assert not path.exists()


def test_cli_info_wallet(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    path = tmp_path / "wallet_info.json"
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(path), "--password", "info123"
    ])
    with patch("builtins.print"):
        with pytest.raises(SystemExit):
            main()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "info",
        "--path", str(path), "--password", "info123"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert "address" in output["data"]
        assert e.value.code == 0


def test_cli_rename_wallet(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    old_path = tmp_path / "wallet_old.json"
    new_path = tmp_path / "wallet_new.json"

    wallet = MinerWallet(password="rename123", wallet_path=str(old_path))
    wallet.save_to_file()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "rename",
        "--path", str(old_path),
        "--new_path", str(new_path),
        "--password", "rename123"
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["renamed_to"] == str(new_path)
        assert new_path.exists()
        assert not old_path.exists()
        assert e.value.code == 0

def test_cli_sign_message(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    wallet = MinerWallet(password="abc123")
    message = "Behind The Random Co. test message"

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "tx", "sign",
        "--private_key", wallet.private_key,
        "--message", message
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert "signature" in output["data"]
        assert isinstance(output["data"]["signature"], str)
        assert e.value.code == 0


def test_cli_verify_signature(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet, sign_message

    wallet = MinerWallet(password="xyz789")
    message = "Doğrulama testi"
    signature = sign_message(wallet.private_key, message)

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "tx", "verify-signature",
        "--public_key", wallet.public_key,
        "--message", message,
        "--signature", signature
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["valid"] is True
        assert e.value.code == 0

@pytest.mark.xfail(reason="Genesis bloğundaki ilk coinbase ödülü kilitli olduğu için işlem yapılamaz.")
def test_cli_send_transaction(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet
    from bhrc_blockchain.core.blockchain.blockchain import Blockchain
    from bhrc_blockchain.core.blockchain.mining import mine_block
    from bhrc_blockchain.core.mempool.mempool import mempool
    from bhrc_blockchain.core.utxo.utxo_manager import UTXOManager

    chain = Blockchain()

    sender_path = tmp_path / "sender_wallet.json"
    sender_wallet = MinerWallet(password="abc123", wallet_path=str(sender_path))
    sender_wallet.save_to_file()

    mine_block(chain.chain, miner_address=sender_wallet.address)
    UTXOManager.rebuild_from_chain(chain.chain)

    receiver_wallet = MinerWallet(password="xyz789")

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "tx", "send",
        "--path", str(sender_path),
        "--password", "abc123",
        "--recipient", receiver_wallet.address,
        "--amount", "0.1",
        "--fee", "0.001",
        "--message", "Merhaba!",
        "--note", "Test işlemi"
    ])

    main()
    assert any(tx["recipient"] == receiver_wallet.address for tx in mempool), "İşlem mempool'a düşmedi"


@pytest.mark.xfail(reason="Genesis ödülü harcanamaz, bu nedenle subprocess testi bilinçli olarak başarısız.")
def test_main_cli_send_transaction(tmp_path):
    from bhrc_blockchain.core.wallet.wallet import MinerWallet
    import subprocess

    sender_path = tmp_path / "sender_subprocess.json"
    sender_wallet = MinerWallet(password="test123", wallet_path=str(sender_path))
    sender_wallet.save_to_file()

    receiver_wallet = MinerWallet(password="other456")

    result = subprocess.run([
        "python3", CLI_PATH, "tx", "send",
        "--path", str(sender_path),
        "--password", "test123",
        "--recipient", receiver_wallet.address,
        "--amount", "0.25",
        "--fee", "0.001",
        "--message", "Subprocess denemesi",
        "--note", "Beklenen başarısızlık"
    ], capture_output=True, text=True)

    assert result.returncode == 0
    assert "mempool" in result.stdout.lower() or "recipient" in result.stdout.lower()

def test_cli_create_with_mnemonic(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic
    test_path = tmp_path / "wallet_with_mnemonic.json"
    test_mnemonic = generate_mnemonic()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(test_path),
        "--password", "abc123",
        "--mnemonic", test_mnemonic
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert "address" in output["data"]
        assert "private_key" in output["data"]
        assert e.value.code == 0

    assert test_path.exists()

def test_cli_import_wallet_from_mnemonic(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic

    mnemonic = generate_mnemonic()
    path = tmp_path / "import_wallet_mnemonic.json"

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "import",
        "--path", str(path),
        "--password", "mypw",
        "--mnemonic", mnemonic
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        out = json.loads(mock_print.call_args[0][0])
        assert out["status"] == "success"
        assert "address" in out["data"]
        assert e.value.code == 0
    assert path.exists()

def test_cli_import_wallet_from_private_key(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    wallet = MinerWallet(password="pw123")
    private_key = wallet.private_key
    path = tmp_path / "import_wallet_pk.json"

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "import",
        "--path", str(path),
        "--password", "pw123",
        "--private_key", private_key
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        out = json.loads(mock_print.call_args[0][0])
        assert out["status"] == "success"
        assert "address" in out["data"]
        assert e.value.code == 0

    assert path.exists()

def test_cli_delete_wallet_file_not_found(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    nonexistent_path = tmp_path / "nonexistent_wallet.json"

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "delete",
        "--path", str(nonexistent_path)
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "error"
        assert "bulunamadı" in output["message"].lower()
        assert e.value.code == 1

def test_cli_generate_child_wallet(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, generate_child_wallet

    mnemonic = generate_mnemonic()
    child = generate_child_wallet(mnemonic, 3)

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "child-wallet",
        "--mnemonic", mnemonic,
        "--index", "3"
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert output["data"]["address"] == child["address"]
        assert output["data"]["public_key"] == child["public_key"]
        assert output["data"]["private_key"] == child["private_key"]
        assert e.value.code == 0

def test_cli_from_hardware_wallet(monkeypatch):
    from bhrc_blockchain.wallet_cli import main

    dummy_wallet = {
        "private_key": "00" * 32,
        "public_key": "11" * 64,
        "address": "xBHR" + "A" * 60
    }

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "from-hardware"
    ])

    with patch("bhrc_blockchain.wallet_cli.from_hardware_wallet_cli", return_value=dummy_wallet):
        with patch("builtins.print") as mock_print:
            with pytest.raises(SystemExit) as e:
                main()
            output = json.loads(mock_print.call_args[0][0])
            assert output["status"] == "success"
            assert output["data"]["address"] == dummy_wallet["address"]
            assert output["data"]["public_key"] == dummy_wallet["public_key"]
            assert output["data"]["private_key"] == dummy_wallet["private_key"]
            assert e.value.code == 0

def test_cli_generate_mnemonic_direct():
    from bhrc_blockchain.wallet_cli import generate_mnemonic_cli
    mnemonic = generate_mnemonic_cli()
    assert isinstance(mnemonic, str)
    assert len(mnemonic.split()) >= 12


def test_cli_export_wallet_with_mnemonic(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    path = tmp_path / "wallet_with_mnemonic.json"
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(path), "--password", "mnemonicpw"
    ])
    with patch("builtins.print"):
        with pytest.raises(SystemExit):
            main()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "export",
        "--path", str(path),
        "--password", "mnemonicpw",
        "--mnemonic"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert "mnemonic" in output["data"]


def test_cli_delete_wallet_file_missing(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    missing_path = tmp_path / "missing_wallet.json"
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "delete",
        "--path", str(missing_path)
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "error"
        assert "bulunamadı" in output["message"].lower()
        assert e.value.code == 1


def test_cli_verify_and_verify_integrity_output(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic, generate_child_wallet

    mnemonic = generate_mnemonic()
    child = generate_child_wallet(mnemonic, 0)

    # verify
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify",
        "--private_key", child["private_key"],
        "--address", child["address"]
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert isinstance(output["data"]["valid"], bool)

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify-integrity",
        "--private_key", child["private_key"],
        "--public_key", child["public_key"],
        "--address", child["address"],
        "--mnemonic", mnemonic,
        "--password", ""
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        out = json.loads(mock_print.call_args[0][0])
        assert out["status"] == "success"
        assert isinstance(out["data"]["valid"], bool)


def test_cli_from_hardware_import_executes(monkeypatch):
    from bhrc_blockchain.wallet_cli import main

    dummy_wallet = {
        "private_key": "00" * 32,
        "public_key": "11" * 64,
        "address": "xBHR" + "A" * 60
    }

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "from-hardware"
    ])
    with patch("bhrc_blockchain.wallet_cli.from_hardware_wallet_cli", return_value=dummy_wallet):
        with patch("builtins.print") as mock_print:
            with pytest.raises(SystemExit):
                main()
            out = json.loads(mock_print.call_args[0][0])
            assert out["status"] == "success"
            assert out["data"]["address"] == dummy_wallet["address"]

def test_cli_verify_output_success(monkeypatch):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    wallet = MinerWallet(password="abc")
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify",
        "--private_key", wallet.private_key,
        "--address", wallet.address
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        printed = mock_print.call_args[0][0]
        output = json.loads(printed)
        assert output["status"] == "success"
        assert isinstance(output["data"]["valid"], bool)
        assert e.value.code == 0


def test_cli_export_wallet_only_address_branch(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    path = tmp_path / "wallet_branch_test.json"
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(path), "--password", "branchpw"
    ])
    with patch("builtins.print"):
        with pytest.raises(SystemExit):
            main()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "export",
        "--path", str(path), "--password", "branchpw",
        "--only-address"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        out = json.loads(mock_print.call_args[0][0])
        assert "address" in out["data"]
        assert "private_key" not in out["data"]
        assert e.value.code == 0


def test_cli_final_generic_output(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    path = tmp_path / "wallet_final.json"
    wallet = MinerWallet(password="fin123", wallet_path=str(path))
    wallet.save_to_file()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "show",
        "--path", str(path),
        "--password", "fin123"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert "address" in output["data"]
        assert "public_key" in output["data"]
        assert "private_key" in output["data"]

def test_cli_wallet_mnemonic_lambda(monkeypatch):
    from bhrc_blockchain.wallet_cli import main

    fake_mnemonic = "word " * 12

    monkeypatch.setattr("sys.argv", ["wallet_cli.py", "wallet", "mnemonic"])
    with patch("bhrc_blockchain.wallet_cli.generate_mnemonic_cli", return_value=fake_mnemonic.strip()):
        with patch("builtins.print") as mock_print:
            with pytest.raises(SystemExit) as e:
                main()
            output = json.loads(mock_print.call_args[0][0])
            assert output["status"] == "success"
            assert "mnemonic" in output["data"]
            assert len(output["data"]["mnemonic"].split()) >= 12
            assert e.value.code == 0

def test_cli_export_wallet_with_real_mnemonic(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import generate_mnemonic

    mnemonic_words = generate_mnemonic().split()
    path = tmp_path / "wallet_with_mnemonic_export.json"

    # create wallet with mnemonic
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--path", str(path),
        "--password", "testpass",
        "--mnemonic", *mnemonic_words
    ])
    with patch("builtins.print"):
        with pytest.raises(SystemExit):
            main()

    # export wallet with --mnemonic
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "export",
        "--path", str(path),
        "--password", "testpass",
        "--mnemonic"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        out = json.loads(mock_print.call_args[0][0])
        assert out["status"] == "success"
        assert "mnemonic" in out["data"]
        assert isinstance(out["data"]["mnemonic"], str)
        assert len(out["data"]["mnemonic"].split()) >= 12

def test_cli_output_success_paths(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet

    path = tmp_path / "wallet_out_success.json"
    wallet = MinerWallet(password="abc", wallet_path=str(path))
    wallet.save_to_file()

    # Test: read/info → triggers final 'else' → line 416
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "info",
        "--path", str(path),
        "--password", "abc"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        printed = json.loads(mock_print.call_args[0][0])
        assert printed["status"] == "success"
        assert "address" in printed["data"]

    # Test: read/verify-integrity → line 399
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "read", "verify-integrity",
        "--private_key", wallet.private_key,
        "--public_key", wallet.public_key,
        "--address", wallet.address,
        "--password", "abc"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "success"
        assert "valid" in output["data"]

    # Test: wallet/export with --only-address → line 385
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "export",
        "--path", str(path),
        "--password", "abc",
        "--only-address"
    ])
    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        out = json.loads(mock_print.call_args[0][0])
        assert out["status"] == "success"
        assert "address" in out["data"]
        assert "private_key" not in out["data"]

def test_cli_send_transaction_txid_output(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet
    from bhrc_blockchain.core.blockchain.blockchain import Blockchain
    from bhrc_blockchain.core.blockchain.mining import mine_block
    from bhrc_blockchain.core.utxo.utxo_manager import UTXOManager
    from bhrc_blockchain.core.mempool.mempool import mempool

    # Zinciri BHRC kurallarına göre manuel başlat
    chain = Blockchain(autoload=False)
    chain.create_genesis_block()                     # 0 → kilitli
    sender_path = tmp_path / "txid_wallet.json"
    sender_wallet = MinerWallet(password="abc", wallet_path=str(sender_path))
    sender_wallet.save_to_file()

    # Spendable ödül kazandır
    chain.mine_block(miner_address=sender_wallet.address, miner_private_key=sender_wallet.private_key)
    UTXOManager.rebuild_from_chain(chain.chain)

    receiver_wallet = MinerWallet(password="xyz")

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "tx", "send",
        "--path", str(sender_path),
        "--password", "abc",
        "--recipient", receiver_wallet.address,
        "--amount", "0.1",
        "--fee", "0.001",
        "--message", "txid testi",
        "--note", "çıktı kontrolü"
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()

        printed_lines = [call[0][0] for call in mock_print.call_args_list]
        txid_line = [line for line in printed_lines if "Gönderilen işlem kimliği" in line]

        assert len(txid_line) == 1
        assert "✅ Gönderilen işlem kimliği:" in txid_line[0]
        assert len(txid_line[0].split(":")[-1].strip()) >= 32

def test_cli_create_missing_path(monkeypatch):
    from bhrc_blockchain.wallet_cli import main

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--password", "abc123"
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "error"
        assert "dosya yolu" in output["message"].lower()
        assert e.value.code == 1


def test_cli_import_wallet_missing_inputs(monkeypatch):
    from bhrc_blockchain.wallet_cli import main

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "import",
        "--path", "wallets/dummy.json",
        "--password", "test123"
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "error"
        assert "import için" in output["message"].lower()
        assert e.value.code == 1


def test_cli_delete_wallet_file_not_found_explicit(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main

    fake_path = tmp_path / "no_wallet_here.json"

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "delete",
        "--path", str(fake_path)
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        out = json.loads(mock_print.call_args[0][0])
        assert out["status"] == "error"
        assert "bulunamadı" in out["message"].lower()
        assert e.value.code == 1


def test_cli_send_transaction_logs_txid(monkeypatch, tmp_path, caplog):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet
    from bhrc_blockchain.core.blockchain.blockchain import Blockchain
    from bhrc_blockchain.core.utxo.utxo_manager import UTXOManager

    chain = Blockchain(autoload=False)
    chain.create_genesis_block()

    sender_path = tmp_path / "wallet_logtest.json"
    sender_wallet = MinerWallet(password="abc", wallet_path=str(sender_path))
    sender_wallet.save_to_file()
    chain.mine_block(miner_address=sender_wallet.address, miner_private_key=sender_wallet.private_key)
    UTXOManager.rebuild_from_chain(chain.chain)

    receiver_wallet = MinerWallet(password="xyz")

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "tx", "send",
        "--path", str(sender_path),
        "--password", "abc",
        "--recipient", receiver_wallet.address,
        "--amount", "0.1",
        "--fee", "0.001"
    ])

    with patch("builtins.print"):
        with pytest.raises(SystemExit):
            with caplog.at_level("INFO"):
                main()

    logs = "\n".join(record.message for record in caplog.records)
    assert "İşlem gönderildi" in logs
    assert any("txid" in line or len(line.strip()) >= 32 for line in logs.splitlines())


def test_cli_send_transaction_output_success_json(monkeypatch, tmp_path):
    from bhrc_blockchain.wallet_cli import main
    from bhrc_blockchain.core.wallet.wallet import MinerWallet
    from bhrc_blockchain.core.blockchain.blockchain import Blockchain
    from bhrc_blockchain.core.utxo.utxo_manager import UTXOManager

    chain = Blockchain(autoload=False)
    chain.create_genesis_block()

    sender_path = tmp_path / "wallet_output.json"
    sender_wallet = MinerWallet(password="abc", wallet_path=str(sender_path))
    sender_wallet.save_to_file()
    chain.mine_block(miner_address=sender_wallet.address, miner_private_key=sender_wallet.private_key)
    UTXOManager.rebuild_from_chain(chain.chain)

    receiver_wallet = MinerWallet(password="xyz")

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "tx", "send",
        "--path", str(sender_path),
        "--password", "abc",
        "--recipient", receiver_wallet.address,
        "--amount", "0.1",
        "--fee", "0.001"
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit):
            main()
        out = json.loads(mock_print.call_args_list[-1][0][0])
        assert out["status"] == "success"
        assert "txid" in out["data"]

def test_cli_output_error_called(monkeypatch):
    from bhrc_blockchain.wallet_cli import main

    # Geçerli grup ve komut ama bilinçli olarak eksik/yanlış parametre (ValueError tetiklenecek)
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "wallet", "create",
        "--password", "abc123"
        # --path verilmedi → create_wallet_cli içinde ValueError fırlatır
    ])

    with patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as e:
            main()
        output = json.loads(mock_print.call_args[0][0])
        assert output["status"] == "error"
        assert "dosya yolu" in output["message"].lower()
        assert e.value.code == 1

