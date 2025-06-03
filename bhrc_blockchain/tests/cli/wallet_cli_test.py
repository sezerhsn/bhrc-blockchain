import subprocess
import json
import pytest
from types import SimpleNamespace
from bhrc_blockchain.wallet_cli import (
    create_wallet_cli,
    load_wallet_cli,
    verify_wallet_cli,
    generate_mnemonic_cli
)
import os

CLI_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../bhrc_blockchain/wallet_cli.py"))

def test_create_wallet_direct(tmp_path):
    args = SimpleNamespace(path=str(tmp_path / "w1.json"), password="testpass")
    result = create_wallet_cli(args)
    assert "private_key" in result
    assert "public_key" in result
    assert "address" in result
    assert os.path.exists(args.path)


def test_create_wallet_from_mnemonic():
    mnemonic = generate_mnemonic_cli()
    args = SimpleNamespace(path=None, password=f"mnemonic:{mnemonic}")
    result = create_wallet_cli(args)
    assert "private_key" in result
    assert "public_key" in result
    assert "address" in result


def test_generate_mnemonic_format():
    phrase = generate_mnemonic_cli()
    words = phrase.strip().split()
    assert isinstance(phrase, str)
    assert len(words) >= 12


def test_verify_wallet_valid():
    args = SimpleNamespace(path=None, password="testpass")
    result = create_wallet_cli(args)
    private_key = result["private_key"]
    address = result["address"]
    args_verify = SimpleNamespace(private_key=private_key, address=address)
    is_valid = verify_wallet_cli(args_verify)
    assert is_valid is True


def test_verify_wallet_invalid():
    args_verify = SimpleNamespace(private_key="invalid", address="fakeaddress")
    with pytest.raises(ValueError, match="Geçersiz hex private key"):
        verify_wallet_cli(args_verify)


def test_load_wallet(tmp_path):
    path = str(tmp_path / "w2.json")
    pw = "abc123"
    args_create = SimpleNamespace(path=path, password=pw)
    _ = create_wallet_cli(args_create)

    args_load = SimpleNamespace(path=path, password=pw)
    result = load_wallet_cli(args_load)
    assert "private_key" in result
    assert "public_key" in result
    assert "address" in result

def test_main_cli_create(tmp_path):
    path = tmp_path / "sub_wallet.json"
    result = subprocess.run(
        ["python3", CLI_PATH, "create", "--path", str(path), "--password", "abc"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert "address" in output
    assert os.path.exists(path)


def test_main_cli_mnemonic():
    result = subprocess.run(
        ["python3", CLI_PATH, "mnemonic"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert isinstance(result.stdout.strip(), str)
    assert len(result.stdout.strip().split()) >= 12


def test_main_cli_verify_valid():
    # Önce bir cüzdan oluştur
    create = subprocess.run(
        ["python3", CLI_PATH, "create", "--password", "abc"],
        capture_output=True,
        text=True
    )
    data = json.loads(create.stdout)
    private_key = data["private_key"]
    address = data["address"]

    result = subprocess.run(
        ["python3", CLI_PATH, "verify", "--private_key", private_key, "--address", address],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "true" in result.stdout.strip()


def test_main_cli_verify_invalid():
    result = subprocess.run(
        ["python3", CLI_PATH, "verify", "--private_key", "invalid", "--address", "fake"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 1
    assert "false" in result.stdout.strip()

def test_wallet_create_cli():
    output_path = "wallets/test_wallet_cli.json"
    try:
        result = subprocess.run(
            [
                "python3",
                "bhrc_blockchain/wallet_cli.py",
                "create",
                "--path", output_path,
                "--password", "test123"  # 👈 Şifre eklendi
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        assert result.returncode == 0
        assert b"address" in result.stdout
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)

def test_wallet_generate_mnemonic_cli():
    result = subprocess.run(
        ["python3", "bhrc_blockchain/wallet_cli.py", "mnemonic"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5
    )
    assert result.returncode == 0
    assert len(result.stdout.decode().strip().split()) >= 12  # 12+ kelimelik mnemonic beklenir

