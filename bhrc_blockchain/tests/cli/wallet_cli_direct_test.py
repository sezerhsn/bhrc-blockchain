import pytest
import json
import os
from unittest.mock import patch
from bhrc_blockchain import wallet_cli
from bhrc_blockchain.core.wallet.wallet import MinerWallet as Wallet

def test_cli_create(monkeypatch):
    test_path = "wallets/test_wallet_direct.json"
    monkeypatch.setattr("sys.argv", ["wallet_cli.py", "create", "--path", test_path, "--password", "123456"])
    with patch("builtins.print") as mock_print:
        wallet_cli.main()
        output = json.loads(mock_print.call_args[0][0])
        assert "address" in output
    if os.path.exists(test_path):
        os.remove(test_path)

def test_cli_mnemonic(monkeypatch):
    monkeypatch.setattr("sys.argv", ["wallet_cli.py", "mnemonic"])
    with patch("builtins.print") as mock_print:
        wallet_cli.main()
        phrase = mock_print.call_args[0][0]
        assert len(phrase.split()) >= 12

def test_cli_verify(monkeypatch):
    from bhrc_blockchain.core.wallet.wallet import MinerWallet as Wallet
    w = Wallet(password="test123")
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py",
        "verify",
        "--private_key", w.private_key,
        "--address", w.address
    ])
    with patch("sys.stdout.write") as mock_write:
        try:
            wallet_cli.main()
        except SystemExit as e:
            assert e.code == 0

        written = "".join([call[0][0] for call in mock_write.call_args_list])
        assert "true" in written

def test_cli_no_command(monkeypatch):
    monkeypatch.setattr("sys.argv", ["wallet_cli.py"])
    with pytest.raises(SystemExit) as e:
        wallet_cli.main()
    assert e.value.code != 0

def test_cli_verify_fail(monkeypatch):
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "verify",
        "--private_key", "invalidkey",
        "--address", "invalidaddress"
    ])
    with patch("sys.stdout.write") as mock_write:
        with pytest.raises(SystemExit) as e:
            wallet_cli.main()
        written = "".join([call[0][0] for call in mock_write.call_args_list])
        assert "false" in written
        assert e.value.code == 1

def test_cli_create_missing_password(monkeypatch):
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "create", "--path", "wallets/temp.json"
    ])
    with pytest.raises(ValueError, match="Şifreleme için parola belirtilmeli"):
        wallet_cli.main()

def test_cli_load_corrupt_json(monkeypatch):
    corrupt_path = "wallets/corrupt.json"
    with open(corrupt_path, "w") as f:
        f.write("{ this is not valid JSON ")

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "load",
        "--path", corrupt_path,
        "--password", "123"
    ])

    with pytest.raises(json.decoder.JSONDecodeError):
        wallet_cli.main()

    os.remove(corrupt_path)

def test_cli_create_error(monkeypatch):
    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "create", "--path", "wallets/x.json"
    ])
    with pytest.raises(ValueError, match="Şifre gerekli"):
        wallet_cli.main()

def test_cli_load_success(monkeypatch):
    from bhrc_blockchain.core.wallet.wallet import MinerWallet
    path = "wallets/test_load.json"
    MinerWallet(password="abc123", wallet_path=path).save_to_file()

    monkeypatch.setattr("sys.argv", [
        "wallet_cli.py", "load", "--path", path, "--password", "abc123"
    ])
    with patch("builtins.print") as mock_print, patch("bhrc_blockchain.wallet_cli.logger") as mock_logger:
        wallet_cli.main()
        assert mock_logger.info.called
        assert mock_print.called
    os.remove(path)

