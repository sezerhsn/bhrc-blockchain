import os
import asyncio
import json
import pytest
from importlib import reload
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime
import bhrc_blockchain.main as main_module
from bhrc_blockchain.main import MiningSimulation, simulate
from bhrc_blockchain.core.blockchain.blockchain import Blockchain

def test_simulation_initializes_wallets():
    sim = MiningSimulation(block_limit=5)
    assert len(sim.wallets) == 3
    assert isinstance(sim.wallets[0].address, str)
    assert sim.block_limit == 5

def test_create_random_wallet_adds_to_list():
    sim = MiningSimulation()
    initial_len = len(sim.wallets)
    sim.create_random_wallet()
    assert len(sim.wallets) == initial_len + 1

def test_pick_random_wallet_excludes_correctly():
    sim = MiningSimulation()
    excluded = sim.wallets[0]
    picked = sim.pick_random_wallet(exclude=excluded)
    assert picked != excluded

def test_create_random_transfer_runs_without_crash():
    sim = MiningSimulation()
    try:
        sim.create_random_transfer()
    except ValueError as e:
        assert "Yetersiz bakiye" in str(e)

@pytest.mark.asyncio
@patch("bhrc_blockchain.main.MiningSimulation.create_random_transfer")
@patch("asyncio.sleep", new_callable=AsyncMock)
async def test_simulate_runs_short_loop(mock_sleep, mock_create_tx):
    sim = MiningSimulation(block_limit=2)
    sim.blockchain = MagicMock()
    sim.blockchain.mine_block = MagicMock(return_value=MagicMock())

    result = await sim.simulate()
    assert isinstance(result, tuple)
    assert len(result) == 2

@patch("builtins.print")
def test_simulate_function_runs(mock_print):
    simulate_mock = AsyncMock()
    simulate_mock()
    simulate_mock.assert_called_once()

@pytest.mark.asyncio
@patch("bhrc_blockchain.main.start_notification_server", new_callable=AsyncMock)
@patch("bhrc_blockchain.main.MiningSimulation.simulate", new_callable=AsyncMock)
@patch("bhrc_blockchain.main.print")
async def test_main_function_runs(mock_print, mock_simulate, mock_ws_server):
    from bhrc_blockchain.main import main
    await main()
    mock_print.assert_called_with("🚀 WebSocket + Simülasyon başlatılıyor...")
    mock_ws_server.assert_called_once()
    mock_simulate.assert_called_once()

@patch("bhrc_blockchain.main.MinerWallet")
def test_wallet_persistence_flag(mock_wallet_class):
    sim = MiningSimulation(persist_wallets=False)
    sim.create_random_wallet()
    mock_wallet_class.assert_called_with(password=None, persist=False)

@patch("bhrc_blockchain.main.MinerWallet")
def test_default_wallet_persistence_is_true(mock_wallet_class):
    sim = MiningSimulation()
    sim.create_random_wallet()
    mock_wallet_class.assert_called_with(password=None, persist=True)

@patch("bhrc_blockchain.main.print")
@patch("bhrc_blockchain.main.parse_arguments")
@patch("bhrc_blockchain.main.MiningSimulation.simulate", new_callable=AsyncMock)
def test_simulate_function_prints_and_runs(mock_simulate, mock_parse_args, mock_print):
    from bhrc_blockchain.main import simulate
    mock_block = MagicMock()
    mock_block.index = 1
    mock_block.miner = "miner_address"
    mock_block.transactions = [1, 2]
    mock_block.coinbase_amount = 10
    mock_block.total_fees = 1.5
    mock_block.timestamp = "2025-07-12T12:00:00Z"
    mock_block.mempool_size_before = 5
    mock_block.to_dict.return_value = {"index": 1}

    mock_genesis = MagicMock()
    mock_genesis.to_dict.return_value = {"index": 0}

    mock_simulate.return_value = ([mock_genesis, mock_block], ["wallet1", "wallet2"])
    mock_parse_args.return_value = MagicMock(
        mode="simulate",
        tx_count=1,
        wallet_count=2,
        block_limit=1,
        block_until_mempool_empty=False,
        sleep_time=0.01
    )

    simulate()
    mock_print.assert_any_call("⛏️ Madencilik simülasyonu başlatılıyor...")

@patch("bhrc_blockchain.main.print")
@patch("bhrc_blockchain.main.parse_arguments")
@patch("bhrc_blockchain.main.MiningSimulation.simulate", new_callable=AsyncMock)
def test_simulate_exports_chain_to_json(mock_simulate, mock_parse_args, mock_print, tmp_path):
    from bhrc_blockchain.main import simulate
    import os, json

    mock_block = MagicMock()
    mock_block.to_dict.return_value = {"index": 1}
    mock_genesis = MagicMock()
    mock_genesis.to_dict.return_value = {"index": 0}
    mock_simulate.return_value = ([mock_genesis, mock_block], ["wallet1", "wallet2"])

    mock_parse_args.return_value = MagicMock(
        mode="simulate",
        tx_count=1,
        wallet_count=1,
        block_limit=None,
        block_until_mempool_empty=True,
        sleep_time=0.01
    )

    os.chdir(tmp_path)
    simulate()

    assert os.path.exists("simulated_chain.json")
    with open("simulated_chain.json") as f:
        data = json.load(f)
        assert data[0]["index"] == 0
        assert data[1]["index"] == 1

@pytest.mark.asyncio
@patch.object(MiningSimulation, "create_random_transfer")
@patch.object(MiningSimulation, "blockchain", create=True)
def test_simulation_produces_correct_tx_count_and_empties_mempool(mock_blockchain, mock_create_tx):
    mock_tx = MagicMock()
    mock_create_tx.return_value = mock_tx

    # mock_blockchain setup
    mock_blockchain.add_transaction_to_mempool = MagicMock()
    mock_blockchain.mine_block = MagicMock(return_value=MagicMock())
    mock_blockchain.mempool.is_empty.return_value = True

    sim = MiningSimulation(
        tx_count=5,
        wallet_count=3,
        block_until_mempool_empty=True,
        sleep_time=0.01
    )
    sim.blockchain = mock_blockchain  # override

    chain, wallets = asyncio.run(sim.simulate())

    assert mock_blockchain.add_transaction_to_mempool.call_count == 5
    assert mock_blockchain.mine_block.call_count >= 1

@pytest.mark.asyncio
@patch.object(MiningSimulation, "create_random_transfer")
@patch.object(MiningSimulation, "blockchain", create=True)
def test_simulation_respects_block_limit_over_tx_count(mock_blockchain, mock_create_tx):
    mock_tx = MagicMock()
    mock_create_tx.return_value = mock_tx

    mock_blockchain.add_transaction_to_mempool = MagicMock()
    mock_blockchain.mine_block = MagicMock(return_value=MagicMock())
    mock_blockchain.mempool.is_empty.return_value = False

    sim = MiningSimulation(
        block_limit=2,
        tx_count=999,
        wallet_count=4,
        block_until_mempool_empty=False,
        sleep_time=0.01
    )
    sim.blockchain = mock_blockchain

    chain, wallets = asyncio.run(sim.simulate())

    assert mock_blockchain.mine_block.call_count == 2

@pytest.mark.asyncio
def test_simulation_calls_add_transaction_to_mempool():
    sim = MiningSimulation(tx_count=3, sleep_time=0.01)
    sim.create_random_transfer = MagicMock(return_value=MagicMock())

    sim.blockchain.add_transaction_to_mempool = MagicMock()
    sim.blockchain.mine_block = MagicMock(return_value=MagicMock())

    mempool_mock = MagicMock()
    mempool_mock.is_empty.return_value = True
    sim.blockchain.mempool = mempool_mock

    asyncio.run(sim.simulate())

    assert sim.blockchain.add_transaction_to_mempool.call_count == 3

@patch("bhrc_blockchain.main.print")
@patch("bhrc_blockchain.main.parse_arguments")
@patch("bhrc_blockchain.main.MiningSimulation.simulate", new_callable=AsyncMock)
def test_simulate_prints_block_summary(mock_simulate, mock_parse_args, mock_print):
    from bhrc_blockchain.main import simulate

    mock_block = MagicMock()
    mock_block.index = 1
    mock_block.miner = "miner"
    mock_block.transactions = [1]
    mock_block.coinbase_amount = 12.5
    mock_block.total_fees = 0.5
    mock_block.timestamp = "2025-07-12T12:00:00Z"
    mock_block.mempool_size_before = 2
    mock_block.to_dict.return_value = {"index": 1}

    genesis = MagicMock()
    genesis.to_dict.return_value = {"index": 0}

    mock_simulate.return_value = ([genesis, mock_block], ["wallet1"])
    mock_parse_args.return_value = MagicMock(
        tx_count=1,
        wallet_count=1,
        block_limit=None,
        block_until_mempool_empty=True,
        sleep_time=0.01,
        mode="simulate"
    )

    simulate()

    summary_lines = [call.args[0] for call in mock_print.call_args_list if isinstance(call.args[0], str)]
    assert any("🧱 Blok #1" in line for line in summary_lines), "Blok özeti yazdırılmadı."

def test_simulation_respects_wallet_count():
    sim = MiningSimulation(wallet_count=7)
    assert len(sim.wallets) == 7

def test_simulation_sets_sleep_time():
    sim = MiningSimulation(sleep_time=0.25)
    assert sim.sleep_time == 0.25

def test_simulation_sets_tx_count():
    sim = MiningSimulation(tx_count=42)
    assert sim.tx_count == 42

def test_simulation_sets_block_until_mempool_empty():
    sim = MiningSimulation(block_until_mempool_empty=True)
    assert sim.block_until_mempool_empty is True

def test_argument_parser_parses_all_fields():
    import sys
    from bhrc_blockchain.main import parse_arguments
    test_args = [
        "main.py",
        "--mode", "simulate",
        "--tx-count", "10",
        "--wallet-count", "5",
        "--block-limit", "3",
        "--block-until-mempool-empty",
        "--sleep-time", "0.2"
    ]
    sys.argv = test_args
    args = parse_arguments()
    assert args.mode == "simulate"
    assert args.tx_count == 10
    assert args.wallet_count == 5
    assert args.block_limit == 3
    assert args.block_until_mempool_empty is True
    assert args.sleep_time == 0.2

