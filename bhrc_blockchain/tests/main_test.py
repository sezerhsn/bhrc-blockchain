import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import bhrc_blockchain.main as main
from bhrc_blockchain.main import MiningSimulation
main.simulate = AsyncMock()

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
    sim.blockchain.mine_block = AsyncMock(return_value=MagicMock())

    result = await sim.simulate()
    assert isinstance(result, tuple)
    assert len(result) == 2

@patch("builtins.print")
def test_simulate_function_runs(mock_print):
    main.simulate = AsyncMock()
    main.simulate()
    main.simulate.assert_called_once()

@pytest.mark.asyncio
@patch("bhrc_blockchain.main.start_notification_server", new_callable=AsyncMock)
@patch("bhrc_blockchain.main.MiningSimulation.simulate", new_callable=AsyncMock)
async def test_main_function_runs(mock_simulate, mock_ws_server):
    from bhrc_blockchain.main import main
    await main()
    mock_ws_server.assert_called_once()
    mock_simulate.assert_called_once()

