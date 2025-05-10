import pytest
import asyncio
import subprocess
import sys
import os

from bhrc_blockchain.main import MiningSimulation

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
    sim.create_random_transfer()  # sadece exception fırlatmamasını test ediyoruz

@pytest.mark.asyncio
async def test_simulate_runs_short_loop():
    sim = MiningSimulation(block_limit=2)
    chain, mempool_state = await sim.simulate()
    assert len(chain) >= 2
    assert isinstance(mempool_state, list)

def test_main_runs_as_script():
    file_path = os.path.join(os.path.dirname(__file__), "main.py")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    result = subprocess.run([sys.executable, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    assert result.returncode == 0
    assert b"Toplam blok" in result.stdout
