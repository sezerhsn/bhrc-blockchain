import os
import logging
import pytest
from bhrc_blockchain.core.logger.logging_utils import setup_logger
from bhrc_blockchain.config.config import Config

def test_logger_multiple_calls_does_not_duplicate_handlers():
    logger1 = setup_logger("TestLogger")
    count1 = len(logger1.handlers)

    logger2 = setup_logger("TestLogger")
    count2 = len(logger2.handlers)

    assert logger1 is logger2
    assert count1 == count2

def test_logger_output_to_file(tmp_path):
    log_dir = tmp_path / "bhrc_blockchain/logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "bhrc.log"

    logger = setup_logger("FileLogger", str(log_path))
    logger.info("Test log entry")

    logger.handlers[0].flush()
    assert log_path.exists()
    with open(log_path) as f:
        content = f.read()
    assert "Test log entry" in content

def test_config_defaults(monkeypatch):
    monkeypatch.delenv("BLOCK_REWARD", raising=False)
    monkeypatch.delenv("MAX_BLOCK_SIZE", raising=False)

    assert isinstance(Config.BLOCK_REWARD, float)
    assert Config.BLOCK_REWARD == 64.0
    assert Config.MAX_BLOCK_SIZE == 1453000

def test_config_env_override(monkeypatch):
    monkeypatch.setenv("BLOCK_REWARD", "100")
    monkeypatch.setenv("MAX_BLOCK_SIZE", "999999")

    from importlib import reload
    from bhrc_blockchain.config import config
    reload(config)
    assert config.Config.BLOCK_REWARD == 100.0
    assert config.Config.MAX_BLOCK_SIZE == 999999

