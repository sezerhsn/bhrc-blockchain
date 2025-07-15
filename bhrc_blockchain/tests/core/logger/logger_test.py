from bhrc_blockchain.core.logger.logger import setup_logger
import logging

def test_setup_logger_returns_logger():
    logger = setup_logger("test_logger")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_logger"
    assert logger.level == logging.INFO
    assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)

