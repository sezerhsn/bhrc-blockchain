import os
import tempfile
import logging
from bhrc_blockchain.core.logger.logging_utils import setup_logger

def test_setup_logger_creates_logger_with_handlers():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        path = tf.name

    logger = setup_logger("test_logger_utils", path)
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_logger_utils"
    assert logger.level == logging.INFO

    handler_types = [type(h).__name__ for h in logger.handlers]
    assert "RichHandler" in handler_types
    assert "FileHandler" in handler_types

    test_msg = "Logger test message"
    logger.info(test_msg)
    with open(path) as f:
        content = f.read()
    assert test_msg in content

    os.remove(path)

