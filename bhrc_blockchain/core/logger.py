import logging
from rich.logging import RichHandler

def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    stream_handler = RichHandler()
    stream_handler.setFormatter(formatter)

    file_handler = logging.FileHandler("bhrc_blockchain/logs/bhrc.log")
    file_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(stream_handler)
        logger.addHandler(file_handler)

    return logger

def test_logger_multiple_calls():
    from bhrc_blockchain.logger import setup_logger

    logger_name = "test_logger_branch"

    # İlk çağrıda handler'lar eklenir
    logger1 = setup_logger(logger_name)
    handler_count_first = len(logger1.handlers)

    # İkinci çağrı aynı logger'ı döndürür, yeni handler eklenmemeli
    logger2

