import logging
from logging.handlers import RotatingFileHandler

def setup_logger(log_file: str, level=logging.INFO):
    logger = logging.getLogger("ransomware_detector")
    logger.setLevel(level)

    if logger.handlers:
        return logger

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

def log_info(logger, msg: str):
    logger.info(msg)

def log_error(logger, msg: str):
    logger.error(msg)

def log_warning(logger, msg: str):
    logger.warning(msg)