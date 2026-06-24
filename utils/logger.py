"""
Logging configuration.
"""
import logging
import os

def configure_logger(log_file: str = None, level: int = logging.INFO):
    if log_file is None:
        log_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "keylogger_detection.log"))
    
    # ponytail: one line basicConfig instead of manual handlers
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.FileHandler(log_file, encoding="utf-8"), logging.StreamHandler()]
    )
