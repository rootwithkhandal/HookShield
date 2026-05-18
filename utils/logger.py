"""
Logging configuration for LogDefender.
Call configure_logger() once at application startup.
"""
import logging
import os


def configure_logger(log_file: str = None, level: int = logging.INFO):
    """Configure the root logger with file + console handlers."""
    if log_file is None:
        log_file = os.path.join(
            os.path.dirname(__file__), "..", "keylogger_detection.log"
        )
    log_file = os.path.abspath(log_file)

    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Avoid adding duplicate handlers if called more than once
    root = logging.getLogger()
    if root.handlers:
        return

    root.setLevel(level)

    # File handler
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter(log_format, datefmt=date_format))
    root.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter(log_format, datefmt=date_format))
    root.addHandler(ch)

    logging.info("Logger configured. Log file: %s", log_file)
