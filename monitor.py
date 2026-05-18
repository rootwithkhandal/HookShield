"""
Standalone monitor entry point.
Runs all detection checks on a configurable interval.
"""
import argparse
import logging

from utils.logger import configure_logger
from main import monitor_system


def main():
    parser = argparse.ArgumentParser(description="LogDefender background monitor")
    parser.add_argument(
        "--directory", "-d",
        default=".",
        help="Directory to scan for suspicious files (default: current directory)",
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=60,
        help="Seconds between scan cycles (default: 60)",
    )
    args = parser.parse_args()

    configure_logger()
    logging.info("Monitor starting — directory=%s, interval=%ds", args.directory, args.interval)
    monitor_system(directory=args.directory, interval=args.interval)


if __name__ == "__main__":
    main()
