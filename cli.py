"""
LogDefender CLI entry point.

Usage:
    python cli.py                          # one-shot scan (current directory)
    python cli.py --directory C:\\Users    # scan a specific directory
    python cli.py --monitor --interval 30  # continuous monitoring every 30 s
"""
import argparse
import logging
import sys

from utils.logger import configure_logger
from main import detect_keyloggers, scanning_files, detect_network, monitor_system


def run_once(directory: str):
    """Run a single detection pass and print a summary."""
    print("=" * 60)
    print("LogDefender — single scan")
    print("=" * 60)

    processes = detect_keyloggers()
    files, _ = scanning_files(directory)
    connections = detect_network(processes, files)

    print("\n--- Summary ---")
    print(f"  Suspicious processes : {len(processes)}")
    print(f"  Suspicious files     : {len(files)}")
    print(f"  Suspicious connections: {len(connections)}")

    if not (processes or files or connections):
        print("\n✅ No keylogger activity detected.")
    else:
        print("\n⚠  Threats detected — check logs for details.")

    return bool(processes or files or connections)


def main():
    parser = argparse.ArgumentParser(
        description="LogDefender — keylogger detection tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--directory", "-d",
        default=".",
        help="Directory to scan for suspicious files",
    )
    parser.add_argument(
        "--monitor", "-m",
        action="store_true",
        help="Run in continuous monitoring mode",
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=60,
        help="Seconds between scans in monitor mode",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    args = parser.parse_args()

    configure_logger(level=logging.DEBUG if args.verbose else logging.INFO)

    if args.monitor:
        logging.info("Starting monitor mode (interval=%ds, directory=%s)", args.interval, args.directory)
        monitor_system(directory=args.directory, interval=args.interval)
    else:
        threat_found = run_once(args.directory)
        sys.exit(1 if threat_found else 0)


if __name__ == "__main__":
    main()
