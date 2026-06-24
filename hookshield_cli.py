import argparse
import sys
import subprocess
import os
import asyncio

def main():
    parser = argparse.ArgumentParser(description="HookShield Security Tooling")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Monitor Subcommand
    monitor_parser = subparsers.add_parser("monitor", help="Start the HookShield background monitor (requires Administrator)")
    monitor_parser.add_argument("--red-team", action="store_true", help="Run Red Team Evasion Testing Mode")

    # Scan Subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a directory for malicious files using YARA & VirusTotal")
    scan_parser.add_argument("directory", help="Directory to scan")

    # Dashboard Subcommand
    subparsers.add_parser("dashboard", help="Launch the HookShield Web Dashboard (Streamlit)")

    args = parser.parse_args()

    if args.command == "monitor":
        import main as orchestrator
        if args.red_team:
            from core.red_team import run_red_team_simulation
            import threading
            threading.Thread(target=run_red_team_simulation, daemon=True).start()
        
        orchestrator.configure_logger()
        orchestrator.logger.info("Starting HookShield CLI Monitor...")
        try:
            asyncio.run(orchestrator.monitor_system())
        except KeyboardInterrupt:
            orchestrator.logger.info("HookShield shut down.")

    elif args.command == "scan":
        from core.file_scanner import scan_files
        print(f"[*] Starting HookShield File Scanner on: {args.directory}")
        results = scan_files(args.directory)
        if results:
            print(f"[!] Found {len(results)} suspicious files:")
            for r in results:
                print(f"  -> {r}")
        else:
            print("[✓] No suspicious files found.")

    elif args.command == "dashboard":
        dash_path = os.path.join(os.path.dirname(__file__), "web", "dashboard.py")
        print(f"[*] Launching HookShield Dashboard: {dash_path}")
        subprocess.run(["streamlit", "run", dash_path])

if __name__ == "__main__":
    main()
