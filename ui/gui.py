"""
LogDefender GUI — built with CustomTkinter.
Tabs: Dashboard | Process Manager | File Scanner | Network | Quarantine | Startup | Settings
"""
import io
import logging
import os
import subprocess
import sys
import threading
import datetime
import tkinter as tk
from tkinter import messagebox, filedialog

import customtkinter as ctk
import psutil
from pprint import pformat

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import (
    detect_keyloggers, scanning_files, detect_network,
    detect_clipboard, scan_startup, kill_process,
)
from core.file_scanner import scan_single_file, scan_files as core_scan_files
from core.remote_connection_detector import detect_remote_connections
from core.quarantine import quarantine_file, list_quarantined, restore_file, delete_quarantined
from utils.network_blocker import block_suspicious_ips
from utils.ip_scanner import get_all_ips
from utils.dblogs import insert_log, db_network_ip, export_logs_csv, export_threats_csv, get_threat_stats
from utils.config_loader import load_config, load_known_hashes
from utils.email_sender import send_email

logger = logging.getLogger(__name__)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def _load_scan_config():
    cfg = load_config()
    return cfg.get("virus_total_api_key", ""), load_known_hashes()


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class KeyloggerDetectApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("LogDefender")
        self.geometry("1150x720")
        self.resizable(True, True)
        self._monitor_running = False
        self._monitor_thread = None
        self._build_ui()
        self._refresh_sysinfo()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(
            header, text="🛡️  LogDefender",
            font=("Helvetica", 24, "bold"), text_color="#00d4ff"
        ).pack(side="left", padx=20, pady=12)
        self.sysinfo_label = ctk.CTkLabel(
            header, text="", font=("Courier", 11), text_color="#aaaaaa"
        )
        self.sysinfo_label.pack(side="right", padx=20)

        # Tab view
        self.tabs = ctk.CTkTabview(self, height=620)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(8, 4))

        for tab in ["Dashboard", "Processes", "File Scanner", "Network", "Quarantine", "Startup", "Settings"]:
            self.tabs.add(tab)

        self._build_dashboard_tab()
        self._build_process_tab()
        self._build_file_tab()
        self._build_network_tab()
        self._build_quarantine_tab()
        self._build_startup_tab()
        self._build_settings_tab()

        # Status bar
        self.status = ctk.CTkLabel(self, text="Ready", text_color="gray", font=("Helvetica", 12))
        self.status.pack(pady=(2, 6))

    # ------------------------------------------------------------------
    # Dashboard tab
    # ------------------------------------------------------------------

    def _build_dashboard_tab(self):
        tab = self.tabs.tab("Dashboard")

        # Metric cards row
        cards = ctk.CTkFrame(tab, fg_color="transparent")
        cards.pack(fill="x", pady=(10, 6), padx=10)

        self._metric_total   = self._metric_card(cards, "Total Threats", "0", "#e74c3c")
        self._metric_unresolv = self._metric_card(cards, "Unresolved",   "0", "#e67e22")
        self._metric_procs   = self._metric_card(cards, "Processes",     "0", "#9b59b6")
        self._metric_files   = self._metric_card(cards, "Files",         "0", "#2980b9")
        self._metric_network = self._metric_card(cards, "Network",       "0", "#27ae60")

        # Output box
        self.dash_output = ctk.CTkTextbox(tab, height=320, font=("Courier", 11))
        self.dash_output.pack(fill="both", expand=True, padx=10, pady=6)

        # Buttons
        btn_row = ctk.CTkFrame(tab, fg_color="transparent")
        btn_row.pack(pady=6)
        ctk.CTkButton(btn_row, text="▶  Full Scan",      command=self._full_scan_thread, width=130).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="⟳  Refresh Stats",  command=self._refresh_stats,    width=130).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="📄  Export CSV",     command=self._export_csv,       width=130).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="📊  Open Dashboard", command=self._open_web_dash,    width=130).pack(side="left", padx=6)

        # Real-time monitor toggle
        mon_row = ctk.CTkFrame(tab, fg_color="transparent")
        mon_row.pack(pady=4)
        ctk.CTkLabel(mon_row, text="Real-time monitor:").pack(side="left", padx=(0, 8))
        self._monitor_switch = ctk.CTkSwitch(mon_row, text="Off", command=self._toggle_monitor)
        self._monitor_switch.pack(side="left")
        ctk.CTkLabel(mon_row, text="Interval (s):").pack(side="left", padx=(16, 4))
        self._interval_entry = ctk.CTkEntry(mon_row, width=60, placeholder_text="60")
        self._interval_entry.pack(side="left")

        self._refresh_stats()

    def _metric_card(self, parent, label: str, value: str, colour: str):
        frame = ctk.CTkFrame(parent, fg_color=colour, corner_radius=10, width=160, height=70)
        frame.pack(side="left", padx=8, expand=True, fill="x")
        frame.pack_propagate(False)
        ctk.CTkLabel(frame, text=label, font=("Helvetica", 11), text_color="white").pack(pady=(8, 0))
        val_lbl = ctk.CTkLabel(frame, text=value, font=("Helvetica", 22, "bold"), text_color="white")
        val_lbl.pack()
        return val_lbl

    # ------------------------------------------------------------------
    # Process Manager tab
    # ------------------------------------------------------------------

    def _build_process_tab(self):
        tab = self.tabs.tab("Processes")

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=8)
        ctk.CTkButton(top, text="🔍 Scan Processes", command=self._scan_processes_thread, width=160).pack(side="left", padx=6)
        ctk.CTkButton(top, text="🖥️ Clipboard Check", command=self._clipboard_check_thread, width=160).pack(side="left", padx=6)
        ctk.CTkButton(top, text="🔄 Refresh List",   command=self._refresh_proc_list,      width=140).pack(side="left", padx=6)

        # Suspicious process list
        ctk.CTkLabel(tab, text="Suspicious Processes:", anchor="w").pack(fill="x", padx=12)
        self.proc_listbox = tk.Listbox(
            tab, bg="#1e1e2e", fg="#ff6b6b", selectbackground="#3a3a5c",
            font=("Courier", 11), height=10, relief="flat", bd=0
        )
        self.proc_listbox.pack(fill="both", expand=True, padx=12, pady=4)

        kill_row = ctk.CTkFrame(tab, fg_color="transparent")
        kill_row.pack(pady=6)
        ctk.CTkButton(
            kill_row, text="💀 Kill Selected Process",
            command=self._kill_selected, fg_color="#c0392b", hover_color="#e74c3c", width=200
        ).pack(side="left", padx=8)

        self.proc_output = ctk.CTkTextbox(tab, height=120, font=("Courier", 11))
        self.proc_output.pack(fill="x", padx=12, pady=4)

    # ------------------------------------------------------------------
    # File Scanner tab
    # ------------------------------------------------------------------

    def _build_file_tab(self):
        tab = self.tabs.tab("File Scanner")

        path_row = ctk.CTkFrame(tab, fg_color="transparent")
        path_row.pack(fill="x", padx=12, pady=10)
        ctk.CTkLabel(path_row, text="Path:").pack(side="left", padx=(0, 6))
        self.file_input = ctk.CTkEntry(path_row, width=500, placeholder_text="File or directory path…")
        self.file_input.pack(side="left", padx=4)
        ctk.CTkButton(path_row, text="Browse", command=self._browse_path, width=80).pack(side="left", padx=4)

        btn_row = ctk.CTkFrame(tab, fg_color="transparent")
        btn_row.pack(pady=6)
        ctk.CTkButton(btn_row, text="🔍 Scan",       command=self._scan_file_thread,      width=130).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="🔒 Quarantine", command=self._quarantine_selected,   width=130).pack(side="left", padx=6)

        self.file_output = ctk.CTkTextbox(tab, height=380, font=("Courier", 11))
        self.file_output.pack(fill="both", expand=True, padx=12, pady=6)

    # ------------------------------------------------------------------
    # Network tab
    # ------------------------------------------------------------------

    def _build_network_tab(self):
        tab = self.tabs.tab("Network")

        btn_row = ctk.CTkFrame(tab, fg_color="transparent")
        btn_row.pack(pady=10)
        ctk.CTkButton(btn_row, text="🌐 Detect IPs",    command=self._scan_net_ip_thread, width=140).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="➕ Add IP",         command=self._open_ip_window,     width=120).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="🚫 Block Packets",  command=self._block_ips_thread,   width=140).pack(side="left", padx=6)

        self.net_output = ctk.CTkTextbox(tab, height=460, font=("Courier", 11))
        self.net_output.pack(fill="both", expand=True, padx=12, pady=6)

    # ------------------------------------------------------------------
    # Quarantine tab
    # ------------------------------------------------------------------

    def _build_quarantine_tab(self):
        tab = self.tabs.tab("Quarantine")

        btn_row = ctk.CTkFrame(tab, fg_color="transparent")
        btn_row.pack(pady=10)
        ctk.CTkButton(btn_row, text="🔄 Refresh",          command=self._refresh_quarantine, width=120).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="↩️  Restore Selected", command=self._restore_selected,   width=160).pack(side="left", padx=6)
        ctk.CTkButton(
            btn_row, text="🗑️  Delete Selected",
            command=self._delete_quarantined, fg_color="#c0392b", hover_color="#e74c3c", width=160
        ).pack(side="left", padx=6)

        ctk.CTkLabel(tab, text="Quarantined Files:", anchor="w").pack(fill="x", padx=12)
        self.quar_listbox = tk.Listbox(
            tab, bg="#1e1e2e", fg="#f39c12", selectbackground="#3a3a5c",
            font=("Courier", 11), height=16, relief="flat", bd=0
        )
        self.quar_listbox.pack(fill="both", expand=True, padx=12, pady=4)
        self._quarantine_items = []  # parallel list of dicts
        self._refresh_quarantine()

    # ------------------------------------------------------------------
    # Startup Scanner tab
    # ------------------------------------------------------------------

    def _build_startup_tab(self):
        tab = self.tabs.tab("Startup")

        btn_row = ctk.CTkFrame(tab, fg_color="transparent")
        btn_row.pack(pady=10)
        ctk.CTkButton(btn_row, text="🔍 Scan Startup Entries", command=self._scan_startup_thread, width=200).pack(side="left", padx=6)

        self.startup_output = ctk.CTkTextbox(tab, height=460, font=("Courier", 11))
        self.startup_output.pack(fill="both", expand=True, padx=12, pady=6)

    # ------------------------------------------------------------------
    # Settings tab
    # ------------------------------------------------------------------

    def _build_settings_tab(self):
        tab = self.tabs.tab("Settings")

        ctk.CTkLabel(tab, text="Configuration", font=("Helvetica", 16, "bold")).pack(pady=(16, 8))

        cfg = load_config()
        email_cfg = cfg.get("email", {})

        form = ctk.CTkFrame(tab)
        form.pack(padx=30, pady=10, fill="x")

        fields = [
            ("VirusTotal API Key",  cfg.get("virus_total_api_key", ""), False),
            ("Email Sender",        email_cfg.get("sender", ""),        False),
            ("Email Password",      email_cfg.get("password", ""),      True),
            ("Email Receiver",      email_cfg.get("receiver", ""),      False),
        ]
        self._settings_entries = {}
        for label, default, is_password in fields:
            row = ctk.CTkFrame(form, fg_color="transparent")
            row.pack(fill="x", pady=6, padx=10)
            ctk.CTkLabel(row, text=label, width=180, anchor="w").pack(side="left")
            entry = ctk.CTkEntry(row, width=380, show="*" if is_password else "")
            entry.insert(0, default)
            entry.pack(side="left", padx=8)
            self._settings_entries[label] = entry

        ctk.CTkButton(tab, text="💾 Save Settings", command=self._save_settings, width=180).pack(pady=12)
        ctk.CTkLabel(
            tab,
            text="💡 Tip: Use a .env file or environment variables to avoid storing secrets in config.yaml",
            text_color="gray", font=("Helvetica", 11)
        ).pack(pady=4)

    # ------------------------------------------------------------------
    # Dashboard actions
    # ------------------------------------------------------------------

    def _full_scan_thread(self):
        threading.Thread(target=self._full_scan, daemon=True).start()

    def _full_scan(self):
        self._set_status("Running full scan…", "orange")
        self.dash_output.delete("1.0", "end")
        buf = io.StringIO(); old = sys.stdout; sys.stdout = buf
        try:
            insert_log("INFO", "Full scan started.", "gui")
            procs = detect_keyloggers()
            path = self.file_input.get().strip() if hasattr(self, "file_input") else "."
            files, _ = scanning_files(path or ".")
            conns = detect_network(procs, files)
            clips = detect_clipboard()
            starts = scan_startup()
            print(f"Processes  : {len(procs)} suspicious")
            print(f"Files      : {len(files)} suspicious")
            print(f"Connections: {len(conns)} suspicious")
            print(f"Clipboard  : {len(clips)} suspicious")
            print(f"Startup    : {len(starts)} suspicious")
        except Exception as e:
            print(f"Error: {e}")
            insert_log("ERROR", str(e), "full_scan")
        finally:
            sys.stdout = old
        self.dash_output.insert("end", buf.getvalue())
        self._refresh_stats()
        self._set_status("Full scan complete.", "green")

    def _refresh_stats(self):
        stats = get_threat_stats()
        self._metric_total.configure(text=str(stats["total"]))
        self._metric_unresolv.configure(text=str(stats["unresolved"]))
        self._metric_procs.configure(text=str(stats["by_type"].get("process", 0)))
        self._metric_files.configure(text=str(stats["by_type"].get("file", 0)))
        self._metric_network.configure(text=str(stats["by_type"].get("network", 0)))

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"logdefender_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not path:
            return
        try:
            csv_data = export_logs_csv(include_network=True)
            with open(path, "w", newline="", encoding="utf-8") as f:
                f.write(csv_data)
            messagebox.showinfo("Export", f"Logs exported to:\n{path}")
            insert_log("INFO", f"Logs exported to {path}", "gui")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _open_web_dash(self):
        try:
            script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "web", "dashboard.py"))
            subprocess.Popen(["streamlit", "run", script])
            insert_log("INFO", "Web dashboard opened.", "gui")
        except Exception as e:
            messagebox.showerror("Error", f"Could not launch dashboard:\n{e}")

    def _toggle_monitor(self):
        if self._monitor_switch.get():
            self._monitor_switch.configure(text="On")
            self._start_realtime_monitor()
        else:
            self._monitor_switch.configure(text="Off")
            self._monitor_running = False
            self._set_status("Real-time monitor stopped.", "gray")

    def _start_realtime_monitor(self):
        try:
            interval = int(self._interval_entry.get() or "60")
        except ValueError:
            interval = 60
        self._monitor_running = True
        self._set_status(f"Real-time monitor active (every {interval}s)…", "#00d4ff")

        def _loop():
            import time
            while self._monitor_running:
                try:
                    detect_keyloggers()
                    detect_clipboard()
                    detect_network()
                    self.after(0, self._refresh_stats)
                except Exception as e:
                    logger.error("Monitor loop error: %s", e)
                time.sleep(interval)

        self._monitor_thread = threading.Thread(target=_loop, daemon=True)
        self._monitor_thread.start()

    # ------------------------------------------------------------------
    # Process tab actions
    # ------------------------------------------------------------------

    def _scan_processes_thread(self):
        threading.Thread(target=self._scan_processes, daemon=True).start()

    def _scan_processes(self):
        self._set_status("Scanning processes…", "orange")
        self.proc_listbox.delete(0, "end")
        self.proc_output.delete("1.0", "end")
        self._suspicious_procs = []
        try:
            from core.process_detector import detect_suspicious_processes
            procs = detect_suspicious_processes()
            self._suspicious_procs = procs
            if procs:
                for p in procs:
                    self.proc_listbox.insert("end", f"[PID {p['pid']}]  {p['name']}  —  {p['cmdline'][:80]}")
                self.proc_output.insert("end", f"⚠  {len(procs)} suspicious process(es) found.\n")
                insert_log("WARN", f"{len(procs)} suspicious processes.", "process_tab")
            else:
                self.proc_output.insert("end", "✅ No suspicious processes found.\n")
        except Exception as e:
            self.proc_output.insert("end", f"Error: {e}\n")
        self._set_status("Process scan complete.", "green")

    def _clipboard_check_thread(self):
        threading.Thread(target=self._clipboard_check, daemon=True).start()

    def _clipboard_check(self):
        self._set_status("Checking clipboard access…", "orange")
        self.proc_output.delete("1.0", "end")
        try:
            hits = detect_clipboard()
            if hits:
                self.proc_output.insert("end", f"⚠  Suspicious clipboard access by {len(hits)} process(es):\n")
                for h in hits:
                    self.proc_output.insert("end", f"  PID {h['pid']}  {h['name']}  [{h['detection_method']}]\n")
            else:
                self.proc_output.insert("end", "✅ No suspicious clipboard activity.\n")
        except Exception as e:
            self.proc_output.insert("end", f"Error: {e}\n")
        self._set_status("Clipboard check complete.", "green")

    def _refresh_proc_list(self):
        threading.Thread(target=self._scan_processes, daemon=True).start()

    def _kill_selected(self):
        sel = self.proc_listbox.curselection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a process from the list first.")
            return
        idx = sel[0]
        if not hasattr(self, "_suspicious_procs") or idx >= len(self._suspicious_procs):
            return
        proc = self._suspicious_procs[idx]
        if not messagebox.askyesno(
            "Confirm Kill",
            f"Terminate process:\n  {proc['name']}  (PID {proc['pid']})\n\nThis cannot be undone."
        ):
            return
        success = kill_process(proc["pid"])
        if success:
            self.proc_listbox.delete(idx)
            self._suspicious_procs.pop(idx)
            self.proc_output.insert("end", f"✅ Terminated: {proc['name']} (PID {proc['pid']})\n")
            messagebox.showinfo("Done", f"Process {proc['name']} terminated.")
        else:
            messagebox.showerror("Failed", f"Could not terminate PID {proc['pid']}. Try running as administrator.")

    # ------------------------------------------------------------------
    # File Scanner tab actions
    # ------------------------------------------------------------------

    def _browse_path(self):
        path = filedialog.askdirectory()
        if not path:
            path = filedialog.askopenfilename()
        if path:
            self.file_input.delete(0, "end")
            self.file_input.insert(0, path)

    def _scan_file_thread(self):
        threading.Thread(target=self._scan_file, daemon=True).start()

    def _scan_file(self):
        self._set_status("Scanning…", "orange")
        self.file_output.delete("1.0", "end")
        path = self.file_input.get().strip()
        if not path:
            messagebox.showwarning("Input Error", "Enter a file or directory path.")
            self._set_status("Ready", "gray")
            return

        self._last_suspicious_files = []
        buf = io.StringIO(); old = sys.stdout; sys.stdout = buf
        try:
            api_key, known_hashes = _load_scan_config()
            insert_log("INFO", "File scan started.", path)
            if os.path.isdir(path):
                suspicious = core_scan_files(path, known_hashes, api_key)
            else:
                suspicious = scan_single_file(path, known_hashes, api_key)

            self._last_suspicious_files = suspicious
            if suspicious:
                print(f"⚠  {len(suspicious)} suspicious item(s) found:")
                for f in suspicious:
                    print(f"   {f}")
                insert_log("WARN", "Suspicious files found.", path)
                send_email(
                    subject="🚨 SCRAMBLE — Suspicious File Detected",
                    body=f"Suspicious files detected:\n{suspicious}\n\nPath: {path}"
                )
            else:
                print("✅ No threats found.")
                insert_log("INFO", "No threats found.", path)
        except Exception as e:
            print(f"Error: {e}")
            insert_log("ERROR", str(e), path)
        finally:
            sys.stdout = old

        self.file_output.insert("end", buf.getvalue())
        self._set_status("File scan complete.", "green")

    def _quarantine_selected(self):
        if not hasattr(self, "_last_suspicious_files") or not self._last_suspicious_files:
            messagebox.showinfo("Quarantine", "Run a scan first. Suspicious files will be listed for quarantine.")
            return
        quarantined = []
        failed = []
        for f in self._last_suspicious_files:
            result = quarantine_file(f)
            if result:
                quarantined.append(f)
            else:
                failed.append(f)
        msg = ""
        if quarantined:
            msg += f"Quarantined {len(quarantined)} file(s).\n"
        if failed:
            msg += f"Failed to quarantine {len(failed)} file(s) (may already be moved)."
        messagebox.showinfo("Quarantine Result", msg or "Nothing to quarantine.")
        self._last_suspicious_files = []
        self._refresh_quarantine()

    # ------------------------------------------------------------------
    # Network tab actions
    # ------------------------------------------------------------------

    def _scan_net_ip_thread(self):
        threading.Thread(target=self._scan_net_ip, daemon=True).start()

    def _scan_net_ip(self):
        self._set_status("Scanning network IPs…", "orange")
        self.net_output.delete("1.0", "end")
        ip_data = get_all_ips()
        self.net_output.insert("end", pformat(ip_data, indent=2))
        self._set_status("IP scan complete.", "green")

    def _open_ip_window(self):
        win = tk.Toplevel(self)
        win.title("Add Suspicious IP")
        win.geometry("340x170")
        win.resizable(False, False)
        tk.Label(win, text="IP Address to track:").pack(pady=12)
        ip_entry = tk.Entry(win, width=34)
        ip_entry.pack(pady=4)

        def _submit():
            ip = ip_entry.get().strip()
            if not ip:
                messagebox.showwarning("Input Error", "Enter a valid IP address.", parent=win)
                return
            try:
                db_network_ip("WARN", "Manually added suspicious IP.", ip)
                insert_log("INFO", f"IP {ip} added to watchlist.", "gui")
                messagebox.showinfo("Success", f"IP {ip} added to watchlist.", parent=win)
                win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=win)

        tk.Button(win, text="Add IP", command=_submit, width=18).pack(pady=10)

    def _block_ips_thread(self):
        threading.Thread(target=self._block_ips, daemon=True).start()

    def _block_ips(self):
        self._set_status("Blocking suspicious IPs…", "orange")
        self.net_output.delete("1.0", "end")
        buf = io.StringIO(); old = sys.stdout; sys.stdout = buf
        try:
            blocked = block_suspicious_ips()
            if blocked:
                insert_log("WARN", f"Blocked IPs: {blocked}", "network_blocker")
            else:
                print("No IPs were blocked.")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            sys.stdout = old
        self.net_output.insert("end", buf.getvalue())
        self._set_status("IP blocking complete.", "green")

    # ------------------------------------------------------------------
    # Quarantine tab actions
    # ------------------------------------------------------------------

    def _refresh_quarantine(self):
        self.quar_listbox.delete(0, "end")
        self._quarantine_items = list_quarantined()
        if not self._quarantine_items:
            self.quar_listbox.insert("end", "  (quarantine is empty)")
            return
        for item in self._quarantine_items:
            size_kb = item["size_bytes"] / 1024
            self.quar_listbox.insert(
                "end",
                f"  {item['filename']}  |  {size_kb:.1f} KB  |  orig: {item['original_path']}"
            )

    def _restore_selected(self):
        sel = self.quar_listbox.curselection()
        if not sel or not self._quarantine_items:
            messagebox.showwarning("No Selection", "Select a quarantined file first.")
            return
        item = self._quarantine_items[sel[0]]
        if messagebox.askyesno("Restore", f"Restore:\n{item['filename']}\nto:\n{item['original_path']}?"):
            if restore_file(item["quarantine_path"]):
                messagebox.showinfo("Restored", "File restored successfully.")
            else:
                messagebox.showerror("Failed", "Could not restore file. Check logs.")
            self._refresh_quarantine()

    def _delete_quarantined(self):
        sel = self.quar_listbox.curselection()
        if not sel or not self._quarantine_items:
            messagebox.showwarning("No Selection", "Select a quarantined file first.")
            return
        item = self._quarantine_items[sel[0]]
        if messagebox.askyesno("Delete", f"Permanently delete:\n{item['filename']}\n\nThis cannot be undone."):
            if delete_quarantined(item["quarantine_path"]):
                messagebox.showinfo("Deleted", "File permanently deleted.")
            else:
                messagebox.showerror("Failed", "Could not delete file.")
            self._refresh_quarantine()

    # ------------------------------------------------------------------
    # Startup tab actions
    # ------------------------------------------------------------------

    def _scan_startup_thread(self):
        threading.Thread(target=self._scan_startup, daemon=True).start()

    def _scan_startup(self):
        self._set_status("Scanning startup entries…", "orange")
        self.startup_output.delete("1.0", "end")
        try:
            entries = scan_startup()
            if entries:
                self.startup_output.insert("end", f"⚠  {len(entries)} suspicious startup entry(ies) found:\n\n")
                for e in entries:
                    self.startup_output.insert("end", f"  Source : {e.get('source')}\n")
                    if e.get("source") == "registry":
                        self.startup_output.insert("end", f"  Hive   : {e.get('hive')}\n")
                        self.startup_output.insert("end", f"  Key    : {e.get('key')}\n")
                        self.startup_output.insert("end", f"  Name   : {e.get('name')}\n")
                        self.startup_output.insert("end", f"  Value  : {e.get('value')}\n")
                    else:
                        self.startup_output.insert("end", f"  Folder : {e.get('folder')}\n")
                        self.startup_output.insert("end", f"  File   : {e.get('filename')}\n")
                    self.startup_output.insert("end", "\n")
            else:
                self.startup_output.insert("end", "✅ No suspicious startup entries found.\n")
        except Exception as ex:
            self.startup_output.insert("end", f"Error: {ex}\n")
        self._set_status("Startup scan complete.", "green")

    # ------------------------------------------------------------------
    # Settings tab actions
    # ------------------------------------------------------------------

    def _save_settings(self):
        import yaml
        cfg_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "config.yaml")
        )
        try:
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}

        cfg["virus_total_api_key"] = self._settings_entries["VirusTotal API Key"].get().strip()
        cfg.setdefault("email", {})
        cfg["email"]["sender"]   = self._settings_entries["Email Sender"].get().strip()
        cfg["email"]["password"] = self._settings_entries["Email Password"].get().strip()
        cfg["email"]["receiver"] = self._settings_entries["Email Receiver"].get().strip()

        try:
            with open(cfg_path, "w") as f:
                yaml.dump(cfg, f, default_flow_style=False)
            messagebox.showinfo("Saved", "Settings saved to config.yaml.\n\nConsider using a .env file for secrets.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save settings:\n{e}")

    # ------------------------------------------------------------------
    # System info
    # ------------------------------------------------------------------

    def _refresh_sysinfo(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            boot = datetime.datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.datetime.now() - boot
            hours, rem = divmod(int(uptime.total_seconds()), 3600)
            mins = rem // 60
            self.sysinfo_label.configure(
                text=f"CPU {cpu:.0f}%  |  RAM {mem.percent:.0f}%  |  Uptime {hours}h {mins}m"
            )
        except Exception:
            pass
        self.after(5000, self._refresh_sysinfo)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: str, color: str = "gray"):
        self.after(0, lambda: self.status.configure(text=text, text_color=color))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = KeyloggerDetectApp()
    app.mainloop()
