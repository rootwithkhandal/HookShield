"""
LogDefender — Streamlit dashboard.
Run with: streamlit run web/dashboard.py
"""
import os
import sys
from datetime import datetime

import pandas as pd
import streamlit as st

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs.db"))
def get_db(): return sqlite3.connect(db_path)

st.set_page_config(page_title="LogDefender", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ LogDefender")
page = st.sidebar.radio("View", ["Overview", "Detection Logs", "Network Logs", "Threat History"])

refresh_interval = st.sidebar.slider("Auto-refresh (s)", 5, 120, 30)
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=refresh_interval * 1000, key="dash_refresh")
except ImportError:
    st.sidebar.caption("Install streamlit-autorefresh for live updates.")

severity_filter = st.sidebar.multiselect(
    "Severity filter", ["INFO", "WARN", "ERROR"], default=["INFO", "WARN", "ERROR"]
)

st.sidebar.divider()
try:
    logs_csv = pd.read_sql("SELECT * FROM logs", get_db()).to_csv(index=False)
    st.sidebar.download_button("📥 Export Logs CSV", logs_csv, "logs.csv", "text/csv")
    threats_csv = pd.read_sql("SELECT * FROM threat_history", get_db()).to_csv(index=False)
    st.sidebar.download_button("📥 Export Threats CSV", threats_csv, "threats.csv", "text/csv")
except Exception:
    st.sidebar.caption("No logs to export.")

# ---------------------------------------------------------------------------
# Overview page
# ---------------------------------------------------------------------------
if page == "Overview":
    st.title("🛡️ LogDefender — Overview")

    try: df_t = pd.read_sql("SELECT * FROM threat_history", get_db())
    except: df_t = pd.DataFrame()

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Threats", len(df_t))
    c2.metric("Unresolved", len(df_t[df_t['resolved'] == 0]) if len(df_t) else 0)
    c3.metric("Process Threats", len(df_t[df_t['threat_type'] == 'process']) if len(df_t) else 0)
    c4.metric("File Threats", len(df_t[df_t['threat_type'] == 'file']) if len(df_t) else 0)
    c5.metric("Network Threats", len(df_t[df_t['threat_type'] == 'network']) if len(df_t) else 0)

    st.divider()
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("Threats by Type")
        if len(df_t): st.bar_chart(df_t['threat_type'].value_counts())
        else: st.info("No threat data yet.")
    with col_right:
        st.subheader("Threats by Severity")
        if len(df_t): st.bar_chart(df_t['severity'].value_counts())
        else: st.info("No threat data yet.")

    if len(df_t): st.caption(f"Last threat detected: {df_t['timestamp'].max()}")

# ---------------------------------------------------------------------------
# Detection Logs page
# ---------------------------------------------------------------------------
elif page == "Detection Logs":
    st.title("📋 Detection Logs")

    try: df = pd.read_sql("SELECT * FROM logs ORDER BY id DESC", get_db())
    except: df = pd.DataFrame()
    if len(df):
        if severity_filter:
            df = df[df["level"].isin(severity_filter)]

        def _highlight(row):
            colour_map = {"ERROR": "#ff4b4b", "WARN": "#ffa500", "INFO": "#1f77b4"}
            c = colour_map.get(row["level"], "")
            return [f"background-color: {c}22" for _ in row]

        st.dataframe(df.style.apply(_highlight, axis=1), use_container_width=True, height=420)

        c1, c2, c3 = st.columns(3)
        c1.metric("Total", len(df))
        c2.metric("Warnings", int((df["level"] == "WARN").sum()))
        c3.metric("Errors",   int((df["level"] == "ERROR").sum()))

        # Timeline chart
        if "timestamp" in df.columns:
            st.subheader("Log Volume Over Time")
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            df["date"] = df["timestamp"].dt.date
            timeline = df.groupby("date").size().reset_index(name="count")
            st.line_chart(timeline.set_index("date"))
    else:
        st.info("No detection logs yet.")

# ---------------------------------------------------------------------------
# Network Logs page
# ---------------------------------------------------------------------------
elif page == "Network Logs":
    st.title("🌐 Network / IP Logs")

    if ip := st.text_input("Flag Suspicious IP"):
        if st.button("Add"):
            with get_db() as db:
                db.execute("INSERT INTO network_ip (timestamp, level, message, source_ip) VALUES (datetime('now', 'localtime'), 'WARN', 'Manually added.', ?)", (ip,))
            st.success(f"Flagged {ip}")

    try: df_net = pd.read_sql("SELECT * FROM network_ip ORDER BY id DESC", get_db())
    except: df_net = pd.DataFrame()
    if len(df_net):
        if severity_filter:
            df_net = df_net[df_net["level"].isin(severity_filter)]
        st.dataframe(df_net, use_container_width=True, height=400)

        if "source_ip" in df_net.columns:
            st.subheader("Top Suspicious IPs")
            top_ips = df_net["source_ip"].value_counts().head(10).reset_index()
            top_ips.columns = ["IP", "Count"]
            st.bar_chart(top_ips.set_index("IP"))

            st.metric("Unique IPs tracked", df_net["source_ip"].nunique())
    else:
        st.info("No network logs yet.")

# ---------------------------------------------------------------------------
# Threat History page
# ---------------------------------------------------------------------------
elif page == "Threat History":
    st.title("🔴 Threat History")

    show_resolved = st.checkbox("Show resolved threats", value=False)
    try:
        q = "SELECT * FROM threat_history" + ("" if show_resolved else " WHERE resolved=0") + " ORDER BY id DESC"
        df_t = pd.read_sql(q, get_db())
    except: df_t = pd.DataFrame()

    if len(df_t):

        def _threat_highlight(row):
            colour_map = {"HIGH": "#ff4b4b", "MEDIUM": "#ffa500", "LOW": "#2ecc71"}
            c = colour_map.get(row.get("severity", ""), "")
            return [f"background-color: {c}22" for _ in row]

        st.dataframe(df_t.style.apply(_threat_highlight, axis=1), use_container_width=True, height=400)

        c1, c2, c3 = st.columns(3)
        c1.metric("Total threats",    len(df_t))
        c2.metric("High severity",    int((df_t["severity"] == "HIGH").sum()))
        c3.metric("Medium severity",  int((df_t["severity"] == "MEDIUM").sum()))

        # Threat type breakdown
        st.subheader("Threat Type Breakdown")
        type_counts = df_t["threat_type"].value_counts().reset_index()
        type_counts.columns = ["Type", "Count"]
        st.bar_chart(type_counts.set_index("Type"))
    else:
        st.info("No threat history yet. Run a scan to populate this view.")
