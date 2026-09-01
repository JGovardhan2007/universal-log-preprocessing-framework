#!/usr/bin/env python3
"""
Universal Log Pre-processing Framework (ULPF)
Clean 3-Page SOC & Forensic Ingestion System
1. 📊 Main Dashboard (Analytics & AI Threat Hunting)
2. ⚡ Live Streamer (Real-time Raw -> SHA-256 -> Formatted JSON & Live Dual-Buffer)
3. 🗄️ Database & Storage Vault (Raw .log vs Formatted .json Batches)
"""

import os
import sys
import time
import json
import pandas as pd
import pyarrow.parquet as pq
import plotly.express as px
import streamlit as st
from datetime import datetime, timezone

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core_engine.live_service import LiveLogPipelineService, RAW_STORAGE_DIR, FORMATTED_STORAGE_DIR
try:
    from dashboard.ai_anomaly import ThreatAnomalyDetector
except ImportError:
    from ai_anomaly import ThreatAnomalyDetector

# Page configuration
st.set_page_config(
    page_title="ULPF | Universal Log Pre-processing Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Design Styling
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">

<style>
    .stApp {
        background: #090d16;
        color: #e2e8f0;
        font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
    }
    #MainMenu, footer, header {visibility: hidden;}
    .block-container {
        padding-top: 1.2rem;
        padding-bottom: 2rem;
        max-width: 96% !important;
    }
    .header-box {
        background: linear-gradient(135deg, #0f172a 0%, #172033 50%, #0e304f 100%);
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 18px 24px;
        margin-bottom: 16px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .kpi-card {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    .kpi-label {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: #94a3b8;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .kpi-val {
        font-size: 24px;
        font-weight: 800;
        color: #ffffff;
        margin: 0;
    }
    .buffer-box {
        background: #0b1120;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 16px;
    }
    .stream-card {
        background: #0b1120;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 14px;
        margin-bottom: 12px;
    }
    .raw-box {
        background-color: #020617;
        border: 1px solid #334155;
        border-left: 4px solid #f59e0b;
        border-radius: 6px;
        padding: 10px 14px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #fbbf24;
        word-break: break-all;
    }
    .sha-box {
        background-color: #020617;
        border: 1px solid #1e293b;
        border-left: 4px solid #38bdf8;
        border-radius: 6px;
        padding: 8px 12px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #38bdf8;
        margin: 6px 0;
        word-break: break-all;
    }
    .json-box {
        background-color: #020617;
        border: 1px solid #1e293b;
        border-left: 4px solid #10b981;
        border-radius: 6px;
        padding: 10px 14px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #34d399;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Live Pipeline Service
service = LiveLogPipelineService.get_instance()

# -------------------------------------------------------------
# SIDEBAR: Navigation & Live Engine Controls
# -------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ ULPF Control")
    page_selection = st.radio(
        "Navigation",
        ["📊 Main Dashboard", "⚡ Live Streamer", "🗄️ Database Vault"],
        index=1  # Default to Live Streamer
    )

    st.markdown("---")
    st.markdown("### ⚙️ Live Stream Generator")

    # Start / Stop Engine
    if service.is_running:
        status_label = "🟢 GENERATOR & LISTENER ACTIVE"
        btn_label = "⏹️ Stop Ingestion Stream"
        btn_type = "secondary"
    else:
        status_label = "⚪ INGESTION IDLE"
        btn_label = "▶️ Start Live Stream (UDP 5140)"
        btn_type = "primary"

    st.markdown(f"**Status:** `{status_label}`")

    if st.button(btn_label, type=btn_type, use_container_width=True):
        if service.is_running:
            service.stop()
        else:
            service.start(eps=st.session_state.get("speed_slider", 10))
        st.rerun()

    # Rate Speed Slider
    speed = st.slider("Generation Rate (Logs / sec)", min_value=1, max_value=50, value=service.logs_per_second, key="speed_slider")
    if service.is_running and speed != service.logs_per_second:
        service.set_speed(speed)

    st.markdown("---")
    st.markdown("### 📦 Batch Constraint Settings")
    batch_threshold = st.select_slider(
        "Logs per File Batch",
        options=[50, 100, 200, 500, 1000],
        value=service.batch_size_threshold,
        help="Number of logs collected into in-memory buffers before converting to .log and .json files."
    )
    if batch_threshold != service.batch_size_threshold:
        service.set_batch_threshold(batch_threshold)

    st.markdown("---")
    st.markdown("### 📡 Wire Configuration")
    st.caption(f"• **Port:** UDP 5140 (Syslog)\n• **Active Batch Limit:** {service.batch_size_threshold} logs\n• **Raw Path:** `data/storage/raw/`\n• **JSON Path:** `data/storage/formatted/`")


# Top Header
st.markdown("""
<div class="header-box">
    <div>
        <h2 style="margin:0; font-size:20px; font-weight:700; color:#ffffff;">Universal Log Pre-processing Framework (ULPF)</h2>
        <p style="margin:3px 0 0 0; font-size:12px; color:#94a3b8;">NTRO Problem Statement 26156 • High-Throughput Live Ingestion & Dual-Buffer Storage Architecture</p>
    </div>
    <div style="font-size:12px; font-weight:600; color:#34d399; background:rgba(16,185,129,0.1); padding:5px 14px; border-radius:4px; border:1px solid rgba(16,185,129,0.3);">
        PORT 5140 • OCSF v1.1.0
    </div>
</div>
""", unsafe_allow_html=True)


# =============================================================
# PAGE 1: 📊 MAIN DASHBOARD (Analytics & AI Threat Hunting)
# =============================================================
if page_selection == "📊 Main Dashboard":
    st.markdown("### 📊 Enterprise Analytics & AI Threat Intelligence")
    st.caption("Aggregated analytics and unsupervised Isolation Forest threat detection across all formatted records.")

    # Load stored parquet data
    parquet_path = os.path.join(PROJECT_ROOT, "data", "stream_buffer.parquet")
    df = pd.DataFrame()
    if os.path.exists(parquet_path):
        try:
            df = pq.read_table(parquet_path).to_pandas()
            if not df.empty:
                if "vendor" in df.columns and "vendor_name" not in df.columns:
                    df["vendor_name"] = df["vendor"]
                detector = ThreatAnomalyDetector(contamination=0.08)
                df = detector.fit_predict(df)
        except Exception:
            df = pd.DataFrame()

    # KPI Metrics
    total_logs = len(df) if not df.empty else service.stats["total_formatted"]
    current_eps = service.stats["current_eps"]
    anomalies = len(df[df["is_anomaly"] == True]) if not df.empty and "is_anomaly" in df.columns else 0
    file_info = service.get_stored_files()
    total_batches = len(file_info["raw_files"])

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">Total Ingested Logs</div><div class="kpi-val" style="color:#38bdf8;">{total_logs:,}</div></div>', unsafe_allow_html=True)
    with k2:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">Current Throughput</div><div class="kpi-val" style="color:#34d399;">{current_eps} EPS</div></div>', unsafe_allow_html=True)
    with k3:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">AI Flagged Anomalies</div><div class="kpi-val" style="color:#fb7185;">{anomalies:,}</div></div>', unsafe_allow_html=True)
    with k4:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">Batches Stored on Disk</div><div class="kpi-val" style="color:#a5b4fc;">{total_batches} Batches</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if df.empty:
        st.info("No logs in database yet. Switch to '⚡ Live Streamer' and click 'Start Live Stream' to begin ingestion.")
    else:
        # Charts Row
        c1, c2 = st.columns([2, 1])
        with c1:
            st.markdown("#### 🤖 AI Threat Hunting & Port Entropy")
            fig = px.scatter(
                df,
                x="src_port",
                y="dst_port",
                color="anomaly_score",
                size="anomaly_score",
                hover_data=["src_ip", "dst_ip", "vendor_name", "disposition"],
                color_continuous_scale="Viridis",
                template="plotly_dark",
                height=340
            )
            fig.update_layout(plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font=dict(family="Plus Jakarta Sans", color="#94a3b8"))
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown("#### 🏢 Ingestion by Vendor")
            if "vendor_name" in df.columns:
                v_counts = df["vendor_name"].value_counts().reset_index()
                v_counts.columns = ["Vendor", "Count"]
                fig_pie = px.pie(v_counts, values="Count", names="Vendor", hole=0.45, template="plotly_dark", height=340)
                fig_pie.update_layout(plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font=dict(family="Plus Jakarta Sans", color="#94a3b8"))
                st.plotly_chart(fig_pie, use_container_width=True)

        # Flagged High-Risk Anomalies Table
        high_risk = df[df["anomaly_score"] > 0.70] if "anomaly_score" in df.columns else pd.DataFrame()
        st.markdown(f"#### 🚨 Flagged Security Anomalies ({len(high_risk)} Detected)")
        if not high_risk.empty:
            cols = ["ingest_timestamp", "vendor_name", "src_ip", "src_port", "dst_ip", "dst_port", "disposition", "anomaly_score"]
            available = [c for c in cols if c in high_risk.columns]
            st.dataframe(high_risk[available].tail(20).iloc[::-1], use_container_width=True, height=220)


# =============================================================
# PAGE 2: ⚡ LIVE STREAMER (Real-time Flow & Dual-Buffer Status)
# =============================================================
elif page_selection == "⚡ Live Streamer":
    st.markdown("### ⚡ Real-Time Log Ingestion Streamer")
    st.caption("Live top-to-bottom pipeline: Raw String (Port 5140) ➔ Hardware SHA-256 Wire Key ➔ Standardized OCSF JSON.")

    # Live In-Memory Dual-Buffer Progress Widget
    buf_status = service.get_buffer_status()
    st.markdown('<div class="buffer-box">', unsafe_allow_html=True)
    bcol1, bcol2, bcol3 = st.columns([3, 3, 2])
    with bcol1:
        st.markdown(f"**📥 In-Memory Raw Buffer:** `{buf_status['raw_count']} / {buf_status['threshold']}` logs ({buf_status['percentage']}%)")
        st.progress(buf_status['fraction'])
    with bcol2:
        st.markdown(f"**📋 In-Memory Formatted JSON Buffer:** `{buf_status['formatted_count']} / {buf_status['threshold']}` records")
        st.progress(buf_status['fraction'])
    with bcol3:
        if st.button("⚡ Flush Buffers to Disk Now", use_container_width=True):
            service.flush_now()
            st.success("Buffers converted to .log & .json files!")
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    # Live Stream Controls Bar
    c_ctrl1, c_ctrl2, c_ctrl3 = st.columns([2, 1, 1])
    with c_ctrl1:
        auto_refresh = st.checkbox("🔄 Auto-Refresh Stream (1s)", value=True)
    with c_ctrl2:
        if st.button("Refresh Now", use_container_width=True):
            st.rerun()
    with c_ctrl3:
        if st.button("Clear Live View", use_container_width=True):
            service.live_stream_queue.clear()
            st.rerun()

    # Fetch live records from the in-memory queue
    stream_events = service.get_live_stream()

    if not stream_events:
        st.info("Live stream idle. Click '▶️ Start Live Stream (UDP 5140)' in the sidebar to begin continuous streaming.")
    else:
        st.write(f"**Showing last {len(stream_events)} streaming events:**")
        # Render scrolling list (newest on top)
        for item in reversed(stream_events[-20:]):
            st.markdown('<div class="stream-card">', unsafe_allow_html=True)
            col1, col2, col3 = st.columns([5, 4, 5])

            with col1:
                st.markdown(f"**[RAW LOG INGRESS]** <span style='font-size:11px; color:#94a3b8;'>({item['timestamp']})</span>", unsafe_allow_html=True)
                st.markdown(f'<div class="raw-box">{item["raw_string"]}</div>', unsafe_allow_html=True)

            with col2:
                st.markdown("**[CRYPTOGRAPHIC WIRE FINGERPRINT]**", unsafe_allow_html=True)
                st.markdown(f'<div class="sha-box">SHA-256:<br><b>{item["sha256_key"]}</b></div>', unsafe_allow_html=True)
                disp = item.get("disposition", "Unknown")
                disp_color = "#10b981" if disp.lower() in ["allowed", "accept", "pass"] else "#ef4444"
                st.markdown(f"<span style='font-size:12px;'>Vendor: <b>{item.get('vendor')}</b> | Status: <span style='color:{disp_color}; font-weight:700;'>{disp.upper()}</span></span>", unsafe_allow_html=True)

            with col3:
                st.markdown("**[NORMALIZED OCSF JSON]**", unsafe_allow_html=True)
                preview = {
                    "event_id": item["formatted_json"].get("event_id", "")[:13] + "...",
                    "class_uid": 4001,
                    "disposition": item["formatted_json"].get("disposition", "Unknown"),
                    "src_endpoint": f"{item['formatted_json'].get('src_ip')}:{item['formatted_json'].get('src_port')}",
                    "dst_endpoint": f"{item['formatted_json'].get('dst_ip')}:{item['formatted_json'].get('dst_port')}",
                    "protocol": item["formatted_json"].get("protocol_name", "TCP")
                }
                st.markdown(f'<div class="json-box">{json.dumps(preview, indent=2)}</div>', unsafe_allow_html=True)

            st.markdown('</div>', unsafe_allow_html=True)

    # Auto-refresh loop if enabled
    if auto_refresh and service.is_running:
        time.sleep(1.0)
        st.rerun()


# =============================================================
# PAGE 3: 🗄️ DATABASE & STORAGE VAULT
# =============================================================
elif page_selection == "🗄️ Database Vault":
    st.markdown("### 🗄️ Database & Dual-Storage Vault")
    st.caption("Partitioned files generated upon batch constraint fulfillment (Raw .log vs Formatted .json).")

    # Real-time Buffer Status Card
    buf_status = service.get_buffer_status()
    st.markdown(f"""
    <div class="buffer-box">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <b>Current In-Memory Dual Buffers:</b> <code>{buf_status['raw_count']} / {buf_status['threshold']} logs buffered</code> ({buf_status['percentage']}%)
                <div style="font-size:12px; color:#94a3b8; margin-top:2px;">Dual files (.log and .json) will automatically be created when threshold ({buf_status['threshold']}) is reached.</div>
            </div>
            <div>
                <span style="font-size:12px; color:#34d399; font-weight:600;">Last File Created: {buf_status['time_since_flush']}s ago</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    files_data = service.get_stored_files()
    raw_files = files_data["raw_files"]
    formatted_files = files_data["formatted_files"]

    dcol1, dcol2 = st.columns(2)

    with dcol1:
        st.markdown(f"#### 📄 Raw Log Files (`.log`) — {len(raw_files)} Files")
        if raw_files:
            df_raw = pd.DataFrame(raw_files)
            st.dataframe(df_raw[["filename", "records", "size_kb", "timestamp"]], use_container_width=True, height=260)
        else:
            st.info(f"No raw log files created yet. Batches flush automatically every {service.batch_size_threshold} records.")

    with dcol2:
        st.markdown(f"#### 📋 Formatted JSON Files (`.json`) — {len(formatted_files)} Files")
        if formatted_files:
            df_fmt = pd.DataFrame(formatted_files)
            st.dataframe(df_fmt[["filename", "records", "size_kb", "timestamp"]], use_container_width=True, height=260)
        else:
            st.info("No formatted JSON files created yet.")

    st.markdown("---")
    st.markdown("### 🔍 Dual-File Content Inspector")

    if raw_files and formatted_files:
        sel_idx = st.selectbox("Select Batch to Inspect", options=range(len(raw_files)), format_func=lambda i: raw_files[i]["filename"])
        selected_raw = raw_files[sel_idx]
        selected_fmt = formatted_files[sel_idx] if sel_idx < len(formatted_files) else None

        vcol1, vcol2 = st.columns(2)
        with vcol1:
            st.markdown(f"**Raw Log File Content:** `{selected_raw['filename']}`")
            with open(selected_raw["path"], "r", encoding="utf-8") as f:
                st.code(f.read()[:2000] + ("\n... [Truncated preview]" if selected_raw["records"] > 15 else ""), language="text")

        with vcol2:
            if selected_fmt:
                st.markdown(f"**Formatted JSON Content:** `{selected_fmt['filename']}`")
                with open(selected_fmt["path"], "r", encoding="utf-8") as f:
                    st.code(f.read()[:2000] + ("\n... [Truncated preview]" if selected_fmt["records"] > 5 else ""), language="json")
    else:
        st.info("Generate batches to enable side-by-side inspection.")
