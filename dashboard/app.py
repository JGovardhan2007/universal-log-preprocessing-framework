#!/usr/bin/env python3
"""
Universal Log Pre-processing Framework (ULPF)
Minimalist Professional Interface (Cream-White Theme)
1. 📊 Dashboard: Analytics, KPIs & AI Threat Detection
2. ⚡ Live Streamer: Section 1 (Raw String | SHA-256 Key) ➔ Section 2 (Formatted JSON)
3. 🗄️ Database: Raw .log Files vs Formatted .json Batches
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

# Streamlit Page Setup
st.set_page_config(
    page_title="ULPF | Universal Log Pre-processing Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Clean Minimalist Cream-White Theme CSS
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<style>
    /* Global Base */
    .stApp {
        background-color: #fbfbfa;
        color: #1c1917;
        font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
    }
    
    #MainMenu, footer, header {visibility: hidden;}
    [data-testid="stSidebar"] {display: none;}
    
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2.5rem;
        max-width: 95% !important;
    }

    /* Top Navigation Header */
    .top-navbar {
        background: #ffffff;
        border: 1px solid #e7e5e4;
        border-radius: 12px;
        padding: 16px 24px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
    }
    
    .brand-title {
        font-size: 20px;
        font-weight: 700;
        color: #0f172a;
        margin: 0;
        letter-spacing: -0.3px;
    }

    .brand-subtitle {
        font-size: 12px;
        color: #78716c;
        margin-top: 2px;
    }

    /* Metric Cards */
    .metric-card {
        background: #ffffff;
        border: 1px solid #e7e5e4;
        border-radius: 10px;
        padding: 18px 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    }

    .metric-label {
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: #78716c;
        margin-bottom: 4px;
    }

    .metric-val {
        font-size: 26px;
        font-weight: 800;
        color: #0f172a;
        margin: 0;
    }

    /* Live Stream Dual Section Cards */
    .stream-box {
        background: #ffffff;
        border: 1px solid #e7e5e4;
        border-radius: 10px;
        padding: 16px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
        height: 100%;
    }

    .stream-box-title {
        font-size: 13px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #44403c;
        margin-bottom: 12px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #f5f5f4;
        padding-bottom: 8px;
    }

    /* Scrollable items */
    .raw-item {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-left: 3px solid #f59e0b;
        border-radius: 6px;
        padding: 8px 12px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #b45309;
        margin-bottom: 8px;
        word-break: break-all;
        line-height: 1.4;
    }

    .sha-item {
        background: #f0fdf4;
        border: 1px solid #dcfce7;
        border-left: 3px solid #16a34a;
        border-radius: 6px;
        padding: 8px 12px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #15803d;
        margin-bottom: 8px;
        word-break: break-all;
        line-height: 1.4;
    }

    .json-container {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-left: 4px solid #0284c7;
        border-radius: 8px;
        padding: 14px 18px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #0369a1;
        margin-bottom: 10px;
    }

    /* Transition Banner */
    .transition-divider {
        background: #ffffff;
        border: 1px dashed #cbd5e1;
        border-radius: 8px;
        padding: 8px;
        text-align: center;
        margin: 16px 0;
        font-size: 12px;
        font-weight: 600;
        color: #64748b;
    }

    /* Streamlit Tab Buttons */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: #f5f5f4;
        padding: 4px 6px;
        border-radius: 8px;
        border: 1px solid #e7e5e4;
    }

    .stTabs [data-baseweb="tab"] {
        height: 38px;
        border-radius: 6px;
        color: #57534e;
        font-weight: 600;
        font-size: 13px;
        padding: 0 20px;
    }

    .stTabs [aria-selected="true"] {
        background: #ffffff !important;
        color: #0f172a !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08) !important;
    }
</style>
""", unsafe_allow_html=True)

# Service Singleton
service = LiveLogPipelineService.get_instance()

# -------------------------------------------------------------
# Top Navigation & Brand Header
# -------------------------------------------------------------
st.markdown("""
<div class="top-navbar">
    <div>
        <h1 class="brand-title">Universal Log Pre-processing Framework (ULPF)</h1>
        <div class="brand-subtitle">NTRO Problem Statement 26156 • High-Throughput Live Ingestion & Normalization Engine</div>
    </div>
    <div style="font-size:12px; font-weight:600; color:#15803d; background:#f0fdf4; border:1px solid #bbf7d0; padding:6px 14px; border-radius:6px;">
        STATUS: OPERATIONAL (UDP 5140)
    </div>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# Main Top Tab Switcher
# -------------------------------------------------------------
tab_dashboard, tab_streamer, tab_database = st.tabs([
    "📊 Main Dashboard",
    "⚡ Live Streamer",
    "🗄️ Database Vault"
])


# =============================================================
# PAGE 1: 📊 MAIN DASHBOARD
# =============================================================
with tab_dashboard:
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

    total_logs = len(df) if not df.empty else service.stats["total_formatted"]
    current_eps = service.stats["current_eps"]
    anomalies = len(df[df["is_anomaly"] == True]) if not df.empty and "is_anomaly" in df.columns else 0
    file_info = service.get_stored_files()
    total_batches = len(file_info["raw_files"])

    # 4 Minimalist KPI Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Total Ingested Logs</div><div class="metric-val" style="color:#0284c7;">{total_logs:,}</div></div>', unsafe_allow_html=True)
    with k2:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Current Speed</div><div class="metric-val" style="color:#16a34a;">{current_eps} EPS</div></div>', unsafe_allow_html=True)
    with k3:
        st.markdown(f'<div class="metric-card"><div class="metric-label">AI Anomalies Detected</div><div class="metric-val" style="color:#dc2626;">{anomalies:,}</div></div>', unsafe_allow_html=True)
    with k4:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Stored Batches</div><div class="metric-val" style="color:#7c3aed;">{total_batches} Files</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if df.empty:
        st.info("No records in buffer. Switch to '⚡ Live Streamer' and click 'Start Ingestion' to begin generating stream.")
    else:
        # Charts Row (Light theme)
        c1, c2 = st.columns([2, 1])
        with c1:
            st.markdown("#### AI Threat Anomaly Scatter Plot")
            fig = px.scatter(
                df,
                x="src_port",
                y="dst_port",
                color="anomaly_score",
                size="anomaly_score",
                hover_data=["src_ip", "dst_ip", "vendor_name", "disposition"],
                color_continuous_scale="Reds",
                template="plotly_white",
                height=320
            )
            fig.update_layout(plot_bgcolor="#ffffff", paper_bgcolor="#ffffff", font=dict(family="Plus Jakarta Sans", color="#1c1917"))
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown("#### Ingestion by Log Source")
            if "vendor_name" in df.columns:
                v_counts = df["vendor_name"].value_counts().reset_index()
                v_counts.columns = ["Source", "Count"]
                fig_pie = px.pie(v_counts, values="Count", names="Source", hole=0.4, template="plotly_white", height=320)
                fig_pie.update_layout(plot_bgcolor="#ffffff", paper_bgcolor="#ffffff", font=dict(family="Plus Jakarta Sans", color="#1c1917"))
                st.plotly_chart(fig_pie, use_container_width=True)

        # Flagged Threats
        high_risk = df[df["anomaly_score"] > 0.70] if "anomaly_score" in df.columns else pd.DataFrame()
        st.markdown(f"#### Flagged Security Outliers ({len(high_risk)} Detected)")
        if not high_risk.empty:
            cols = ["ingest_timestamp", "vendor_name", "src_ip", "src_port", "dst_ip", "dst_port", "disposition", "anomaly_score"]
            available = [c for c in cols if c in high_risk.columns]
            st.dataframe(high_risk[available].tail(15).iloc[::-1], use_container_width=True, height=200)


# =============================================================
# PAGE 2: ⚡ LIVE STREAMER (Dual-Section Pipeline Layout)
# =============================================================
with tab_streamer:
    # Top Control Bar (Clean & Simple)
    ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns([2, 2, 2, 2])

    with ctrl_col1:
        if service.is_running:
            if st.button("⏹️ Stop Stream", type="secondary", use_container_width=True):
                service.stop()
                st.rerun()
        else:
            if st.button("▶️ Start Live Stream", type="primary", use_container_width=True):
                service.start(eps=st.session_state.get("stream_rate", 10))
                st.rerun()

    with ctrl_col2:
        stream_rate = st.selectbox("Stream Speed", options=[5, 10, 25, 50], index=1, key="stream_rate")
        if service.is_running and stream_rate != service.logs_per_second:
            service.set_speed(stream_rate)

    with ctrl_col3:
        auto_scroll = st.checkbox("Live Auto-Scroll (1s)", value=True)

    with ctrl_col4:
        if st.button("⚡ Flush to Files Now", use_container_width=True):
            service.flush_now()
            st.success("Buffer flushed to .log and .json files!")
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Get Live Events Sliding Window (last 15 records)
    stream_events = service.get_live_stream()

    if not stream_events:
        st.info("Live stream idle. Click '▶️ Start Live Stream' to watch raw strings convert into SHA-256 and formatted JSON.")
    else:
        # -------------------------------------------------------------
        # SECTION 1: Top 2 Parallel Columns (Raw String vs SHA-256 Key)
        # -------------------------------------------------------------
        col_raw_sec, col_sha_sec = st.columns(2)

        # Show latest 10 events
        visible_top_events = stream_events[-10:]

        with col_raw_sec:
            st.markdown("""
            <div class="stream-box">
                <div class="stream-box-title">
                    <span>1. RAW LOG INGRESS (PORT 5140)</span>
                    <span style="font-size:11px; color:#78716c;">Top-to-Bottom Scroll</span>
                </div>
            """, unsafe_allow_html=True)
            for item in visible_top_events:
                st.markdown(f'<div class="raw-item">[{item["timestamp"]}] {item["raw_string"]}</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_sha_sec:
            st.markdown("""
            <div class="stream-box">
                <div class="stream-box-title">
                    <span>2. HARDWARE SHA-256 WIRE KEY</span>
                    <span style="font-size:11px; color:#15803d;">Cryptographic Binding</span>
                </div>
            """, unsafe_allow_html=True)
            for item in visible_top_events:
                st.markdown(f'<div class="sha-item">SHA-256: <b>{item["sha256_key"]}</b></div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # -------------------------------------------------------------
        # TRANSITION DIVIDER: As items scroll down into Section 2
        # -------------------------------------------------------------
        st.markdown("""
        <div class="transition-divider">
            ⬇ <b>NORMALIZATION PIPELINE TRANSITION LAYER</b> — Incoming logs formatted into OCSF JSON Schema ⬇
        </div>
        """, unsafe_allow_html=True)

        # -------------------------------------------------------------
        # SECTION 2: Bottom Full-Width Big Container (Formatted JSON)
        # -------------------------------------------------------------
        st.markdown("""
        <div class="stream-box">
            <div class="stream-box-title">
                <span>3. FORMATTED OCSF JSON SCRIPT OUTPUT (CLASS 4001)</span>
                <span style="font-size:11px; color:#0369a1;">Standardized Analytics Ready</span>
            </div>
        """, unsafe_allow_html=True)

        # Display the formatted JSON scripts for the events flowing down
        for item in reversed(stream_events[-3:]):
            json_preview = {
                "event_id": item["formatted_json"].get("event_id"),
                "class_uid": 4001,
                "disposition": item["formatted_json"].get("disposition", "Unknown"),
                "src_endpoint": {
                    "ip": item["formatted_json"].get("src_ip"),
                    "port": item["formatted_json"].get("src_port"),
                    "country": item["formatted_json"].get("src_country", "Local")
                },
                "dst_endpoint": {
                    "ip": item["formatted_json"].get("dst_ip"),
                    "port": item["formatted_json"].get("dst_port"),
                    "country": item["formatted_json"].get("dst_country", "Local")
                },
                "metadata": {
                    "hash": item["sha256_key"],
                    "ingest_timestamp": item["formatted_json"].get("ingest_timestamp")
                }
            }
            st.markdown(f'<div class="json-container">{json.dumps(json_preview, indent=2)}</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

    # Live auto-scroll timer
    if auto_scroll and service.is_running:
        time.sleep(1.0)
        st.rerun()


# =============================================================
# PAGE 3: 🗄️ DATABASE & STORAGE VAULT
# =============================================================
with tab_database:
    st.markdown("### 🗄️ Database & Dual-File Storage Vault")
    st.caption("Raw `.log` files and formatted `.json` files automatically created upon batch threshold completion.")

    # Storage info
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
        sel_idx = st.selectbox("Select Batch File to Inspect", options=range(len(raw_files)), format_func=lambda i: raw_files[i]["filename"])
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
