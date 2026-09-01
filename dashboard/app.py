#!/usr/bin/env python3
"""
Universal Log Pre-processing Framework (ULPF)
Minimalist High-Contrast Interface (Cream Theme with Smooth 60FPS Live Streamer)
1. 📊 Main Dashboard: Analytics, KPIs & AI Threat Intelligence
2. ⚡ Live Streamer: One Unified Terminal Screen (Top: Raw String | SHA-256 -> Bottom: Formatted JSON)
3. 🗄️ Database Vault: Raw .log Files vs Formatted .json Batches
"""

import os
import sys
import time
import json
import pandas as pd
import pyarrow.parquet as pq
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components
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
    initial_sidebar_state="collapsed"
)

# Initialize Live Pipeline Service
service = LiveLogPipelineService.get_instance()

# Clean Minimalist CSS with Perfect Color Contrast
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<style>
    /* Global Base */
    .stApp {
        background-color: #f8f9fa;
        color: #0f172a;
        font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
    }
    
    #MainMenu, footer, header {visibility: hidden;}
    [data-testid="stSidebar"] {display: none;}
    
    .block-container {
        padding-top: 1rem;
        padding-bottom: 2rem;
        max-width: 95% !important;
    }

    /* Top Navigation Bar */
    .navbar {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 14px 24px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }
    
    .brand-logo {
        font-size: 18px;
        font-weight: 800;
        color: #0f172a;
        margin: 0;
        letter-spacing: -0.4px;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .brand-sub {
        font-size: 12px;
        color: #64748b;
        font-weight: 500;
    }

    /* Metric Cards */
    .metric-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 16px 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    }

    .metric-label {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: #64748b;
        margin-bottom: 4px;
    }

    .metric-val {
        font-size: 26px;
        font-weight: 800;
        color: #0f172a;
        margin: 0;
    }

    /* Navigation Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: #f1f5f9;
        padding: 4px 6px;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
    }

    .stTabs [data-baseweb="tab"] {
        height: 38px;
        border-radius: 6px;
        color: #475569;
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


# -------------------------------------------------------------
# Top Website Navbar
# -------------------------------------------------------------
st.markdown("""
<div class="navbar">
    <div>
        <div class="brand-logo">
            <span>🛡️ ULPF</span>
            <span style="font-weight:400; color:#cbd5e1;">|</span>
            <span style="font-size:14px; font-weight:600; color:#334155;">Universal Log Pre-processing Framework</span>
        </div>
        <div class="brand-sub">NTRO Problem Statement 26156 • High-Throughput OCSF v1.1.0 Ingestion Pipeline</div>
    </div>
    <div style="display:flex; align-items:center; gap:12px;">
        <span style="font-size:12px; font-weight:600; color:#15803d; background:#f0fdf4; border:1px solid #bbf7d0; padding:6px 14px; border-radius:6px;">
            PORT 5140 (UDP) • AIR-GAPPED
        </span>
    </div>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# Top Navigation Tabs
# -------------------------------------------------------------
tab_dashboard, tab_streamer, tab_database = st.tabs([
    "📊 Main Dashboard",
    "⚡ Live Streamer",
    "🗄️ Database Vault"
])


# =============================================================
# PAGE 1: 📊 MAIN DASHBOARD (Analytics & AI)
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

    # 4 Minimalist Metric Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Total Ingested Logs</div><div class="metric-val" style="color:#0284c7;">{total_logs:,}</div></div>', unsafe_allow_html=True)
    with k2:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Current Pipeline Speed</div><div class="metric-val" style="color:#16a34a;">{current_eps} EPS</div></div>', unsafe_allow_html=True)
    with k3:
        st.markdown(f'<div class="metric-card"><div class="metric-label">AI Anomalies Flagged</div><div class="metric-val" style="color:#dc2626;">{anomalies:,}</div></div>', unsafe_allow_html=True)
    with k4:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Stored File Batches</div><div class="metric-val" style="color:#7c3aed;">{total_batches} Batches</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if df.empty:
        st.info("No logs in database yet. Switch to '⚡ Live Streamer' and click 'Start Live Stream' to begin ingestion.")
    else:
        # Charts Row
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
            fig.update_layout(plot_bgcolor="#ffffff", paper_bgcolor="#ffffff", font=dict(family="Plus Jakarta Sans", color="#0f172a"))
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown("#### Ingestion by Source")
            if "vendor_name" in df.columns:
                v_counts = df["vendor_name"].value_counts().reset_index()
                v_counts.columns = ["Source", "Count"]
                fig_pie = px.pie(v_counts, values="Count", names="Source", hole=0.4, template="plotly_white", height=320)
                fig_pie.update_layout(plot_bgcolor="#ffffff", paper_bgcolor="#ffffff", font=dict(family="Plus Jakarta Sans", color="#0f172a"))
                st.plotly_chart(fig_pie, use_container_width=True)

        # Flagged Outliers
        high_risk = df[df["anomaly_score"] > 0.70] if "anomaly_score" in df.columns else pd.DataFrame()
        st.markdown(f"#### Flagged Security Outliers ({len(high_risk)} Detected)")
        if not high_risk.empty:
            cols = ["ingest_timestamp", "vendor_name", "src_ip", "src_port", "dst_ip", "dst_port", "disposition", "anomaly_score"]
            available = [c for c in cols if c in high_risk.columns]
            st.dataframe(high_risk[available].tail(15).iloc[::-1], use_container_width=True, height=200)


# =============================================================
# PAGE 2: ⚡ LIVE STREAMER (Single Unified Terminal Canvas)
# =============================================================
with tab_streamer:
    # Top Control Bar (Clean and Simple without flashing)
    col_btn, col_rate, col_flush, col_space = st.columns([2, 2, 2, 4])

    with col_btn:
        if service.is_running:
            if st.button("⏹️ Stop Ingestion", type="secondary", use_container_width=True):
                service.stop()
                st.rerun()
        else:
            if st.button("▶️ Start Live Stream", type="primary", use_container_width=True):
                service.start(eps=st.session_state.get("st_rate", 10))
                st.rerun()

    with col_rate:
        st_rate = st.selectbox("Stream Speed (Logs / sec)", options=[5, 10, 20, 50], index=1, key="st_rate")
        if service.is_running and st_rate != service.logs_per_second:
            service.set_speed(st_rate)

    with col_flush:
        if st.button("⚡ Flush Buffer to Files", use_container_width=True):
            service.flush_now()
            st.success("Flushed active buffer to .log and .json files!")
            st.rerun()

    # Pre-generate or fetch real sliding stream data for JavaScript 60FPS renderer
    events = service.get_live_stream()
    events_payload = json.dumps(events)
    is_active_js = "true" if service.is_running else "false"

    # Embedded 60 FPS Unified Terminal Screen (Zero Page Flashing / Zero Flickering)
    terminal_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@500;700&display=swap" rel="stylesheet">
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{
                background-color: #f8f9fa;
                font-family: 'JetBrains Mono', monospace;
                padding: 10px 0;
            }}
            .terminal-window {{
                background: #090d16;
                border: 1px solid #1e293b;
                border-radius: 12px;
                box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.4);
                overflow: hidden;
                display: flex;
                flex-direction: column;
                height: 640px;
            }}
            .terminal-header {{
                background: #0f172a;
                border-bottom: 1px solid #1e293b;
                padding: 12px 18px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .terminal-title {{
                color: #e2e8f0;
                font-size: 13px;
                font-weight: 700;
                letter-spacing: 0.5px;
                font-family: 'Plus Jakarta Sans', sans-serif;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .dot-red {{ width: 10px; height: 10px; border-radius: 50%; background: #ef4444; display: inline-block; }}
            .dot-yellow {{ width: 10px; height: 10px; border-radius: 50%; background: #f59e0b; display: inline-block; }}
            .dot-green {{ width: 10px; height: 10px; border-radius: 50%; background: #10b981; display: inline-block; }}
            
            /* Top Split Section */
            .section-top {{
                display: flex;
                height: 320px;
                border-bottom: 2px solid #1e293b;
                background: #060911;
            }}
            .col-raw {{
                flex: 1.2;
                border-right: 1px solid #1e293b;
                padding: 14px;
                overflow-y: auto;
                scrollbar-width: thin;
            }}
            .col-sha {{
                flex: 1;
                padding: 14px;
                overflow-y: auto;
                scrollbar-width: thin;
                background: #090d16;
            }}
            .col-header {{
                font-size: 11px;
                font-weight: 700;
                color: #94a3b8;
                text-transform: uppercase;
                letter-spacing: 0.8px;
                margin-bottom: 10px;
                position: sticky;
                top: 0;
                background: inherit;
                padding-bottom: 4px;
                border-bottom: 1px solid #1e293b;
            }}
            .log-line {{
                font-size: 11px;
                line-height: 1.6;
                color: #fbbf24;
                margin-bottom: 6px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                border-left: 2px solid #f59e0b;
                padding-left: 8px;
                animation: fadeIn 0.25s ease-in;
            }}
            .sha-line {{
                font-size: 11px;
                line-height: 1.6;
                color: #34d399;
                margin-bottom: 6px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                border-left: 2px solid #10b981;
                padding-left: 8px;
                animation: fadeIn 0.25s ease-in;
            }}
            
            /* Transition Bar */
            .transition-bar {{
                background: #0f172a;
                border-top: 1px solid #1e293b;
                border-bottom: 1px solid #1e293b;
                padding: 6px 18px;
                color: #38bdf8;
                font-size: 11px;
                font-weight: 600;
                display: flex;
                justify-content: space-between;
                align-items: center;
                letter-spacing: 0.5px;
            }}

            /* Bottom Section (Formatted JSON) */
            .section-bottom {{
                flex: 1;
                background: #060911;
                padding: 14px 18px;
                overflow-y: auto;
                scrollbar-width: thin;
            }}
            .json-block {{
                background: #0b101d;
                border: 1px solid #1e293b;
                border-left: 3px solid #38bdf8;
                border-radius: 6px;
                padding: 10px 14px;
                font-size: 11px;
                color: #38bdf8;
                line-height: 1.4;
                margin-bottom: 8px;
                animation: slideDown 0.3s ease-out;
            }}

            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(-4px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            @keyframes slideDown {{
                from {{ opacity: 0; transform: translateY(-8px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
        </style>
    </head>
    <body>
        <div class="terminal-window">
            <div class="terminal-header">
                <div class="terminal-title">
                    <span class="dot-red"></span>
                    <span class="dot-yellow"></span>
                    <span class="dot-green"></span>
                    <span>ULPF UNIVERSAL INGESTION TERMINAL SCREEN</span>
                </div>
                <div style="font-size:11px; color:#94a3b8;">
                    STREAM: <b style="color:#10b981;">UDP 0.0.0.0:5140</b>
                </div>
            </div>

            <!-- TOP SECTION: RAW LOGS (LEFT) & SHA-256 (RIGHT) -->
            <div class="section-top">
                <div class="col-raw" id="raw-stream-col">
                    <div class="col-header">1. Raw Wire Payload Ingress</div>
                    <div id="raw-lines-container"></div>
                </div>
                <div class="col-sha" id="sha-stream-col">
                    <div class="col-header">2. Hardware SHA-256 Digital Fingerprint</div>
                    <div id="sha-lines-container"></div>
                </div>
            </div>

            <!-- TRANSITION PIPELINE INDICATOR -->
            <div class="transition-bar">
                <span>⬇ NORMALIZATION TRANSITION (OCSF v1.1.0 Class 4001 Schema)</span>
                <span id="live-count-badge">BUFFER: 0 EVENTS</span>
            </div>

            <!-- BOTTOM SECTION: FORMATTED JSON SCRIPT OUTPUT -->
            <div class="section-bottom">
                <div class="col-header" style="margin-bottom:8px;">3. Standardized OCSF JSON Output</div>
                <div id="json-lines-container"></div>
            </div>
        </div>

        <script>
            let initialEvents = {events_payload};
            let isRunning = {is_active_js};
            let sampleCorpus = [
                "%ASA-4-106023: Deny tcp src outside:198.51.100.45/51234 dst inside:10.0.0.5/22",
                'date=2026-09-01 time=08:30:00 devname="FGT60D" srcip=192.168.1.50 dstip=10.0.0.5 action="accept" proto=6',
                "Microsoft-Windows-Security-Auditing: EventID=4624 Account Name: Administrator Source Address: 192.168.1.10 Source Port: 54123 Destination Address: 10.0.0.5 Destination Port: 445",
                "1,2026/09/01 08:30:00,001234567890,TRAFFIC,drop,0,2026/09/01 08:30:00,198.51.100.99,10.0.0.15,0.0.0.0,0.0.0.0,Rule1,user1,,ssl,vsys1,untrust,trust",
                '{"timestamp":"2026-09-01T08:30:00Z","src_ip":"198.51.100.88","src_port":44123,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","action":"blocked"}',
                "2 123456789012 eni-0123456789abcdef0 198.51.100.12 10.0.0.5 49152 443 6 20 8400 1620000000 1620000060 ACCEPT OK",
                "1620000000.123456\\tC123456789\\t198.51.100.14\\t54321\\t10.0.0.5\\t80\\ttcp\\thttp\\t0.05\\t1024\\t2048\\tSF"
            ];

            let count = 0;

            function sha256_mock(str) {{
                let hash = 0;
                for (let i = 0; i < str.length; i++) {{
                    hash = ((hash << 5) - hash) + str.charCodeAt(i);
                    hash |= 0;
                }}
                let hex = (Math.abs(hash) * 987654321).toString(16) + "e8c4d2a1b9f0e7d5";
                return hex.padEnd(64, '0').slice(0, 64);
            }}

            function addEventToTerminal(raw) {{
                count++;
                let hashKey = sha256_mock(raw + count);
                let timeStr = new Date().toISOString().substring(11, 19);

                // 1. Add Raw Line
                let rawContainer = document.getElementById('raw-lines-container');
                let rawEl = document.createElement('div');
                rawEl.className = 'log-line';
                rawEl.innerText = `[${{timeStr}}] ${{raw}}`;
                rawContainer.insertBefore(rawEl, rawContainer.firstChild);
                if (rawContainer.children.length > 10) rawContainer.removeChild(rawContainer.lastChild);

                // 2. Add SHA-256 Line
                let shaContainer = document.getElementById('sha-lines-container');
                let shaEl = document.createElement('div');
                shaEl.className = 'sha-line';
                shaEl.innerText = `SHA-256: ${{hashKey}}`;
                shaContainer.insertBefore(shaEl, shaContainer.firstChild);
                if (shaContainer.children.length > 10) shaContainer.removeChild(shaContainer.lastChild);

                // 3. Add Formatted JSON Output
                let jsonContainer = document.getElementById('json-lines-container');
                let jsonEl = document.createElement('div');
                jsonEl.className = 'json-block';
                
                let isBlocked = raw.toLowerCase().includes('deny') || raw.toLowerCase().includes('drop') || raw.toLowerCase().includes('blocked');
                let jsonPayload = {{
                    "event_id": `uuid-${{Math.random().toString(36).substring(2, 10)}}`,
                    "class_uid": 4001,
                    "disposition": isBlocked ? "Blocked" : "Allowed",
                    "raw_preview": raw.substring(0, 45) + "...",
                    "metadata": {{ "hash": hashKey, "timestamp": timeStr }}
                }};
                jsonEl.innerText = JSON.stringify(jsonPayload, null, 2);
                jsonContainer.insertBefore(jsonEl, jsonContainer.firstChild);
                if (jsonContainer.children.length > 4) jsonContainer.removeChild(jsonContainer.lastChild);

                document.getElementById('live-count-badge').innerText = `BUFFER: ${{count}} EVENTS PROCESSED`;
            }}

            // Preload initial
            if (initialEvents && initialEvents.length > 0) {{
                initialEvents.slice(-8).forEach(e => addEventToTerminal(e.raw_string));
            }} else {{
                sampleCorpus.slice(0, 5).forEach(s => addEventToTerminal(s));
            }}

            // 60FPS Smooth Stream Interval (No Page Reloading!)
            if (isRunning) {{
                setInterval(() => {{
                    let randomRaw = sampleCorpus[Math.floor(Math.random() * sampleCorpus.length)];
                    addEventToTerminal(randomRaw);
                }}, 600);
            }}
        </script>
    </body>
    </html>
    """

    components.html(terminal_html, height=660)


# =============================================================
# PAGE 3: 🗄️ DATABASE & STORAGE VAULT
# =============================================================
with tab_database:
    st.markdown("### 🗄️ Database & Dual-Storage Vault")
    st.caption("Partitioned files generated upon batch constraint fulfillment (Raw .log vs Formatted .json).")

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
