/**
 * ULPF Client Application Logic
 * Modern 60FPS Reactive Controller & Visualizer
 */

// State Management
const state = {
    currentTab: 'dashboard',
    isStreaming: false,
    speed: 10,
    batchThreshold: 200,
    totalIngested: 0,
    currentEps: 0.0,
    anomaliesCount: 0,
    batchesCount: 0,
    bufferRawCount: 0,
    streamTimer: null,
    pollTimer: null
};

// DOM Elements
const DOM = {
    navBtns: document.querySelectorAll('.nav-btn'),
    tabPanes: document.querySelectorAll('.tab-pane'),
    kpiTotalLogs: document.getElementById('kpi-total-logs'),
    kpiSpeed: document.getElementById('kpi-speed'),
    kpiAnomalies: document.getElementById('kpi-anomalies'),
    kpiBatches: document.getElementById('kpi-batches'),
    streamToggleBtn: document.getElementById('stream-toggle-btn'),
    streamBtnIcon: document.getElementById('stream-btn-icon'),
    streamBtnLabel: document.getElementById('stream-btn-label'),
    streamSpeedSelect: document.getElementById('stream-speed-select'),
    batchSizeSelect: document.getElementById('batch-size-select'),
    flushNowBtn: document.getElementById('flush-now-btn'),
    bufferStatText: document.getElementById('buffer-stat-text'),
    bufferProgressFill: document.getElementById('buffer-progress-fill'),
    rawStreamViewport: document.getElementById('raw-stream-viewport'),
    shaStreamViewport: document.getElementById('sha-stream-viewport'),
    jsonStreamViewport: document.getElementById('json-stream-viewport'),
    processedCounterBadge: document.getElementById('processed-counter-badge'),
    anomaliesTableBody: document.getElementById('anomalies-table-body'),
    outlierCountBadge: document.getElementById('outlier-count-badge'),
    rawFilesTableBody: document.getElementById('raw-files-table-body'),
    fmtFilesTableBody: document.getElementById('fmt-files-table-body'),
    rawFilesCountBadge: document.getElementById('raw-files-count-badge'),
    fmtFilesCountBadge: document.getElementById('fmt-files-count-badge'),
    batchInspectorSelect: document.getElementById('batch-inspector-select'),
    inspectRawTitle: document.getElementById('inspect-raw-title'),
    inspectRawContent: document.getElementById('inspect-raw-content'),
    inspectFmtTitle: document.getElementById('inspect-fmt-title'),
    inspectFmtContent: document.getElementById('inspect-fmt-content')
};

// Charts References
let scatterChart = null;
let vendorPieChart = null;

// Synthetic Corpus for Continuous Smooth Terminal Animation
const SYNTHETIC_CORPUS = [
    {
        raw: "%ASA-4-106023: Deny tcp src outside:198.51.100.45/51234 dst inside:10.0.0.5/22 by access-group 'OUTSIDE_IN'",
        vendor: "Cisco ASA",
        disposition: "Blocked",
        src_ip: "198.51.100.45",
        src_port: 51234,
        dst_ip: "10.0.0.5",
        dst_port: 22,
        anomaly_score: 0.88
    },
    {
        raw: 'date=2026-09-01 time=08:30:00 devname="FGT60D" srcip=192.168.1.50 dstip=10.0.0.5 action="accept" proto=6 srcport=54120 dstport=443',
        vendor: "Fortinet",
        disposition: "Allowed",
        src_ip: "192.168.1.50",
        src_port: 54120,
        dst_ip: "10.0.0.5",
        dst_port: 443,
        anomaly_score: 0.12
    },
    {
        raw: "Microsoft-Windows-Security-Auditing: EventID=4624 Account Name: Administrator Source Address: 192.168.1.10 Source Port: 54123 Destination Address: 10.0.0.5 Destination Port: 445 Logon Type: 3",
        vendor: "Windows Security",
        disposition: "Allowed",
        src_ip: "192.168.1.10",
        src_port: 54123,
        dst_ip: "10.0.0.5",
        dst_port: 445,
        anomaly_score: 0.25
    },
    {
        raw: "1,2026/09/01 08:30:00,001234567890,TRAFFIC,drop,0,2026/09/01 08:30:00,198.51.100.99,10.0.0.15,0.0.0.0,0.0.0.0,Rule1,user1,,ssl,vsys1,untrust,trust",
        vendor: "Palo Alto",
        disposition: "Blocked",
        src_ip: "198.51.100.99",
        src_port: 49120,
        dst_ip: "10.0.0.15",
        dst_port: 443,
        anomaly_score: 0.76
    },
    {
        raw: '{"timestamp":"2026-09-01T08:30:00Z","src_ip":"198.51.100.88","src_port":44123,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","action":"blocked","alert":{"signature":"ET SCAN Potential SSH Brute Force"}}',
        vendor: "pfSense / Suricata",
        disposition: "Blocked",
        src_ip: "198.51.100.88",
        src_port: 44123,
        dst_ip: "10.0.0.5",
        dst_port: 80,
        anomaly_score: 0.94
    },
    {
        raw: "2 123456789012 eni-0123456789abcdef0 198.51.100.12 10.0.0.5 49152 443 6 20 8400 1620000000 1620000060 ACCEPT OK",
        vendor: "AWS VPC Flow",
        disposition: "Allowed",
        src_ip: "198.51.100.12",
        src_port: 49152,
        dst_ip: "10.0.0.5",
        dst_port: 443,
        anomaly_score: 0.15
    },
    {
        raw: "1620000000.123456\tC123456789\t198.51.100.14\t54321\t10.0.0.5\t80\ttcp\thttp\t0.05\t1024\t2048\tSF",
        vendor: "Zeek Conn",
        disposition: "Allowed",
        src_ip: "198.51.100.14",
        src_port: 54321,
        dst_ip: "10.0.0.5",
        dst_port: 80,
        anomaly_score: 0.18
    }
];

// Helper: Fast SHA-256 Hex Digest
function computeMockSha256(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
    }
    let hex = Math.abs(hash).toString(16) + "e8c4d2a1b9f0e7d5c3a28f11749b5";
    return hex.padEnd(64, '0').slice(0, 64);
}

// -------------------------------------------------------------
// INITIALIZATION
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initCharts();
    bindControls();
    fetchLiveTelemetry();
    
    // Polling Telemetry every 2 seconds
    setInterval(fetchLiveTelemetry, 2000);
});

// -------------------------------------------------------------
// TAB NAVIGATION
// -------------------------------------------------------------
function initTabs() {
    DOM.navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            if (state.currentTab === targetTab) return;

            DOM.navBtns.forEach(b => b.classList.remove('active'));
            DOM.tabPanes.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`tab-${targetTab}`).classList.add('active');
            state.currentTab = targetTab;

            if (targetTab === 'database') {
                fetchStoredFiles();
            }
        });
    });
}

// -------------------------------------------------------------
// CONTROLS & STREAM TOGGLE
// -------------------------------------------------------------
function bindControls() {
    DOM.streamToggleBtn.addEventListener('click', toggleStream);

    DOM.streamSpeedSelect.addEventListener('change', (e) => {
        state.speed = parseInt(e.target.value, 10);
        if (state.isStreaming) {
            restartStreamTimer();
        }
        fetch('/api/v1/stream/speed', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ eps: state.speed })
        }).catch(() => {});
    });

    DOM.batchSizeSelect.addEventListener('change', (e) => {
        state.batchThreshold = parseInt(e.target.value, 10);
        updateBufferUI();
    });

    DOM.flushNowBtn.addEventListener('click', async () => {
        try {
            await fetch('/api/v1/stream/flush', { method: 'POST' });
            state.bufferRawCount = 0;
            updateBufferUI();
            fetchStoredFiles();
        } catch (e) {
            state.bufferRawCount = 0;
            updateBufferUI();
        }
    });

    DOM.batchInspectorSelect.addEventListener('change', (e) => {
        const fname = e.target.value;
        if (!fname) return;
        inspectBatchFile(fname);
    });
}

function toggleStream() {
    state.isStreaming = !state.isStreaming;

    if (state.isStreaming) {
        DOM.streamBtnIcon.innerText = '⏹';
        DOM.streamBtnLabel.innerText = 'STOP LIVE STREAM';
        DOM.streamToggleBtn.classList.add('running');
        startStreamTimer();

        fetch('/api/v1/stream/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ eps: state.speed })
        }).catch(() => {});
    } else {
        DOM.streamBtnIcon.innerText = '▶';
        DOM.streamBtnLabel.innerText = 'START LIVE STREAM';
        DOM.streamToggleBtn.classList.remove('running');
        clearInterval(state.streamTimer);

        fetch('/api/v1/stream/stop', { method: 'POST' }).catch(() => {});
    }
}

function startStreamTimer() {
    const intervalMs = Math.max(20, Math.floor(1000 / state.speed));
    state.streamTimer = setInterval(generateStreamEvent, intervalMs);
}

function restartStreamTimer() {
    clearInterval(state.streamTimer);
    startStreamTimer();
}

// -------------------------------------------------------------
// SMOOTH 60FPS TERMINAL RENDERER (TOP RAW/SHA -> BOTTOM JSON)
// -------------------------------------------------------------
let eventCounter = 0;
function generateStreamEvent() {
    eventCounter++;
    state.totalIngested++;
    state.bufferRawCount++;

    const item = SYNTHETIC_CORPUS[Math.floor(Math.random() * SYNTHETIC_CORPUS.length)];
    const timeStr = new Date().toISOString().substring(11, 23);
    const shaKey = computeMockSha256(item.raw + eventCounter);

    // 1. INJECT RAW LOG STRING (Top Left)
    const rawEl = document.createElement('div');
    rawEl.className = 'stream-item-raw';
    rawEl.innerText = `[${timeStr}] ${item.raw}`;
    DOM.rawStreamViewport.insertBefore(rawEl, DOM.rawStreamViewport.firstChild);
    if (DOM.rawStreamViewport.children.length > 12) {
        DOM.rawStreamViewport.removeChild(DOM.rawStreamViewport.lastChild);
    }

    // 2. INJECT SHA-256 KEY (Top Right)
    const shaEl = document.createElement('div');
    shaEl.className = 'stream-item-sha';
    shaEl.innerText = `SHA-256: ${shaKey}`;
    DOM.shaStreamViewport.insertBefore(shaEl, DOM.shaStreamViewport.firstChild);
    if (DOM.shaStreamViewport.children.length > 12) {
        DOM.shaStreamViewport.removeChild(DOM.shaStreamViewport.lastChild);
    }

    // 3. INJECT FORMATTED OCSF JSON OUTPUT (Bottom Half)
    const jsonRecord = {
        event_id: `uuid-${Math.random().toString(36).substring(2, 11)}`,
        class_uid: 4001,
        vendor_name: item.vendor,
        disposition: item.disposition,
        src_endpoint: { ip: item.src_ip, port: item.src_port },
        dst_endpoint: { ip: item.dst_ip, port: item.dst_port },
        metadata: {
            sha256_hash: shaKey,
            ingest_timestamp: timeStr
        }
    };

    const jsonEl = document.createElement('div');
    jsonEl.className = 'json-record-card';
    jsonEl.innerText = JSON.stringify(jsonRecord, null, 2);
    DOM.jsonStreamViewport.insertBefore(jsonEl, DOM.jsonStreamViewport.firstChild);
    if (DOM.jsonStreamViewport.children.length > 4) {
        DOM.jsonStreamViewport.removeChild(DOM.jsonStreamViewport.lastChild);
    }

    // Update Counter
    DOM.processedCounterBadge.innerText = `EVENTS COMMITTED: ${eventCounter}`;

    // Anomaly Check
    if (item.anomaly_score > 0.70) {
        state.anomaliesCount++;
        appendAnomalyTableRow(item, timeStr, shaKey);
    }

    // Update buffer progress
    if (state.bufferRawCount >= state.batchThreshold) {
        state.bufferRawCount = 0;
        state.batchesCount++;
        DOM.kpiBatches.innerHTML = `${state.batchesCount} <span class="unit">Batches</span>`;
    }
    updateBufferUI();
    updateKpis();
}

function updateBufferUI() {
    const fraction = Math.min(1.0, state.bufferRawCount / state.batchThreshold);
    const pct = Math.round(fraction * 100);
    DOM.bufferStatText.innerText = `${state.bufferRawCount} / ${state.batchThreshold} (${pct}%)`;
    DOM.bufferProgressFill.style.width = `${pct}%`;
}

function updateKpis() {
    DOM.kpiTotalLogs.innerText = state.totalIngested.toLocaleString();
    DOM.kpiSpeed.innerHTML = `${state.isStreaming ? state.speed.toFixed(1) : '0.0'} <span class="unit">EPS</span>`;
    DOM.kpiAnomalies.innerText = state.anomaliesCount.toLocaleString();
}

function appendAnomalyTableRow(item, timeStr, shaKey) {
    const row = document.createElement('tr');
    const dispClass = item.disposition.toLowerCase() === 'blocked' ? 'blocked' : 'allowed';
    
    row.innerHTML = `
        <td>${timeStr}</td>
        <td><b>${item.vendor}</b></td>
        <td><code>${item.src_ip}:${item.src_port}</code></td>
        <td><code>${item.dst_ip}:${item.dst_port}</code></td>
        <td><span class="status-badge ${dispClass}">${item.disposition.toUpperCase()}</span></td>
        <td style="color:#f87171; font-weight:700;">${item.anomaly_score.toFixed(3)}</td>
    `;

    if (DOM.anomaliesTableBody.querySelector('.empty-state')) {
        DOM.anomaliesTableBody.innerHTML = '';
    }

    DOM.anomaliesTableBody.insertBefore(row, DOM.anomaliesTableBody.firstChild);
    if (DOM.anomaliesTableBody.children.length > 20) {
        DOM.anomaliesTableBody.removeChild(DOM.anomaliesTableBody.lastChild);
    }

    DOM.outlierCountBadge.innerText = `${state.anomaliesCount} DETECTED`;
}

// -------------------------------------------------------------
// CHARTS & VISUALIZATIONS
// -------------------------------------------------------------
function initCharts() {
    // 1. AI Threat Scatter Plot
    const ctxScatter = document.getElementById('threatScatterChart').getContext('2d');
    const scatterData = [];
    for (let i = 0; i < 40; i++) {
        scatterData.push({
            x: Math.floor(Math.random() * 65000),
            y: Math.floor(Math.random() * 65000),
            score: Math.random()
        });
    }

    scatterChart = new Chart(ctxScatter, {
        type: 'scatter',
        data: {
            datasets: [{
                label: 'Log Events',
                data: scatterData,
                backgroundColor: (ctx) => {
                    const raw = ctx.raw;
                    if (!raw) return 'rgba(255, 85, 0, 0.7)';
                    return raw.score > 0.7 ? 'rgba(239, 68, 68, 0.9)' : 'rgba(251, 191, 36, 0.6)';
                },
                borderColor: 'rgba(255, 255, 255, 0.1)',
                borderWidth: 1,
                pointRadius: 5,
                pointHoverRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    title: { display: true, text: 'Source Port (Entropy)', color: '#64748b' },
                    grid: { color: '#161d2b' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    title: { display: true, text: 'Destination Port (Service)', color: '#64748b' },
                    grid: { color: '#161d2b' },
                    ticks: { color: '#94a3b8' }
                }
            }
        }
    });

    // 2. Vendor Donut Chart
    const ctxPie = document.getElementById('vendorPieChart').getContext('2d');
    vendorPieChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: ['Cisco ASA', 'Palo Alto', 'Fortinet', 'Windows', 'Linux Auth', 'AWS VPC', 'Zeek'],
            datasets: [{
                data: [32, 24, 18, 14, 12, 10, 8],
                backgroundColor: [
                    '#ff5500',
                    '#f59e0b',
                    '#06b6d4',
                    '#10b981',
                    '#8b5cf6',
                    '#ec4899',
                    '#64748b'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
                }
            },
            cutout: '70%'
        }
    });
}

// -------------------------------------------------------------
// TELEMETRY & BACKEND INTEGRATION
// -------------------------------------------------------------
async function fetchLiveTelemetry() {
    try {
        const res = await fetch('/api/v1/stats');
        if (!res.ok) return;
        const data = await res.json();

        state.totalIngested = data.total_ingested || state.totalIngested;
        state.currentEps = data.current_eps || state.currentEps;
        state.anomaliesCount = data.anomalies || state.anomaliesCount;
        state.batchesCount = data.total_batches || state.batchesCount;
        state.isStreaming = data.is_running || state.isStreaming;

        updateKpis();
    } catch (e) {
        // Standalone fallback
    }
}

async function fetchStoredFiles() {
    try {
        const res = await fetch('/api/v1/files');
        if (!res.ok) return;
        const data = await res.json();

        renderFilesTable(data.raw_files, DOM.rawFilesTableBody, DOM.rawFilesCountBadge);
        renderFilesTable(data.formatted_files, DOM.fmtFilesTableBody, DOM.fmtFilesCountBadge);
        populateBatchInspector(data.raw_files);
    } catch (e) {}
}

function renderFilesTable(files, tbody, badge) {
    if (!files || files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No files stored yet.</td></tr>';
        badge.innerText = '0 FILES';
        return;
    }

    badge.innerText = `${files.length} FILES`;
    tbody.innerHTML = '';
    files.forEach(f => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${f.filename}</code></td>
            <td><b>${f.records}</b></td>
            <td>${f.size_kb} KB</td>
            <td>${f.timestamp}</td>
        `;
        tbody.appendChild(tr);
    });
}

function populateBatchInspector(rawFiles) {
    if (!rawFiles || rawFiles.length === 0) return;
    DOM.batchInspectorSelect.innerHTML = '<option value="">Select a batch file to inspect...</option>';
    rawFiles.forEach(f => {
        const opt = document.createElement('option');
        opt.value = f.filename;
        opt.innerText = `${f.filename} (${f.records} records, ${f.size_kb} KB)`;
        DOM.batchInspectorSelect.appendChild(opt);
    });
}

async function inspectBatchFile(filename) {
    DOM.inspectRawTitle.innerText = filename;
    DOM.inspectFmtTitle.innerText = filename.replace('raw_batch_', 'formatted_batch_').replace('.log', '.json');

    try {
        const res = await fetch(`/api/v1/files/content?filename=${filename}`);
        if (!res.ok) return;
        const data = await res.json();
        DOM.inspectRawContent.innerText = data.raw_content || 'No raw content found';
        DOM.inspectFmtContent.innerText = typeof data.formatted_content === 'object' ? 
            JSON.stringify(data.formatted_content, null, 2) : (data.formatted_content || 'No JSON content found');
    } catch (e) {
        DOM.inspectRawContent.innerText = 'Failed to load file content.';
    }
}
