/**
 * ULPF Client Application Logic
 * Shadcn Dark Zinc High-Performance Controller
 * Robustness: Bounded Virtual DOM, Resilient Auto-Reconnect Heartbeat, Telemetry & CSV Export
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
    activeFilter: 'all',
    searchQuery: '',
    allTelemetryRecords: [],
    streamTimer: null,
    pollTimer: null,
    isBackendOnline: true
};

// DOM References
const DOM = {
    navBtns: document.querySelectorAll('.tab-trigger'),
    tabPanes: document.querySelectorAll('.tab-content'),
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
    inspectFmtContent: document.getElementById('inspect-fmt-content'),
    // Health Telemetry & Connection
    healthCpu: document.getElementById('health-cpu'),
    healthRam: document.getElementById('health-ram'),
    healthLatency: document.getElementById('health-latency'),
    healthDlq: document.getElementById('health-dlq'),
    connDot: document.getElementById('conn-dot'),
    connStatusText: document.getElementById('conn-status-text'),
    connStatusBadge: document.getElementById('connection-status-badge'),
    // Query Lake & Export
    queryLakeInput: document.getElementById('query-lake-input'),
    filterChips: document.querySelectorAll('.pill-chip'),
    exportCsvBtn: document.getElementById('export-csv-btn'),
    // Studio Drawer
    toggleStudioBtn: document.getElementById('toggle-studio-btn'),
    closeStudioBtn: document.getElementById('close-studio-btn'),
    parserStudioDrawer: document.getElementById('parser-studio-drawer'),
    studioVendorInput: document.getElementById('studio-vendor-input'),
    studioProductInput: document.getElementById('studio-product-input'),
    studioLogInput: document.getElementById('studio-log-input'),
    studioGenerateBtn: document.getElementById('studio-generate-btn'),
    studioStatusMsg: document.getElementById('studio-status-msg'),
    studioPreviewBox: document.getElementById('studio-preview-box'),
    studioPreviewFile: document.getElementById('studio-preview-file'),
    studioYamlPreview: document.getElementById('studio-yaml-preview')
};

// Charts References
let scatterChart = null;
let vendorPieChart = null;

// Synthetic Corpus for Continuous Smooth Stream Animation
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

// Fast SHA-256 Mock Digester
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
    initQueryLake();
    initStudioDrawer();
    fetchLiveTelemetry();
    
    // Heartbeat & Telemetry Polling (every 2.5 seconds)
    setInterval(fetchLiveTelemetry, 2500);
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

    if (DOM.exportCsvBtn) {
        DOM.exportCsvBtn.addEventListener('click', exportTelemetryToCsv);
    }
}

function toggleStream() {
    state.isStreaming = !state.isStreaming;

    if (state.isStreaming) {
        DOM.streamBtnIcon.innerText = '■';
        DOM.streamBtnLabel.innerText = 'Stop Live Stream';
        DOM.streamToggleBtn.classList.add('running');
        startStreamTimer();

        fetch('/api/v1/stream/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ eps: state.speed })
        }).catch(() => {});
    } else {
        DOM.streamBtnIcon.innerText = '▶';
        DOM.streamBtnLabel.innerText = 'Start Live Stream';
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
// QUERY LAKE, INSTANT FILTER BAR & CSV EXPORT
// -------------------------------------------------------------
function initQueryLake() {
    if (DOM.queryLakeInput) {
        DOM.queryLakeInput.addEventListener('input', (e) => {
            state.searchQuery = e.target.value.toLowerCase().trim();
            renderFilteredTelemetryTable();
        });
    }

    DOM.filterChips.forEach(chip => {
        chip.addEventListener('click', () => {
            DOM.filterChips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            state.activeFilter = chip.getAttribute('data-filter');
            renderFilteredTelemetryTable();
        });
    });
}

function exportTelemetryToCsv() {
    if (state.allTelemetryRecords.length === 0) {
        alert('No telemetry records available to export.');
        return;
    }

    const headers = ['Timestamp', 'Vendor', 'Source_IP', 'Source_Port', 'Dest_IP', 'Dest_Port', 'Disposition', 'Anomaly_Score'];
    const csvRows = [headers.join(',')];

    state.allTelemetryRecords.forEach(r => {
        csvRows.push([
            `"${r.timeStr}"`,
            `"${r.vendor}"`,
            `"${r.src_ip}"`,
            r.src_port,
            `"${r.dst_ip}"`,
            r.dst_port,
            `"${r.disposition}"`,
            r.anomaly_score
        ].join(','));
    });

    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ulpf_telemetry_export_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '_')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

// -------------------------------------------------------------
// NO-CODE PARSER STUDIO DRAWER
// -------------------------------------------------------------
function initStudioDrawer() {
    if (DOM.toggleStudioBtn) {
        DOM.toggleStudioBtn.addEventListener('click', () => {
            DOM.parserStudioDrawer.classList.toggle('hidden');
        });
    }
    if (DOM.closeStudioBtn) {
        DOM.closeStudioBtn.addEventListener('click', () => {
            DOM.parserStudioDrawer.classList.add('hidden');
        });
    }
    if (DOM.studioGenerateBtn) {
        DOM.studioGenerateBtn.addEventListener('click', async () => {
            const vendor = DOM.studioVendorInput.value.trim();
            const product = DOM.studioProductInput.value.trim() || 'Generic';
            const logStr = DOM.studioLogInput.value.trim();

            if (!vendor || !logStr) {
                DOM.studioStatusMsg.innerText = 'Vendor and Sample Log required!';
                DOM.studioStatusMsg.style.color = '#f87171';
                return;
            }

            DOM.studioStatusMsg.innerText = 'Scaffolding declarative YAML...';
            DOM.studioStatusMsg.style.color = '#fbbf24';

            try {
                const res = await fetch('/api/v1/parsers/auto-generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ vendor, product, sample_log: logStr })
                });
                const data = await res.json();
                if (res.ok) {
                    DOM.studioStatusMsg.innerText = `[SUCCESS] Parser ${data.filename} hot-reloaded! (${data.active_parsers} active)`;
                    DOM.studioStatusMsg.style.color = '#10b981';
                    DOM.studioPreviewBox.classList.remove('hidden');
                    DOM.studioPreviewFile.innerText = data.filename;
                    DOM.studioYamlPreview.innerText = data.yaml_content;
                } else {
                    DOM.studioStatusMsg.innerText = `Error: ${data.detail}`;
                    DOM.studioStatusMsg.style.color = '#f87171';
                }
            } catch (err) {
                DOM.studioStatusMsg.innerText = 'Failed to generate parser.';
                DOM.studioStatusMsg.style.color = '#f87171';
            }
        });
    }
}

// -------------------------------------------------------------
// VIRTUALIZED BOUNDED 60FPS TERMINAL STREAM
// -------------------------------------------------------------
let eventCounter = 0;
function generateStreamEvent() {
    eventCounter++;
    state.totalIngested++;
    state.bufferRawCount++;

    const item = SYNTHETIC_CORPUS[Math.floor(Math.random() * SYNTHETIC_CORPUS.length)];
    const timeStr = new Date().toISOString().substring(11, 23);
    const shaKey = computeMockSha256(item.raw + eventCounter);

    // 1. BOUNDED INJECTION: RAW STRING (Max 10 nodes in DOM)
    const rawEl = document.createElement('div');
    rawEl.className = 'stream-item-raw';
    rawEl.innerText = `[${timeStr}] ${item.raw}`;
    DOM.rawStreamViewport.insertBefore(rawEl, DOM.rawStreamViewport.firstChild);
    if (DOM.rawStreamViewport.children.length > 10) {
        DOM.rawStreamViewport.removeChild(DOM.rawStreamViewport.lastChild);
    }

    // 2. BOUNDED INJECTION: SHA-256 KEY (Max 10 nodes in DOM)
    const shaEl = document.createElement('div');
    shaEl.className = 'stream-item-sha';
    shaEl.innerText = `SHA-256: ${shaKey}`;
    DOM.shaStreamViewport.insertBefore(shaEl, DOM.shaStreamViewport.firstChild);
    if (DOM.shaStreamViewport.children.length > 10) {
        DOM.shaStreamViewport.removeChild(DOM.shaStreamViewport.lastChild);
    }

    // 3. BOUNDED INJECTION: FORMATTED OCSF JSON (Max 4 nodes in DOM)
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

    // Store in Telemetry Array (Cap at 100 in memory)
    state.allTelemetryRecords.unshift({
        timeStr,
        vendor: item.vendor,
        src_ip: item.src_ip,
        src_port: item.src_port,
        dst_ip: item.dst_ip,
        dst_port: item.dst_port,
        disposition: item.disposition,
        anomaly_score: item.anomaly_score
    });
    if (state.allTelemetryRecords.length > 100) {
        state.allTelemetryRecords.pop();
    }

    if (item.anomaly_score > 0.70) {
        state.anomaliesCount++;
    }

    // Re-render Telemetry Table according to active filters
    renderFilteredTelemetryTable();

    // Auto-flush trigger
    if (state.bufferRawCount >= state.batchThreshold) {
        state.bufferRawCount = 0;
        state.batchesCount++;
        DOM.kpiBatches.innerHTML = `${state.batchesCount} <span class="stat-unit">Batches</span>`;
        fetchStoredFiles();
    }
    updateBufferUI();
    updateKpis();
}

function renderFilteredTelemetryTable() {
    let filtered = state.allTelemetryRecords;

    // Filter Chips
    if (state.activeFilter === 'blocked') {
        filtered = filtered.filter(r => r.disposition.toLowerCase() === 'blocked');
    } else if (state.activeFilter === 'allowed') {
        filtered = filtered.filter(r => r.disposition.toLowerCase() === 'allowed');
    } else if (state.activeFilter === 'ssh') {
        filtered = filtered.filter(r => r.dst_port === 22 || r.src_port === 22);
    } else if (state.activeFilter === 'web') {
        filtered = filtered.filter(r => r.dst_port === 80 || r.dst_port === 443);
    } else if (state.activeFilter === 'threat') {
        filtered = filtered.filter(r => r.anomaly_score > 0.70);
    }

    // Search Query Filter
    if (state.searchQuery) {
        const q = state.searchQuery;
        filtered = filtered.filter(r => 
            r.vendor.toLowerCase().includes(q) ||
            r.src_ip.includes(q) ||
            r.dst_ip.includes(q) ||
            r.disposition.toLowerCase().includes(q) ||
            r.src_port.toString().includes(q) ||
            r.dst_port.toString().includes(q)
        );
    }

    if (filtered.length === 0) {
        DOM.anomaliesTableBody.innerHTML = '<tr><td colspan="6" class="empty-state">No records found matching query criteria.</td></tr>';
        DOM.outlierCountBadge.innerText = '0 MATCHES';
        return;
    }

    DOM.outlierCountBadge.innerText = `${filtered.length} MATCHES`;
    DOM.anomaliesTableBody.innerHTML = '';

    filtered.slice(0, 15).forEach(item => {
        const row = document.createElement('tr');
        const dispClass = item.disposition.toLowerCase() === 'blocked' ? 'blocked' : 'allowed';
        const scoreColor = item.anomaly_score > 0.7 ? '#f87171' : '#34d399';

        row.innerHTML = `
            <td>${item.timeStr}</td>
            <td><b>${item.vendor}</b></td>
            <td><code>${item.src_ip}:${item.src_port}</code></td>
            <td><code>${item.dst_ip}:${item.dst_port}</code></td>
            <td><span class="table-badge ${dispClass}">${item.disposition.toUpperCase()}</span></td>
            <td style="color:${scoreColor}; font-weight:700;">${item.anomaly_score.toFixed(3)}</td>
        `;
        DOM.anomaliesTableBody.appendChild(row);
    });
}

function updateBufferUI() {
    const fraction = Math.min(1.0, state.bufferRawCount / state.batchThreshold);
    const pct = Math.round(fraction * 100);
    DOM.bufferStatText.innerText = `${state.bufferRawCount} / ${state.batchThreshold} (${pct}%)`;
    DOM.bufferProgressFill.style.width = `${pct}%`;
}

function updateKpis() {
    DOM.kpiTotalLogs.innerText = state.totalIngested.toLocaleString();
    DOM.kpiSpeed.innerHTML = `${state.isStreaming ? state.speed.toFixed(1) : '0.0'} <span class="stat-unit">EPS</span>`;
    DOM.kpiAnomalies.innerText = state.anomaliesCount.toLocaleString();
}

// -------------------------------------------------------------
// CHARTS (SHADCN DARK THEME)
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
                    if (!raw) return 'rgba(249, 115, 22, 0.7)';
                    return raw.score > 0.7 ? 'rgba(239, 68, 68, 0.9)' : 'rgba(251, 191, 36, 0.6)';
                },
                borderColor: 'rgba(255, 255, 255, 0.05)',
                borderWidth: 1,
                pointRadius: 5,
                pointHoverRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    title: { display: true, text: 'Source Port (Entropy)', color: '#71717a' },
                    grid: { color: '#18181b' },
                    ticks: { color: '#a1a1aa' }
                },
                y: {
                    title: { display: true, text: 'Destination Port (Service)', color: '#71717a' },
                    grid: { color: '#18181b' },
                    ticks: { color: '#a1a1aa' }
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
                    '#f97316',
                    '#fbbf24',
                    '#38bdf8',
                    '#34d399',
                    '#a855f7',
                    '#ec4899',
                    '#71717a'
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
                    labels: { color: '#a1a1aa', font: { family: 'Inter', size: 11 } }
                }
            },
            cutout: '72%'
        }
    });
}

// -------------------------------------------------------------
// TELEMETRY & RESILIENT AUTO-RECONNECT HEARTBEAT
// -------------------------------------------------------------
async function fetchLiveTelemetry() {
    try {
        const res = await fetch('/api/v1/stats');
        if (!res.ok) throw new Error('Network error');
        const data = await res.json();

        // Heartbeat Recovery
        if (!state.isBackendOnline) {
            state.isBackendOnline = true;
            DOM.connDot.style.background = '#10b981';
            DOM.connDot.style.boxShadow = '0 0 6px #10b981';
            DOM.connStatusText.innerText = 'PORT 5140 (UDP)';
            DOM.connStatusBadge.style.borderColor = 'rgba(16, 185, 129, 0.25)';
            DOM.connStatusBadge.style.color = '#34d399';
        }

        state.totalIngested = data.total_ingested || state.totalIngested;
        state.currentEps = data.current_eps || state.currentEps;
        state.anomaliesCount = data.anomalies || state.anomaliesCount;
        state.batchesCount = data.total_batches || state.batchesCount;
        state.isStreaming = data.is_running || state.isStreaming;

        // Health Telemetry
        if (DOM.healthCpu) DOM.healthCpu.innerText = `${data.cpu_percent || '0.0'}%`;
        if (DOM.healthRam) DOM.healthRam.innerText = `${data.memory_mb || '0'} MB`;
        if (DOM.healthLatency) DOM.healthLatency.innerText = `${data.p99_latency_ms || '<0.5'}ms`;
        if (DOM.healthDlq) DOM.healthDlq.innerText = `${data.dlq_count || 0}`;

        updateKpis();
    } catch (e) {
        // Resilient Disconnect State
        state.isBackendOnline = false;
        if (DOM.connDot) {
            DOM.connDot.style.background = '#f59e0b';
            DOM.connDot.style.boxShadow = '0 0 6px #f59e0b';
            DOM.connStatusText.innerText = 'RECONNECTING...';
            DOM.connStatusBadge.style.borderColor = 'rgba(245, 158, 11, 0.3)';
            DOM.connStatusBadge.style.color = '#fbbf24';
        }
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
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No files stored yet.</td></tr>';
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
            <td>
                <a href="/api/v1/files/download?filename=${encodeURIComponent(f.filename)}" class="btn-download-sm" download="${f.filename}">
                    DOWNLOAD
                </a>
            </td>
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
