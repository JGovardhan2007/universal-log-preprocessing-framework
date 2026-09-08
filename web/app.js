/**
 * ULPF Client Application Logic
 * Military-Grade SOC Threat Intelligence & Forensic Cyber Architecture
 * Pure Shadcn Dark Zinc Design System - Zero Emojis
 * 100% Connected to Real Live & Historical Data Engine
 */

// Global State
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
    
    // Real Severity Counters
    sevCritical: 0,
    sevHigh: 0,
    sevMedium: 0,
    sevLow: 0,
    
    // Sparkline Velocity History
    velocityHistory: [],
    
    // Telemetry Collections
    allTelemetryRecords: [],
    activeAlerts: [],
    
    streamTimer: null,
    pollTimer: null,
    isBackendOnline: true
};

// DOM References
const DOM = {
    navBtns: document.querySelectorAll('.tab-trigger'),
    tabPanes: document.querySelectorAll('.tab-content'),
    
    // Executive KPIs
    sevCountCritical: document.getElementById('sev-count-critical'),
    sevCountHigh: document.getElementById('sev-count-high'),
    sevCountMedium: document.getElementById('sev-count-medium'),
    sevCountLow: document.getElementById('sev-count-low'),
    kpiTotalLogs: document.getElementById('kpi-total-logs'),
    kpiSpeed: document.getElementById('kpi-speed'),
    velocitySparkline: document.getElementById('velocitySparkline'),
    
    // MITRE SVG Canvas
    mitreContainer: document.getElementById('mitre-flow-container'),
    mitreSvgCanvas: document.getElementById('mitre-svg-canvas'),
    
    // Entity Ranking Lists
    deviceRankingList: document.getElementById('device-ranking-list'),
    userRankingList: document.getElementById('user-ranking-list'),
    offenseRankingList: document.getElementById('offense-ranking-list'),
    
    // Operational Tables & Dynamic Filter Banner
    activeFilterBanner: document.getElementById('active-filter-banner'),
    filterBannerValue: document.getElementById('filter-banner-value'),
    btnClearFilter: document.getElementById('btn-clear-filter'),
    alertsTableBody: document.getElementById('alerts-table-body'),
    timelineTableBody: document.getElementById('timeline-table-body'),
    activeAlertsCountBadge: document.getElementById('active-alerts-count-badge'),
    queryLakeInput: document.getElementById('query-lake-input'),
    filterChips: document.querySelectorAll('.pill-chip'),
    exportCsvBtn: document.getElementById('export-csv-btn'),
    
    // Live Streamer (Tab 2)
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
    studioYamlPreview: document.getElementById('studio-yaml-preview'),
    
    // Database Vault (Tab 3)
    rawFilesTableBody: document.getElementById('raw-files-table-body'),
    fmtFilesTableBody: document.getElementById('fmt-files-table-body'),
    rawFilesCountBadge: document.getElementById('raw-files-count-badge'),
    fmtFilesCountBadge: document.getElementById('fmt-files-count-badge'),
    batchInspectorSelect: document.getElementById('batch-inspector-select'),
    inspectRawTitle: document.getElementById('inspect-raw-title'),
    inspectRawContent: document.getElementById('inspect-raw-content'),
    inspectFmtTitle: document.getElementById('inspect-fmt-title'),
    inspectFmtContent: document.getElementById('inspect-fmt-content'),
    
    // Dual-Pane Forensic Modal
    forensicModal: document.getElementById('forensic-modal'),
    modalEventId: document.getElementById('modal-event-id'),
    modalEventTime: document.getElementById('modal-event-time'),
    modalRawPayload: document.getElementById('modal-raw-payload'),
    modalShaDigest: document.getElementById('modal-sha-digest'),
    modalJsonPayload: document.getElementById('modal-json-payload'),
    modalCloseBtn: document.getElementById('modal-close-btn'),
    modalDismissBtn: document.getElementById('modal-dismiss-btn'),
    modalCopyShaBtn: document.getElementById('modal-copy-sha-btn'),
    modalCopyJsonBtn: document.getElementById('modal-copy-json-btn')
};

// Charts References
let severityDonutChart = null;
let severityTrendChart = null;
let scatterChart = null;

// Global Filter State
state.customFilter = null; // { type: 'severity' | 'mitre_tactic' | 'mitre_tech' | 'geo_asn' | 'device' | 'user' | 'offense', value: string, label: string }

function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Real Standard Web Crypto SHA-256
async function computeRealSha256(str) {
    if (!str) return "0x0000000000000000000000000000000000000000000000000000000000000000";
    try {
        const msgBuffer = new TextEncoder().encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return "0x" + hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
        return "0x" + "0".repeat(64);
    }
}

// -------------------------------------------------------------
// INITIALIZATION
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initExecutiveKpis();
    initMitreFlow();
    initGeoThreatMapInteractivity();
    initCharts();
    initQueryLake();
    initControls();
    initStudioDrawer();
    initForensicModal();
    
    fetchLiveTelemetry();
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
            } else if (targetTab === 'dashboard') {
                setTimeout(drawMitreConnections, 100);
            }
        });
    });
}

// -------------------------------------------------------------
// 1. EXECUTIVE KPIS & VELOCITY SPARKLINE
// -------------------------------------------------------------
function initExecutiveKpis() {
    renderVelocitySparkline();

    // Interactive Severity Cards Filtering
    const critCard = document.querySelector('.sev-card.sev-critical');
    if (critCard) {
        critCard.addEventListener('click', () => {
            toggleFilter('severity', 'Critical', 'Severity: Critical');
        });
    }

    const highCard = document.querySelector('.sev-card.sev-high');
    if (highCard) {
        highCard.addEventListener('click', () => {
            toggleFilter('severity', 'High', 'Severity: High');
        });
    }

    const medCard = document.querySelector('.sev-card.sev-medium');
    if (medCard) {
        medCard.addEventListener('click', () => {
            toggleFilter('severity', 'Medium', 'Severity: Medium');
        });
    }

    const lowCard = document.querySelector('.sev-card.sev-low');
    if (lowCard) {
        lowCard.addEventListener('click', () => {
            toggleFilter('severity', 'Low', 'Severity: Low');
        });
    }

    // Velocity card clicks clear all filters
    const velCard = document.querySelector('.velocity-card');
    if (velCard) {
        velCard.style.cursor = 'pointer';
        velCard.addEventListener('click', () => {
            clearGlobalFilter();
        });
    }
}

function renderVelocitySparkline() {
    const canvas = DOM.velocitySparkline;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    
    ctx.clearRect(0, 0, w, h);
    
    const data = state.velocityHistory;
    const max = Math.max(...data, 20);
    const min = Math.min(...data, 0);
    const range = max - min || 1;
    const step = w / (data.length - 1);
    
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(249, 115, 22, 0.35)');
    grad.addColorStop(1, 'rgba(249, 115, 22, 0.0)');
    
    ctx.beginPath();
    ctx.moveTo(0, h - ((data[0] - min) / range) * (h - 8) - 4);
    
    for (let i = 1; i < data.length; i++) {
        const x = i * step;
        const y = h - ((data[i] - min) / range) * (h - 8) - 4;
        ctx.lineTo(x, y);
    }
    
    ctx.strokeStyle = '#f97316';
    ctx.lineWidth = 2;
    ctx.stroke();
    
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();
    
    const lastY = h - ((data[data.length - 1] - min) / range) * (h - 8) - 4;
    ctx.beginPath();
    ctx.arc(w - 2, lastY, 3, 0, Math.PI * 2);
    ctx.fillStyle = '#ffffff';
    ctx.fill();
}

function updateVelocitySparkline(newEps) {
    state.velocityHistory.push(newEps);
    if (state.velocityHistory.length > 20) {
        state.velocityHistory.shift();
    }
    renderVelocitySparkline();
}

// -------------------------------------------------------------
// 2. MITRE ATT&CK TACTIC-TO-TECHNIQUE FLOW
// -------------------------------------------------------------
const MITRE_MAPPINGS = [
    { tactic: 'initial-access', tech: 't1046', color: '#10b981' },
    { tactic: 'initial-access', tech: 't1110', color: '#ef4444' },
    { tactic: 'execution', tech: 't1059', color: '#f97316' },
    { tactic: 'defense-evasion', tech: 't1070', color: '#f59e0b' },
    { tactic: 'credential-access', tech: 't1110', color: '#ef4444' },
    { tactic: 'c2', tech: 't1071', color: '#ef4444' }
];

function initMitreFlow() {
    window.addEventListener('resize', drawMitreConnections);
    setTimeout(drawMitreConnections, 200);

    const nodes = document.querySelectorAll('.mitre-node');
    nodes.forEach(node => {
        node.addEventListener('mouseenter', () => {
            const tactic = node.getAttribute('data-tactic');
            const tech = node.getAttribute('data-tech');
            highlightMitreConnections(tactic, tech);
        });
        node.addEventListener('mouseleave', () => {
            if (state.customFilter && (state.customFilter.type === 'mitre_tactic' || state.customFilter.type === 'mitre_tech')) {
                highlightMitreConnections(
                    state.customFilter.type === 'mitre_tactic' ? state.customFilter.value : null,
                    state.customFilter.type === 'mitre_tech' ? state.customFilter.value : null
                );
            } else {
                drawMitreConnections();
            }
        });

        // Interactive Click to Filter
        node.addEventListener('click', () => {
            const tactic = node.getAttribute('data-tactic');
            const tech = node.getAttribute('data-tech');
            if (tactic) {
                const title = node.querySelector('.node-title')?.innerText || tactic;
                toggleFilter('mitre_tactic', tactic, `Tactic: ${title}`);
            } else if (tech) {
                const techId = node.querySelector('.tech-id')?.innerText || tech;
                const techName = node.querySelector('.tech-name')?.innerText || '';
                toggleFilter('mitre_tech', tech, `Technique: ${techId} (${techName})`);
            }
        });
    });
}

function initGeoThreatMapInteractivity() {
    const threatNodes = document.querySelectorAll('.threat-node');
    threatNodes.forEach(node => {
        node.addEventListener('click', () => {
            const city = node.getAttribute('data-city');
            const asn = node.getAttribute('data-asn');
            if (asn) {
                toggleFilter('geo_asn', asn, `Origin ASN: ${asn} (${city})`);
            } else if (city) {
                toggleFilter('geo_city', city, `Origin City: ${city}`);
            }
        });
    });
}

function drawMitreConnections() {
    const svg = DOM.mitreSvgCanvas;
    if (!svg || !DOM.mitreContainer) return;

    const containerRect = DOM.mitreContainer.getBoundingClientRect();
    if (containerRect.width === 0) return;

    svg.innerHTML = '';
    const svgRect = svg.getBoundingClientRect();

    MITRE_MAPPINGS.forEach(m => {
        const tacticEl = document.querySelector(`.node-tactic[data-tactic="${m.tactic}"]`);
        const techEl = document.querySelector(`.node-technique[data-tech="${m.tech}"]`);
        
        if (!tacticEl || !techEl) return;

        const tRect = tacticEl.getBoundingClientRect();
        const techRect = techEl.getBoundingClientRect();

        const x1 = 0;
        const y1 = tRect.top - svgRect.top + (tRect.height / 2);
        const x2 = svgRect.width;
        const y2 = techRect.top - svgRect.top + (techRect.height / 2);

        const dx = (x2 - x1) / 2;
        const pathData = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', pathData);
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke', m.color);
        path.setAttribute('stroke-width', '1.5');
        path.setAttribute('stroke-opacity', '0.45');
        path.classList.add('mitre-link');
        path.setAttribute('data-tactic', m.tactic);
        path.setAttribute('data-tech', m.tech);

        svg.appendChild(path);
    });

    if (state.customFilter && (state.customFilter.type === 'mitre_tactic' || state.customFilter.type === 'mitre_tech')) {
        highlightMitreConnections(
            state.customFilter.type === 'mitre_tactic' ? state.customFilter.value : null,
            state.customFilter.type === 'mitre_tech' ? state.customFilter.value : null
        );
    }
}

function highlightMitreConnections(tactic, tech) {
    const links = document.querySelectorAll('.mitre-link');
    links.forEach(l => {
        const lTactic = l.getAttribute('data-tactic');
        const lTech = l.getAttribute('data-tech');
        if ((tactic && lTactic === tactic) || (tech && lTech === tech)) {
            l.setAttribute('stroke-opacity', '1.0');
            l.setAttribute('stroke-width', '3');
        } else {
            l.setAttribute('stroke-opacity', '0.1');
            l.setAttribute('stroke-width', '1');
        }
    });
}

// -------------------------------------------------------------
// 3. CHARTS & TELEMETRY VISUALIZATIONS
// -------------------------------------------------------------
function initCharts() {
    // 1. Severity Donut Chart with Interactive Slice Clicking
    const ctxDonut = document.getElementById('severityDonutChart').getContext('2d');
    severityDonutChart = new Chart(ctxDonut, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [state.sevCritical, state.sevHigh, state.sevMedium, state.sevLow],
                backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981'],
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#a1a1aa', font: { family: 'Inter', size: 10 } }
                }
            },
            cutout: '70%',
            onClick: (e, elements) => {
                if (elements && elements.length > 0) {
                    const idx = elements[0].index;
                    const labels = ['Critical', 'High', 'Medium', 'Low'];
                    const sev = labels[idx];
                    toggleFilter('severity', sev, `Severity: ${sev}`);
                }
            }
        }
    });

    // 2. Multi-Series Trend Line Chart
    const ctxTrend = document.getElementById('severityTrendChart').getContext('2d');
    severityTrendChart = new Chart(ctxTrend, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Critical',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.08)',
                    tension: 0.3,
                    borderWidth: 1.5,
                    pointRadius: 2
                },
                {
                    label: 'High',
                    data: [],
                    borderColor: '#f97316',
                    backgroundColor: 'transparent',
                    tension: 0.3,
                    borderWidth: 1.5,
                    pointRadius: 2
                },
                {
                    label: 'Medium',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'transparent',
                    tension: 0.3,
                    borderWidth: 1.5,
                    pointRadius: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: { color: '#71717a', font: { family: 'Inter', size: 10 } }
                }
            },
            scales: {
                x: { grid: { color: '#18181b' }, ticks: { color: '#71717a' } },
                y: { grid: { color: '#18181b' }, ticks: { color: '#71717a' } }
            }
        }
    });

    // 3. AI Threat Entropy Scatter Matrix
    const ctxScatter = document.getElementById('threatScatterChart').getContext('2d');
    scatterChart = new Chart(ctxScatter, {
        type: 'scatter',
        data: {
            datasets: [{
                label: 'Entropy Points',
                data: [],
                backgroundColor: (ctx) => {
                    const raw = ctx.raw;
                    if (!raw) return 'rgba(249, 115, 22, 0.7)';
                    return raw.score > 0.7 ? 'rgba(239, 68, 68, 0.9)' : 'rgba(251, 191, 36, 0.6)';
                },
                borderWidth: 0,
                pointRadius: 4,
                pointHoverRadius: 7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    title: { display: true, text: 'Source Port Entropy', color: '#71717a', font: { size: 10 } },
                    grid: { color: '#18181b' },
                    ticks: { color: '#71717a' }
                },
                y: {
                    title: { display: true, text: 'Target Port', color: '#71717a', font: { size: 10 } },
                    grid: { color: '#18181b' },
                    ticks: { color: '#71717a' }
                }
            }
        }
    });
}

// -------------------------------------------------------------
// FILTER CONTROLS & DYNAMIC FEEDBACK
// -------------------------------------------------------------
function toggleFilter(type, value, label) {
    if (state.customFilter && state.customFilter.type === type && state.customFilter.value === value) {
        clearGlobalFilter();
    } else {
        applyGlobalFilter(type, value, label);
    }
}

function applyGlobalFilter(type, value, label) {
    state.customFilter = { type, value, label };
    
    if (DOM.activeFilterBanner && DOM.filterBannerValue) {
        DOM.filterBannerValue.innerText = label;
        DOM.activeFilterBanner.style.display = 'flex';
    }
    
    updateActiveFilterUI();
    renderAlertsTable();
    renderTimelineTable();
}

function clearGlobalFilter() {
    state.customFilter = null;
    if (DOM.activeFilterBanner) {
        DOM.activeFilterBanner.style.display = 'none';
    }
    updateActiveFilterUI();
    renderAlertsTable();
    renderTimelineTable();
}

function updateActiveFilterUI() {
    // 1. Severity cards active class
    const sevCards = document.querySelectorAll('.sev-card');
    sevCards.forEach(c => c.classList.remove('active-filter'));
    if (state.customFilter && state.customFilter.type === 'severity') {
        const val = state.customFilter.value.toLowerCase();
        const activeCard = document.querySelector(`.sev-card.sev-${val}`);
        if (activeCard) activeCard.classList.add('active-filter');
    }

    // 2. MITRE nodes active class
    const mitreNodes = document.querySelectorAll('.mitre-node');
    mitreNodes.forEach(n => n.classList.remove('active-filter'));
    if (state.customFilter) {
        if (state.customFilter.type === 'mitre_tactic') {
            const el = document.querySelector(`.node-tactic[data-tactic="${state.customFilter.value}"]`);
            if (el) el.classList.add('active-filter');
            highlightMitreConnections(state.customFilter.value, null);
        } else if (state.customFilter.type === 'mitre_tech') {
            const el = document.querySelector(`.node-technique[data-tech="${state.customFilter.value}"]`);
            if (el) el.classList.add('active-filter');
            highlightMitreConnections(null, state.customFilter.value);
        } else {
            drawMitreConnections();
        }
    } else {
        drawMitreConnections();
    }
}

// -------------------------------------------------------------
// 4. REAL DATA DASHBOARD BINDING & UPDATER
// -------------------------------------------------------------
function updateDashboardRealData(analytics) {
    if (!analytics) return;

    // 1. Executive KPIs
    if (analytics.kpis) {
        state.totalIngested = analytics.kpis.total_logs;
        state.sevCritical = analytics.kpis.severity.critical;
        state.sevHigh = analytics.kpis.severity.high;
        state.sevMedium = analytics.kpis.severity.medium;
        state.sevLow = analytics.kpis.severity.low;
        updateKpisUI();
    }

    // 2. MITRE Flow Tactics & Techniques
    if (analytics.mitre_flow) {
        const tactics = analytics.mitre_flow.tactics;
        const techs = analytics.mitre_flow.techniques;

        const updateNodeCounter = (selector, count) => {
            const el = document.querySelector(selector);
            if (el) el.innerText = `${count} Events`;
        };
        const updateTechCounter = (selector, count) => {
            const el = document.querySelector(selector);
            if (el) el.innerText = `${count} Incidents`;
        };

        updateNodeCounter('.node-tactic[data-tactic="initial-access"] .node-counter', tactics['initial-access']);
        updateNodeCounter('.node-tactic[data-tactic="execution"] .node-counter', tactics['execution']);
        updateNodeCounter('.node-tactic[data-tactic="defense-evasion"] .node-counter', tactics['defense-evasion']);
        updateNodeCounter('.node-tactic[data-tactic="credential-access"] .node-counter', tactics['credential-access']);
        updateNodeCounter('.node-tactic[data-tactic="c2"] .node-counter', tactics['c2']);

        updateTechCounter('.node-technique[data-tech="t1046"] .node-counter', techs['t1046']);
        updateTechCounter('.node-technique[data-tech="t1059"] .node-counter', techs['t1059']);
        updateTechCounter('.node-technique[data-tech="t1070"] .node-counter', techs['t1070']);
        updateTechCounter('.node-technique[data-tech="t1110"] .node-counter', techs['t1110']);
        updateTechCounter('.node-technique[data-tech="t1071"] .node-counter', techs['t1071']);
    }

    // 3. Geo Threats ASN Overlay (Interactive)
    if (analytics.geo_threats && Array.isArray(analytics.geo_threats)) {
        const overlay = document.querySelector('.geo-asn-overlay');
        if (overlay) {
            overlay.innerHTML = analytics.geo_threats.slice(0, 4).map((g, idx) => {
                const badgeClass = idx === 0 ? 'badge-crit' : (idx === 1 ? 'badge-high' : 'badge-med');
                return `
                    <div class="asn-row" data-asn="${g.asn}" data-loc="${g.location}">
                        <span class="asn-pill ${badgeClass}">${g.asn}</span>
                        <span class="asn-location">${g.location}</span>
                        <span class="asn-count">${g.count} Attacks</span>
                    </div>
                `;
            }).join('');

            overlay.querySelectorAll('.asn-row').forEach(row => {
                row.addEventListener('click', () => {
                    const asn = row.getAttribute('data-asn');
                    const loc = row.getAttribute('data-loc');
                    toggleFilter('geo_asn', asn, `Origin ASN: ${asn} (${loc})`);
                });
            });
        }
    }

    // 4. Entity Profiling Panels (Interactive)
    if (analytics.devices && DOM.deviceRankingList) {
        DOM.deviceRankingList.innerHTML = analytics.devices.map(d => `
            <div class="ranking-item" data-device="${d.name}">
                <div class="ranking-top-row">
                    <span class="ranking-name">${d.name}</span>
                    <span class="ranking-meta">${d.records.toLocaleString()} Logs (${d.percentage}%)</span>
                </div>
                <div class="ranking-track">
                    <div class="ranking-fill orange" style="width: ${d.percentage}%"></div>
                </div>
            </div>
        `).join('');

        DOM.deviceRankingList.querySelectorAll('.ranking-item').forEach(item => {
            item.addEventListener('click', () => {
                const dev = item.getAttribute('data-device');
                toggleFilter('device', dev, `Device: ${dev}`);
            });
        });
    }

    if (analytics.users && DOM.userRankingList) {
        DOM.userRankingList.innerHTML = analytics.users.map(u => {
            const fillClass = u.score > 90 ? 'crimson' : (u.score > 70 ? 'orange' : 'cyan');
            return `
                <div class="ranking-item" data-user="${u.name}">
                    <div class="ranking-top-row">
                        <span class="ranking-name">${u.name}</span>
                        <span class="ranking-meta">Risk: ${u.score} (${u.severity}, ${u.events} ev)</span>
                    </div>
                    <div class="ranking-track">
                        <div class="ranking-fill ${fillClass}" style="width: ${u.score}%"></div>
                    </div>
                </div>
            `;
        }).join('');

        DOM.userRankingList.querySelectorAll('.ranking-item').forEach(item => {
            item.addEventListener('click', () => {
                const usr = item.getAttribute('data-user');
                toggleFilter('user', usr, `User Identity: ${usr}`);
            });
        });
    }

    if (analytics.offenses && DOM.offenseRankingList) {
        DOM.offenseRankingList.innerHTML = analytics.offenses.map(o => {
            const fillClass = o.percentage > 30 ? 'crimson' : (o.percentage > 15 ? 'orange' : 'cyan');
            return `
                <div class="ranking-item" data-offense="${o.name}">
                    <div class="ranking-top-row">
                        <span class="ranking-name">${o.name}</span>
                        <span class="ranking-meta">${o.events} Events (${o.percentage}%)</span>
                    </div>
                    <div class="ranking-track">
                        <div class="ranking-fill ${fillClass}" style="width: ${o.percentage}%"></div>
                    </div>
                </div>
            `;
        }).join('');

        DOM.offenseRankingList.querySelectorAll('.ranking-item').forEach(item => {
            item.addEventListener('click', () => {
                const off = item.getAttribute('data-offense');
                toggleFilter('offense', off, `Attack: ${off}`);
            });
        });
    }

    // 5. AI Threat Matrix Scatter Points
    if (analytics.scatter_points && scatterChart && analytics.scatter_points.length > 0) {
        scatterChart.data.datasets[0].data = analytics.scatter_points;
        scatterChart.update('none');
    }

    // 6. Recent Alerts (Real Data Population)
    if (analytics.recent_alerts && analytics.recent_alerts.length > 0) {
        state.activeAlerts = analytics.recent_alerts;
        renderAlertsTable();
    }

    // 7. Recent Timeline (Real Data Population)
    if (analytics.recent_timeline && analytics.recent_timeline.length > 0) {
        state.allTelemetryRecords = analytics.recent_timeline;
        renderTimelineTable();
    }

    // 8. Rolling Real Severity Trend Chart
    if (severityTrendChart && analytics.kpis) {
        const timeLabel = new Date().toISOString().substring(11, 19);
        const labels = severityTrendChart.data.labels;
        if (labels.length === 0 || labels[labels.length - 1] !== timeLabel) {
            labels.push(timeLabel);
            if (labels.length > 10) labels.shift();

            severityTrendChart.data.datasets[0].data.push(state.sevCritical);
            if (severityTrendChart.data.datasets[0].data.length > 10) severityTrendChart.data.datasets[0].data.shift();

            severityTrendChart.data.datasets[1].data.push(state.sevHigh);
            if (severityTrendChart.data.datasets[1].data.length > 10) severityTrendChart.data.datasets[1].data.shift();

            severityTrendChart.data.datasets[2].data.push(state.sevMedium);
            if (severityTrendChart.data.datasets[2].data.length > 10) severityTrendChart.data.datasets[2].data.shift();

            severityTrendChart.update('none');
        }
    }
}

// -------------------------------------------------------------
// 5. OPERATIONAL TELEMETRY & LIVE TABLES
// -------------------------------------------------------------
function renderAlertsTable() {
    DOM.alertsTableBody.innerHTML = '';
    let filteredAlerts = state.activeAlerts;

    if (state.customFilter) {
        const { type, value } = state.customFilter;
        const vLower = value.toLowerCase();

        if (type === 'severity') {
            filteredAlerts = filteredAlerts.filter(a => (a.severity || '').toLowerCase() === vLower);
        } else if (type === 'mitre_tactic') {
            filteredAlerts = filteredAlerts.filter(a =>
                (a.tactic || '').toLowerCase().includes(vLower) ||
                (a.name || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'mitre_tech') {
            filteredAlerts = filteredAlerts.filter(a =>
                (a.tactic || '').toLowerCase().includes(vLower) ||
                (a.name || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'geo_asn') {
            filteredAlerts = filteredAlerts.filter(a =>
                (a.src || '').includes(value) ||
                (a.raw || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'device') {
            filteredAlerts = filteredAlerts.filter(a =>
                (a.vendor || '').toLowerCase().includes(vLower) ||
                (a.raw || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'user') {
            filteredAlerts = filteredAlerts.filter(a =>
                (a.user || '').toLowerCase().includes(vLower) ||
                (a.raw || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'offense') {
            filteredAlerts = filteredAlerts.filter(a =>
                (a.name || '').toLowerCase().includes(vLower) ||
                (a.tactic || '').toLowerCase().includes(vLower)
            );
        }
    }

    if (filteredAlerts.length === 0) {
        DOM.alertsTableBody.innerHTML = '<tr><td colspan="7" class="empty-state">No alerts matching active filter.</td></tr>';
        DOM.activeAlertsCountBadge.innerText = `0 MATCHES`;
        return;
    }

    filteredAlerts.forEach((a, idx) => {
        const tr = document.createElement('tr');
        const sevClass = a.severity === 'Critical' ? 'badge-crit' : (a.severity === 'High' ? 'badge-high' : 'badge-med');
        const statusClass = a.status === 'OPEN' ? 'status-open' : (a.status === 'UNDER REVIEW' ? 'status-review' : 'status-resolved');

        tr.innerHTML = `
            <td>${a.time}</td>
            <td><b>${a.name}</b> <span class="text-muted">(${a.tactic})</span></td>
            <td><span class="${sevClass}">${a.severity.toUpperCase()}</span></td>
            <td><code>${a.src}</code></td>
            <td><code>${a.dst}</code></td>
            <td>
                <button class="triage-status-btn ${statusClass}" data-idx="${idx}">
                    [ ${a.status} ]
                </button>
            </td>
            <td>
                <button class="btn-inspect-sm" data-idx="${idx}">INSPECT</button>
            </td>
        `;

        tr.querySelector('.btn-inspect-sm').addEventListener('click', (e) => {
            e.stopPropagation();
            openForensicModalFromAlert(a);
        });

        tr.addEventListener('click', () => {
            openForensicModalFromAlert(a);
        });

        const triageBtn = tr.querySelector('.triage-status-btn');
        triageBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            cycleTriageStatus(idx);
        });

        DOM.alertsTableBody.appendChild(tr);
    });

    const openCount = filteredAlerts.filter(a => a.status !== 'RESOLVED').length;
    DOM.activeAlertsCountBadge.innerText = `${openCount} UNRESOLVED`;
}

function cycleTriageStatus(idx) {
    const a = state.activeAlerts[idx];
    if (!a) return;
    if (a.status === 'OPEN') a.status = 'UNDER REVIEW';
    else if (a.status === 'UNDER REVIEW') a.status = 'RESOLVED';
    else a.status = 'OPEN';
    
    fetch('/api/v1/threats/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: a.id, status: a.status })
    }).catch(() => {});

    renderAlertsTable();
}

function initQueryLake() {
    if (DOM.queryLakeInput) {
        DOM.queryLakeInput.addEventListener('input', (e) => {
            state.searchQuery = e.target.value.toLowerCase().trim();
            renderTimelineTable();
        });
    }

    DOM.filterChips.forEach(chip => {
        chip.addEventListener('click', () => {
            DOM.filterChips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            state.activeFilter = chip.getAttribute('data-filter');
            renderTimelineTable();
        });
    });

    if (DOM.exportCsvBtn) {
        DOM.exportCsvBtn.addEventListener('click', exportTelemetryToCsv);
    }

    if (DOM.btnClearFilter) {
        DOM.btnClearFilter.addEventListener('click', () => {
            clearGlobalFilter();
        });
    }
}

function renderTimelineTable() {
    let filtered = state.allTelemetryRecords;

    // Apply Preset Filter
    if (state.activeFilter === 'blocked') {
        filtered = filtered.filter(r => (r.disposition || '').toLowerCase() === 'blocked');
    } else if (state.activeFilter === 'allowed') {
        filtered = filtered.filter(r => (r.disposition || '').toLowerCase() === 'allowed');
    } else if (state.activeFilter === 'ssh') {
        filtered = filtered.filter(r => r.dst_port === 22 || r.src_port === 22);
    } else if (state.activeFilter === 'web') {
        filtered = filtered.filter(r => r.dst_port === 80 || r.dst_port === 443);
    } else if (state.activeFilter === 'threat') {
        filtered = filtered.filter(r => (r.anomaly_score || 0) > 0.70);
    }

    // Apply Interactive Card Global Filter
    if (state.customFilter) {
        const { type, value } = state.customFilter;
        const vLower = value.toLowerCase();

        if (type === 'severity') {
            if (vLower === 'critical') {
                filtered = filtered.filter(r => (r.anomaly_score || 0) >= 0.85);
            } else if (vLower === 'high') {
                filtered = filtered.filter(r => (r.anomaly_score || 0) >= 0.70 && (r.anomaly_score || 0) < 0.85);
            } else if (vLower === 'medium') {
                filtered = filtered.filter(r => (r.anomaly_score || 0) >= 0.40 && (r.anomaly_score || 0) < 0.70);
            } else {
                filtered = filtered.filter(r => (r.anomaly_score || 0) < 0.40);
            }
        } else if (type === 'mitre_tactic' || type === 'mitre_tech') {
            filtered = filtered.filter(r =>
                (r.alert_name || '').toLowerCase().includes(vLower) ||
                (r.raw || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'geo_asn') {
            filtered = filtered.filter(r =>
                (r.src_ip || '').includes(value) ||
                (r.raw || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'device') {
            filtered = filtered.filter(r =>
                (r.vendor || '').toLowerCase().includes(vLower) ||
                (r.raw || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'user') {
            filtered = filtered.filter(r =>
                (r.user || '').toLowerCase().includes(vLower) ||
                (r.raw || '').toLowerCase().includes(vLower)
            );
        } else if (type === 'offense') {
            filtered = filtered.filter(r =>
                (r.alert_name || '').toLowerCase().includes(vLower) ||
                (r.raw || '').toLowerCase().includes(vLower)
            );
        }
    }

    // Apply Search Input
    if (state.searchQuery) {
        const q = state.searchQuery;
        filtered = filtered.filter(r =>
            (r.vendor || '').toLowerCase().includes(q) ||
            (r.user || '').toLowerCase().includes(q) ||
            (r.src_ip || '').includes(q) ||
            (r.dst_ip || '').includes(q) ||
            (r.disposition || '').toLowerCase().includes(q) ||
            (r.alert_name || '').toLowerCase().includes(q)
        );
    }

    if (filtered.length === 0) {
        DOM.timelineTableBody.innerHTML = '<tr><td colspan="7" class="empty-state">No telemetry records matching active filter.</td></tr>';
        return;
    }

    DOM.timelineTableBody.innerHTML = '';
    filtered.slice(0, 15).forEach((item, idx) => {
        const tr = document.createElement('tr');
        const disp = item.disposition || 'Allowed';
        const dispClass = disp.toLowerCase() === 'blocked' ? 'blocked' : 'allowed';
        const ocsfClass = item.dst_port === 22 || item.dst_port === 445 ? 'OCSF 3001 (Auth)' : 'OCSF 4001 (Network)';

        tr.innerHTML = `
            <td>${item.timeStr}</td>
            <td><b>${ocsfClass}</b></td>
            <td><code>${item.user || 'system'}</code></td>
            <td><code>${item.src_ip}:${item.src_port}</code></td>
            <td><code>${item.dst_ip}:${item.dst_port}</code></td>
            <td><span class="table-badge ${dispClass}">${disp.toUpperCase()}</span></td>
            <td><button class="btn-inspect-sm">INSPECT</button></td>
        `;

        tr.addEventListener('click', () => {
            openForensicModalFromRecord(item);
        });

        DOM.timelineTableBody.appendChild(tr);
    });
}

function exportTelemetryToCsv() {
    if (state.allTelemetryRecords.length === 0) {
        alert('No telemetry records available to export.');
        return;
    }

    const headers = ['Timestamp', 'Vendor', 'Identity', 'Source_IP', 'Source_Port', 'Dest_IP', 'Dest_Port', 'Disposition', 'Anomaly_Score'];
    const csvRows = [headers.join(',')];

    state.allTelemetryRecords.forEach(r => {
        csvRows.push([
            `"${r.timeStr}"`,
            `"${r.vendor}"`,
            `"${r.user}"`,
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
    a.download = `ulpf_soc_telemetry_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '_')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

// -------------------------------------------------------------
// 6. DUAL-PANE FORENSIC INSPECTOR MODAL
// -------------------------------------------------------------
function initForensicModal() {
    DOM.modalCloseBtn.addEventListener('click', closeForensicModal);
    DOM.modalDismissBtn.addEventListener('click', closeForensicModal);

    DOM.forensicModal.addEventListener('click', (e) => {
        if (e.target === DOM.forensicModal) closeForensicModal();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !DOM.forensicModal.classList.contains('hidden')) {
            closeForensicModal();
        }
    });

    DOM.modalCopyShaBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(DOM.modalShaDigest.innerText);
        DOM.modalCopyShaBtn.innerText = 'Copied!';
        setTimeout(() => DOM.modalCopyShaBtn.innerText = 'Copy Hash', 1500);
    });

    DOM.modalCopyJsonBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(DOM.modalJsonPayload.innerText);
        DOM.modalCopyJsonBtn.innerText = 'Copied!';
        setTimeout(() => DOM.modalCopyJsonBtn.innerText = 'Copy JSON', 1500);
    });
}

async function openForensicModalFromRecord(item) {
    const sha = item.sha256 || await computeRealSha256(item.raw || '');
    const eventId = (item.ocsf && item.ocsf.event_id) ? item.ocsf.event_id : `evt-${Date.now()}`;

    DOM.modalEventId.innerText = eventId;
    DOM.modalEventTime.innerText = `${new Date().toISOString().slice(0, 10)} ${item.timeStr || ''} UTC`;
    DOM.modalRawPayload.innerText = item.raw || 'No raw wire payload available';
    DOM.modalShaDigest.innerText = sha;

    const ocsfJson = item.ocsf || {
        event_id: eventId,
        class_name: "Security Telemetry Ingress",
        vendor_name: item.vendor || "Generic Ingress",
        disposition: item.disposition || "Allowed",
        actor: { user: { name: item.user || "root" } },
        src_endpoint: { ip: item.src_ip, port: item.src_port },
        dst_endpoint: { ip: item.dst_ip, port: item.dst_port },
        metadata: {
            sha256_hash: sha,
            ingest_time: item.timeStr
        },
        raw_data: item.raw
    };

    DOM.modalJsonPayload.innerText = JSON.stringify(ocsfJson, null, 2);
    DOM.forensicModal.classList.remove('hidden');
}

function openForensicModalFromAlert(alert) {
    const item = {
        raw: alert.raw,
        user: alert.user,
        vendor: alert.vendor,
        src_ip: (alert.src || '').split(':')[0],
        src_port: parseInt((alert.src || '').split(':')[1] || 0, 10),
        dst_ip: (alert.dst || '').split(':')[0],
        dst_port: parseInt((alert.dst || '').split(':')[1] || 0, 10),
        disposition: "Blocked",
        anomaly_score: alert.severity === 'Critical' ? 0.95 : 0.80,
        timeStr: alert.time,
        sha256: alert.sha256,
        ocsf: alert.ocsf
    };
    openForensicModalFromRecord(item);
}

function closeForensicModal() {
    DOM.forensicModal.classList.add('hidden');
}

// -------------------------------------------------------------
// 7. LIVE INGESTION STREAMER & VIRTUALIZED DOM
// -------------------------------------------------------------
function initControls() {
    DOM.streamToggleBtn.addEventListener('click', toggleStream);

    DOM.streamSpeedSelect.addEventListener('change', (e) => {
        state.speed = parseInt(e.target.value, 10);
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

    const copyRawBtn = document.getElementById('copy-inspect-raw-btn');
    if (copyRawBtn) {
        copyRawBtn.addEventListener('click', () => {
            const rawText = DOM.inspectRawContent.innerText;
            navigator.clipboard.writeText(rawText);
            copyRawBtn.innerText = 'Copied!';
            setTimeout(() => copyRawBtn.innerText = 'Copy Raw', 1500);
        });
    }

    const copyFmtBtn = document.getElementById('copy-inspect-fmt-btn');
    if (copyFmtBtn) {
        copyFmtBtn.addEventListener('click', () => {
            const fmtText = DOM.inspectFmtContent.innerText;
            navigator.clipboard.writeText(fmtText);
            copyFmtBtn.innerText = 'Copied!';
            setTimeout(() => copyFmtBtn.innerText = 'Copy JSON', 1500);
        });
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
    clearInterval(state.streamTimer);
    state.streamTimer = setInterval(fetchAndRenderLiveStream, 500);
}

async function fetchAndRenderLiveStream() {
    if (!state.isStreaming && state.currentTab !== 'streamer') return;
    try {
        const res = await fetch('/api/v1/stream/live');
        if (!res.ok) return;
        const records = await res.json();
        if (!records || records.length === 0) return;

        // Render latest 8 wire logs from socket receiver
        const recent = records.slice(-8).reverse();
        DOM.rawStreamViewport.innerHTML = recent.map(r => `
            <div class="stream-item-raw">[${r.timestamp}] ${escapeHtml(r.raw_string)}</div>
        `).join('');

        DOM.shaStreamViewport.innerHTML = recent.map(r => `
            <div class="stream-item-sha">SHA-256: ${r.sha256_key}</div>
        `).join('');

        const recentJson = records.slice(-4).reverse();
        DOM.jsonStreamViewport.innerHTML = recentJson.map(r => `
            <div class="json-record-card">${escapeHtml(JSON.stringify(r.formatted_json, null, 2))}</div>
        `).join('');

        DOM.processedCounterBadge.innerText = `EVENTS COMMITTED: ${records.length}`;
        
        fetchLiveTelemetry();
    } catch (e) {}
}

function updateKpisUI() {
    DOM.kpiTotalLogs.innerText = state.totalIngested.toLocaleString();
    DOM.kpiSpeed.innerText = `${state.isStreaming ? state.speed.toFixed(1) : '0.0'} EPS`;
    
    if (DOM.sevCountCritical) DOM.sevCountCritical.innerText = state.sevCritical.toLocaleString();
    if (DOM.sevCountHigh) DOM.sevCountHigh.innerText = state.sevHigh.toLocaleString();
    if (DOM.sevCountMedium) DOM.sevCountMedium.innerText = state.sevMedium.toLocaleString();
    if (DOM.sevCountLow) DOM.sevCountLow.innerText = state.sevLow.toLocaleString();

    if (severityDonutChart) {
        severityDonutChart.data.datasets[0].data = [state.sevCritical, state.sevHigh, state.sevMedium, state.sevLow];
        severityDonutChart.update('none');
    }
}

function updateBufferUI() {
    const fraction = Math.min(1.0, state.bufferRawCount / state.batchThreshold);
    const pct = Math.round(fraction * 100);
    DOM.bufferStatText.innerText = `${state.bufferRawCount} / ${state.batchThreshold} (${pct}%)`;
    DOM.bufferProgressFill.style.width = `${pct}%`;
}

// -------------------------------------------------------------
// 8. TELEMETRY & AUTO-RECONNECT HEARTBEAT
// -------------------------------------------------------------
async function fetchLiveTelemetry() {
    try {
        const res = await fetch('/api/v1/stats');
        if (!res.ok) throw new Error('Network error');
        const data = await res.json();

        if (!state.isBackendOnline) {
            state.isBackendOnline = true;
            DOM.connDot.style.background = '#10b981';
            DOM.connDot.style.boxShadow = '0 0 6px #10b981';
            DOM.connStatusText.innerText = 'PORT 5140 (UDP)';
            DOM.connStatusBadge.style.borderColor = 'rgba(16, 185, 129, 0.25)';
            DOM.connStatusBadge.style.color = '#34d399';
        }

        state.currentEps = data.current_eps || state.currentEps;
        state.anomaliesCount = data.anomalies || state.anomaliesCount;
        state.batchesCount = data.total_batches || state.batchesCount;
        state.isStreaming = data.is_running || state.isStreaming;

        if (DOM.healthCpu) DOM.healthCpu.innerText = `${data.cpu_percent || '0.0'}%`;
        if (DOM.healthRam) DOM.healthRam.innerText = `${data.memory_mb || '0'} MB`;
        if (DOM.healthLatency) DOM.healthLatency.innerText = `${data.p99_latency_ms || '<0.5'}ms`;
        if (DOM.healthDlq) DOM.healthDlq.innerText = `${data.dlq_count || 0}`;

        // Ingest Real-Time Analytics from Server
        if (data.analytics) {
            updateDashboardRealData(data.analytics);
        }

    } catch (e) {
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

// -------------------------------------------------------------
// 9. DATABASE VAULT BATCH INSPECTION & NO-CODE STUDIO
// -------------------------------------------------------------
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
            <td><code title="${f.filename}">${f.filename}</code></td>
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
    const fmtFilename = filename.replace('raw_batch_', 'formatted_batch_').replace('.log', '.json');
    DOM.inspectRawTitle.innerText = filename;
    DOM.inspectRawTitle.title = filename;
    DOM.inspectFmtTitle.innerText = fmtFilename;
    DOM.inspectFmtTitle.title = fmtFilename;

    try {
        const res = await fetch(`/api/v1/files/content?filename=${filename}`);
        if (!res.ok) return;
        const data = await res.json();
        
        DOM.inspectRawContent.innerText = data.raw_content || 'No raw content found';
        
        let formattedText = '';
        if (typeof data.formatted_content === 'object' && data.formatted_content !== null) {
            formattedText = JSON.stringify(data.formatted_content, null, 2);
        } else if (typeof data.formatted_content === 'string') {
            try {
                formattedText = JSON.stringify(JSON.parse(data.formatted_content), null, 2);
            } catch (e) {
                formattedText = data.formatted_content;
            }
        } else {
            formattedText = 'No JSON content found';
        }
        DOM.inspectFmtContent.innerText = formattedText;
    } catch (e) {
        DOM.inspectRawContent.innerText = 'Failed to load file content.';
        DOM.inspectFmtContent.innerText = 'Failed to load file content.';
    }
}

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
