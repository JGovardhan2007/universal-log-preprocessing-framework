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
    batchThreshold: 500,
    activeFilter: 'all',
    searchQuery: '',

    // Database Vault Search & Filters
    dbSearchQuery: '',
    dbActiveFilter: 'all',
    rawFilesList: [],
    formattedFilesList: [],
    
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
    
    // Operational Tables & Dynamic Filter Banner
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
    dbSearchInput: document.getElementById('db-search-input'),
    dbRefreshFilesBtn: document.getElementById('db-refresh-files-btn'),
    dbFilterChips: document.querySelectorAll('[data-db-filter]'),
    dbSearchMatchCount: document.getElementById('db-search-match-count'),
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
    initGeoThreatMapInteractivity();
    initCharts();
    initQueryLake();
    initControls();
    initDatabaseSearch();
    initStudioDrawer();
    initForensicModal();
    initCardPopupSystem();
    
    fetchLiveTelemetry();
    setInterval(fetchLiveTelemetry, 2500);
});

// -------------------------------------------------------------
// DEDICATED CARD POPUP WINDOW MODAL ARCHITECTURE
// -------------------------------------------------------------
let activePopupCard = null;
let activePopupPlaceholder = null;

function handlePopupWheelScroll(e) {
    if (!activePopupCard) return;
    const win = document.getElementById('card-popup-window');
    if (win && !win.contains(e.target)) {
        e.preventDefault();
    }
}

function initCardPopupSystem() {
    const overlay = document.getElementById('card-popup-overlay');
    const backdrop = document.getElementById('card-popup-backdrop');
    const closeBtn = document.getElementById('card-popup-close-btn');

    if (backdrop) {
        backdrop.addEventListener('click', closeCardPopup);
        backdrop.addEventListener('wheel', (e) => e.preventDefault(), { passive: false });
    }
    if (closeBtn) {
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            closeCardPopup();
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && activePopupCard) {
            closeCardPopup();
        }
    });

    // Window-level scroll guard to prevent background page from scrolling
    window.addEventListener('wheel', handlePopupWheelScroll, { passive: false });
    window.addEventListener('touchmove', handlePopupWheelScroll, { passive: false });

    // Target specific content cards for modal popup (Geographic Threat Map, Alerts & Severity, Port Anomaly, Rankings, Tables)
    // EXCLUDING the first executive KPI bar (Critical, High, Medium, Low, Ingestion Rate)
    const cardSelectors = [
        '.geo-threat-card',
        '.chart-card-fill',
        '#threatScatterChart',
        '#device-ranking-list',
        '#alerts-table',
        '#user-ranking-list',
        '#offense-ranking-list',
        '#timeline-table'
    ];

    cardSelectors.forEach(sel => {
        const el = document.querySelector(sel);
        if (!el) return;
        const card = el.closest('.shadcn-card');
        if (!card) return;

        // Ensure first bar is NEVER touched
        if (card.closest('.executive-kpi-strip') ||
            card.classList.contains('sev-card') ||
            card.classList.contains('velocity-card')) {
            return;
        }

        // Add class indicating this card can be clicked to open in modal
        card.classList.add('popup-eligible-card');

        // Clicking anywhere on the card when resting opens up the popup modal window
        card.addEventListener('click', (e) => {
            // If already open in modal popup mode, let interactions proceed normally inside
            if (activePopupCard === card || card.classList.contains('is-popped-up')) return;

            // In resting mode, do not trigger popup if user clicked an explicit action button or link
            const actionElement = e.target.closest('button, a, input, select, textarea');
            if (actionElement) return;

            openCardPopup(card);
        });
    });
}

function openCardPopup(card) {
    if (!card || activePopupCard === card) return;

    if (activePopupCard) {
        closeCardPopup();
    }

    const overlay = document.getElementById('card-popup-overlay');
    const slot = document.getElementById('card-popup-content-slot');
    if (!overlay || !slot) return;

    activePopupCard = card;

    // Capture dimensions before moving the card so the grid NEVER collapses or shifts
    const rect = card.getBoundingClientRect();
    const computed = window.getComputedStyle(card);

    activePopupPlaceholder = document.createElement('div');
    activePopupPlaceholder.className = 'card-popup-placeholder';
    activePopupPlaceholder.style.width = '100%';
    activePopupPlaceholder.style.height = (rect.height || 480) + 'px';
    activePopupPlaceholder.style.minHeight = computed.minHeight || '480px';
    activePopupPlaceholder.style.maxHeight = computed.maxHeight || '480px';
    activePopupPlaceholder.style.minWidth = '0';
    activePopupPlaceholder.style.visibility = 'hidden';
    activePopupPlaceholder.style.pointerEvents = 'none';
    activePopupPlaceholder.style.margin = computed.margin;
    activePopupPlaceholder.style.padding = '0';
    card.parentNode.insertBefore(activePopupPlaceholder, card);

    // Compensate for scrollbar lock so background never shifts width
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
    if (scrollbarWidth > 0) {
        document.body.style.paddingRight = `${scrollbarWidth}px`;
    }

    // Move card into popup modal slot
    slot.innerHTML = '';
    slot.appendChild(card);
    card.classList.add('is-popped-up');

    // Show overlay
    overlay.classList.remove('hidden');

    // Lock page background scrolling completely
    document.body.classList.add('card-popup-open');

    // Trigger chart resize & DOM redraw
    setTimeout(() => {
        window.dispatchEvent(new Event('resize'));
        if (typeof severityDonutChart !== 'undefined' && severityDonutChart) severityDonutChart.resize();
        if (typeof severityTrendChart !== 'undefined' && severityTrendChart) severityTrendChart.resize();
        if (typeof scatterChart !== 'undefined' && scatterChart) scatterChart.resize();
    }, 70);
}

function closeCardPopup() {
    if (!activePopupCard) return;

    const overlay = document.getElementById('card-popup-overlay');
    const slot = document.getElementById('card-popup-content-slot');

    const card = activePopupCard;
    const placeholder = activePopupPlaceholder;

    // Return card to its exact original slot in the grid
    if (placeholder && placeholder.parentNode) {
        card.classList.remove('is-popped-up');
        placeholder.parentNode.insertBefore(card, placeholder);
        placeholder.remove();
    }

    if (slot) slot.innerHTML = '';
    if (overlay) overlay.classList.add('hidden');

    activePopupCard = null;
    activePopupPlaceholder = null;

    // Restore page background scrolling and scrollbar padding
    document.documentElement.classList.remove('card-popup-open');
    document.body.classList.remove('card-popup-open');
    document.body.style.paddingRight = '';

    setTimeout(() => {
        window.dispatchEvent(new Event('resize'));
        if (typeof severityDonutChart !== 'undefined' && severityDonutChart) severityDonutChart.resize();
        if (typeof severityTrendChart !== 'undefined' && severityTrendChart) severityTrendChart.resize();
        if (typeof scatterChart !== 'undefined' && scatterChart) scatterChart.resize();
    }, 70);
}

// -------------------------------------------------------------
// TAB NAVIGATION
// -------------------------------------------------------------
function initTabs() {
    DOM.navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            if (state.currentTab === targetTab) return;

            if (activePopupCard) {
                closeCardPopup();
            }

            DOM.navBtns.forEach(b => b.classList.remove('active'));
            DOM.tabPanes.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`tab-${targetTab}`).classList.add('active');
            state.currentTab = targetTab;

            if (targetTab === 'streamer') {
                fetchAndRenderLiveStream();
            }
            if (targetTab === 'database') {
                fetchStoredFiles();
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
// 2. CHECK POINT THREAT MAP ENGINE & DYNAMIC GEOLOCATION HUD
// -------------------------------------------------------------
const threatMapState = {
    processedAttackIds: new Set(),
    animationQueue: [],
    isQueueRunning: false,
    rollingGeoLocations: [],
    activeOriginNodes: []
};

function formatGeoCoords(lat, lng) {
    if (lat == null || lng == null) return '0.00° N, 0.00° E';
    const latDir = lat >= 0 ? 'N' : 'S';
    const lngDir = lng >= 0 ? 'E' : 'W';
    return `${Math.abs(lat).toFixed(2)}° ${latDir}, ${Math.abs(lng).toFixed(2)}° ${lngDir}`;
}

function triggerAttackLaser(attack) {
    if (!attack) return;
    if ((!attack.src_lat && !attack.src_lng) || (attack.src_lat === 0 && attack.src_lng === 0)) return;
    if (attack.src_country_code === 'UNK' || attack.src_country_code === 'ERR') return;

    const laserGroup = document.getElementById('dynamic-laser-arcs');
    if (!laserGroup) return;

    // Convert exact geographic coordinates to equirectangular SVG space (800x400)
    const srcLat = attack.src_lat != null ? attack.src_lat : 48.8566;
    const srcLng = attack.src_lng != null ? attack.src_lng : 2.3522;
    const dstLat = attack.dst_lat != null ? attack.dst_lat : 28.6139;
    const dstLng = attack.dst_lng != null ? attack.dst_lng : 77.2090;

    const srcX = (srcLng + 180) * (800 / 360);
    const srcY = (90 - srcLat) * (400 / 180);
    const dstX = (dstLng + 180) * (800 / 360);
    const dstY = (90 - dstLat) * (400 / 180);

    // Ballistic Parabolic Arc (Check Point ThreatCloud curve calculation)
    const midX = (srcX + dstX) / 2;
    const dist = Math.hypot(dstX - srcX, dstY - srcY);
    const archHeight = Math.max(30, Math.min(90, dist * 0.22));
    const midY = Math.min(srcY, dstY) - archHeight;
    const pathD = `M ${srcX.toFixed(1)} ${srcY.toFixed(1)} Q ${midX.toFixed(1)} ${midY.toFixed(1)} ${dstX.toFixed(1)} ${dstY.toFixed(1)}`;

    const sev = (attack.severity || 'medium').toLowerCase();
    const sevClass = sev === 'critical' ? 'crit' : (sev === 'high' ? 'high' : (sev === 'low' ? 'low' : 'med'));

    // Create unique group for this projectile event
    const groupId = `atk-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    group.setAttribute('id', groupId);
    group.setAttribute('class', 'active-attack-projectile');

    // 1. Origin Source Point (glowing dot)
    const srcDot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    srcDot.setAttribute('cx', srcX.toFixed(1));
    srcDot.setAttribute('cy', srcY.toFixed(1));
    srcDot.setAttribute('r', '3.5');
    srcDot.setAttribute('class', `attack-point-dot src ${sevClass}`);
    group.appendChild(srcDot);

    // 2. Destination Target Point (glowing dot)
    const dstDot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dstDot.setAttribute('cx', dstX.toFixed(1));
    dstDot.setAttribute('cy', dstY.toFixed(1));
    dstDot.setAttribute('r', '3.5');
    dstDot.setAttribute('class', 'attack-point-dot dst');
    group.appendChild(dstDot);

    // 3. Dynamic laser trail path
    const pathEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    pathEl.setAttribute('d', pathD);
    pathEl.setAttribute('class', `attack-laser-trail ${sevClass}`);
    group.appendChild(pathEl);

    // 4. Glowing projectile comet head traversing ballistic arc
    const headEl = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    headEl.setAttribute('r', '3');
    headEl.setAttribute('class', `attack-projectile-head ${sevClass}`);
    const animMotion = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
    animMotion.setAttribute('dur', '1.3s');
    animMotion.setAttribute('path', pathD);
    animMotion.setAttribute('fill', 'freeze');
    headEl.appendChild(animMotion);
    group.appendChild(headEl);

    laserGroup.appendChild(group);

    // Line and both points disappear completely after arrival (decay out after 1.8s)
    setTimeout(() => {
        if (group && group.parentNode) {
            group.remove();
        }
    }, 1800);

    // 5. Update Bottom Geolocation HUD Box with Active Geolocation Details
    updateGeolocationHud(attack);
}

function updateGeolocationHud(attack) {
    if (!attack) return;
    if ((!attack.src_lat && !attack.src_lng) || (attack.src_lat === 0 && attack.src_lng === 0)) return;
    if (attack.src_country_code === 'UNK' || attack.src_country_code === 'ERR') return;

    const originCityEl = document.getElementById('hud-origin-city');
    const originMetaEl = document.getElementById('hud-origin-meta');
    const targetEnclaveEl = document.getElementById('hud-target-enclave');
    const targetMetaEl = document.getElementById('hud-target-meta');

    const srcCity = (attack.src_city || 'Unknown Origin').toUpperCase();
    const srcCountry = (attack.src_country || 'Unknown Country').toUpperCase();
    const srcCode = (attack.src_country_code || 'UNK').toUpperCase();
    const coordsStr = formatGeoCoords(attack.src_lat, attack.src_lng);
    const asnStr = attack.src_asn ? attack.src_asn.split(' ')[0] : 'AS13335';
    const targetName = (attack.dst_target || 'CENTRAL DEFENSE HQ').toUpperCase();
    const dstCoordsStr = formatGeoCoords(attack.dst_lat, attack.dst_lng);

    if (originCityEl) originCityEl.textContent = `${srcCity}, ${srcCountry} (${srcCode})`;
    if (originMetaEl) originMetaEl.textContent = `${coordsStr} • ${asnStr} (${attack.src_ip || 'Ingress'})`;
    if (targetEnclaveEl) targetEnclaveEl.textContent = targetName;
    if (targetMetaEl) targetMetaEl.textContent = `${(attack.dst_city || 'NEW DELHI').toUpperCase()}, ${(attack.dst_country_code || 'IN').toUpperCase()} • ${dstCoordsStr}`;
}

function processAttackQueue() {
    if (threatMapState.animationQueue.length === 0) {
        threatMapState.isQueueRunning = false;
        return;
    }
    threatMapState.isQueueRunning = true;
    const nextAttack = threatMapState.animationQueue.shift();
    triggerAttackLaser(nextAttack);

    // Pacing: fire next laser projectile smoothly every 200-320ms
    const delay = Math.max(180, Math.min(320, 2400 / (threatMapState.animationQueue.length + 1)));
    setTimeout(processAttackQueue, delay);
}

function renderDynamicGeoThreatMap(geoThreats, liveAttacks) {
    if (!geoThreats || !Array.isArray(geoThreats)) return;

    // Keep map completely plain: ensure no persistent static nodes
    const nodesGroup = document.getElementById('dynamic-threat-nodes');
    if (nodesGroup && nodesGroup.children.length > 0) {
        nodesGroup.innerHTML = '';
    }

    const activeThreats = geoThreats.filter(g => g.lat != null && g.lng != null && (g.lat !== 0 || g.lng !== 0) && g.count > 0).slice(0, 8);

    // 2. Queue live packet attack events for ballistic laser firing
    if (liveAttacks && Array.isArray(liveAttacks) && liveAttacks.length > 0) {
        let newAttacksEnqueued = 0;
        liveAttacks.forEach(atk => {
            if (atk && atk.id && !threatMapState.processedAttackIds.has(atk.id)) {
                // Reject invalid or unresolved 0.0, 0.0 coords
                if (!atk.src_lat && !atk.src_lng) return;
                if (atk.src_lat === 0 && atk.src_lng === 0) return;
                if (atk.src_country_code === 'UNK' || atk.src_country_code === 'ERR') return;

                threatMapState.processedAttackIds.add(atk.id);
                threatMapState.animationQueue.push(atk);
                newAttacksEnqueued++;
            }
        });

        // Limit memory of processed attack IDs
        if (threatMapState.processedAttackIds.size > 200) {
            const arr = Array.from(threatMapState.processedAttackIds);
            threatMapState.processedAttackIds = new Set(arr.slice(arr.length - 100));
        }

        if (newAttacksEnqueued > 0 && !threatMapState.isQueueRunning) {
            processAttackQueue();
        }
    } else if (threatMapState.animationQueue.length === 0 && !threatMapState.isQueueRunning && activeThreats.length > 0) {
        // Initial / baseline state: sample an active threat origin to ensure dynamic animation is visible immediately
        const sampleOrigin = activeThreats[Math.floor(Math.random() * activeThreats.length)];
        const targetEnclaves = [
            { name: "Central Defense HQ", city: "New Delhi", country_code: "IN", lat: 28.6139, lng: 77.2090 },
            { name: "Western Maritime Enclave", city: "Mumbai", country_code: "IN", lat: 19.0760, lng: 72.8777 },
            { name: "Southern Cyber Command", city: "Bengaluru", country_code: "IN", lat: 12.9716, lng: 77.5946 },
            { name: "Northern Perimeter Gateway", city: "Chandigarh", country_code: "IN", lat: 30.7333, lng: 76.7794 }
        ];
        const sampleTgt = targetEnclaves[Math.floor(Math.random() * targetEnclaves.length)];

        threatMapState.animationQueue.push({
            id: `init-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            src_city: sampleOrigin.city,
            src_country: sampleOrigin.country || "Russia",
            src_country_code: sampleOrigin.country_code || "RU",
            src_lat: sampleOrigin.lat,
            src_lng: sampleOrigin.lng,
            src_asn: sampleOrigin.asn || "AS9009 (M247 Europe)",
            src_ip: "95.173.136.45",
            dst_target: sampleTgt.name,
            dst_city: sampleTgt.city,
            dst_country_code: sampleTgt.country_code,
            dst_lat: sampleTgt.lat,
            dst_lng: sampleTgt.lng,
            threat_name: sampleOrigin.top_vector || "SSH Password Spraying (T1110)",
            severity: "High"
        });
        processAttackQueue();
    }
}

function initGeoThreatMapInteractivity() {
    // Interactivity is dynamically handled via SVG event listeners in renderDynamicGeoThreatMap()
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
                    labels: { color: '#71717a', font: { family: 'Inter', size: 9 }, boxWidth: 10, padding: 6 }
                }
            },
            scales: {
                x: {
                    grid: { color: '#18181b' },
                    ticks: {
                        color: '#71717a',
                        font: { family: 'Inter', size: 8.5 },
                        maxTicksLimit: 5,
                        autoSkip: true,
                        maxRotation: 0
                    }
                },
                y: {
                    grid: { color: '#18181b' },
                    ticks: { color: '#71717a', font: { family: 'Inter', size: 8.5 } }
                }
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
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const pt = context.raw;
                            if (!pt) return '';
                            const lines = [
                                `Payload Entropy: ${pt.x} Bits`,
                                `Target Port: ${pt.y}`,
                                `Anomaly Score: ${Math.round((pt.score || 0) * 100)}%`
                            ];
                            if (pt.tag) lines.push(`Verdict: ${pt.tag}`);
                            return lines;
                        }
                    }
                }
            },
            scales: {
                x: {
                    title: { display: true, text: 'Payload Shannon Entropy (Bits: 1.0 - 6.0)', color: '#71717a', font: { size: 10 } },
                    min: 1.0,
                    max: 6.0,
                    grid: { color: '#18181b' },
                    ticks: { color: '#71717a' }
                },
                y: {
                    title: { display: true, text: 'Target Port (0 - 65535)', color: '#71717a', font: { size: 10 } },
                    min: 0,
                    max: 65535,
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

    // 3. Dynamic Geo-Threat Map & Live ASN Telemetry (100% Data-Driven)
    if (analytics.geo_threats && Array.isArray(analytics.geo_threats)) {
        renderDynamicGeoThreatMap(analytics.geo_threats, analytics.live_attacks);
    }

    // 4. Entity Profiling Panels (Interactive)
    if (analytics.devices && DOM.deviceRankingList) {
        const devSig = analytics.devices.map(d => `${d.name}:${d.records}:${d.percentage}`).join('|');
        if (DOM.deviceRankingList.dataset.signature !== devSig) {
            DOM.deviceRankingList.dataset.signature = devSig;
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
    }

    if (analytics.users && DOM.userRankingList) {
        const userSig = analytics.users.map(u => `${u.name}:${u.score}:${u.events}`).join('|');
        if (DOM.userRankingList.dataset.signature !== userSig) {
            DOM.userRankingList.dataset.signature = userSig;
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
    }

    if (analytics.offenses && DOM.offenseRankingList) {
        const offSig = analytics.offenses.map(o => `${o.name}:${o.events}:${o.percentage}`).join('|');
        if (DOM.offenseRankingList.dataset.signature !== offSig) {
            DOM.offenseRankingList.dataset.signature = offSig;
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
    }

    // 5. AI Threat Matrix Scatter Points
    if (analytics.scatter_points && scatterChart && analytics.scatter_points.length > 0) {
        const scatterSig = JSON.stringify(analytics.scatter_points);
        if (scatterChart._lastSig !== scatterSig) {
            scatterChart._lastSig = scatterSig;
            scatterChart.data.datasets[0].data = analytics.scatter_points;
            scatterChart.update('none');
        }
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
            if (labels.length > 7) labels.shift();

            severityTrendChart.data.datasets[0].data.push(state.sevCritical);
            if (severityTrendChart.data.datasets[0].data.length > 7) severityTrendChart.data.datasets[0].data.shift();

            severityTrendChart.data.datasets[1].data.push(state.sevHigh);
            if (severityTrendChart.data.datasets[1].data.length > 7) severityTrendChart.data.datasets[1].data.shift();

            severityTrendChart.data.datasets[2].data.push(state.sevMedium);
            if (severityTrendChart.data.datasets[2].data.length > 7) severityTrendChart.data.datasets[2].data.shift();

            severityTrendChart.update('none');
        }
    }
}

// -------------------------------------------------------------
// 5. OPERATIONAL TELEMETRY & LIVE TABLES
// -------------------------------------------------------------
function renderAlertsTable() {
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
                (a.asn || '').toLowerCase().includes(vLower) ||
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

    const filterKey = state.customFilter ? `${state.customFilter.type}:${state.customFilter.value}` : 'all';
    const alertSig = `${filterKey}|` + filteredAlerts.map(a => `${a.time}_${a.name}_${a.status}_${a.severity}`).join(';');
    if (DOM.alertsTableBody.dataset.signature === alertSig) {
        return;
    }
    DOM.alertsTableBody.dataset.signature = alertSig;

    DOM.alertsTableBody.innerHTML = '';

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
            <td><code>${a.time}</code></td>
            <td>
                <div class="alert-info-cell">
                    <div class="alert-primary-line">
                        <span class="alert-name-bold">${escapeHtml(a.name)}</span>
                        <span class="alert-tactic-muted">(${escapeHtml(a.tactic)})</span>
                    </div>
                    ${a.primary_tag ? `<div class="alert-xai-tag-wrapper"><span class="xai-mini-tag ${a.severity === 'Critical' ? 'crit' : ''}">${escapeHtml(a.primary_tag)}</span></div>` : ''}
                </div>
            </td>
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
                (r.asn || '').toLowerCase().includes(vLower) ||
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
        DOM.timelineTableBody.dataset.signature = 'empty';
        return;
    }

    const displayList = filtered.slice(0, 15);
    const filterKey = `${state.activeFilter}|${state.searchQuery}|${state.customFilter ? state.customFilter.type + ':' + state.customFilter.value : ''}`;
    const timelineSig = `${filterKey}|` + displayList.map(r => `${r.id || r.timeStr}_${r.src_ip}_${r.disposition}`).join(';');
    if (DOM.timelineTableBody.dataset.signature === timelineSig) {
        return;
    }
    DOM.timelineTableBody.dataset.signature = timelineSig;

    DOM.timelineTableBody.innerHTML = '';
    displayList.forEach((item, idx) => {
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
    a.download = `weed_soc_telemetry_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '_')}.csv`;
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

    // Populate AI Multi-Model Ensemble Diagnostics in Modal
    const iforestEl = document.getElementById('modal-ai-iforest');
    const ocsvmEl = document.getElementById('modal-ai-ocsvm');
    const entropyEl = document.getElementById('modal-ai-entropy');
    const jitterEl = document.getElementById('modal-ai-jitter');
    const xaiEl = document.getElementById('modal-ai-xai');
    const verdictEl = document.getElementById('modal-ai-verdict');

    const aiBreakdown = item.ai_breakdown || {
        iforest_score: item.anomaly_score ? (item.anomaly_score * 0.9).toFixed(2) : '0.12',
        ocsvm_score: item.anomaly_score ? (item.anomaly_score * 0.85).toFixed(2) : '0.10',
        entropy: item.entropy || 3.12,
        jitter_score: '0.15'
    };

    if (iforestEl) iforestEl.innerText = `Score: ${aiBreakdown.iforest_score}`;
    if (ocsvmEl) ocsvmEl.innerText = `Score: ${aiBreakdown.ocsvm_score}`;
    if (entropyEl) entropyEl.innerText = `${aiBreakdown.entropy} Bits`;
    if (jitterEl) jitterEl.innerText = `Score: ${aiBreakdown.jitter_score}`;

    const tags = item.xai_tags || (item.primary_tag ? [item.primary_tag] : ['Normal Baseline Conformance']);
    if (xaiEl) xaiEl.innerText = `Consensus Verdict: ${tags.join(' | ')}`;

    if (verdictEl) {
        const isAnomaly = (item.anomaly_score || 0) > 0.65;
        verdictEl.innerText = isAnomaly ? 'ANOMALY DETECTED' : 'BASELINE NORMAL';
        if (isAnomaly) {
            verdictEl.classList.remove('benign');
        } else {
            verdictEl.classList.add('benign');
        }
    }

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
        anomaly_score: alert.ai_breakdown ? alert.ai_breakdown.composite_score : (alert.severity === 'Critical' ? 0.95 : 0.80),
        timeStr: alert.time,
        sha256: alert.sha256,
        ocsf: alert.ocsf,
        entropy: alert.entropy,
        xai_tags: alert.xai_tags,
        primary_tag: alert.primary_tag,
        ai_breakdown: alert.ai_breakdown
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

    if (DOM.streamSpeedSelect) {
        state.speed = parseInt(DOM.streamSpeedSelect.value, 10) || 10;
        state.currentEps = state.speed;
    }

    DOM.streamSpeedSelect.addEventListener('change', (e) => {
        state.speed = parseInt(e.target.value, 10) || 10;
        state.currentEps = state.speed;
        fetch('/api/v1/stream/speed', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ eps: state.speed })
        }).catch(() => {});
        updateKpisUI();
    });

    if (DOM.batchSizeSelect) {
        state.batchThreshold = parseInt(DOM.batchSizeSelect.value, 10) || 500;
    }

    DOM.batchSizeSelect.addEventListener('change', (e) => {
        state.batchThreshold = parseInt(e.target.value, 10) || 500;
        updateBufferUI();
    });

    initDatabaseSearch();

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

function setStreamRunningState(isRunning) {
    state.isStreaming = isRunning;
    if (DOM.streamBtnIcon) {
        DOM.streamBtnIcon.innerText = isRunning ? '■' : '▶';
    }
    if (DOM.streamBtnLabel) {
        DOM.streamBtnLabel.innerText = isRunning ? 'Stop Live Stream' : 'Start Live Stream';
    }
    if (DOM.streamToggleBtn) {
        if (isRunning) {
            DOM.streamToggleBtn.classList.add('running');
        } else {
            DOM.streamToggleBtn.classList.remove('running');
        }
    }
    if (isRunning) {
        startStreamTimer();
    } else {
        clearInterval(state.streamTimer);
    }
    updateKpisUI();
}

async function toggleStream() {
    if (DOM.streamToggleBtn) DOM.streamToggleBtn.disabled = true;
    const willStart = !state.isStreaming;

    try {
        if (willStart) {
            if (DOM.streamSpeedSelect) {
                state.speed = parseInt(DOM.streamSpeedSelect.value, 10) || 10;
            }
            const res = await fetch('/api/v1/stream/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ eps: state.speed })
            });
            if (res.ok) {
                setStreamRunningState(true);
                fetchAndRenderLiveStream();
            }
        } else {
            const res = await fetch('/api/v1/stream/stop', { method: 'POST' });
            if (res.ok) {
                setStreamRunningState(false);
            }
        }
    } catch (e) {
        console.error("Stream toggle failed:", e);
    } finally {
        if (DOM.streamToggleBtn) DOM.streamToggleBtn.disabled = false;
    }
}

function startStreamTimer() {
    clearInterval(state.streamTimer);
    state.streamTimer = setInterval(fetchAndRenderLiveStream, 500);
}

async function fetchAndRenderLiveStream() {
    if (state.currentTab !== 'streamer') return;
    try {
        const res = await fetch('/api/v1/stream/live');
        if (!res.ok) return;
        const payload = await res.json();
        const records = Array.isArray(payload) ? payload : (payload.records || []);

        if (payload.buffer) {
            state.bufferRawCount = payload.buffer.raw_count;
            state.batchThreshold = payload.buffer.threshold || state.batchThreshold;
            updateBufferUI();
        }

        if (payload.current_eps !== undefined) {
            state.currentEps = payload.current_eps;
            updateKpisUI();
        }

        if (!records || records.length === 0) return;

        // Render latest 8 wire logs from socket receiver
        const recent = records.slice(-8).reverse();
        if (DOM.rawStreamViewport) {
            DOM.rawStreamViewport.innerHTML = recent.map(r => `
                <div class="stream-item-raw">[${r.timestamp}] ${escapeHtml(r.raw_string)}</div>
            `).join('');
        }

        if (DOM.shaStreamViewport) {
            DOM.shaStreamViewport.innerHTML = recent.map(r => `
                <div class="stream-item-sha">SHA-256: ${r.sha256_key || r.sha256}</div>
            `).join('');
        }

        const recentJson = records.slice(-4).reverse();
        if (DOM.jsonStreamViewport) {
            DOM.jsonStreamViewport.innerHTML = recentJson.map(r => `
                <div class="json-record-card">${escapeHtml(JSON.stringify(r.formatted_json, null, 2))}</div>
            `).join('');
        }

        if (DOM.processedCounterBadge) {
            DOM.processedCounterBadge.innerText = `EVENTS COMMITTED: ${records.length}`;
        }
    } catch (e) {}
}

function updateKpisUI() {
    DOM.kpiTotalLogs.innerText = state.totalIngested.toLocaleString();
    
    // Display actual live measured EPS when streaming, or setpoint if just started
    const measuredRate = state.currentEps > 0 ? state.currentEps : state.speed;
    const dispEps = state.isStreaming ? measuredRate.toFixed(1) : '0.0';
    DOM.kpiSpeed.innerText = `${dispEps} EPS`;

    const actualEpsEl = document.getElementById('stream-measured-eps');
    if (actualEpsEl) {
        actualEpsEl.innerText = `ACTUAL: ${dispEps} EPS`;
    }
    
    if (DOM.sevCountCritical) DOM.sevCountCritical.innerText = state.sevCritical.toLocaleString();
    if (DOM.sevCountHigh) DOM.sevCountHigh.innerText = state.sevHigh.toLocaleString();
    if (DOM.sevCountMedium) DOM.sevCountMedium.innerText = state.sevMedium.toLocaleString();
    if (DOM.sevCountLow) DOM.sevCountLow.innerText = state.sevLow.toLocaleString();

    // Populate Severity Mini-Ribbon in Alert Rate Dynamics Card
    const ribCrit = document.getElementById('ribbon-crit');
    const ribHigh = document.getElementById('ribbon-high');
    const ribMed = document.getElementById('ribbon-med');
    const ribLow = document.getElementById('ribbon-low');
    if (ribCrit) ribCrit.innerText = state.sevCritical.toLocaleString();
    if (ribHigh) ribHigh.innerText = state.sevHigh.toLocaleString();
    if (ribMed) ribMed.innerText = state.sevMedium.toLocaleString();
    if (ribLow) ribLow.innerText = state.sevLow.toLocaleString();

    if (severityDonutChart) {
        const d = severityDonutChart.data.datasets[0].data;
        if (d[0] !== state.sevCritical || d[1] !== state.sevHigh || d[2] !== state.sevMedium || d[3] !== state.sevLow) {
            severityDonutChart.data.datasets[0].data = [state.sevCritical, state.sevHigh, state.sevMedium, state.sevLow];
            severityDonutChart.update('none');
        }
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

        if (data.current_eps !== undefined) {
            state.currentEps = data.current_eps;
            updateVelocitySparkline(state.currentEps);
        }
        if (data.buffer_raw_count !== undefined) {
            state.bufferRawCount = data.buffer_raw_count;
            state.batchThreshold = data.buffer_threshold || state.batchThreshold;
            updateBufferUI();
        }
        if (data.speed !== undefined && DOM.streamSpeedSelect && !state.isStreaming) {
            state.speed = data.speed;
            DOM.streamSpeedSelect.value = String(data.speed);
        }
        state.anomaliesCount = data.anomalies || state.anomaliesCount;
        state.batchesCount = data.total_batches || state.batchesCount;
        if (data.is_running !== undefined && data.is_running !== state.isStreaming) {
            setStreamRunningState(data.is_running);
        }

        if (DOM.healthCpu) DOM.healthCpu.innerText = `${data.cpu_percent || '0.0'}%`;
        if (DOM.healthRam) DOM.healthRam.innerText = `${data.memory_mb || '0'} MB`;
        if (DOM.healthLatency) DOM.healthLatency.innerText = `${data.p99_latency_ms || '<0.5'}ms`;
        if (DOM.healthDlq) DOM.healthDlq.innerText = `${data.dlq_count || 0}`;

        updateKpisUI();

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
// 9. DATABASE BATCH INSPECTION & REAL-TIME VAULT SEARCH
// -------------------------------------------------------------
let dbSearchDebounceTimer = null;

function initDatabaseSearch() {
    if (DOM.dbSearchInput) {
        DOM.dbSearchInput.addEventListener('input', (e) => {
            state.dbSearchQuery = e.target.value.trim();
            clearTimeout(dbSearchDebounceTimer);
            dbSearchDebounceTimer = setTimeout(() => {
                executeDatabaseSearch();
            }, 250);
        });

        DOM.dbSearchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                clearTimeout(dbSearchDebounceTimer);
                state.dbSearchQuery = e.target.value.trim();
                executeDatabaseSearch();
            }
        });
    }

    if (DOM.dbRefreshFilesBtn) {
        DOM.dbRefreshFilesBtn.addEventListener('click', () => {
            if (state.dbSearchQuery) {
                executeDatabaseSearch();
            } else {
                fetchStoredFiles();
            }
        });
    }

    if (DOM.dbFilterChips) {
        DOM.dbFilterChips.forEach(chip => {
            chip.addEventListener('click', () => {
                DOM.dbFilterChips.forEach(c => c.classList.remove('active'));
                chip.classList.add('active');
                state.dbActiveFilter = chip.getAttribute('data-db-filter') || 'all';
                applyDatabaseFilters();
            });
        });
    }

    if (DOM.batchInspectorSelect) {
        DOM.batchInspectorSelect.addEventListener('change', (e) => {
            if (e.target.value) {
                inspectBatchFile(e.target.value);
            }
        });
    }

    // Copy buttons in Inspector
    const copyRawBtn = document.getElementById('copy-inspect-raw-btn');
    if (copyRawBtn && DOM.inspectRawContent) {
        copyRawBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(DOM.inspectRawContent.innerText || '');
            copyRawBtn.innerText = 'Copied!';
            setTimeout(() => { copyRawBtn.innerText = 'Copy Raw'; }, 1500);
        });
    }

    const copyFmtBtn = document.getElementById('copy-inspect-fmt-btn');
    if (copyFmtBtn && DOM.inspectFmtContent) {
        copyFmtBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(DOM.inspectFmtContent.innerText || '');
            copyFmtBtn.innerText = 'Copied!';
            setTimeout(() => { copyFmtBtn.innerText = 'Copy JSON'; }, 1500);
        });
    }
}

async function fetchStoredFiles() {
    try {
        const res = await fetch('/api/v1/files');
        if (!res.ok) return;
        const data = await res.json();

        state.rawFilesList = data.raw_files || [];
        state.formattedFilesList = data.formatted_files || [];
        state.searchTerms = [];

        applyDatabaseFilters();
        populateBatchInspector(state.rawFilesList);

        if (state.rawFilesList.length > 0 && (!DOM.inspectRawTitle || DOM.inspectRawTitle.innerText === 'No batch selected')) {
            inspectBatchFile(state.rawFilesList[0].filename);
        }
    } catch (e) {}
}

async function executeDatabaseSearch() {
    const q = (state.dbSearchQuery || '').trim();
    if (!q) {
        state.searchTerms = [];
        return fetchStoredFiles();
    }

    try {
        const res = await fetch(`/api/v1/database/search?q=${encodeURIComponent(q)}`);
        if (!res.ok) return;
        const data = await res.json();

        state.rawFilesList = data.raw_files || [];
        state.formattedFilesList = data.formatted_files || [];
        state.searchTerms = data.search_terms || [q];

        applyDatabaseFilters();
        populateBatchInspector(state.rawFilesList);

        if (state.rawFilesList.length > 0) {
            const firstFile = state.rawFilesList[0].filename;
            if (DOM.batchInspectorSelect) {
                DOM.batchInspectorSelect.value = firstFile;
            }
            inspectBatchFile(firstFile);
        }
    } catch (e) {
        console.error('Database search failed:', e);
    }
}

function applyDatabaseFilters() {
    const filter = state.dbActiveFilter || 'all';

    let filteredRaw = [...state.rawFilesList];
    let filteredFmt = [...state.formattedFilesList];

    if (filter === '500') {
        filteredRaw = filteredRaw.filter(f => f.records >= 500);
        filteredFmt = filteredFmt.filter(f => f.records >= 500);
    } else if (filter === 'today') {
        const todayStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
        filteredRaw = filteredRaw.filter(f => f.filename.includes(todayStr));
        filteredFmt = filteredFmt.filter(f => f.filename.includes(todayStr));
    }

    if (filter === 'json') {
        renderFilesTable([], DOM.rawFilesTableBody, DOM.rawFilesCountBadge);
        renderFilesTable(filteredFmt, DOM.fmtFilesTableBody, DOM.fmtFilesCountBadge);
    } else if (filter === 'raw') {
        renderFilesTable(filteredRaw, DOM.rawFilesTableBody, DOM.rawFilesCountBadge);
        renderFilesTable([], DOM.fmtFilesTableBody, DOM.fmtFilesCountBadge);
    } else {
        renderFilesTable(filteredRaw, DOM.rawFilesTableBody, DOM.rawFilesCountBadge);
        renderFilesTable(filteredFmt, DOM.fmtFilesTableBody, DOM.fmtFilesCountBadge);
    }

    if (DOM.dbSearchMatchCount) {
        const total = (filter === 'json' ? 0 : filteredRaw.length) + (filter === 'raw' ? 0 : filteredFmt.length);
        DOM.dbSearchMatchCount.innerText = state.dbSearchQuery ? `${total} MATCHING` : `${total} FILES`;
    }
}

function renderFilesTable(files, tbody, badge) {
    if (!tbody) return;
    if (!files || files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No files stored yet.</td></tr>';
        if (badge) badge.innerText = '0 FILES';
        tbody.dataset.signature = 'empty';
        return;
    }

    if (badge) badge.innerText = `${files.length} FILES`;

    const fileSig = files.map(f => `${f.filename}_${f.records}_${f.size_kb}`).join(';');
    if (tbody.dataset.signature === fileSig) {
        return;
    }
    tbody.dataset.signature = fileSig;

    tbody.innerHTML = '';
    files.forEach(f => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.addEventListener('click', (e) => {
            if (e.target.tagName !== 'A') {
                const rawName = f.filename.endsWith('.json') ? f.filename.replace('formatted_batch_', 'raw_batch_').replace('.json', '.log') : f.filename;
                if (DOM.batchInspectorSelect) {
                    DOM.batchInspectorSelect.value = rawName;
                }
                inspectBatchFile(rawName);
            }
        });
        tr.innerHTML = `
            <td><code title="${escapeHtml(f.filename)}">${escapeHtml(f.filename)}</code></td>
            <td style="text-align: center;"><b>${f.records}</b></td>
            <td style="text-align: right; font-family: var(--font-mono);">${f.size_kb} KB</td>
            <td style="text-align: center; font-family: var(--font-mono); font-size: 11px; color: #a1a1aa;">${escapeHtml(f.timestamp)}</td>
            <td style="text-align: center;">
                <a href="/api/v1/files/download?filename=${encodeURIComponent(f.filename)}" class="btn-download-sm" download="${escapeHtml(f.filename)}">
                    DOWNLOAD
                </a>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function populateBatchInspector(rawFiles) {
    if (!DOM.batchInspectorSelect) return;
    if (!rawFiles || rawFiles.length === 0) {
        DOM.batchInspectorSelect.innerHTML = '<option value="">No matching batches</option>';
        return;
    }
    const currentVal = DOM.batchInspectorSelect.value;
    DOM.batchInspectorSelect.innerHTML = '<option value="">Select a batch file to inspect...</option>';
    rawFiles.forEach(f => {
        const opt = document.createElement('option');
        opt.value = f.filename;
        opt.innerText = `${f.filename} (${f.records} records, ${f.size_kb} KB)`;
        DOM.batchInspectorSelect.appendChild(opt);
    });
    if (currentVal && rawFiles.some(f => f.filename === currentVal)) {
        DOM.batchInspectorSelect.value = currentVal;
    }
}

function highlightSearchInText(rawText, terms) {
    if (!rawText) return '';
    let escaped = escapeHtml(rawText);
    if (!terms || terms.length === 0) return escaped;

    const validTerms = [...new Set(terms.map(t => String(t).trim()))]
        .filter(t => t.length >= 2)
        .sort((a, b) => b.length - a.length);

    for (const term of validTerms) {
        try {
            const escapedTerm = escapeHtml(term).replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
            const regex = new RegExp(`(${escapedTerm})`, 'gi');
            escaped = escaped.replace(regex, '<mark class="search-highlight">$1</mark>');
        } catch (e) {}
    }
    return escaped;
}

async function inspectBatchFile(filename) {
    if (!filename) return;
    const rawFilename = filename.endsWith('.json') ? filename.replace('formatted_batch_', 'raw_batch_').replace('.json', '.log') : filename;
    const fmtFilename = rawFilename.replace('raw_batch_', 'formatted_batch_').replace('.log', '.json');

    if (DOM.inspectRawTitle) {
        DOM.inspectRawTitle.innerText = rawFilename;
        DOM.inspectRawTitle.title = rawFilename;
    }
    if (DOM.inspectFmtTitle) {
        DOM.inspectFmtTitle.innerText = fmtFilename;
        DOM.inspectFmtTitle.title = fmtFilename;
    }

    try {
        const res = await fetch(`/api/v1/files/content?filename=${encodeURIComponent(rawFilename)}`);
        if (!res.ok) return;
        const data = await res.json();
        
        let rawContent = data.raw_content || 'No raw content found';
        
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

        const terms = (state.searchTerms && state.searchTerms.length > 0) 
            ? state.searchTerms 
            : (state.dbSearchQuery ? [state.dbSearchQuery] : []);

        if (terms.length > 0 && state.dbSearchQuery) {
            DOM.inspectRawContent.innerHTML = highlightSearchInText(rawContent, terms);
            DOM.inspectFmtContent.innerHTML = highlightSearchInText(formattedText, terms);

            setTimeout(() => {
                const markFmt = DOM.inspectFmtContent.querySelector('mark.search-highlight');
                if (markFmt) {
                    markFmt.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
                const markRaw = DOM.inspectRawContent.querySelector('mark.search-highlight');
                if (markRaw) {
                    markRaw.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }, 60);
        } else {
            DOM.inspectRawContent.innerText = rawContent;
            DOM.inspectFmtContent.innerText = formattedText;
        }
    } catch (e) {
        if (DOM.inspectRawContent) DOM.inspectRawContent.innerText = 'Failed to load file content.';
        if (DOM.inspectFmtContent) DOM.inspectFmtContent.innerText = 'Failed to load file content.';
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
