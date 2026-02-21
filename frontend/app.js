let currentData = null;
let compareData = null;
let scanHistory = JSON.parse(localStorage.getItem("ls_history") || "[]");

const API_BASE = "http://localhost:3000";

document.addEventListener("DOMContentLoaded", () => {
    lucide.createIcons();
    updateHistoryBadge();

    document.getElementById("url-input").addEventListener("keydown", e => {
        if (e.key === "Enter") scan();
    });
});

function toggleTheme() {
    document.body.classList.toggle("light");
    const isLight = document.body.classList.contains("light");
    const icon = document.getElementById("theme-icon");
    icon.setAttribute("data-lucide", isLight ? "sun" : "moon");
    localStorage.setItem("ls_theme", isLight ? "light" : "dark");
    lucide.createIcons();
}

(function () {
    if (localStorage.getItem("ls_theme") === "light") {
        document.body.classList.add("light");
        const icon = document.getElementById("theme-icon");
        if (icon) icon.setAttribute("data-lucide", "sun");
    }
})();

function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    const icons = { info: "info", success: "check-circle", error: "alert-circle" };
    toast.innerHTML = `<i data-lucide="${icons[type] || "info"}" style="width:16px;height:16px;flex-shrink:0"></i><span>${message}</span>`;
    container.appendChild(toast);
    lucide.createIcons();
    setTimeout(() => {
        toast.classList.add("removing");
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

const SCAN_STEPS = [
    { id: "dns", label: "DNS Resolution", icon: "globe" },
    { id: "whois", label: "WHOIS Lookup", icon: "file-search" },
    { id: "ssl", label: "SSL Certificate", icon: "lock" },
    { id: "headers", label: "HTTP Headers", icon: "shield" },
    { id: "redirects", label: "Redirect Chain", icon: "arrow-right-circle" },
    { id: "phishing", label: "Phishing Detection", icon: "alert-triangle" },
    { id: "tech", label: "Technology Detection", icon: "cpu" },
    { id: "perf", label: "Performance Test", icon: "zap" },
];

function showScanProgress() {
    const el = document.getElementById("scan-progress");
    const stepsEl = document.getElementById("scan-steps");
    stepsEl.innerHTML = SCAN_STEPS.map(s => `
    <div class="scan-step" id="step-${s.id}">
      <div class="scan-step-icon"><i data-lucide="${s.icon}" style="width:14px;height:14px"></i></div>
      <span>${s.label}</span>
    </div>
  `).join("");
    el.classList.add("active");
    lucide.createIcons();
    animateSteps();
}

async function animateSteps() {
    const bar = document.getElementById("scan-bar-fill");
    for (let i = 0; i < SCAN_STEPS.length; i++) {
        const step = document.getElementById(`step-${SCAN_STEPS[i].id}`);
        step.classList.add("active");
        step.querySelector(".scan-step-icon").innerHTML = '<div class="step-spinner"></div>';
        bar.style.width = `${((i + 0.5) / SCAN_STEPS.length) * 100}%`;
        await sleep(300 + Math.random() * 400);
        step.classList.remove("active");
        step.classList.add("done");
        step.querySelector(".scan-step-icon").innerHTML = '<i data-lucide="check" style="width:14px;height:14px"></i>';
        lucide.createIcons();
        bar.style.width = `${((i + 1) / SCAN_STEPS.length) * 100}%`;
    }
}

function hideScanProgress() {
    document.getElementById("scan-progress").classList.remove("active");
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function scan() {
    const input = document.getElementById("url-input");
    const btn = document.getElementById("scan-btn");
    let url = input.value.trim();
    if (!url) { showToast("Please enter a URL to scan", "error"); return; }

    document.getElementById("results").classList.remove("active");
    document.getElementById("compare-container").classList.remove("active");

    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader-2" class="spinner" style="width:18px;height:18px"></i><span>Analyzing...</span>';
    lucide.createIcons();

    showScanProgress();

    try {
        const fetchUrl = `${API_BASE}/api/analyze`;
        const res = await fetch(fetchUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url.startsWith("http") ? url : "https://" + url })
        });

        const json = await res.json();

        if (json.status === "ok") {
            await sleep(600);
            hideScanProgress();
            currentData = json.data;
            renderResults(json.data);
            addToHistory(json.data);
            if (json.cached) showToast("Results loaded from cache", "info");
            else showToast(`Scan complete — ${json.data.risk.level}`, json.data.risk.level === "Safe" ? "success" : "error");
        } else {
            hideScanProgress();
            showToast(json.message || "Analysis failed", "error");
        }
    } catch (e) {
        hideScanProgress();
        showToast(`Connection failed: ${e.message}`, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="scan" style="width:18px;height:18px"></i><span>Analyze</span>';
        lucide.createIcons();
    }
}

function renderResults(data) {
    const resultsEl = document.getElementById("results");
    resultsEl.classList.add("active");

    renderOverview(data);
    renderSSLTab(data);
    renderDNSTab(data);
    renderRedirectsTab(data);
    renderTechTab(data);
    renderHeadersTab(data);
    renderPhishingTab(data);
    renderWHOISTab(data);
    renderPerformanceTab(data);
    renderPreview(data);

    switchTab("ssl");
    lucide.createIcons();

    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderOverview(data) {
    const risk = data.risk;
    const levelClass = risk.level === "Safe" ? "safe" : risk.level === "Suspicious" ? "suspicious" : "high";

    drawGauge(risk.percentage, levelClass);

    document.getElementById("gauge-score").textContent = risk.score;
    document.getElementById("gauge-score").className = `gauge-score text-${levelClass}`;

    const labels = { safe: "SECURE", suspicious: "SUSPICIOUS", high: "HIGH RISK" };
    const labelEl = document.getElementById("gauge-label");
    labelEl.textContent = labels[levelClass];
    labelEl.className = `gauge-label text-${levelClass}`;
    document.getElementById("gauge-sublabel").textContent = `${risk.score} / ${risk.maxScore}`;

    document.getElementById("overview-domain").textContent = data.domain;
    document.getElementById("overview-url").textContent = data.url;

    const metaEl = document.getElementById("overview-meta");
    metaEl.innerHTML = `
    <div class="overview-meta-item">
      <i data-lucide="calendar" style="width:14px;height:14px"></i>
      <span class="overview-meta-label">Created:</span>
      <span>${formatDate(data.domainCreated)}</span>
    </div>
    <div class="overview-meta-item">
      <i data-lucide="server" style="width:14px;height:14px"></i>
      <span class="overview-meta-label">Registrar:</span>
      <span>${truncate(data.registrar, 30)}</span>
    </div>
    <div class="overview-meta-item">
      <i data-lucide="${data.ssl?.valid ? 'lock' : 'unlock'}" style="width:14px;height:14px"></i>
      <span class="overview-meta-label">SSL:</span>
      <span>${data.ssl?.valid ? 'Valid' : 'Invalid'}</span>
    </div>
    <div class="overview-meta-item">
      <i data-lucide="zap" style="width:14px;height:14px"></i>
      <span class="overview-meta-label">Speed:</span>
      <span>${data.performance?.responseTime ? data.performance.responseTime + 'ms' : 'N/A'}</span>
    </div>
    ${data.statusCode ? `
    <div class="overview-meta-item">
      <i data-lucide="activity" style="width:14px;height:14px"></i>
      <span class="overview-meta-label">Status:</span>
      <span>${data.statusCode}</span>
    </div>` : ''}
  `;

    const signalsEl = document.getElementById("signals-grid");
    let positiveHTML = '';
    let negativeHTML = '';

    if (risk.positives && risk.positives.length > 0) {
        positiveHTML = `
      <div class="signal-box positive">
        <div class="signal-box-title"><i data-lucide="shield-check" style="width:16px;height:16px"></i> Positive Signals (${risk.positives.length})</div>
        ${risk.positives.map(p => `<div class="signal-item"><i data-lucide="check" style="width:12px;height:12px"></i>${p}</div>`).join('')}
      </div>`;
    }

    if (risk.reasons && risk.reasons.length > 0) {
        negativeHTML = `
      <div class="signal-box negative">
        <div class="signal-box-title"><i data-lucide="alert-triangle" style="width:16px;height:16px"></i> Risk Factors (${risk.reasons.length})</div>
        ${risk.reasons.map(r => `<div class="signal-item"><i data-lucide="x" style="width:12px;height:12px"></i>${r}</div>`).join('')}
      </div>`;
    }

    signalsEl.innerHTML = positiveHTML + negativeHTML;
}

function drawGauge(percentage, levelClass) {
    const canvas = document.getElementById("gauge-canvas");
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const size = 160;

    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + "px";
    canvas.style.height = size + "px";
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const radius = 65;
    const lineWidth = 10;
    const startAngle = 0.75 * Math.PI;
    const endAngle = 2.25 * Math.PI;
    const totalArc = endAngle - startAngle;

    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.strokeStyle = "rgba(100,100,140,0.15)";
    ctx.lineWidth = lineWidth;
    ctx.lineCap = "round";
    ctx.stroke();

    const colors = {
        safe: { start: "#22c55e", end: "#4ade80" },
        suspicious: { start: "#f59e0b", end: "#fbbf24" },
        high: { start: "#ef4444", end: "#f87171" }
    };
    const c = colors[levelClass] || colors.safe;

    const safetyPercentage = 100 - percentage;
    const fillAngle = startAngle + (totalArc * safetyPercentage / 100);

    const grad = ctx.createLinearGradient(0, size, size, 0);
    grad.addColorStop(0, c.start);
    grad.addColorStop(1, c.end);

    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, fillAngle);
    ctx.strokeStyle = grad;
    ctx.lineWidth = lineWidth;
    ctx.lineCap = "round";
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, fillAngle);
    ctx.strokeStyle = c.start;
    ctx.lineWidth = lineWidth + 6;
    ctx.globalAlpha = 0.15;
    ctx.lineCap = "round";
    ctx.stroke();
    ctx.globalAlpha = 1;
}

function renderSSLTab(data) {
    const el = document.getElementById("tab-ssl");
    if (!data.ssl) { el.innerHTML = '<p style="color:var(--text-muted)">SSL data not available</p>'; return; }
    const ssl = data.ssl;

    if (!ssl.valid) {
        el.innerHTML = `
      <div class="detail-card" style="border-left:3px solid var(--red)">
        <div class="detail-card-title" style="color:var(--red)"><i data-lucide="shield-off" style="width:16px;height:16px"></i> SSL Certificate Invalid</div>
        <p style="font-size:13px;color:var(--text-secondary)">${ssl.error || 'Could not verify SSL certificate'}</p>
      </div>`;
        return;
    }

    const daysColor = ssl.daysRemaining > 30 ? 'var(--green)' : ssl.daysRemaining > 14 ? 'var(--orange)' : 'var(--red)';

    el.innerHTML = `
    <div class="detail-card" style="border-left:3px solid var(--green)">
      <div class="detail-card-title"><i data-lucide="shield-check" style="width:16px;height:16px"></i> SSL Certificate Details</div>
      <div class="kv-row"><span class="kv-key">Status</span><span class="kv-value" style="color:var(--green);font-weight:700">✓ Valid</span></div>
      <div class="kv-row"><span class="kv-key">Issuer</span><span class="kv-value">${ssl.issuer}</span></div>
      <div class="kv-row"><span class="kv-key">Subject</span><span class="kv-value">${ssl.subject}</span></div>
      <div class="kv-row"><span class="kv-key">Protocol</span><span class="kv-value">${ssl.protocol || 'N/A'}</span></div>
      <div class="kv-row"><span class="kv-key">Valid From</span><span class="kv-value">${ssl.validFrom || 'N/A'}</span></div>
      <div class="kv-row"><span class="kv-key">Valid To</span><span class="kv-value">${ssl.validTo || 'N/A'}</span></div>
      <div class="kv-row"><span class="kv-key">Days Remaining</span><span class="kv-value" style="color:${daysColor};font-weight:700">${ssl.daysRemaining} days</span></div>
      ${ssl.bits ? `<div class="kv-row"><span class="kv-key">Key Size</span><span class="kv-value">${ssl.bits} bits</span></div>` : ''}
      <div class="kv-row"><span class="kv-key">Serial</span><span class="kv-value">${ssl.serialNumber || 'N/A'}</span></div>
      <div class="kv-row"><span class="kv-key">Fingerprint</span><span class="kv-value">${ssl.fingerprint || 'N/A'}</span></div>
    </div>`;
}

function renderDNSTab(data) {
    const el = document.getElementById("tab-dns");
    if (!data.dns) { el.innerHTML = '<p style="color:var(--text-muted)">DNS data not available</p>'; return; }

    const dnsTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
    let html = '';

    dnsTypes.forEach(type => {
        const records = data.dns[type];
        if (!records || (Array.isArray(records) && records.length === 0)) return;

        html += `<div class="detail-card">
      <div class="detail-card-title"><span class="dns-badge">${type}</span> Records</div>
      <table class="dns-table">
        <thead><tr><th>#</th><th>Value</th>${type === 'MX' ? '<th>Priority</th>' : ''}</tr></thead>
        <tbody>`;

        if (type === 'SOA' && records && typeof records === 'object' && !Array.isArray(records)) {
            html += `<tr><td>1</td><td>${records.nsname || ''} — ${records.hostmaster || ''}</td></tr>`;
        } else if (Array.isArray(records)) {
            records.forEach((r, i) => {
                if (type === 'MX') {
                    html += `<tr><td>${i + 1}</td><td>${r.exchange}</td><td>${r.priority}</td></tr>`;
                } else {
                    html += `<tr><td>${i + 1}</td><td>${typeof r === 'string' ? r : JSON.stringify(r)}</td></tr>`;
                }
            });
        }

        html += `</tbody></table></div>`;
    });

    el.innerHTML = html || '<p style="color:var(--text-muted);padding:16px">No DNS records found</p>';
}

function renderRedirectsTab(data) {
    const el = document.getElementById("tab-redirects");
    if (!data.redirectChain || data.redirectChain.length === 0) {
        el.innerHTML = '<p style="color:var(--text-muted);padding:16px">No redirect data available</p>';
        return;
    }

    el.innerHTML = `
    <div class="detail-card">
      <div class="detail-card-title">
        <i data-lucide="arrow-right-circle" style="width:16px;height:16px"></i>
        Redirect Chain (${data.redirectChain.length} ${data.redirectChain.length === 1 ? 'hop' : 'hops'})
      </div>
      <div class="redirect-chain">
        ${data.redirectChain.map((r, i) => {
        const statusClass = r.status >= 200 && r.status < 300 ? 's2xx' :
            r.status >= 300 && r.status < 400 ? 's3xx' :
                r.status >= 400 && r.status < 500 ? 's4xx' : 's5xx';
        return `
            <div class="redirect-item">
              <div class="redirect-dot"></div>
              <div class="redirect-url">${r.url}</div>
              <span class="redirect-status ${statusClass}">${r.status} ${r.statusText}</span>
            </div>`;
    }).join('')}
      </div>
    </div>`;
}

function renderTechTab(data) {
    const el = document.getElementById("tab-tech");
    if (!data.technologies || data.technologies.length === 0) {
        el.innerHTML = '<p style="color:var(--text-muted);padding:16px">No technologies detected via headers</p>';
        return;
    }

    el.innerHTML = `
    <div class="tech-grid">
      ${data.technologies.map(t => `
        <div class="tech-item">
          <div class="tech-icon"><i data-lucide="${t.icon}" style="width:18px;height:18px"></i></div>
          <div>
            <div class="tech-name">${t.name}</div>
            <div class="tech-cat">${t.cat}</div>
          </div>
        </div>
      `).join('')}
    </div>`;
}

function renderHeadersTab(data) {
    const el = document.getElementById("tab-headers");
    if (!data.headers || Object.keys(data.headers).length === 0) {
        el.innerHTML = '<p style="color:var(--text-muted);padding:16px">No headers available</p>';
        return;
    }

    const important = [
        "content-security-policy", "strict-transport-security", "x-frame-options",
        "x-content-type-options", "x-xss-protection", "referrer-policy", "permissions-policy"
    ];

    const securityHeaders = {};
    const otherHeaders = {};

    Object.entries(data.headers).forEach(([k, v]) => {
        if (important.includes(k)) securityHeaders[k] = v;
        else otherHeaders[k] = v;
    });

    let html = `
    <div class="detail-card">
      <div class="detail-card-title"><i data-lucide="shield" style="width:16px;height:16px"></i> Security Headers</div>
      <table class="headers-table">
        <thead><tr><th>Header</th><th>Value</th></tr></thead>
        <tbody>`;

    important.forEach(h => {
        const val = data.headers[h];
        html += `<tr>
      <td>${h}</td>
      <td>${val
                ? `<span style="color:var(--green)">✓</span> ${truncate(val, 60)}`
                : `<span style="color:var(--red)">✗ Missing</span>`
            }</td>
    </tr>`;
    });

    html += `</tbody></table></div>`;

    if (Object.keys(otherHeaders).length > 0) {
        html += `
    <div class="detail-card">
      <div class="detail-card-title"><i data-lucide="list" style="width:16px;height:16px"></i> All Headers (${Object.keys(otherHeaders).length})</div>
      <table class="headers-table">
        <thead><tr><th>Header</th><th>Value</th></tr></thead>
        <tbody>${Object.entries(otherHeaders).map(([k, v]) =>
            `<tr><td>${k}</td><td>${truncate(v, 80)}</td></tr>`
        ).join('')}</tbody>
      </table>
    </div>`;
    }

    el.innerHTML = html;
}

function renderPhishingTab(data) {
    const el = document.getElementById("tab-phishing");

    if (!data.phishing || data.phishing.length === 0) {
        el.innerHTML = `
      <div class="phishing-safe">
        <div class="phishing-safe-text">
          <i data-lucide="shield-check" style="width:20px;height:20px"></i>
          No phishing / typosquatting indicators detected
        </div>
      </div>`;
        return;
    }

    el.innerHTML = data.phishing.map(p => `
    <div class="phishing-alert">
      <div class="phishing-alert-title">
        <i data-lucide="alert-octagon" style="width:18px;height:18px"></i>
        Typosquatting Warning
      </div>
      <div class="phishing-alert-text">
        ${p.warning}<br>
        <strong style="color:var(--text-primary)">Similarity distance: ${p.distance}</strong> — This domain closely resembles <strong>${p.similarTo}</strong>
      </div>
    </div>
  `).join('');
}

function renderWHOISTab(data) {
    const el = document.getElementById("tab-whois");
    el.innerHTML = `
    <div class="detail-card">
      <div class="detail-card-title"><i data-lucide="file-search" style="width:16px;height:16px"></i> WHOIS Information</div>
      <div class="kv-row"><span class="kv-key">Domain</span><span class="kv-value">${data.domain}</span></div>
      <div class="kv-row"><span class="kv-key">Registrar</span><span class="kv-value">${data.registrar}</span></div>
      <div class="kv-row"><span class="kv-key">Created</span><span class="kv-value">${formatDate(data.domainCreated)}</span></div>
      <div class="kv-row"><span class="kv-key">Expires</span><span class="kv-value">${formatDate(data.expiryDate)}</span></div>
      <div class="kv-row"><span class="kv-key">Updated</span><span class="kv-value">${formatDate(data.updatedDate)}</span></div>
      <div class="kv-row"><span class="kv-key">Name Servers</span><span class="kv-value">${formatNS(data.nameServers)}</span></div>
      <div class="kv-row"><span class="kv-key">DNSSEC</span><span class="kv-value">${data.dnssec || 'Unknown'}</span></div>
      <div class="kv-row"><span class="kv-key">Cloudflare</span><span class="kv-value">${data.cloudflare ? '<span style="color:var(--green)">Yes</span>' : 'No'}</span></div>
    </div>`;
}

function renderPerformanceTab(data) {
    const el = document.getElementById("tab-perf");
    const perf = data.performance;
    if (!perf || perf.responseTime === null) {
        el.innerHTML = '<p style="color:var(--text-muted);padding:16px">Performance data not available</p>';
        return;
    }

    const ratingColors = { Fast: 'var(--green)', Average: 'var(--orange)', Slow: 'var(--red)', Unreachable: 'var(--red)' };
    const color = ratingColors[perf.rating] || 'var(--text-muted)';
    const barWidth = Math.min(100, (perf.responseTime / 5000) * 100);

    el.innerHTML = `
    <div class="perf-card">
      <div>
        <div class="perf-time" style="color:${color}">${perf.responseTime}<span class="perf-unit">ms</span></div>
        <div class="perf-label">Response Time — <strong style="color:${color}">${perf.rating}</strong></div>
      </div>
      <div class="perf-bar">
        <div class="perf-bar-fill" style="width:${barWidth}%;background:${color}"></div>
      </div>
    </div>`;

    setTimeout(() => {
        const fill = el.querySelector('.perf-bar-fill');
        if (fill) fill.style.width = barWidth + '%';
    }, 100);
}

function renderPreview(data) {
    document.getElementById("preview-url-text").textContent = `https://${data.domain}`;
    document.getElementById("preview-frame").src = `https://${data.domain}`;
}

function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

    const btn = document.querySelector(`[data-tab="${tabId}"]`);
    const content = document.getElementById(`tab-${tabId}`);
    if (btn) btn.classList.add("active");
    if (content) content.classList.add("active");

    lucide.createIcons();
}

function addToHistory(data) {
    const entry = {
        domain: data.domain,
        url: data.url,
        risk: data.risk.level,
        score: data.risk.score,
        scannedAt: data.scannedAt,
        data: data
    };

    scanHistory = scanHistory.filter(h => h.domain !== entry.domain);
    scanHistory.unshift(entry);
    if (scanHistory.length > 50) scanHistory.pop();

    localStorage.setItem("ls_history", JSON.stringify(scanHistory));
    updateHistoryBadge();
}

function updateHistoryBadge() {
    const badge = document.getElementById("history-badge");
    if (scanHistory.length > 0) {
        badge.textContent = scanHistory.length;
        badge.style.display = "flex";
    } else {
        badge.style.display = "none";
    }
}

function toggleHistory() {
    const overlay = document.getElementById("history-overlay");
    const drawer = document.getElementById("history-drawer");
    const isOpen = drawer.classList.contains("open");

    if (isOpen) {
        overlay.classList.remove("open");
        drawer.classList.remove("open");
    } else {
        overlay.classList.add("open");
        drawer.classList.add("open");
        renderHistory();
    }
}

function renderHistory() {
    const list = document.getElementById("history-list");

    if (scanHistory.length === 0) {
        list.innerHTML = `
      <div class="history-empty">
        <i data-lucide="search" style="width:40px;height:40px;margin-bottom:12px;opacity:0.3"></i>
        <p>No scans yet</p>
        <p style="font-size:12px;margin-top:4px">Your scan history will appear here</p>
      </div>`;
        lucide.createIcons();
        return;
    }

    list.innerHTML = scanHistory.map((h, i) => {
        const levelClass = h.risk === "Safe" ? "safe" : h.risk === "Suspicious" ? "suspicious" : "high";
        return `
      <div class="history-item" onclick="loadHistoryItem(${i})">
        <div class="history-item-dot ${levelClass}"></div>
        <div class="history-item-info">
          <div class="history-item-domain">${h.domain}</div>
          <div class="history-item-date">${formatDateShort(h.scannedAt)}</div>
        </div>
        <span class="history-item-badge ${levelClass}">${h.risk}</span>
      </div>`;
    }).join('');
}

function loadHistoryItem(index) {
    const item = scanHistory[index];
    if (item && item.data) {
        currentData = item.data;
        renderResults(item.data);
        toggleHistory();
        showToast(`Loaded scan for ${item.domain}`, "info");
    }
}

function clearHistory() {
    if (!confirm("Clear all scan history?")) return;
    scanHistory = [];
    localStorage.removeItem("ls_history");
    updateHistoryBadge();
    renderHistory();
    showToast("History cleared", "success");
}

function openBulkModal() {
    document.getElementById("bulk-modal").classList.add("open");
    document.getElementById("bulk-results").innerHTML = "";
}

function closeBulkModal() {
    document.getElementById("bulk-modal").classList.remove("open");
}

async function startBulkScan() {
    const textarea = document.getElementById("bulk-urls");
    const urls = textarea.value.split("\n").map(u => u.trim()).filter(u => u.length > 0);

    if (urls.length === 0) { showToast("Enter at least one URL", "error"); return; }
    if (urls.length > 10) { showToast("Maximum 10 URLs allowed", "error"); return; }

    const btn = document.getElementById("bulk-scan-btn");
    btn.disabled = true;
    btn.textContent = "Scanning...";

    try {
        const res = await fetch(`${API_BASE}/api/bulk-analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ urls })
        });

        const json = await res.json();
        if (json.status === "ok") {
            renderBulkResults(json.results);
            showToast(`Bulk scan complete — ${json.results.length} URLs`, "success");
        } else {
            showToast(json.message || "Bulk scan failed", "error");
        }
    } catch {
        showToast("Connection failed", "error");
    } finally {
        btn.disabled = false;
        btn.textContent = "Start Bulk Scan";
    }
}

function renderBulkResults(results) {
    const el = document.getElementById("bulk-results");

    el.innerHTML = results.map((r, i) => {
        if (r.status === "error") {
            return `<div class="bulk-result-item"><span class="bulk-result-domain">${r.url}</span><span class="bulk-result-badge badge-high">Error</span></div>`;
        }
        const d = r.data;
        const levelClass = d.risk.level === "Safe" ? "safe" : d.risk.level === "Suspicious" ? "suspicious" : "high";
        return `
      <div class="bulk-result-item" onclick="loadBulkResult(${i})">
        <div>
          <div class="bulk-result-domain">${d.domain}</div>
          <div style="font-size:11px;color:var(--text-muted)">Score: ${d.risk.score}</div>
        </div>
        <span class="bulk-result-badge badge-${levelClass}">${d.risk.level}</span>
      </div>`;
    }).join('');

    window._bulkResults = results;
}

function loadBulkResult(index) {
    const result = window._bulkResults?.[index];
    if (result && result.data) {
        currentData = result.data;
        addToHistory(result.data);
        closeBulkModal();
        renderResults(result.data);
        showToast(`Loaded: ${result.data.domain}`, "info");
    }
}

function openCompareMode() {
    if (scanHistory.length < 2) {
        showToast("Need at least 2 scans in history to compare", "error");
        return;
    }

    const last2 = scanHistory.slice(0, 2);
    const container = document.getElementById("compare-container");
    container.classList.add("active");

    container.innerHTML = last2.map(h => {
        const d = h.data;
        const levelClass = h.risk === "Safe" ? "safe" : h.risk === "Suspicious" ? "suspicious" : "high";
        return `
      <div class="compare-card">
        <div class="compare-card-header">
          <span class="compare-domain">${d.domain}</span>
          <span class="compare-badge badge-${levelClass}">${d.risk.level}</span>
        </div>
        <div class="compare-metric"><span class="compare-metric-key">Risk Score</span><span class="compare-metric-value">${d.risk.score} / ${d.risk.maxScore}</span></div>
        <div class="compare-metric"><span class="compare-metric-key">SSL</span><span class="compare-metric-value">${d.ssl?.valid ? '✓ Valid' : '✗ Invalid'}</span></div>
        <div class="compare-metric"><span class="compare-metric-key">CDN</span><span class="compare-metric-value">${d.cloudflare ? '✓ Yes' : '✗ No'}</span></div>
        <div class="compare-metric"><span class="compare-metric-key">Created</span><span class="compare-metric-value">${formatDate(d.domainCreated)}</span></div>
        <div class="compare-metric"><span class="compare-metric-key">Response Time</span><span class="compare-metric-value">${d.performance?.responseTime ? d.performance.responseTime + 'ms' : 'N/A'}</span></div>
        <div class="compare-metric"><span class="compare-metric-key">Positive Signals</span><span class="compare-metric-value">${d.risk.positives?.length || 0}</span></div>
        <div class="compare-metric"><span class="compare-metric-key">Risk Factors</span><span class="compare-metric-value">${d.risk.reasons?.length || 0}</span></div>
        <div class="compare-metric"><span class="compare-metric-key">Technologies</span><span class="compare-metric-value">${d.technologies?.length || 0}</span></div>
      </div>`;
    }).join('');

    container.scrollIntoView({ behavior: "smooth" });
    showToast("Comparing last 2 scans", "info");
}

function exportPDF() {
    if (!currentData) { showToast("No scan results to export", "error"); return; }

    const d = currentData;
    const content = `
LINKSCANNER SECURITY REPORT
============================
Generated: ${new Date().toLocaleString()}

DOMAIN: ${d.domain}
URL: ${d.url}

OVERALL RISK: ${d.risk.level} (${d.risk.score} / ${d.risk.maxScore})

--- SSL INFO ---
Status: ${d.ssl?.valid ? 'Valid' : 'Invalid'}
Issuer: ${d.ssl?.issuer || 'N/A'}
Remaining: ${d.ssl?.daysRemaining || 0} days

--- DNS INFO ---
A: ${d.dns?.A?.join(', ') || 'None'}
MX: ${d.dns?.MX?.map(m => m.exchange).join(', ') || 'None'}

--- TECH STACK ---
${d.technologies?.map(t => t.name).join(', ') || 'None detected'}

--- RISK FACTORS ---
${d.risk.reasons?.map(r => '- ' + r).join('\n') || 'None detected'}

--- POSITIVE SIGNALS ---
${d.risk.positives?.map(p => '- ' + p).join('\n') || 'None detected'}

Exported from LinkScanner v2.0
`;

    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report_${d.domain}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Report downloaded as TXT", "success");
}

function formatDate(dateStr) {
    if (!dateStr || dateStr === "Private or Unknown" || dateStr === "Unknown") return "Unknown";
    try {
        const d = new Date(dateStr);
        if (isNaN(d.getTime())) return dateStr;
        return d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
    } catch { return dateStr; }
}

function formatDateShort(dateStr) {
    try {
        const d = new Date(dateStr);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch { return dateStr; }
}

function formatNS(ns) {
    if (Array.isArray(ns)) return ns.join(", ");
    return ns || "Unknown";
}

function truncate(str, len) {
    if (!str) return "";
    return str.length > len ? str.substring(0, len) + "..." : str;
}
