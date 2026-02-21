<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description"
    content="LinkScanner — Advanced open-source URL security scanner. Analyze any link for SSL, DNS, phishing, redirect chains and more.">
  <title>LinkScanner — Advanced Link Security Scanner</title>
  <link rel="icon" href="https://cdn-icons-png.flaticon.com/512/1267/1267935.png">
  <link rel="stylesheet" href="style.css">
  <script src="https://unpkg.com/lucide@latest"></script>
</head>

<body>
  <div class="app-container">
    <nav class="nav">
      <a href="/" class="nav-brand">
        <div class="nav-logo">
          <i data-lucide="scan" style="width:22px;height:22px"></i>
        </div>
        <div>
          <span class="nav-title">LinkScanner</span>
          <span class="nav-version">v2.0</span>
        </div>
      </a>
      <div class="nav-actions">
        <button class="nav-btn tooltip" data-tooltip="Compare" onclick="openCompareMode()">
          <i data-lucide="columns-2" style="width:18px;height:18px"></i>
        </button>
        <button class="nav-btn tooltip" data-tooltip="Export Report" onclick="exportPDF()">
          <i data-lucide="download" style="width:18px;height:18px"></i>
        </button>
        <button class="nav-btn tooltip" data-tooltip="Scan History" onclick="toggleHistory()">
          <i data-lucide="history" style="width:18px;height:18px"></i>
          <span class="badge" id="history-badge" style="display:none">0</span>
        </button>
        <button class="nav-btn tooltip" data-tooltip="Toggle Theme" onclick="toggleTheme()">
          <i data-lucide="moon" style="width:18px;height:18px" id="theme-icon"></i>
        </button>
      </div>
    </nav>

    <section class="hero">
      <h1 class="hero-title">
        Scan Any Link.<br>
        <span class="hero-gradient">Stay Secure.</span>
      </h1>
      <p class="hero-subtitle">
        Advanced open-source URL security scanner. Analyze SSL certificates, DNS records, redirect chains, phishing
        detection and more.
      </p>
      <div class="hero-stats">
        <div class="hero-stat"><i data-lucide="shield-check" style="width:14px;height:14px"></i> SSL Analysis</div>
        <div class="hero-stat"><i data-lucide="globe" style="width:14px;height:14px"></i> DNS Records</div>
        <div class="hero-stat"><i data-lucide="alert-triangle" style="width:14px;height:14px"></i> Phishing Detection
        </div>
        <div class="hero-stat"><i data-lucide="zap" style="width:14px;height:14px"></i> Performance</div>
      </div>
    </section>

    <div class="search-container">
      <div class="search-inner">
        <div class="search-icon">
          <i data-lucide="link" style="width:20px;height:20px"></i>
        </div>
        <input type="text" id="url-input" class="search-input" placeholder="Enter URL to scan — e.g. example.com"
          autocomplete="off" spellcheck="false">
        <button id="scan-btn" class="search-btn" onclick="scan()">
          <i data-lucide="scan" style="width:18px;height:18px"></i>
          <span>Analyze</span>
        </button>
      </div>
    </div>

    <div class="action-bar">
      <button class="action-btn" onclick="openBulkModal()">
        <i data-lucide="layers" style="width:16px;height:16px"></i>
        Bulk Scan
      </button>
      <button class="action-btn" onclick="openCompareMode()">
        <i data-lucide="columns-2" style="width:16px;height:16px"></i>
        Compare
      </button>
      <button class="action-btn" onclick="toggleHistory()">
        <i data-lucide="clock" style="width:16px;height:16px"></i>
        History
      </button>
    </div>

    <div id="scan-progress" class="scan-progress">
      <div class="scan-progress-title">
        <div class="spinner-dot"></div>
        Scanning in progress...
      </div>
      <div class="scan-steps" id="scan-steps"></div>
      <div class="scan-bar">
        <div class="scan-bar-fill" id="scan-bar-fill"></div>
      </div>
    </div>

    <div id="compare-container" class="compare-container"></div>

    <div id="results" class="results">
      <div class="overview-card">
        <div class="gauge-container">
          <canvas id="gauge-canvas"></canvas>
          <div class="gauge-center">
            <div class="gauge-score" id="gauge-score">0</div>
            <div class="gauge-label" id="gauge-label">—</div>
            <div class="gauge-sublabel" id="gauge-sublabel">0 / 20</div>
          </div>
        </div>
        <div class="overview-info">
          <div class="overview-domain" id="overview-domain">—</div>
          <div class="overview-url" id="overview-url">—</div>
          <div class="overview-meta" id="overview-meta"></div>
          <div class="signals-grid" id="signals-grid"></div>
        </div>
      </div>

      <div class="tabs-container">
        <div class="tabs-header">
          <button class="tab-btn active" data-tab="ssl" onclick="switchTab('ssl')">
            <i data-lucide="lock" style="width:14px;height:14px"></i> SSL
          </button>
          <button class="tab-btn" data-tab="dns" onclick="switchTab('dns')">
            <i data-lucide="globe" style="width:14px;height:14px"></i> DNS
          </button>
          <button class="tab-btn" data-tab="redirects" onclick="switchTab('redirects')">
            <i data-lucide="arrow-right-circle" style="width:14px;height:14px"></i> Redirects
          </button>
          <button class="tab-btn" data-tab="tech" onclick="switchTab('tech')">
            <i data-lucide="cpu" style="width:14px;height:14px"></i> Tech Stack
          </button>
          <button class="tab-btn" data-tab="headers" onclick="switchTab('headers')">
            <i data-lucide="shield" style="width:14px;height:14px"></i> Headers
          </button>
          <button class="tab-btn" data-tab="phishing" onclick="switchTab('phishing')">
            <i data-lucide="alert-triangle" style="width:14px;height:14px"></i> Phishing
          </button>
          <button class="tab-btn" data-tab="whois" onclick="switchTab('whois')">
            <i data-lucide="file-search" style="width:14px;height:14px"></i> WHOIS
          </button>
          <button class="tab-btn" data-tab="perf" onclick="switchTab('perf')">
            <i data-lucide="zap" style="width:14px;height:14px"></i> Performance
          </button>
        </div>
        <div class="tab-panel">
          <div class="tab-content active" id="tab-ssl"></div>
          <div class="tab-content" id="tab-dns"></div>
          <div class="tab-content" id="tab-redirects"></div>
          <div class="tab-content" id="tab-tech"></div>
          <div class="tab-content" id="tab-headers"></div>
          <div class="tab-content" id="tab-phishing"></div>
          <div class="tab-content" id="tab-whois"></div>
          <div class="tab-content" id="tab-perf"></div>
        </div>
      </div>

      <div class="preview-container">
        <div class="preview-header">
          <div class="preview-dots">
            <div class="preview-dot r"></div>
            <div class="preview-dot y"></div>
            <div class="preview-dot g"></div>
          </div>
          <div class="preview-url-bar" id="preview-url-text">https://—</div>
        </div>
        <iframe id="preview-frame" class="preview-frame" sandbox title="Site Preview"></iframe>
      </div>
    </div>
  </div>

  <footer class="footer">
    <div class="footer-links">
      <a href="https://github.com/aozdev" target="_blank" class="footer-link">
        <i data-lucide="github" style="width:16px;height:16px"></i> GitHub
      </a>
      <a href="#" class="footer-link" onclick="openBulkModal();return false;">
        <i data-lucide="layers" style="width:16px;height:16px"></i> Bulk Scan
      </a>
    </div>
    <p class="footer-credit">
      Open-source project by <a href="https://github.com/aozdev" target="_blank">aozdev</a> — LinkScanner v2.0
    </p>
  </footer>

  <div class="history-overlay" id="history-overlay" onclick="toggleHistory()"></div>
  <div class="history-drawer" id="history-drawer">
    <div class="history-header">
      <h2 class="history-title">
        <i data-lucide="history" style="width:20px;height:20px;vertical-align:middle;margin-right:6px"></i> Scan History
      </h2>
      <button class="history-close" onclick="toggleHistory()">
        <i data-lucide="x" style="width:20px;height:20px"></i>
      </button>
    </div>
    <div class="history-list" id="history-list">
      <div class="history-empty">
        <p>No scans yet</p>
      </div>
    </div>
    <div class="history-footer">
      <button class="history-clear-btn" onclick="clearHistory()">
        <i data-lucide="trash-2" style="width:14px;height:14px;vertical-align:middle;margin-right:4px"></i> Clear All
        History
      </button>
    </div>
  </div>

  <div class="modal-overlay" id="bulk-modal">
    <div class="modal">
      <div class="modal-header">
        <h2 class="modal-title">
          <i data-lucide="layers" style="width:20px;height:20px;vertical-align:middle;margin-right:6px"></i> Bulk Scan
        </h2>
        <button class="modal-close" onclick="closeBulkModal()">
          <i data-lucide="x" style="width:20px;height:20px"></i>
        </button>
      </div>
      <div class="modal-body">
        <textarea id="bulk-urls" class="bulk-textarea"
          placeholder="Enter one URL per line:&#10;google.com&#10;github.com&#10;example.com"
          spellcheck="false"></textarea>
        <p class="bulk-hint">Maximum 10 URLs per batch. Each URL will be analyzed for risk level.</p>
        <div id="bulk-results" class="bulk-results"></div>
      </div>
      <div class="modal-footer">
        <button class="btn-secondary" onclick="closeBulkModal()">Cancel</button>
        <button class="btn-primary" id="bulk-scan-btn" onclick="startBulkScan()">Start Bulk Scan</button>
      </div>
    </div>
  </div>

  <div class="toast-container" id="toast-container"></div>
  <script src="app.js"></script>
</body>

</html>
