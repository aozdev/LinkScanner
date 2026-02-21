<p align="center">
  <img src="https://github.com/aozdev/LinkScanner/blob/main/website.png?raw=true" width="80" alt="LinkScanner">
</p>

<h1 align="center">LinkScanner</h1>

<p align="center">
  <strong>Advanced open-source URL security scanner <strong> <br>
  Analyze any link for SSL certificates, DNS records, phishing detection, redirect chains and more.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-22c55e?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/node-%3E%3D18-22c55e?style=flat-square" alt="Node">
  <img src="https://img.shields.io/badge/PRs-welcome-22c55e?style=flat-square" alt="PRs Welcome">
</p>

---

## 🚀 What is LinkScanner?

LinkScanner is a **free, open-source** web application that performs comprehensive security analysis on any URL. Simply enter a link and get an instant security report — no API keys required, no third-party services needed.

Built with a minimal tech stack (Node.js + vanilla HTML/CSS/JS), it runs entirely on your machine using native modules for DNS, TLS, and WHOIS lookups.

---

## ✨ Features

### 🔒 Security & Analysis
| Feature | Description |
|---------|-------------|
| **SSL/TLS Certificate Check** | Validates certificate, shows issuer, expiry, protocol, key size, fingerprint and remaining days |
| **DNS Record Lookup** | Queries A, AAAA, MX, NS, TXT, CNAME, and SOA records |
| **WHOIS Information** | Retrieves registrar, creation/expiry/update dates, nameservers, and DNSSEC status |
| **Redirect Chain Tracking** | Follows up to 10 redirects, showing each hop with status codes |
| **Phishing Detection** | Detects typosquatting by comparing against 40+ popular domains using Levenshtein distance |
| **Technology Detection** | Identifies web servers, frameworks, CDNs, hosting providers, and security layers from headers |
| **HTTP Security Headers** | Checks 7 critical headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, XSS Protection, Referrer-Policy, Permissions-Policy |
| **Performance Measurement** | Measures response time and rates speed (Fast / Average / Slow) |
| **Risk Scoring** | Calculates a risk score (0–20) with positive signals and risk factors |
| **Bulk Scanning** | Scan up to 10 URLs in a single batch request |
| **Rate Limiting** | Built-in rate limiting (30 requests/minute) to prevent abuse |
| **Caching** | 5-minute response cache for repeated lookups |

### 🎨 User Interface
| Feature | Description |
|---------|-------------|
| **Animated Risk Gauge** | Canvas-drawn circular gauge visualizing the risk score |
| **Step-by-Step Progress** | 8-step scanning animation showing real-time analysis progress |
| **8-Tab Result Panel** | Organized tabs: SSL, DNS, Redirects, Tech Stack, Headers, Phishing, WHOIS, Performance |
| **Scan History** | Stores up to 50 scans in localStorage with a slide-out drawer |
| **Compare Mode** | Side-by-side comparison of the last 2 scans |
| **Report Export** | Download a detailed text report of the scan results |
| **Dark / Light Theme** | Toggle between themes with saved preference |
| **Toast Notifications** | Animated notification system for user feedback |
| **Live Preview** | Sandboxed iframe preview of the scanned site |
| **Responsive Design** | Fully responsive layout for mobile and desktop |

---

## 📦 Tech Stack

- **Backend:** Node.js, Express
- **Frontend:** Vanilla HTML, CSS, JavaScript
- **Fonts:** Inter, JetBrains Mono (Google Fonts)
- **Icons:** Lucide Icons
- **Dependencies:** Only 3 npm packages — `express`, `cors`, `whois-json`
- **No external APIs required** — Uses native Node.js `dns`, `tls`, and `fetch` modules

---

## 🛠️ Installation

### Prerequisites
- [Node.js](https://nodejs.org/) v18 or higher

### Setup

```bash
# Clone the repository
git clone https://github.com/aozdev/link-scanner.git
cd link-scanner

# Install dependencies
cd backend
npm install

# Start the server
npm start
```

The application will be available at **http://localhost:3000**

### Environment Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |

---

## 📁 Project Structure

```
link-scanner/
├── backend/
│   ├── server.js          # Express server with all API endpoints
│   ├── package.json       # Dependencies and scripts
│   └── node_modules/
├── frontend/
│   ├── index.html         # Main HTML structure
│   ├── style.css          # Complete CSS design system
│   └── app.js             # Application logic and rendering
├── README.md
└── .gitignore
```

---

## 🔌 API Endpoints

### `POST /api/analyze`
Analyze a single URL.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "status": "ok",
  "data": {
    "domain": "example.com",
    "url": "https://example.com",
    "statusCode": 200,
    "domainCreated": "1995-08-14T04:00:00Z",
    "registrar": "RESERVED-Internet Assigned Numbers Authority",
    "ssl": { "valid": true, "issuer": "DigiCert", "daysRemaining": 120, "..." : "..." },
    "dns": { "A": ["93.184.216.34"], "MX": [], "..." : "..." },
    "redirectChain": [{ "url": "...", "status": 200 }],
    "phishing": [],
    "technologies": [{ "name": "Cloudflare", "cat": "CDN" }],
    "performance": { "responseTime": 245, "rating": "Fast" },
    "risk": { "score": 3, "maxScore": 20, "level": "Safe", "reasons": [], "positives": [] }
  }
}
```

### `POST /api/bulk-analyze`
Analyze multiple URLs (max 10).

**Request:**
```json
{
  "urls": ["google.com", "github.com", "example.com"]
}
```

### `GET /api/health`
Health check endpoint.

---

## 🎯 Risk Scoring System

LinkScanner evaluates URLs on a **0–20 point scale**:

| Score Range | Level | Description |
|-------------|-------|-------------|
| **0 – 3.9** | 🟢 Safe | No significant risks detected |
| **4 – 7.9** | 🟡 Suspicious | Some risk factors present |
| **8 – 20** | 🔴 High Risk | Multiple security concerns |

**Risk factors include:**
- Domain age (new domains score higher risk)
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Invalid or expiring SSL certificates
- Typosquatting similarity to popular domains
- Excessive redirect chains
- Absence of CDN/DDoS protection

**Positive signals include:**
- Valid SSL certificate
- Major CDN detected
- HSTS enabled
- CSP configured
- Established domain (1+ years old)

---

## 🖼️ Screenshots

<img src="https://github.com/aozdev/LinkScanner/blob/main/website.png?raw=true" width="80" alt="LinkScanner Logo">

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Ideas for Contributions
- [ ] Google Safe Browsing API integration
- [ ] VirusTotal API integration
- [ ] Screenshot capture of target site
- [ ] Browser extension (Chrome/Firefox)
- [ ] Docker support
- [ ] Database storage for scan history
- [ ] Webhook support (Discord/Slack notifications)
- [ ] QR code URL scanning
- [ ] PDF report generation
- [ ] Multi-language support

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**aozdev**

- GitHub: [@aozdev](https://github.com/aozdev)

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/aozdev">aozdev</a></sub><br>
  <sub>If you find this useful, please consider giving it a ⭐</sub>
</p>
