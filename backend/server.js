import express from "express";
import whois from "whois-json";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dns from "dns/promises";
import tls from "tls";

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─── Rate Limiting ───────────────────────────────────────────
const rateLimitMap = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 30;
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const requests = rateLimitMap.get(ip).filter(t => now - t < windowMs);
  if (requests.length >= maxRequests) {
    return res.status(429).json({ status: "error", message: "Too many requests. Please wait a moment." });
  }
  requests.push(now);
  rateLimitMap.set(ip, requests);
  next();
}

// ─── Cache ───────────────────────────────────────────────────
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000;
function getCached(key) {
  const cached = cache.get(key);
  if (cached && Date.now() - cached.ts < CACHE_TTL) return cached.data;
  cache.delete(key);
  return null;
}
function setCache(key, data) {
  cache.set(key, { data, ts: Date.now() });
}

app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS"], allowedHeaders: ["Content-Type"] }));
app.use(express.json());

// Request logger for debugging
app.use((req, res, next) => {
  console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.path} from ${req.headers.origin || 'direct'}`);
  next();
});

app.use(express.static(path.join(__dirname, "../frontend")));

// Health check
app.get("/api/health", (req, res) => res.json({ status: "ok", time: Date.now() }));

// ─── Popular Domains for Phishing Detection ──────────────────
const POPULAR_DOMAINS = [
  "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
  "netflix.com", "paypal.com", "instagram.com", "twitter.com", "linkedin.com",
  "youtube.com", "whatsapp.com", "telegram.org", "discord.com", "github.com",
  "stackoverflow.com", "reddit.com", "twitch.tv", "spotify.com", "dropbox.com",
  "yahoo.com", "bing.com", "outlook.com", "office.com", "live.com",
  "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
  "steam.com", "steampowered.com", "epicgames.com", "roblox.com",
  "binance.com", "coinbase.com", "blockchain.com", "metamask.io",
  "trendyol.com", "hepsiburada.com", "sahibinden.com", "n11.com",
  "garanti.com.tr", "akbank.com.tr", "isbank.com.tr", "ziraatbank.com.tr"
];

function levenshtein(a, b) {
  const m = Array.from({ length: b.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++)
    for (let j = 1; j <= a.length; j++)
      m[i][j] = b[i - 1] === a[j - 1]
        ? m[i - 1][j - 1]
        : Math.min(m[i - 1][j - 1] + 1, m[i][j - 1] + 1, m[i - 1][j] + 1);
  return m[b.length][a.length];
}

function checkPhishing(domain) {
  const base = domain.replace(/^www\./, "").split(".").slice(0, -1).join(".");
  const results = [];
  for (const pop of POPULAR_DOMAINS) {
    const popBase = pop.split(".")[0];
    const dist = levenshtein(base, popBase);
    if (dist > 0 && dist <= 2 && base !== popBase) {
      results.push({
        similarTo: pop,
        distance: dist,
        warning: `"${domain}" looks very similar to "${pop}" — possible typosquatting`
      });
    }
  }
  return results;
}

// ─── SSL Certificate Check ──────────────────────────────────
function getSSLInfo(hostname) {
  return new Promise(resolve => {
    try {
      const socket = tls.connect(443, hostname, { servername: hostname, timeout: 5000 }, () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        if (cert && Object.keys(cert).length > 0) {
          resolve({
            valid: true,
            issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
            subject: cert.subject?.CN || "Unknown",
            altNames: cert.subjectaltname || "",
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            serialNumber: cert.serialNumber,
            fingerprint: cert.fingerprint256 ? cert.fingerprint256.substring(0, 30) + "..." : "N/A",
            protocol: socket.getProtocol(),
            bits: cert.bits || null,
            daysRemaining: Math.floor((new Date(cert.valid_to) - Date.now()) / 864e5)
          });
        } else {
          resolve({ valid: false, error: "No certificate found" });
        }
      });
      socket.setTimeout(5000, () => { socket.destroy(); resolve({ valid: false, error: "Timeout" }); });
      socket.on("error", () => resolve({ valid: false, error: "SSL connection failed" }));
    } catch { resolve({ valid: false, error: "SSL check failed" }); }
  });
}

// ─── DNS Records ─────────────────────────────────────────────
async function getDNSRecords(domain) {
  const r = {};
  const tasks = [
    ["A", () => dns.resolve4(domain)],
    ["AAAA", () => dns.resolve6(domain)],
    ["MX", () => dns.resolveMx(domain)],
    ["TXT", () => dns.resolveTxt(domain).then(a => a.map(x => x.join("")))],
    ["NS", () => dns.resolveNs(domain)],
    ["CNAME", () => dns.resolveCname(domain)],
    ["SOA", () => dns.resolveSoa(domain)],
  ];
  await Promise.all(tasks.map(async ([type, fn]) => {
    try { r[type] = await fn(); } catch { r[type] = []; }
  }));
  return r;
}

// ─── Redirect Chain ─────────────────────────────────────────
async function getRedirectChain(url, max = 10) {
  const chain = [];
  let cur = url;
  for (let i = 0; i < max; i++) {
    try {
      const resp = await fetch(cur, {
        method: "GET", redirect: "manual",
        headers: { "User-Agent": "LinkScanner/2.0" },
        signal: AbortSignal.timeout(5000)
      });
      chain.push({ url: cur, status: resp.status, statusText: resp.statusText });
      if ([301, 302, 303, 307, 308].includes(resp.status)) {
        const loc = resp.headers.get("location");
        if (loc) { cur = new URL(loc, cur).toString(); } else break;
      } else break;
    } catch {
      chain.push({ url: cur, status: 0, statusText: "Connection failed" });
      break;
    }
  }
  return chain;
}

// ─── Technology Detection ────────────────────────────────────
function detectTechnologies(headers) {
  const techs = [];
  const hs = JSON.stringify(headers).toLowerCase();
  const server = (headers["server"] || "").toLowerCase();
  const powered = (headers["x-powered-by"] || "").toLowerCase();

  // Server
  if (server.includes("nginx")) techs.push({ name: "Nginx", cat: "Web Server", icon: "server" });
  if (server.includes("apache")) techs.push({ name: "Apache", cat: "Web Server", icon: "server" });
  if (server.includes("litespeed")) techs.push({ name: "LiteSpeed", cat: "Web Server", icon: "server" });
  if (server.includes("microsoft") || server.includes("iis"))
    techs.push({ name: "IIS", cat: "Web Server", icon: "server" });

  // Framework / Language
  if (powered.includes("express")) techs.push({ name: "Express.js", cat: "Framework", icon: "code" });
  if (powered.includes("php")) techs.push({ name: "PHP", cat: "Language", icon: "code" });
  if (powered.includes("asp.net")) techs.push({ name: "ASP.NET", cat: "Framework", icon: "code" });
  if (powered.includes("next")) techs.push({ name: "Next.js", cat: "Framework", icon: "code" });
  if (powered.includes("nuxt")) techs.push({ name: "Nuxt.js", cat: "Framework", icon: "code" });

  // CDN / Proxy
  if (hs.includes("cloudflare")) techs.push({ name: "Cloudflare", cat: "CDN/Security", icon: "shield" });
  if (hs.includes("akamai")) techs.push({ name: "Akamai", cat: "CDN", icon: "cloud" });
  if (hs.includes("fastly")) techs.push({ name: "Fastly", cat: "CDN", icon: "cloud" });
  if (hs.includes("varnish")) techs.push({ name: "Varnish", cat: "Cache", icon: "database" });
  if (hs.includes("sucuri")) techs.push({ name: "Sucuri", cat: "WAF", icon: "shield" });

  // Hosting / Cloud
  if (hs.includes("vercel")) techs.push({ name: "Vercel", cat: "Hosting", icon: "cloud" });
  if (hs.includes("netlify")) techs.push({ name: "Netlify", cat: "Hosting", icon: "cloud" });
  if (hs.includes("heroku")) techs.push({ name: "Heroku", cat: "Hosting", icon: "cloud" });
  if (hs.includes("x-amz") || hs.includes("amazons3"))
    techs.push({ name: "AWS", cat: "Cloud", icon: "cloud" });
  if (hs.includes("x-goog") || server.includes("gws"))
    techs.push({ name: "Google", cat: "Cloud", icon: "cloud" });
  if (hs.includes("x-azure")) techs.push({ name: "Azure", cat: "Cloud", icon: "cloud" });

  // Security features present
  if (headers["content-security-policy"]) techs.push({ name: "CSP", cat: "Security", icon: "shield-check" });
  if (headers["strict-transport-security"]) techs.push({ name: "HSTS", cat: "Security", icon: "lock" });
  if (headers["x-xss-protection"]) techs.push({ name: "XSS-P", cat: "Security", icon: "shield" });
  if (headers["permissions-policy"]) techs.push({ name: "Perm-P", cat: "Security", icon: "shield" });

  // Deduplicate
  const seen = new Set();
  return techs.filter(t => { if (seen.has(t.name)) return false; seen.add(t.name); return true; });
}

// ─── Performance Check (response time) ──────────────────────
async function measurePerformance(url) {
  try {
    const start = Date.now();
    await fetch(url, {
      method: "GET",
      headers: { "User-Agent": "LinkScanner/2.0" },
      signal: AbortSignal.timeout(10000)
    });
    const responseTime = Date.now() - start;
    let rating = "Fast";
    if (responseTime > 3000) rating = "Slow";
    else if (responseTime > 1000) rating = "Average";
    return { responseTime, rating };
  } catch {
    return { responseTime: null, rating: "Unreachable" };
  }
}

// ─── Enhanced Risk Calculation ───────────────────────────────
function calculateRisk({ domainCreated, cloudflare, headers, ssl, phishing, redirectChain }) {
  let score = 0;
  const reasons = [];
  const positives = [];

  // Domain age
  if (domainCreated && domainCreated !== "unknown") {
    const age = (Date.now() - new Date(domainCreated)) / 864e5;
    if (age < 7) { score += 4; reasons.push("Domain is extremely new (< 7 days)"); }
    else if (age < 30) { score += 3; reasons.push("Domain is relatively new (< 30 days)"); }
    else if (age < 90) { score += 1; reasons.push("Domain is less than 3 months old"); }
    else if (age > 1825) positives.push("Domain is over 5 years old — established");
    else if (age > 365) positives.push("Domain is over 1 year old");
  } else {
    score += 2;
    reasons.push("WHOIS creation date could not be verified");
  }

  // CDN
  if (!cloudflare) { score += 1; reasons.push("No major CDN detected"); }
  else positives.push("Major CDN / DDoS protection detected");

  // Security headers
  const secHeaders = [
    ["content-security-policy", 1, "Content-Security-Policy (CSP)"],
    ["strict-transport-security", 1, "HSTS header"],
    ["x-frame-options", 1, "X-Frame-Options"],
    ["x-content-type-options", 0.5, "X-Content-Type-Options"],
    ["x-xss-protection", 0.5, "X-XSS-Protection"],
    ["referrer-policy", 0.5, "Referrer-Policy"],
    ["permissions-policy", 0.5, "Permissions-Policy"],
  ];
  secHeaders.forEach(([h, pts, label]) => {
    if (!headers[h]) { score += pts; reasons.push(`Missing ${label}`); }
    else positives.push(`${label} enabled`);
  });

  // SSL
  if (ssl && !ssl.valid) { score += 3; reasons.push("SSL certificate is invalid or missing"); }
  else if (ssl && ssl.valid) {
    positives.push("Valid SSL certificate");
    if (ssl.daysRemaining < 14) { score += 2; reasons.push(`SSL expires in ${ssl.daysRemaining} days`); }
    else if (ssl.daysRemaining < 30) { score += 1; reasons.push(`SSL expires in ${ssl.daysRemaining} days`); }
  }

  // Phishing
  if (phishing && phishing.length > 0) {
    score += 3;
    phishing.forEach(p => reasons.push(p.warning));
  }

  // Redirects
  if (redirectChain && redirectChain.length > 3) {
    score += 2;
    reasons.push(`Excessive redirects (${redirectChain.length} hops)`);
  } else if (redirectChain && redirectChain.length > 1) {
    score += 0.5;
    reasons.push(`${redirectChain.length} redirects detected`);
  }

  score = Math.round(score * 10) / 10;
  const maxScore = 20;
  const percentage = Math.min(100, Math.round((score / maxScore) * 100));
  let level = "Safe";
  if (score >= 8) level = "High Risk";
  else if (score >= 4) level = "Suspicious";

  return { score, maxScore, percentage, level, reasons, positives };
}

// ─── Main Analyze Endpoint ───────────────────────────────────
app.post("/api/analyze", rateLimit, async (req, res) => {
  try {
    let { url } = req.body;
    if (!url) return res.status(400).json({ status: "error", message: "URL is required" });
    if (!url.startsWith("http")) url = "https://" + url;

    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // Check cache
    const cached = getCached(domain);
    if (cached) return res.json({ status: "ok", data: cached, cached: true });

    // Parallel data gathering
    const [headRes, whoisRes, sslRes, dnsRes, redirectRes, perfRes] = await Promise.allSettled([
      fetch(url, { method: "HEAD", headers: { "User-Agent": "LinkScanner/2.0" }, signal: AbortSignal.timeout(5000) }),
      whois(domain),
      getSSLInfo(domain),
      getDNSRecords(domain),
      getRedirectChain(url),
      measurePerformance(url)
    ]);

    let headers = {};
    let cloudflare = false;
    let statusCode = null;
    if (headRes.status === "fulfilled" && headRes.value) {
      headers = Object.fromEntries(headRes.value.headers.entries());
      cloudflare = (headers["server"] || "").toLowerCase().includes("cloudflare");
      statusCode = headRes.value.status;
    }

    const whoisData = whoisRes.status === "fulfilled" ? whoisRes.value : {};
    const ssl = sslRes.status === "fulfilled" ? sslRes.value : { valid: false, error: "Check failed" };
    const dnsRecords = dnsRes.status === "fulfilled" ? dnsRes.value : {};
    const redirects = redirectRes.status === "fulfilled" ? redirectRes.value : [];
    const performance = perfRes.status === "fulfilled" ? perfRes.value : { responseTime: null, rating: "Unknown" };

    const phishing = checkPhishing(domain);
    const technologies = detectTechnologies(headers);
    const domainCreated = whoisData.creationDate || whoisData.createdDate || whoisData.creation_date;

    const risk = calculateRisk({ domainCreated, cloudflare, headers, ssl, phishing, redirectChain: redirects });

    const data = {
      domain,
      url,
      statusCode,
      domainCreated: domainCreated || "Private or Unknown",
      registrar: whoisData.registrar || "Unknown",
      expiryDate: whoisData.registrarRegistrationExpirationDate || whoisData.expirationDate || "Unknown",
      updatedDate: whoisData.updatedDate || "Unknown",
      nameServers: whoisData.nameServer || "Unknown",
      dnssec: whoisData.dnssec || "Unknown",
      cloudflare,
      headers,
      ssl,
      dns: dnsRecords,
      redirectChain: redirects,
      phishing,
      technologies,
      performance,
      risk,
      scannedAt: new Date().toISOString()
    };

    setCache(domain, data);
    res.json({ status: "ok", data });
  } catch (e) {
    console.error("Analysis Error:", e.message);
    res.status(500).json({ status: "error", message: "Could not analyze the website. Please check the URL." });
  }
});

// ─── Bulk Scan Endpoint ──────────────────────────────────────
app.post("/api/bulk-analyze", rateLimit, async (req, res) => {
  try {
    const { urls } = req.body;
    if (!urls || !Array.isArray(urls) || urls.length === 0)
      return res.status(400).json({ status: "error", message: "URLs array is required" });
    if (urls.length > 10)
      return res.status(400).json({ status: "error", message: "Maximum 10 URLs per request" });

    const results = await Promise.allSettled(urls.map(async rawUrl => {
      let url = rawUrl;
      if (!url.startsWith("http")) url = "https://" + url;
      const domain = new URL(url).hostname;

      const cached = getCached(domain);
      if (cached) return { ...cached, cached: true };

      const [headRes, whoisRes, sslRes] = await Promise.allSettled([
        fetch(url, { method: "HEAD", headers: { "User-Agent": "LinkScanner/2.0" }, signal: AbortSignal.timeout(5000) }),
        whois(domain),
        getSSLInfo(domain)
      ]);

      let headers = {};
      let cloudflare = false;
      if (headRes.status === "fulfilled" && headRes.value) {
        headers = Object.fromEntries(headRes.value.headers.entries());
        cloudflare = (headers["server"] || "").toLowerCase().includes("cloudflare");
      }

      const whoisData = whoisRes.status === "fulfilled" ? whoisRes.value : {};
      const ssl = sslRes.status === "fulfilled" ? sslRes.value : { valid: false };
      const domainCreated = whoisData.creationDate || whoisData.createdDate || whoisData.creation_date;
      const phishing = checkPhishing(domain);
      const technologies = detectTechnologies(headers);
      const risk = calculateRisk({ domainCreated, cloudflare, headers, ssl, phishing });

      const data = {
        domain, url,
        domainCreated: domainCreated || "Unknown",
        cloudflare, ssl, phishing, technologies, risk,
        scannedAt: new Date().toISOString()
      };
      setCache(domain, data);
      return data;
    }));

    res.json({
      status: "ok",
      results: results.map((r, i) => ({
        url: urls[i],
        status: r.status === "fulfilled" ? "ok" : "error",
        data: r.status === "fulfilled" ? r.value : null,
        error: r.status === "rejected" ? r.reason?.message : null
      }))
    });
  } catch (e) {
    console.error("Bulk Error:", e.message);
    res.status(500).json({ status: "error", message: "Bulk analysis failed." });
  }
});

// ─── Start ───────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  🚀 LinkScanner v2.0 Running!\n  Local: http://localhost:${PORT}\n`);
});
