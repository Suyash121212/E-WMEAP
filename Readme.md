# E-WMEAP
### Enterprise Web Misconfiguration & Exposure Assessment Platform

<div align="center">

![E-WMEAP Banner](https://img.shields.io/badge/E--WMEAP-Breach%20Protocol-00ff41?style=for-the-badge&labelColor=0a0f1e&color=00ff41)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Cost](https://img.shields.io/badge/Cost-$0%20Free-00ff41?style=for-the-badge)

**A next-generation ethical hacking platform that performs multi-layer web security assessment with live proof-of-concept generation, CVSS v3.1 scoring, vulnerability chaining, and a cinematic 3D hacker dashboard.**

[Features](#features) · [Modules](#scanning-modules) · [Setup](#setup) · [APIs](#apis-used) · [Demo](#demo) · [Screenshots](#screenshots)

</div>

---

## What Is E-WMEAP?

E-WMEAP simulates what a real penetration tester does during a web application security assessment — but automated, repeatable, and visually compelling. Enter any target URL and watch 8 specialist modules scan sequentially through a live hacker terminal, finding misconfigurations, generating actual exploitation proof-of-concept code, and combining findings into vulnerability chains that reveal the true attack surface.

> ⚠️ **Ethical Use Only** — This tool is built for security research and education. Only scan systems you own or have explicit written permission to test.

---

## Features

### Core Scanning
- **8 Independent Modules** — each scanning a different attack surface, running sequentially with live output
- **80+ Paths Probed** per scan across all modules
- **3-Layer False Positive Elimination** — baseline fingerprinting + HTML detection + content signature validation
- **Zero false positives** on modern SPA deployments (Vercel, Netlify, Next.js)

### Advanced Analysis
- **CVSS v3.1 Scoring** — every finding gets an industry-standard score (0–10) with full vector string
- **Vulnerability Chaining** — 10 cross-module chain rules detect when separate findings combine into higher severity
- **Live PoC Generation** — CORS findings produce working HTML exploit files, CSP weaknesses produce XSS payloads, .git exposure triggers source code reconstruction
- **CVE Matching** — detected service versions queried against NVD database for known exploits

### Intelligence & Reporting
- **Threat Intelligence** — Shodan, AlienVault OTX, and AbuseIPDB enrichment
- **Professional PDF Reports** — executive summary + full technical detail, downloadable per scan
- **GitHub Secret Scanner** — auto-discovers target's GitHub org, scans all public repos with 46 secret patterns
- **Scan History** — MongoDB-backed persistence with comparison view

### UI Experience
- **Breach Protocol UI** — dark hacker aesthetic with Three.js 3D globe, scanline overlay, particle field
- **Sequential Live Terminal** — modules activate one by one, findings appear in real-time
- **Animated Score Ring** — grade letter + animated counter on scan completion
- **Red Screen Flash** — critical findings trigger a screen flash animation

---

## Scanning Modules

```
MODULE 1 │ Security Header & TLS Analysis
MODULE 2 │ Port & Service Exposure + CVE Matching
MODULE 3 │ Directory & Endpoint Discovery + PoC Generation
MODULE 4 │ GitHub Repository Secret Scanner (46 patterns)
MODULE 5 │ CORS, JWT & GraphQL Business Logic Checker
MODULE 6 │ Web-Accessible Secret File Scanner
MODULE 7 │ Cloud & Modern Stack Misconfiguration
MODULE 8 │ Risk Engine — CVSS + Chains + Threat Intel + PDF
```

### Module Details

<details>
<summary><strong>Module 1 — Security Header & TLS Analysis</strong></summary>

Checks HTTP security headers for presence and correct configuration. Goes beyond simple presence checks — deeply parses CSP values for dangerous directives.

**Headers checked:** CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, Set-Cookie flags

**Advanced features:**
- CSP deep parsing — detects `unsafe-inline`, `unsafe-eval`, wildcard sources, missing `frame-ancestors`
- Auto-generates XSS PoC payload when `unsafe-inline` confirmed
- Mozilla Observatory API integration for independent grade
- TLS certificate expiry, issuer, protocol version, HSTS preload check
- Letter grade A+ through F
</details>

<details>
<summary><strong>Module 2 — Port & Service Scanner + CVE Matching</strong></summary>

Uses Nmap to detect internet-exposed services. Maps detected versions to real CVEs via the NVD API.

**Ports checked:** 21 (FTP), 22 (SSH), 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis), 2375 (Docker API), 8080 (Jenkins), 9200 (Elasticsearch), and more

**Advanced features:**
- Service version fingerprinting → NVD CVE lookup → CVSS score displayed
- Example: Apache 2.4.49 detected → CVE-2021-41773 (CVSS 9.8) surfaced automatically
- Dangerous port classification with exploitation techniques
</details>

<details>
<summary><strong>Module 3 — Directory & Endpoint Discovery</strong></summary>

Probes 80+ sensitive paths with content validation to eliminate false positives.

**Paths checked:** `.git`, `.env`, `.aws/credentials`, `wp-config.php`, `/admin`, `/phpmyadmin`, backup files, log files, API endpoints, GraphQL, Swagger UI, Spring Boot actuators, and more

**PoC triggers:**
- `/.git` found → git-dumper reconstructs source code → truffleHog scans for secrets
- `/.env` found → parses key names, masks values, flags sensitive credentials  
- `/graphql` found → introspection query → full schema mapped
- `/robots.txt` → Disallow paths extracted as additional targets
</details>

<details>
<summary><strong>Module 4 — GitHub Repository Secret Scanner</strong></summary>

Auto-discovers the GitHub organisation for the target domain. Scans all public repositories with 46 secret regex patterns.

**Secret types detected:** AWS keys, Google API keys, GitHub tokens, Stripe secrets, OpenAI keys, Anthropic keys, private RSA/EC keys, database URLs, JWT tokens, Slack webhooks, DigitalOcean tokens, and 35 more

**Additional checks:**
- Sensitive file detection (`.env`, `id_rsa`, `terraform.tfstate`, `.aws/credentials`)
- Suspicious commit message analysis (detects "remove secret", "oops", "accidentally")
- Placeholder filtering — no false positives from README examples
</details>

<details>
<summary><strong>Module 5 — CORS, JWT & GraphQL Business Logic</strong></summary>

Tests application-layer vulnerabilities that require understanding of web security — not just header checks.

**CORS tests (5 vectors):**
- Wildcard origin (`*`)
- Origin reflection attack
- Null origin bypass (sandboxed iframe)
- Credentials + reflection (Critical — session hijack)
- Subdomain trust (XSS pivot)

**JWT tests (5 vectors):**
- Algorithm confusion (`alg: none`)
- HMAC weak secret brute-force (30 common secrets)
- Expired token replay
- Payload tampering with original signature
- Completely invalid token acceptance

**GraphQL tests:**
- Introspection enabled → full schema + sensitive field mapping
- Query batching → rate limit bypass PoC
- Field suggestions → schema enumeration without introspection
- Unauthenticated data access probe
</details>

<details>
<summary><strong>Module 6 — Web Secret File Scanner</strong></summary>

Scans 42 web-accessible paths for exposed credential files. Uses content signature validation — will not report false positives.

**Files checked:** `.env` variants, `wp-config.php`, `settings.py`, `.aws/credentials`, `id_rsa`, `.bash_history`, `docker-compose.yml`, `.npmrc`, `database.yml`, application logs, and more

**Content validation:** Each file type must contain expected patterns (`.env` must have `=` signs and key patterns, `.git/config` must have `[core]`) before being flagged.
</details>

<details>
<summary><strong>Module 7 — Cloud & Modern Stack Misconfiguration</strong></summary>

Covers attack vectors responsible for the majority of modern enterprise data breaches.

**S3 Bucket Enumeration:**
- 60 candidate bucket names generated per target
- Checks existence and public read access
- Lists file contents, flags sensitive filenames
- No AWS credentials required — pure HTTP

**Subdomain Takeover (28 fingerprints):**
- crt.sh + HackerTarget DNS enumeration
- CNAME resolution against known-vulnerable services
- Confirmed fingerprint matching (GitHub Pages, Heroku, Vercel, Netlify, Azure, Fastly, Shopify, and 21 more)

**Exposed Services:**
Docker API, Kubernetes, Elasticsearch, Jenkins, Prometheus, Grafana, Jupyter, Consul, etcd, RabbitMQ, Airflow, phpMyAdmin, Swagger UI
</details>

<details>
<summary><strong>Module 8 — Risk Engine</strong></summary>

Aggregates all module results into actionable security intelligence.

**CVSS v3.1 Scoring:** 40 pre-mapped finding profiles, accurate formula implementation, full vector string per finding

**Vulnerability Chains (10 rules):**
- CORS reflection + missing HttpOnly → Session Hijack (CVSS 9.3)
- Subdomain takeover + weak CSP → XSS chain (CVSS 9.1)
- Exposed .git + secrets in code → Code + credential breach (CVSS 9.0)
- JWT alg:none + admin endpoint → Privilege escalation (CVSS 9.3)
- Docker API exposed → Full host takeover (CVSS 10.0)
- Public S3 + sensitive files → Data breach (CVSS 9.1)
- And 4 more...

**Threat Intelligence:** Shodan, AlienVault OTX, AbuseIPDB enrichment

**PDF Report:** Executive summary (non-technical) + full technical detail with PoC payloads
</details>

---

## Project Structure

```
e-wmeap/
├── backend/
│   ├── app.py                          # Flask API entry point
│   ├── .env                            # API keys (never commit this)
│   ├── requirements.txt
│   └── modules/
│       ├── header_scanner.py           # Module 1 — Headers + TLS
│       ├── tls_scanner.py              # Module 1 — TLS analysis
│       ├── port_scanner.py             # Module 2 — Ports + CVE
│       ├── directory_scanner.py        # Module 3 — Directory enum
│       ├── github_scanner.py           # Module 4 — GitHub secrets
│       ├── business_logic_scanner.py   # Module 5 — CORS/JWT/GraphQL
│       ├── secret_scanner.py           # Module 6 — Web file secrets
│       ├── cloud_scanner.py            # Module 7 — Cloud misconfig
│       └── risk_engine/
│           ├── __init__.py
│           ├── engine.py               # Module 8 — Aggregation
│           ├── cvss_scorer.py          # CVSS v3.1 formula
│           ├── chains.py               # Vulnerability chain rules
│           ├── threat_intel.py         # Shodan/OTX/AbuseIPDB
│           └── pdf_report.py           # ReportLab PDF generator
│
├── frontend/
│   ├── public/
│   │   └── index.html
│   └── src/
│       ├── App.jsx                     # Main orchestrator
│       ├── breach.css                  # Hacker UI styles
│       └── components/
│           ├── ui/
│           │   ├── ParticleField.jsx   # Animated background
│           │   ├── ThreeScene.jsx      # Three.js 3D globe
│           │   ├── HeroInput.jsx       # Landing page input
│           │   ├── ScanTerminal.jsx    # Live scan terminal
│           │   ├── ScanCompleteBanner.jsx
│           │   └── SeverityBadge.jsx
│           └── modules/
│               ├── HeaderScanner.jsx
│               ├── PortScanner.jsx
│               ├── DirectoryScanner.jsx
│               ├── GitHubScanner.jsx
│               ├── BusinessLogicScanner.jsx
│               ├── SecretScanner.jsx
│               ├── CloudScanner.jsx
│               └── RiskDashboard.jsx
│
└── xss-lab/                            # Educational XSS demo
    ├── victim-site/app.py              # Vulnerable banking site
    ├── attacker-server/app.py          # Cookie collection server
    ├── attacker.html                   # Attack payload launcher
    └── README.txt
```

---

## Setup

### Prerequisites

- Python 3.10+
- Node.js 18+
- Nmap (`apt install nmap` / `brew install nmap`)

### Backend

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/e-wmeap.git
cd e-wmeap

# 2. Create virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate

# 3. Install dependencies
pip install flask flask-cors requests dnspython reportlab python-dotenv

# Optional — for full PoC generation
pip install git-dumper trufflehog

# 4. Create .env file (see API Keys section below)
cp .env.example .env

# 5. Start Flask
cd backend
flask run
# or
python app.py
```

Flask runs on `http://localhost:5000`

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start
```

React runs on `http://localhost:3000`

### Add Font to `public/index.html`

```html
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
```

---

## API Keys

Create a `.env` file in the `backend/` directory:

```env
# Required for GitHub scanning (60 req/hr without, 5000 req/hr with)
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Optional — Threat Intelligence (Module 8)
SHODAN_API_KEY=xxxxxxxxxxxxxxxxxxxx
OTX_API_KEY=xxxxxxxxxxxxxxxxxxxx
ABUSEIPDB_API_KEY=xxxxxxxxxxxxxxxxxxxx
```

### How to get each key

| Key | Where to get | Free limit |
|---|---|---|
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) → Generate new (classic) | 5000 req/hr |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | 1 query/sec |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) → Settings → API | Unlimited |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://abuseipdb.com) → User Account → API | 1000/day |

> All APIs that **require no key**: NVD/CVE, Mozilla Observatory, SSL Labs, HSTS Preload, crt.sh, HackerTarget, AWS S3 HTTP

---

## APIs Used

| API | Module | Free? | Purpose |
|---|---|---|---|
| NVD (NIST) CVE API | 2 | ✅ No key | CVE lookup for detected service versions |
| Mozilla Observatory | 1 | ✅ No key | Independent header security grade |
| SSL Labs API | 1 | ✅ No key | Full TLS grade + cipher analysis |
| HSTS Preload | 1 | ✅ No key | Chrome preload list check |
| crt.sh | 7 | ✅ No key | Certificate transparency → subdomain enum |
| HackerTarget | 7 | ✅ No key | DNS subdomain enumeration |
| GitHub REST API | 4, 6 | ✅ Optional key | Repo listing + file content scanning |
| AWS S3 HTTP | 7 | ✅ No key | Bucket existence + public access check |
| Shodan | 8 | 🔑 Free tier | IP indexed by attackers, open ports, CVEs |
| AlienVault OTX | 8 | 🔑 Free key | Domain/IP threat pulse intelligence |
| AbuseIPDB | 8 | 🔑 Free tier | IP abuse score + ISP info |

---

## Vulnerable Target for Testing

**Never scan sites you don't own.** Use these safe targets:

```
# Deliberately vulnerable test site (owned by Acunetix)
http://testphp.vulnweb.com

# Local DVWA (set up with Docker)
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Or use the included **XSS Lab** for a complete attack demonstration:

```bash
# Terminal 1 — Vulnerable banking site
cd xss-lab/victim-site && python app.py
# → http://localhost:5001  (login: arjun / password123)

# Terminal 2 — Cookie collection server
cd xss-lab/attacker-server && python app.py
# → http://localhost:5002  (watch cookies arrive)

# Terminal 3 — Open attacker.html in browser
# Click "PAYLOAD 2" → session cookie appears on attacker dashboard
# Follow hijack instructions → logged in as victim with no password
```

---

## Demo Walkthrough

```
1. Open http://localhost:3000
   → Landing page: 3D rotating globe + typewriter animation

2. Enter target URL → press INITIATE
   → Screen splits: globe left, live terminal right

3. Watch 7 modules scan sequentially
   → Each module activates with progress bar
   → Critical findings appear with red border in live feed

4. Scan completes
   → Score counter animates 0 → XX
   → Grade letter drops with glow animation
   → Red screen flash if Critical findings

5. Click RISK tab
   → CVSS-scored findings, vulnerability chains, threat intel

6. Click HEADERS tab
   → CSP deep analysis, XSS PoC payload shown

7. Click LOGIC tab
   → CORS PoC HTML (copy → open in browser → steal session)

8. Click "DOWNLOAD PDF"
   → Professional 2-section security report
```

---

## Unique Features vs Existing Tools

| Feature | OWASP ZAP | Nikto | Burp Suite Pro | **E-WMEAP** |
|---|---|---|---|---|
| Cost | Free | Free | $499/year | **Free** |
| CORS exploitation test | Partial | ❌ | ✅ | **✅ 5 vectors + PoC** |
| JWT attack vectors | ❌ | ❌ | Extension | **✅ 5 vectors** |
| CVE matching | ❌ | Basic | ❌ | **✅ NVD API** |
| Vulnerability chaining | ❌ | ❌ | ❌ | **✅ 10 chain rules** |
| GitHub secret scanning | ❌ | ❌ | ❌ | **✅ 46 patterns** |
| S3 bucket enumeration | ❌ | ❌ | ❌ | **✅ 60 candidates** |
| Subdomain takeover | ❌ | ❌ | Extension | **✅ 28 fingerprints** |
| Threat intelligence | ❌ | ❌ | ❌ | **✅ Shodan/OTX/Abuse** |
| CVSS v3.1 per finding | ❌ | ❌ | ✅ | **✅** |
| False positive filtering | ❌ | ❌ | ✅ | **✅ 3-layer system** |
| 3D animated UI | ❌ | ❌ | ❌ | **✅** |

---

## Environment Variables Reference

```env
# Backend .env
GITHUB_TOKEN=             # GitHub personal access token
SHODAN_API_KEY=           # Shodan API key
OTX_API_KEY=              # AlienVault OTX key
ABUSEIPDB_API_KEY=        # AbuseIPDB key
MONGODB_URI=              # MongoDB Atlas URI (optional, for scan history)
```

```env
# Frontend .env
REACT_APP_API_URL=http://127.0.0.1:5000
```

---

## Roadmap

- [ ] MongoDB scan history with comparison view
- [ ] Continuous monitoring with regression alerts
- [ ] CVE matching for all detected service banners
- [ ] Cookie security flag analysis (HttpOnly/Secure/SameSite)
- [ ] Wayback Machine passive recon
- [ ] CI/CD GitHub Action integration
- [ ] Browser extension ("Scan this site" right-click)
- [ ] Rate limiting on deployed API

---

## Legal & Ethical Notice

This tool is developed for **educational purposes and authorized security testing only**.

- Only use against systems you own or have **explicit written permission** to test
- The XSS Lab runs entirely on `localhost` — no real sites are harmed
- Unauthorized scanning may violate computer fraud laws in your jurisdiction (CFAA, Computer Misuse Act, IT Act 2000, etc.)
- The authors accept no liability for misuse

---

## Tech Stack

**Backend:** Python · Flask · Nmap · dnspython · ReportLab · Requests

**Frontend:** React 18 · Tailwind CSS · Three.js · JetBrains Mono · Orbitron

**APIs:** NVD/NIST · Mozilla Observatory · SSL Labs · crt.sh · HackerTarget · GitHub REST · Shodan · AlienVault OTX · AbuseIPDB

**Tools:** git-dumper · truffleHog · FFUF · SecLists

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with 🖤 for ethical hacking education

**E-WMEAP — BREACH PROTOCOL**

</div>