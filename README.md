# SpiderWeb Pro

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Active-brightgreen.svg)]()

```
╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║            ╔═╗┌─┐┬┌┬┐┌─┐┬─┐╦ ╦┌─┐┌┐     ╔═╗╦═╗╔═╗               ║
║            ╚═╗├─┘│ ││├┤ ├┬┘║║║├┤ ├┴┐    ╠═╝╠╦╝║ ║               ║
║            ╚═╝┴  ┴─┴┘└─┘┴└─╚╩╝└─┘└─┘    ╩  ╩╚═╚═╝               ║
║                                                                 ║
║           Advanced Security Intelligence v2.4 - Recon           ║
║                           by g33l0                              ║
║                                                                 ║
║    CVE Correlation | Banner Grabbing | Default Cred Testing     ║
║    WAF Detection   | SSL Scanning   | Sensitive Path Discovery  ║
╚═════════════════════════════════════════════════════════════════╝
```

> Professional security intelligence platform with automated IP/domain reconnaissance, vulnerability assessment, SMTP security analysis, and red team attack chain discovery.

---

## 🎯 Features

### IP Reconnaissance
- **Multi-source IP generation** — aggregates from DNS, URLScan, ThreatCrowd (free) and Shodan, Censys, FOFA, ZoomEye, SecurityTrails (API keys optional)
- **Keyword-based or file-based** input — generate targets from keywords or load from `ips.txt`
- **Up to 4,000 IPs per scan** with country/region filtering
- **Concurrent scanning** — 50 parallel workers with live dashboard showing progress, alive count, and vulnerability count in real time

### Vulnerability Assessment
- **Port scanning** — 15 ports (21, 22, 25, 80, 443, 1433, 2082, 2083, 3306, 5432, 6379, 8080, 8443, 10000, 27017)
- **CVE correlation** via NVD API — matched against grabbed service banners
- **Banner grabbing** — HTTP, SSH, FTP, SMTP fingerprinting with version extraction
- **Default credential testing** — FTP (anonymous, admin), MySQL, SSH, cPanel, Webmin, phpMyAdmin
- **Sensitive path discovery** — 20 paths including `.git/config`, `.env`, `wp-config.php`, `.aws/credentials`, `phpinfo.php`, `adminer.php`, SQL dumps, SSH keys, and more
- **SSL/TLS inspection** — version, cipher, issuer, subject, expiry, SAN domains, vulnerability grading
- **WAF detection** — Cloudflare, AWS WAF, Akamai, ModSecurity, Sucuri, Imperva, F5 BIG-IP, Barracuda
- **HTTP method testing** — PUT, DELETE, TRACE, PATCH dangerous method detection
- **Risk scoring** — 0–10 scale with CRITICAL / HIGH / MEDIUM / LOW / MINIMAL tiers

### IP Classification & Enrichment
- **CDN vs origin detection** — ASN-based, rDNS-based, and port-signature-based classification
- **Force-classification** — hardcoded ASN lists for Cloudflare, Akamai, CloudFront, Fastly, Google, Azure CDN
- **Geolocation** — country, city, region, ISP via ip-api.com (rate-limited, retries on 429)
- **ASN lookup** — autonomous system number and organisation
- **Reverse DNS** — PTR record resolution
- **WHOIS enrichment** — organisation, abuse contact, network range
- **Technology detection** — web server, CMS, frameworks from HTTP headers and page content
- **SSL SAN extraction** — Subject Alternative Names wired into domain attribution

### Domain & Subdomain Recon Mode
- **Keyword-based domain generation** — RapidDNS, crt.sh (free), SecurityTrails, VirusTotal (API optional)
- **Up to 1,000 domains per run** — generated list auto-saved to `domains.txt` next to the script
- **File-based domain scanning** — load `domains.txt` directly (option 2 in Domain mode)
- **Full domain scan** — DNS resolution, web fingerprinting, SSL inspection, WAF detection, hosting classification, subdomain enumeration, concurrent with 30-worker semaphore
- **SMTP security analysis**:
  - Port probing on 25, 465, 587 (concurrent, 3s timeout each)
  - SPF, DKIM, DMARC record validation via DNS
  - Open relay detection
  - TLS/STARTTLS support check
  - Risk scoring: NONE / LOW / MEDIUM / HIGH / CRITICAL

### Red Team Automation
- **Automated attack chain discovery** — scans for .git, .env, exposed databases
- **MITRE ATT&CK mapping** — T1213, T1552.001, T1078, T1046 and more
- **Exploitability ratings** — TRIVIAL / LOW / MEDIUM complexity
- **Safe mode (default)** — read-only, no active exploitation
- **Aggressive mode** — requires explicit authorization token
- **Audit logging** — all operations logged to `spiderweb_redteam_logs/`

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/g33l0/spiderweb.git
cd spiderweb

# Install dependencies
pip install requests beautifulsoup4 aiohttp

# Optional — for SMTP DKIM/SPF/DMARC checks
pip install dnspython
```

**`requirements.txt`:**

```
requests>=2.31.0
beautifulsoup4>=4.12.0
aiohttp>=3.9.0
dnspython>=2.4.0   # optional — enables SMTP DNS record checks
```

> **Windows users:** The tool automatically configures `WindowsSelectorEventLoopPolicy` on startup to prevent `WinError 10054` spam from the Proactor event loop. No manual action needed. ANSI colors are also enabled automatically — Windows Terminal, ConEmu, and ANSICON are all supported; plain cmd.exe falls back to a single-line progress display.

---

## 🚀 Quick Start

```bash
python3 spiderweb.py
```

The tool is fully interactive — no command-line flags required. Dependencies are checked and installed automatically on first run.

---

## 💡 Usage Guide

### Main Menu

```
=== SELECT INPUT METHOD ===

1. Keyword-based IP generation (Multi-source)
2. Scan IPs from file  (ips.txt)
3. Configure API Keys
4. Domain & Subdomain Recon Mode

Choice (1-4) (ESC=Exit):
```

### Option 1 — Keyword-Based IP Scan

```
Keywords (comma-separated): payment-portal, cpanel, admin-login
How many IPs? (max 4000): 100
Target country (2-letter code, or 00 for worldwide): RU for Russia
```

The generator queries all configured sources concurrently, deduplicates, and filters to the requested count. Paid API sources (Shodan, Censys, etc.) are used alongside free sources when keys are configured — all sources run in parallel regardless of how quickly free sources fill the quota.

### Option 2 — File-Based IP Scan

Create `ips.txt` (one IP per line) in the same directory as the script:

```
1.2.3.4
5.6.7.8
```

Then select option 2. The file is loaded, deduplicated, and scanned immediately.

### Option 3 — Configure API Keys

Keys are stored in `spiderweb_config.json` next to the script and persist across runs:

| Key Name | Source |
|---|---|
| `shodan_api_key` | [shodan.io](https://shodan.io) |
| `censys_api_id` + `censys_api_secret` | [censys.io](https://censys.io) |
| `fofa_email` + `fofa_key` | [fofa.info](https://fofa.info) |
| `zoomeye_api_key` | [zoomeye.org](https://zoomeye.org) |
| `securitytrails_api_key` | [securitytrails.com](https://securitytrails.com) |
| `virustotal_api_key` | [virustotal.com](https://virustotal.com) |

Free-tier sources (DNS, URLScan, ThreatCrowd, RapidDNS, crt.sh) work with no keys at all.

### Option 4 — Domain & Subdomain Recon Mode

```
=== DOMAIN & SUBDOMAIN RECON MODE ===

1. Keyword-based domain generation
2. Scan domains from file
0. Back
```

**Sub-option 1** generates a domain list from keywords, saves it to `domains.txt` next to the script, then prompts to run an immediate scan.

**Sub-option 2** reads `domains.txt` from the script directory — this is the file that option 1 writes to, so the workflow is seamless: generate → scan.

---

## 📊 Output Files

### IP Scan Results — `spiderweb_results/`

```
spiderweb_results/
├── scan_YYYYMMDD_HHMMSS_<id>.json     # Full structured data for all IPs
├── scan_YYYYMMDD_HHMMSS_<id>.csv      # Flat spreadsheet (40 columns)
└── vulnerable_YYYYMMDD_HHMMSS_<id>.txt  # CRITICAL/HIGH origin servers only
```

The `.json` file contains complete per-IP data including all nested objects (liveness, hosting classification, SSL info, WAF info, CVE matches, service banners, sensitive paths, WHOIS, geolocation, attack surface analysis).

The `.txt` vulnerability report lists only confirmed origin servers rated CRITICAL or HIGH, with exposed services, CVE matches, service fingerprints, default credential results, sensitive files found, and step-by-step remediation guidance.

### Domain Scan Results — `domain/`

```
domain/
├── domain_scan_results.json    # Full domain scan data
└── domain_scan_results.csv     # Flat spreadsheet
```

---

## 📋 Data Sources

### IP Intelligence

| Source | Type | Auth Required | Notes |
|---|---|---|---|
| DNS | Free | None | Direct resolution |
| URLScan.io | Free | None | Search index |
| ThreatCrowd | Free | None | Threat intel |
| Shodan | Premium | API Key | Full internet scan data |
| Censys | Premium | API ID + Secret | Certificate and host data |
| FOFA | Premium | Email + Key | Chinese internet scan data |
| ZoomEye | Premium | API Key | Chinese internet scan data |
| SecurityTrails | Premium | API Key | DNS history |

### Domain Intelligence

| Source | Type | Auth Required |
|---|---|---|
| RapidDNS | Free | None |
| crt.sh | Free | None |
| SecurityTrails | Premium | API Key |
| VirusTotal | Premium | API Key |

### IP Enrichment

| Source | Data | Notes |
|---|---|---|
| ip-api.com | Geo, ASN, ISP | 45 req/min free; semaphore-gated, auto-retries on 429 |
| NVD (NIST) | CVE data | Matched against grabbed service banners |
| RDNS | Reverse DNS | PTR record lookup |
| WHOIS | Org, abuse contact | Direct WHOIS query |

---

## 🖥️ Live Scan Dashboard

During IP scans the terminal shows a self-refreshing dashboard:

```
=== ADVANCED SECURITY SCAN: 100 IPs ===

[████████████████░░░░░░░░░░░░░░░░░░░]  45.0%  Done:45/100  Remaining:55  Vuln:8  Alive:41
  ▶ 104.20.46.112    Path scan
  ▶ 172.66.146.34    CVE check
  ▶ 45.33.32.156     Banners
  ▶ 8.8.8.8          Enriching
```

The dashboard uses ANSI cursor-up codes on Linux/macOS and Windows Terminal. On plain Windows cmd it falls back to a single overwriting progress line.

---

## 📈 Example Scan Output

```
================================================================================
                      ADVANCED SECURITY ASSESSMENT RESULTS
================================================================================

  Total Alive       : 45
    Origin Servers   : 32
    CDN / Proxies    : 13
  Dead / Filtered   : 0
  Vulnerable Targets : 8
  Total Scanned     : 45

Advanced Features:
  CVE Matches Found      : 5
  Default Creds Accepted : 0
  WAF Detected           : 3

────────────────────────────────────────────────────────────────────────────────
ORIGIN SERVER VULNERABILITY ASSESSMENT
────────────────────────────────────────────────────────────────────────────────

CRITICAL: 3 target(s)

[1] 43.175.xxx.xxx | Risk Score: 10.0/10
    Location   : Singapore, SG
    Exposed Services:
      • MySQL (Port 3306)
      • PostgreSQL (Port 5432)
      • MongoDB (Port 27017)
      • Redis (Port 6379)
    CVE Matches:
      • CVE-2023-48795 [MEDIUM] Score: 5.9
    Top Fixes:
      • CRITICAL: Bind MySQL on port 3306 to 127.0.0.1 only.
      • CRITICAL: Bind MongoDB on port 27017 to 127.0.0.1 only.
```

---

## 🔴 Red Team Attack Chains

When exposed entry points are discovered, SpiderWeb maps complete attack chains:

```
═══════════════════════════════════════════════════════════
RED TEAM AUTOMATION - ATTACK CHAIN DISCOVERY
═══════════════════════════════════════════════════════════

Target: 46.xxx.xxx.xx  (Frankfurt, DE)
  Risk: CRITICAL | Chains: 2

  ⚠⚠⚠ Chain 1: Git → Database Compromise (TRIVIAL)
      1. Download .git directory
         → T1213 - Data from Information Repositories
      2. Extract credentials from config files
         → T1552.001 - Credentials In Files
      3. Connect to MySQL database
         → T1078 - Valid Accounts

  ⚠⚠ Chain 2: Exposed Redis → Remote Code Execution (LOW)
      1. Test Redis connectivity
         → T1046 - Network Service Discovery
      2. Authenticate (no auth required)
         → T1078 - Valid Accounts
      3. Write SSH key via CONFIG SET
         → T1098 - Account Manipulation
```

---

## 🔐 Security & Ethics

**Only use on systems you are authorised to test.**

- **Safe mode (default)** — read-only reconnaissance, no exploitation
- **Aggressive mode** — requires explicit authorization token, not enabled by default
- **Audit logging** — all red team operations are logged with timestamps to `spiderweb_redteam_logs/`
- **Multi-tenant awareness** — warns when scanning shared hosting infrastructure
- **CDN guardrails** — CDN edge nodes are identified and excluded from vulnerability reporting; only confirmed origin servers are flagged

---

## 🧩 Architecture

```
SpiderWebCLI                    ← Interactive menu, scan orchestration
├── MultiSourceIPGenerator      ← Parallel IP collection from 8 sources
├── MultiSourceDomainGenerator  ← Parallel domain collection from 4 sources
├── AsyncScanner                ← Per-IP concurrent scan engine
│   ├── _geo_lookup()           ← Geo + ASN in single ip-api call (rate-limited)
│   ├── _get_ssl_info()         ← TLS cert inspection + SAN extraction
│   ├── _get_web_info()         ← HTTP fingerprinting + header analysis
│   ├── _get_reverse_dns()      ← PTR resolution
│   └── WHOISEnricher           ← WHOIS data
├── ClassificationEngine        ← CDN vs origin classification
├── VulnerabilityAssessor       ← Risk scoring and recommendations
├── BannerGrabber               ← Service fingerprinting on open ports
├── CVECorrelator               ← NVD CVE matching against banners
├── WAFDetector                 ← 8 WAF signature sets
├── SSLScanner                  ← TLS vulnerability assessment
├── SensitivePathScanner        ← 20 sensitive paths, concurrent
├── DefaultCredChecker          ← FTP/MySQL/SSH/cPanel/Webmin/phpMyAdmin
├── SubdomainEnumerator         ← Common subdomain brute-force
├── SMTPSecurityAnalyzer        ← SMTP, SPF, DKIM, DMARC, relay check
└── RedTeamAutomation           ← Attack chain discovery + MITRE mapping
```

---

## ⚙️ Configuration

`spiderweb_config.json` (auto-created on first API key entry):

```json
{
  "shodan_api_key": "",
  "censys_api_id": "",
  "censys_api_secret": "",
  "fofa_email": "",
  "fofa_key": "",
  "zoomeye_api_key": "",
  "securitytrails_api_key": "",
  "virustotal_api_key": ""
}
```

All fields are optional. The tool runs fully on free sources with no configuration.

---

## 🛠️ Navigation

All menus support:

- **`0`** — Go back to previous menu
- **`ESC`** — Exit the tool immediately
- **`y` / `n`** — Strict yes/no prompts (loops until valid input)
- **`Ctrl+C`** — Graceful exit from anywhere

---

## 📝 License

MIT License — see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is for authorised security testing only. Users are responsible for complying with all applicable laws. The authors assume no liability for misuse or damage caused by this tool.

---

## 📧 Contact

**Author:** @g33l0 &nbsp; <a href="https://t.me/x0x0h33l0"><img src="https://upload.wikimedia.org/wikipedia/commons/8/82/Telegram_logo.svg" width="16" alt="Telegram"></a>

**Version:** 2.4 + Red Team Automation v2.5

---

<p align="center">
  <strong>Built for security professionals, by security professionals</strong>
</p>

<p align="center">⭐ Star this repo if you find it useful ⭐</p>
