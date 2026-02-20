# SpiderWeb

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-users%20ready-brightgreen.svg)]()

> Professional security intelligence platform with automated vulnerability assessment and red team attack chain analysis.

## 🎯 Features

- **Multi-Source IP Intelligence** - Aggregate data from 8+ sources (DNS, URLScan, Shodan, Censys, FOFA, ZoomEye, SecurityTrails)
- **Advanced Vulnerability Scanning** - CVE correlation, banner grabbing, default credentials, WAF detection
- **Red Team Automation** - Automated attack chain discovery with MITRE ATT&CK mapping
- **Smart Classification** - CDN/cloud/shared hosting detection with confidence scoring
- **Exploitability Analysis** - Complexity ratings (TRIVIAL/LOW/MEDIUM/HIGH)
- **Professional Reporting** - JSON, CSV, and formatted text output

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/github/spiderweb.git
cd spiderweb

# Install dependencies
pip install -r requirements.txt
```

**requirements.txt:**

```
requests>=2.31.0
beautifulsoup4>=4.12.0
aiohttp>=3.9.0
```

## 🚀 Quick Start

```bash
# Basic scan
python3 spiderweb.py

# Follow the interactive prompts:
# 1. Select input method (keyword-based or file-based)
# 2. Enter keywords: payment-portal,admin-login
# 3. Set target count: 100
# 4. Choose country: US (or 00 for worldwide)
```

## 💡 Usage Examples

### Keyword-Based Scan

```bash
python3 spiderweb.py
# Select: 1 (Keyword-based)
# Keywords: customer-portal,payment-gateway
# Count: 50
# Country: US
```

### File-Based Scan

```bash
# Create ips.txt with one IP per line
echo "192.168.x.xxx" > ips.txt
echo "10.0.x.xx" >> ips.txt

python3 spiderweb.py
# Select: 2 (File-based)
```

### With API Keys (Optional)

Configure API keys for premium data sources:

```bash
python3 spiderweb.py
# Select: 3 (Configure API Keys)
# Enter your Shodan, Censys, FOFA, etc. keys
```

## 📊 Output

SpiderWeb generates comprehensive reports in multiple formats:

```
spiderweb_results/
├── scan_20260218_034532_abc123.json    # Complete scan data
├── scan_20260218_034532_abc123.csv     # Spreadsheet-friendly
└── vulnerable_20260218_034532_abc123.txt  # High-risk findings only
```

### Example Output

```
═══════════════════════════════════════════════════════════
ADVANCED SECURITY ASSESSMENT RESULTS
═══════════════════════════════════════════════════════════

Total Alive      : 45
  Origin Servers  : 32
  CDN / Proxies   : 13
Vulnerable Targets: 8

═══════════════════════════════════════════════════════════
RED TEAM AUTOMATION - ATTACK CHAIN DISCOVERY
═══════════════════════════════════════════════════════════

Target: 46.xxx.xxx.xx (City, Country)
  Risk: CRITICAL | Chains: 2

  ⚠⚠⚠ Chain 1: Git → Database Compromise (TRIVIAL)
      1. Download .git directory
         → T1xxx - Data from Information Repositories
      2. Extract credentials from config files
         → T1xxx.yyy - Credentials In Files
      3. Connect to MySQL database
         → T1xxx - Valid Accounts
```

## 🔐 Security & Ethics

**IMPORTANT:** Only use on systems you are authorized to test.

- ✅ **Safe Mode (Default)** - Read-only reconnaissance, no exploitation
- ⚠️ **Aggressive Mode** - Requires explicit authorization (not enabled by default)
- 📝 **Audit Logging** - All operations logged for compliance
- 🛡️ **Multi-Tenant Awareness** - Warns when scanning shared infrastructure

## 🧩 Key Components

### Vulnerability Assessment

- CVE correlation via NVD API
- Default credential testing (safe mode)
- SSL/TLS vulnerability scanning
- Sensitive path discovery (`.git`, `.env`, config files)
- HTTP method testing (PUT, DELETE, TRACE)

### Red Team Automation

- Automated attack chain discovery
- MITRE ATT&CK framework mapping
- Exploitability analysis
- Credential extraction from source code
- Complexity rating system

### Intelligence Gathering

- Banner grabbing (HTTP, SSH, FTP, SMTP)
- WAF detection (Cloudflare, AWS, Akamai, ModSecurity, etc.)
- Subdomain enumeration
- WHOIS enrichment
- Geolocation mapping

## 📋 Data Sources

|Source        |Type   |Authentication|
|--------------|-------|--------------|
|DNS           |Free   |None          |
|URLScan       |Free   |None          |
|ThreatCrowd   |Free   |None          |
|Shodan        |Premium|API Key       |
|Censys        |Premium|API Key       |
|FOFA          |Premium|API Key       |
|ZoomEye       |Premium|API Key       |
|SecurityTrails|Premium|API Key       |

## 🎓 Advanced Features

### CDN Guardrails

Automatically identifies CDN edge nodes and adjusts risk scoring:

```
✓ Cloudflare, Akamai, Fastly, CloudFront detection
✓ Force-classification via ASN and reverse DNS
✓ Origin discovery recommendations
```

### Attack Chain Analysis

```python
# Discovered chains show complete attack paths:
Chain: Git → Database → Admin Access
  1. Download .git directory (T1213)
  2. Extract DB credentials (T1552.001)
  3. Connect to MySQL (T1078)
  4. Enumerate admin users (T1087)
  5. Escalate to cPanel (T1078)
```

### Confidence Scoring

```
Verification Confidence:
  ✓ CONFIRMED (200 OK + content) = High priority
  ⚠ PARTIAL (403 Forbidden) = Medium priority
  ✗ BLOCKED (404 Not Found) = Low priority
```

## 🛠️ Configuration

API keys are stored in `spiderweb_config.json`:

```json
{
  "shodan_api_key": "YOUR_KEY_HERE",
  "censys_api_id": "YOUR_ID_HERE",
  "censys_api_secret": "YOUR_SECRET_HERE"
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
1. Create your feature branch (`git checkout -b feature/AmazingFeature`)
1. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
1. Push to the branch (`git push origin feature/AmazingFeature`)
1. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the <LICENSE> file for details.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this tool.

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- OWASP Testing Guide
- NVD CVE Database
- All open-source intelligence sources

## 📧 Contact

**Author:** @g33l0 <a href="https://t.me/x0x0h33l0">
  <img src="https://upload.wikimedia.org/wikipedia/commons/8/82/Telegram_logo.svg" width="16" alt="Telegram">
</a>
**Version:** 2.4 + Red Team Automation

-----

<p align="center">
  <strong>Built for security professionals, by security professionals</strong>
</p>

<p align="center">
  ⭐ Star this repo if you find it useful! ⭐
</p>