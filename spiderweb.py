#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         SPIDERWEB PRO v2.4 + RED TEAM v2.5                   ║
║                          Complete Standalone Version                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

SINGLE FILE - NO EXTERNAL DEPENDENCIES REQUIRED

Author: g33l0
Version: 2.4 + Red Team 2.5
Status: Production Ready

FEATURES:
  ✓ Multi-source IP intelligence (8+ sources)
  ✓ Advanced vulnerability scanning
  ✓ Red Team attack chain analysis
  ✓ MITRE ATT&CK framework mapping
  ✓ Professional reporting (JSON/CSV/TXT)

USAGE:
  python3 spiderweb.py

REQUIREMENTS:
  Python 3.8+

DEPENDENCIES (auto-install prompt on first run):
  pip install requests beautifulsoup4 aiohttp

LEGAL:
  Use only on authorized systems. Unauthorized access is illegal.
"""

# ═══════════════════════════════════════════════════════════════════════
#  DEPENDENCY CHECKER
# ═══════════════════════════════════════════════════════════════════════

def check_dependencies():
    """Check and install required dependencies"""
    import sys

    required = {
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'aiohttp': 'aiohttp'
    }

    missing = []
    for package, import_name in required.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package)

    if missing:
        print("\n" + "="*70)
        print("MISSING DEPENDENCIES DETECTED")
        print("="*70)
        print(f"\nThe following packages are required but not installed:")
        for pkg in missing:
            print(f"  ✗ {pkg}")
        print(f"\nTo install all missing dependencies, run:")
        print(f"\n  pip install {' '.join(missing)}")
        print(f"\nOr install all at once:")
        print(f"\n  pip install requests beautifulsoup4 aiohttp")
        print("\n" + "="*70)
        try:
            response = input("\nInstall now? (y/n): ").lower()
            if response == 'y':
                import subprocess
                print(f"\nInstalling dependencies...")
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install'] + missing,
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    print("✓ Dependencies installed successfully!")
                    print("\nPlease run the script again.")
                else:
                    print("✗ Installation failed:")
                    print(result.stderr)
        except KeyboardInterrupt:
            print("\n\nInstallation cancelled.")
        sys.exit(1)

    return True

check_dependencies()

import requests
import re
import time
import json
import csv
import socket
import ssl
import asyncio
import aiohttp
import uuid
import logging
import concurrent.futures
from typing import Set, List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
from collections import defaultdict
from enum import Enum
import sys
import os
from pathlib import Path
import random
import threading
import signal
import hashlib
import base64
import tempfile
from urllib.parse import urljoin


# ═══════════════════════════════════════════════════════════════════════
#  COLORS
# ═══════════════════════════════════════════════════════════════════════
class Colors:
    GREEN   = '\033[92m'
    RED     = '\033[91m'
    WHITE   = '\033[97m'
    CYAN    = '\033[96m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    ENDC    = '\033[0m'
    DIM     = '\033[2m'
    BOLD    = '\033[1m'


class NavigationException(Exception):
    pass


class ExitException(Exception):
    pass


# ═══════════════════════════════════════════════════════════════════════
#  GLOBAL CONFIG
# ═══════════════════════════════════════════════════════════════════════
TIMEOUT_TCP    = 3
TIMEOUT_HTTP   = 5
TIMEOUT_DNS    = 2
TIMEOUT_BANNER = 3
MAX_CONCURRENT = 50  # Windows SelectorEventLoop: select() hard-limits to 512 FDs.
# Each IP scan opens ~8 concurrent sockets; 50×8=400 safely under the limit.
# ProactorEventLoop could handle more but causes WinError 10054 spam on Windows.

# ═══════════════════════════════════════════════════════════════════════
#  CDN / ACCELERATOR FORCE-CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════
FORCE_CDN_ASN_NUMBERS = {
    'AS13335', 'AS209242',
    'AS16625', 'AS20940', 'AS21342', 'AS21357', 'AS34164',
    'AS54113',
    'AS16509', 'AS14618',
    'AS33438',
    'AS19551',
}

FORCE_CDN_PTR_PATTERNS = [
    r'cloudflare', r'cloudflare-dns', r'awsglobalaccelerator\.com',
    r'cloudfront\.net', r'akamaiedge', r'akamai', r'fastly',
    r'edgesuite', r'edgekey', r'footprint\.net', r'stackpath', r'incapsula',
]

# ═══════════════════════════════════════════════════════════════════════
#  v2.4 MULTI-TENANT ASNS
# ═══════════════════════════════════════════════════════════════════════
MULTI_TENANT_ASNS = {
    'AS8560':  'IONOS',
    'AS26496': 'GoDaddy',
    'AS46606': 'HostGator/Bluehost/Newfold',
    'AS16276': 'OVH',
    'AS24940': 'Hetzner',
    'AS13335': 'Cloudflare',
    'AS14061': 'DigitalOcean',
    'AS47583': 'Hostinger',
    'AS6724':  'Strato',
    'AS47544': 'IQ PL Hosting',
}

# ═══════════════════════════════════════════════════════════════════════
#  SHARED HOSTING SIGNALS
# ═══════════════════════════════════════════════════════════════════════
SHARED_HOSTING_SIGNALS = {
    'rdns_patterns': [
        r'shared', r'cpanel', r'dapanel', r'webhost', r'hosting',
        r'host\d+', r'server\d+', r'web\d+', r'vps\d+',
        r'plesk', r'directadmin', r'webmin', r'ispconfig'
    ],
    'control_panels': [
        '/cpanel', '/whm', '/plesk', '/directadmin',
        ':2082', ':2083', ':2086', ':2087', ':8443',
        '/webmail', '/horde', '/roundcube'
    ],
}


# ═══════════════════════════════════════════════════════════════════════
#  ANIMATED SPINNER
# ═══════════════════════════════════════════════════════════════════════
class Spinner:
    FRAMES = ['   ', '.  ', '.. ', '...', ' ..', '  .']

    def __init__(self, message: str = "Generating IPs, Please wait"):
        self.message = message
        self.running = False
        self._thread = None
        self._idx    = 0

    def _spin(self):
        while self.running:
            frame = self.FRAMES[self._idx % len(self.FRAMES)]
            print(f"\r{Colors.CYAN}{self.message}{frame}{Colors.ENDC}", end='', flush=True)
            self._idx += 1
            time.sleep(0.35)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self, final_msg: str = ""):
        self.running = False
        if self._thread:
            self._thread.join()
        print(f"\r{' ' * 70}\r", end='', flush=True)
        if final_msg:
            print(final_msg, flush=True)


# ═══════════════════════════════════════════════════════════════════════
#  VERIFICATION STATUS ENUM
# ═══════════════════════════════════════════════════════════════════════
class VerificationStatus(Enum):
    CONFIRMED = "CONFIRMED"
    PARTIAL   = "PARTIAL"
    BLOCKED   = "BLOCKED"
    UNTESTED  = "UNTESTED"


# ═══════════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class CVEInfo:
    cve_id:      str
    severity:    str
    score:       float
    description: str


@dataclass
class BannerInfo:
    port:    int
    service: str
    banner:  str
    version: Optional[str] = None


@dataclass
class DefaultCredResult:
    service:  str
    username: str
    status:   str


@dataclass
class WAFInfo:
    detected:   bool = False
    waf_name:   Optional[str] = None
    confidence: float = 0.0


@dataclass
class SSLVulnerability:
    vulnerable:   bool = False
    issues:       List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)


@dataclass
class SensitivePathEnhanced:
    path:             str
    status_code:      int
    accessible:       bool
    content_type:     Optional[str] = None
    response_size:    int = 0
    has_content:      bool = False
    verification:     VerificationStatus = VerificationStatus.UNTESTED
    evidence_preview: Optional[str] = None

    def get_verdict(self) -> str:
        if self.status_code == 200 and self.has_content:
            return "✓ CONFIRMED (200 OK, non-empty)"
        elif self.status_code in (403, 401):
            return "⚠ PARTIAL (exists, access denied)"
        elif self.status_code == 404:
            return "✗ BLOCKED (404 Not Found)"
        else:
            return f"? UNKNOWN (HTTP {self.status_code})"


@dataclass
class SubdomainInfo:
    subdomain: str
    resolved:  bool
    ip:        Optional[str] = None


@dataclass
class ExploitabilityNote:
    issue_type:     str
    impact:         str
    safe_exploit:   Optional[str] = None
    bug_bounty_tip: Optional[str] = None


@dataclass
class AttackSurfaceSummary:
    exposed_services:  List[str] = field(default_factory=list)
    sensitive_files:   Dict[str, str] = field(default_factory=dict)
    http_misconfig:    List[str] = field(default_factory=list)
    hosting_type:      str = "UNKNOWN"
    multi_tenant_risk: bool = False
    scope_warning:     Optional[str] = None
    confidence_score:  float = 0.0


@dataclass
class VulnerabilityIndicators:
    exposed_db_port:          bool = False
    exposed_admin_port:       bool = False
    outdated_software:        bool = False
    missing_security_headers: bool = False
    weak_ssl:                 bool = False
    directory_listing:        bool = False
    sql_error_disclosure:     bool = False
    sql_backend_detected:     Optional[str] = None
    dangerous_http_methods:   List[str] = field(default_factory=list)
    sensitive_paths_exposed:  List[str] = field(default_factory=list)
    default_creds_found:      List[str] = field(default_factory=list)
    risk_score:               float = 0.0
    risk_level:               str = "MINIMAL"
    vulnerable_services:      List[str] = field(default_factory=list)
    recommendations:          List[str] = field(default_factory=list)
    verified_findings:        List[SensitivePathEnhanced] = field(default_factory=list)
    exploitability_notes:     List[ExploitabilityNote] = field(default_factory=list)
    attack_surface:           AttackSurfaceSummary = field(default_factory=AttackSurfaceSummary)
    confidence_weighted_score: float = 0.0


@dataclass
class ClassificationSignals:
    asn_signal:  str   = "none"
    asn_weight:  float = 0.0
    rdns_signal: str   = "none"
    rdns_weight: float = 0.0
    port_signal: str   = "none"
    port_weight: float = 0.0
    cert_signal: str   = "none"
    cert_weight: float = 0.0
    http_signal: str   = "none"
    http_weight: float = 0.0


@dataclass
class HostingClassification:
    category:               str = "UNKNOWN"
    provider:               Optional[str] = None
    confidence:             float = 0.0
    is_origin:              bool = False
    is_cdn:                 bool = False
    origin_discovery_paths: List[str] = field(default_factory=list)
    signals:                ClassificationSignals = field(default_factory=ClassificationSignals)


@dataclass
class LivenessStatus:
    status:                   str = "dead"
    network_reachability:     str = "unreachable"
    application_reachability: str = "unavailable"
    tcp_responsive:           bool = False
    http_responsive:          bool = False
    https_responsive:         bool = False
    tls_handshake:            bool = False
    http_status:              Optional[int] = None
    https_status:             Optional[int] = None
    response_time:            Optional[float] = None
    ports_scanned:            List[int] = field(default_factory=list)
    probe_outcomes:           Dict[str, str] = field(default_factory=dict)

    def log_probe(self, probe_type: str, outcome: str):
        self.probe_outcomes[probe_type] = outcome

    def get_debug_info(self) -> str:
        lines = [
            f"Network: {self.network_reachability}",
            f"Application: {self.application_reachability}",
        ]
        if self.probe_outcomes:
            lines.append("Probe Details:")
            for probe, outcome in self.probe_outcomes.items():
                lines.append(f"  • {probe}: {outcome}")
        return "\n".join(lines)


@dataclass
class DomainAttribution:
    reverse_dns:      Optional[str] = None
    tls_san_domains:  List[str] = field(default_factory=list)
    all_domains:      List[str] = field(default_factory=list)
    subdomains_found: List[str] = field(default_factory=list)


@dataclass
class SSLInfo:
    valid:   bool = False
    issuer:  Optional[str] = None
    subject: Optional[str] = None
    expiry:  Optional[str] = None
    version: Optional[str] = None
    cipher:  Optional[str] = None
    ssl_vulnerabilities: SSLVulnerability = field(default_factory=SSLVulnerability)


@dataclass
class WebInfo:
    server:           Optional[str] = None
    title:            Optional[str] = None
    powered_by:       Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    waf_detected:     WAFInfo = field(default_factory=WAFInfo)
    http_methods:     List[str] = field(default_factory=list)
    sensitive_paths:  List[SensitivePathEnhanced] = field(default_factory=list)


@dataclass
class WHOISInfo:
    network_name:  Optional[str] = None
    organization:  Optional[str] = None
    abuse_contact: Optional[str] = None
    net_range:     Optional[str] = None
    country:       Optional[str] = None


@dataclass
class IPAnalysisResult:
    ip: str

    liveness:      LivenessStatus          = field(default_factory=LivenessStatus)
    domains:       DomainAttribution       = field(default_factory=DomainAttribution)
    hosting:       HostingClassification   = field(default_factory=HostingClassification)
    vulnerability: VulnerabilityIndicators = field(default_factory=VulnerabilityIndicators)

    tcp_ports_open: List[int] = field(default_factory=list)
    asn:            Optional[str] = None
    asn_org:        Optional[str] = None
    country:        Optional[str] = None
    country_name:   Optional[str] = None
    city:           Optional[str] = None
    region:         Optional[str] = None
    isp:            Optional[str] = None
    organization:   Optional[str] = None

    ssl:   SSLInfo   = field(default_factory=SSLInfo)
    web:   WebInfo   = field(default_factory=WebInfo)
    whois: WHOISInfo = field(default_factory=WHOISInfo)

    detected_technologies: List[str] = field(default_factory=list)
    service_banners:       List[BannerInfo] = field(default_factory=list)
    cve_matches:           List[CVEInfo] = field(default_factory=list)
    default_creds:         List[DefaultCredResult] = field(default_factory=list)
    data_sources:          List[str] = field(default_factory=list)

    scan_timestamp:  str = field(default_factory=lambda: datetime.now().isoformat())
    source_keywords: List[str] = field(default_factory=list)
    target_country:  Optional[str] = None
    scan_id: str = field(
        default_factory=lambda: hashlib.md5(
            str(datetime.now().timestamp()).encode()
        ).hexdigest()[:8]
    )


# ═══════════════════════════════════════════════════════════════════════
#  EXPLOITABILITY DATABASE
# ═══════════════════════════════════════════════════════════════════════
EXPLOITABILITY_DATABASE = {
    'PUT': ExploitabilityNote(
        issue_type='HTTP PUT Enabled',
        impact='May allow arbitrary file upload/overwrite if no authentication',
        safe_exploit='curl -X PUT http://target/test.txt -d "test"',
        bug_bounty_tip='Test PUT on your own file → file overwrite vulnerability'
    ),
    'DELETE': ExploitabilityNote(
        issue_type='HTTP DELETE Enabled',
        impact='May allow resource deletion if misconfigured',
        safe_exploit='curl -X DELETE http://target/test.txt',
        bug_bounty_tip='Test DELETE on your uploaded file → unauthorized deletion'
    ),
    'TRACE': ExploitabilityNote(
        issue_type='HTTP TRACE Enabled',
        impact='Cross-Site Tracing (XST) + cookie theft in legacy clients',
        safe_exploit='curl -X TRACE http://target/ -H "X-Custom: test"',
        bug_bounty_tip='Low severity but report if httpOnly cookies reflected'
    ),
    'MySQL': ExploitabilityNote(
        issue_type='Exposed MySQL',
        impact='Remote credential brute-force, fingerprinting, potential RCE via UDF',
        safe_exploit='nmap -p 3306 --script mysql-info target',
        bug_bounty_tip='Report as CRITICAL with mysql -h target connection screenshot'
    ),
    'PostgreSQL': ExploitabilityNote(
        issue_type='Exposed PostgreSQL',
        impact='Remote credential brute-force, version disclosure, potential RCE',
        safe_exploit='psql -h target -U postgres (test connection only)',
        bug_bounty_tip='Report with service banner disclosure evidence'
    ),
    'cPanel': ExploitabilityNote(
        issue_type='Exposed cPanel',
        impact='Hosting control panel → full server compromise if weak creds',
        safe_exploit='Visit https://target:2083 and screenshot login page',
        bug_bounty_tip='Check for default credentials, version disclosure'
    ),
    '.git': ExploitabilityNote(
        issue_type='Exposed .git Directory',
        impact='Full source code disclosure → credentials, API keys, logic',
        safe_exploit='git-dumper http://target/.git/ /tmp/repo',
        bug_bounty_tip='Download and search for hardcoded secrets'
    ),
    '.env': ExploitabilityNote(
        issue_type='Exposed .env File',
        impact='Environment variables → database credentials, API keys, secrets',
        safe_exploit='curl http://target/.env',
        bug_bounty_tip='Screenshot showing DB_PASSWORD, AWS keys, or similar'
    ),
    'wp-config.php': ExploitabilityNote(
        issue_type='Exposed wp-config.php',
        impact='WordPress database credentials disclosure',
        safe_exploit='curl http://target/wp-config.php',
        bug_bounty_tip='Report with redacted DB password screenshot'
    ),
    'phpinfo': ExploitabilityNote(
        issue_type='Exposed phpinfo()',
        impact='Full PHP configuration → paths, versions, loaded modules',
        safe_exploit='curl http://target/phpinfo.php',
        bug_bounty_tip='Screenshot showing sensitive directives'
    ),
}


# ═══════════════════════════════════════════════════════════════════════
#  API CONFIG
# ═══════════════════════════════════════════════════════════════════════
class DataSourceConfig:
    def __init__(self):
        self.config_file = Path("spiderweb_config.json")
        self.api_keys    = self._load()

    def _load(self) -> Dict:
        defaults = {
            "shodan_api_key":         "",
            "censys_api_id":          "",
            "censys_api_secret":      "",
            "fofa_email":             "",
            "fofa_key":               "",
            "zoomeye_api_key":        "",
            "securitytrails_api_key": "",
            "virustotal_api_key":     "",
        }
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return {**defaults, **json.load(f)}
            except Exception:
                pass
        return defaults

    def save(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.api_keys, f, indent=2)
        except Exception:
            pass

    def has_shodan(self)         -> bool: return bool(self.api_keys.get('shodan_api_key'))
    def has_censys(self)         -> bool: return bool(self.api_keys.get('censys_api_id') and self.api_keys.get('censys_api_secret'))
    def has_fofa(self)           -> bool: return bool(self.api_keys.get('fofa_email') and self.api_keys.get('fofa_key'))
    def has_zoomeye(self)        -> bool: return bool(self.api_keys.get('zoomeye_api_key'))
    def has_securitytrails(self) -> bool: return bool(self.api_keys.get('securitytrails_api_key'))


# ═══════════════════════════════════════════════════════════════════════
#  CDN FORCE-CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════
def is_force_cdn(asn: str, ptr: str) -> bool:
    asn_upper = (asn or '').upper()
    for asn_num in FORCE_CDN_ASN_NUMBERS:
        if asn_num in asn_upper:
            return True
    ptr_lower = (ptr or '').lower()
    for pattern in FORCE_CDN_PTR_PATTERNS:
        if re.search(pattern, ptr_lower):
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════
#  SCOPE SAFETY GUARDRAILS
# ═══════════════════════════════════════════════════════════════════════
def get_scope_warning(asn: str, category: str) -> Optional[str]:
    if not asn:
        return None
    asn_upper = asn.upper()
    for asn_num, provider in MULTI_TENANT_ASNS.items():
        if asn_num in asn_upper:
            if category in ('SHARED_HOSTING', 'CLOUD_COMPUTE'):
                return (
                    f"⚠ MULTI-TENANT INFRASTRUCTURE ({provider})\n"
                    f"   Multiple tenants/customers may be impacted.\n"
                    f"   LIMIT testing to passive verification only.\n"
                    f"   Active exploitation may affect other tenants."
                )
    return None


def detect_shared_hosting_confidence(reverse_dns: str,
                                     open_ports: List[int],
                                     web_paths: List[str] = None) -> float:
    confidence = 0.0
    if reverse_dns:
        rdns_lower = reverse_dns.lower()
        for pattern in SHARED_HOSTING_SIGNALS['rdns_patterns']:
            if re.search(pattern, rdns_lower):
                confidence += 0.15
                break
    control_ports = [2082, 2083, 2086, 2087, 8443, 10000]
    if any(p in open_ports for p in control_ports):
        confidence += 0.25
    if 21 in open_ports and 3306 in open_ports:
        confidence += 0.20
    if web_paths:
        for path in web_paths:
            for panel in SHARED_HOSTING_SIGNALS['control_panels']:
                if panel in path:
                    confidence += 0.15
                    break
    return min(1.0, confidence)


def calculate_confidence_weighted_score(base_score: float,
                                        verified_findings: List[SensitivePathEnhanced],
                                        total_findings: int) -> float:
    if total_findings == 0:
        return base_score
    confidence_sum = 0.0
    for finding in verified_findings:
        if finding.status_code == 200 and finding.has_content:
            confidence_sum += 1.0
        elif finding.status_code in (403, 401):
            confidence_sum += 0.7
        else:
            confidence_sum += 0.4
    avg_confidence = confidence_sum / total_findings if total_findings > 0 else 0.5
    return base_score * avg_confidence


# ═══════════════════════════════════════════════════════════════════════
#  VULNERABILITY ASSESSOR
# ═══════════════════════════════════════════════════════════════════════
def assess_vulnerability_enhanced(result,
                                   response_headers: Dict = None,
                                   response_body: str = None,
                                   verified_paths: List[SensitivePathEnhanced] = None) -> VulnerabilityIndicators:
    vuln = VulnerabilityIndicators()

    if result.hosting.is_cdn or result.hosting.category == "CDN_EDGE":
        vuln.risk_score = 0.0
        vuln.risk_level = "MINIMAL"
        vuln.confidence_weighted_score = 0.0
        return vuln

    risk_factors = []

    vuln.attack_surface.hosting_type = result.hosting.category
    vuln.attack_surface.scope_warning = get_scope_warning(
        result.asn or '', result.hosting.category
    )
    if vuln.attack_surface.scope_warning:
        vuln.attack_surface.multi_tenant_risk = True

    if 22 in result.tcp_ports_open:
        risk_factors.append(2.0)
        vuln.vulnerable_services.append("SSH (Port 22) - Ensure key-based auth")
        vuln.attack_surface.exposed_services.append("SSH:22")
        vuln.recommendations.append(
            "MEDIUM: SSH exposed. Ensure: key-based auth, no root login, fail2ban enabled."
        )

    if 80 in result.tcp_ports_open or 443 in result.tcp_ports_open:
        risk_factors.append(0.5)

    for port, db_name in {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL',
                          27017: 'MongoDB', 6379: 'Redis'}.items():
        if port in result.tcp_ports_open:
            vuln.exposed_db_port = True
            vuln.sql_backend_detected = db_name
            vuln.vulnerable_services.append(f"{db_name} (Port {port})")
            vuln.attack_surface.exposed_services.append(f"{db_name}:{port}")
            risk_factors.append(4.0)
            if db_name in EXPLOITABILITY_DATABASE:
                vuln.exploitability_notes.append(EXPLOITABILITY_DATABASE[db_name])
            vuln.recommendations.append(
                f"CRITICAL: Bind {db_name} on port {port} to 127.0.0.1 only. "
                f"Block external access via firewall."
            )

    admin_port_map = {
        2082: 'cPanel HTTP', 2083: 'cPanel SSL', 8080: 'Admin Panel',
        8443: 'Admin Panel SSL', 10000: 'Webmin', 8000: 'Dev Server', 2087: 'WHM'
    }
    for port, service in admin_port_map.items():
        if port in result.tcp_ports_open:
            vuln.exposed_admin_port = True
            vuln.vulnerable_services.append(f"{service} (Port {port})")
            vuln.attack_surface.exposed_services.append(f"{service}:{port}")
            risk_factors.append(3.0)
            if 'cPanel' in service and 'cPanel' in EXPLOITABILITY_DATABASE:
                vuln.exploitability_notes.append(EXPLOITABILITY_DATABASE['cPanel'])
            vuln.recommendations.append(
                f"HIGH: Restrict {service} (port {port}) to VPN/IP allowlist."
            )

    known_ports = {22, 80, 443, 3306, 5432, 1433, 27017, 6379, 2082, 2083, 8080, 8443, 10000, 8000, 2087}
    other_ports = set(result.tcp_ports_open) - known_ports
    if other_ports:
        risk_factors.append(len(other_ports) * 0.5)

    if verified_paths:
        confirmed_paths = [p for p in verified_paths if p.status_code == 200 and p.has_content]
        if confirmed_paths:
            vuln.sensitive_paths_exposed = [p.path for p in confirmed_paths]
            risk_factors.append(2.8)
            vuln.vulnerable_services.append(f"Sensitive Files Exposed: {len(confirmed_paths)}")
            for path in confirmed_paths[:10]:
                vuln.attack_surface.sensitive_files[path.path] = path.get_verdict()
                for key in EXPLOITABILITY_DATABASE:
                    if key in path.path:
                        vuln.exploitability_notes.append(EXPLOITABILITY_DATABASE[key])
                        break
            top_paths = ', '.join([p.path for p in confirmed_paths[:3]])
            vuln.recommendations.append(f"HIGH: Remove/protect exposed files: {top_paths}")
        vuln.verified_findings = verified_paths

    if result.web.http_methods:
        dangerous = [m for m in result.web.http_methods if m in ['PUT', 'DELETE', 'TRACE', 'PATCH']]
        if dangerous:
            vuln.dangerous_http_methods = dangerous
            risk_factors.append(1.5)
            vuln.vulnerable_services.append(f"Dangerous HTTP Methods: {', '.join(dangerous)}")
            vuln.attack_surface.http_misconfig.extend(dangerous)
            for method in dangerous:
                if method in EXPLOITABILITY_DATABASE:
                    vuln.exploitability_notes.append(EXPLOITABILITY_DATABASE[method])
            vuln.recommendations.append(f"MEDIUM: Disable HTTP methods: {', '.join(dangerous)}")

    if result.hosting.is_cdn:
        risk_factors.append(-2.0)
    elif result.hosting.category == "DEDICATED_VPS":
        risk_factors.append(2.0)
    elif result.hosting.category == "SHARED_HOSTING":
        risk_factors.append(1.0)

    vuln.risk_score = min(10.0, max(0.0, sum(risk_factors))) if risk_factors else 0.0
    vuln.confidence_weighted_score = calculate_confidence_weighted_score(
        vuln.risk_score, vuln.verified_findings, len(vuln.verified_findings)
    )

    if vuln.verified_findings:
        high_conf = sum(1 for v in vuln.verified_findings if v.status_code == 200 and v.has_content)
        vuln.attack_surface.confidence_score = high_conf / len(vuln.verified_findings)
    else:
        vuln.attack_surface.confidence_score = 0.5

    score = vuln.confidence_weighted_score
    if score >= 7.0:
        vuln.risk_level = "CRITICAL"
    elif score >= 5.0:
        vuln.risk_level = "HIGH"
    elif score >= 3.0:
        vuln.risk_level = "MEDIUM"
    elif score >= 1.0:
        vuln.risk_level = "LOW"
    else:
        vuln.risk_level = "MINIMAL"

    return vuln


# Alias so both old and new call-sites work
class VulnerabilityAssessor:
    @staticmethod
    def assess(result, response_headers=None, response_body=None, verified_paths=None):
        return assess_vulnerability_enhanced(result, response_headers, response_body, verified_paths)


# ═══════════════════════════════════════════════════════════════════════
#  CLASSIFICATION ENGINE
# ═══════════════════════════════════════════════════════════════════════
class ClassificationEngine:

    CDN_ASN = {
        'Cloudflare': ['AS13335', 'AS209242'],
        'Akamai':     ['AS16625', 'AS20940', 'AS21342', 'AS21357', 'AS34164'],
        'Fastly':     ['AS54113'],
        'CloudFront': ['AS16509', 'AS14618'],
        'StackPath':  ['AS33438'],
        'Incapsula':  ['AS19551'],
    }

    CLOUD_ASN = {
        'AWS':          ['AS16509', 'AS14618', 'AS8987'],
        'Google Cloud': ['AS15169', 'AS36040', 'AS396982'],
        'Azure':        ['AS8075', 'AS8068'],
        'DigitalOcean': ['AS14061'],
        'Linode':       ['AS63949'],
        'Vultr':        ['AS20473'],
        'OVH':          ['AS16276'],
        'Hetzner':      ['AS24940'],
    }

    MANAGED_HOSTING = {
        'Squarespace':   ['AS46652'],
        'Wix':           ['AS58182'],
        'Shopify':       ['AS55429'],
        'WordPress.com': ['AS2635'],
    }

    SHARED_HOSTING = {
        'GoDaddy':   ['AS26496'],
        'HostGator': ['AS46606'],
        'Bluehost':  ['AS46606'],
        'Namecheap': ['AS22612'],
        'IONOS':     ['AS8560'],
        'DreamHost': ['AS26347'],
        'Newfold':   ['AS46606', 'AS26496'],
    }

    RDNS_PATTERNS = {
        'cdn':           [r'cloudflare', r'cloudfront', r'akamai', r'fastly', r'cdn', r'cache',
                          r'awsglobalaccelerator', r'edgesuite', r'edgekey'],
        'cloud_frontend':[r'1e100\.net', r'googleusercontent', r'compute\.amazonaws'],
        'cloud_compute': [r'ec2', r'\.compute\.', r'azure', r'cloud'],
        'shared':        [r'shared', r'cpanel', r'plesk', r'directadmin',
                          r'host\d+', r'server\d+'],
    }

    ORIGIN_DISCOVERY = {
        'Cloudflare': [
            'DNS History via SecurityTrails / ViewDNS',
            'Subdomain enumeration (mail., ftp., direct., origin., cpanel.)',
            'Certificate Transparency logs (crt.sh)',
            'IPv6 address lookup (may bypass CDN)',
            'MX record IP lookup',
        ],
        'Akamai': [
            'Origin header injection test',
            'Subdomain scanning for non-proxied assets',
            'Historical DNS records',
        ],
        'Fastly': [
            'Subdomain enumeration',
            'DNS history lookup',
        ],
        'CloudFront': [
            'S3 bucket origin enumeration',
            'Historical DNS / ELB endpoint discovery',
        ],
    }

    @classmethod
    def classify(cls, asn: str, asn_org: str, reverse_dns: str,
                 ports: List[int], ssl_valid: bool, http_responsive: bool,
                 headers: Dict = None) -> HostingClassification:

        signals = ClassificationSignals()

        if is_force_cdn(asn, reverse_dns):
            provider = cls._detect_cdn_provider(asn, reverse_dns)
            paths    = cls.ORIGIN_DISCOVERY.get(provider, ['DNS history', 'Subdomain enumeration'])
            return HostingClassification(
                category='CDN_EDGE', provider=provider, confidence=1.0,
                is_origin=False, is_cdn=True,
                origin_discovery_paths=paths, signals=signals,
            )

        asn_cat, asn_provider, asn_w = cls._analyze_asn(asn)
        signals.asn_signal = asn_cat
        signals.asn_weight = asn_w

        rdns_cat, rdns_w = cls._analyze_rdns(reverse_dns)
        signals.rdns_signal = rdns_cat
        signals.rdns_weight = rdns_w

        port_cat, port_w = cls._analyze_ports(ports)
        signals.port_signal = port_cat
        signals.port_weight = port_w

        if ssl_valid:
            signals.cert_signal = "valid"
            signals.cert_weight = 0.15
        if http_responsive:
            signals.http_signal = "responsive"
            signals.http_weight = 0.10

        cdn_headers_present = False
        if headers:
            cdn_h = ['CF-RAY', 'X-Akamai-Request-ID', 'X-Cache', 'X-Fastly-Request-ID', 'X-Amz-Cf-Id']
            cdn_headers_present = any(h in headers for h in cdn_h)

        if asn_cat == "cdn" or rdns_cat == "cdn" or cdn_headers_present:
            provider = asn_provider or cls._detect_cdn_provider(asn, reverse_dns)
            conf     = min(1.0, asn_w + rdns_w + (0.2 if cdn_headers_present else 0))
            paths    = cls.ORIGIN_DISCOVERY.get(provider, ['DNS history', 'Subdomain enumeration'])
            if conf >= 0.60:
                return HostingClassification(
                    category='CDN_EDGE', provider=provider, confidence=conf,
                    is_origin=False, is_cdn=True,
                    origin_discovery_paths=paths, signals=signals,
                )

        if rdns_cat == "cloud_frontend":
            conf = rdns_w + signals.cert_weight + signals.http_weight
            if conf >= 0.75:
                return HostingClassification(
                    category="CLOUD_FRONTEND", provider=asn_provider,
                    confidence=conf, is_origin=True, is_cdn=False, signals=signals,
                )

        if asn_cat == "cloud" or rdns_cat == "cloud_compute":
            pos  = asn_w + rdns_w + signals.cert_weight
            neg  = signals.port_weight * 0.3 if port_cat == "shared" else 0
            conf = pos - neg
            if conf >= 0.75:
                return HostingClassification(
                    category="CLOUD_COMPUTE", provider=asn_provider,
                    confidence=conf, is_origin=True, is_cdn=False, signals=signals,
                )

        if asn_cat == "managed":
            conf = asn_w + signals.cert_weight + signals.http_weight
            if conf >= 0.75:
                return HostingClassification(
                    category="MANAGED_HOSTING", provider=asn_provider,
                    confidence=conf, is_origin=True, is_cdn=False, signals=signals,
                )

        shared_signals = sum([asn_cat == "shared", rdns_cat == "shared", port_cat == "shared"])
        if shared_signals >= 1:
            conf = min(1.0, asn_w + rdns_w + signals.port_weight)
            if conf >= 0.70 or asn_cat == "shared":
                return HostingClassification(
                    category="SHARED_HOSTING", provider=asn_provider,
                    confidence=max(conf, asn_w), is_origin=True, is_cdn=False, signals=signals,
                )

        if asn_cat in ("generic", "none") and rdns_cat in ("generic", "none") and port_cat == "dedicated":
            conf = (signals.port_weight + signals.cert_weight + signals.http_weight) / 0.75
            if conf >= 0.75:
                return HostingClassification(
                    category="DEDICATED_VPS", provider=None,
                    confidence=conf, is_origin=True, is_cdn=False, signals=signals,
                )

        return HostingClassification(
            category="UNKNOWN", confidence=0.0, is_origin=False, is_cdn=False, signals=signals,
        )

    @classmethod
    def _detect_cdn_provider(cls, asn: str, ptr: str) -> str:
        asn_u = (asn or '').upper()
        ptr_l = (ptr or '').lower()
        if 'AS13335' in asn_u or 'AS209242' in asn_u or 'cloudflare' in ptr_l:
            return 'Cloudflare'
        if any(a in asn_u for a in ['AS16625', 'AS20940', 'AS21342']) or 'akamai' in ptr_l:
            return 'Akamai'
        if 'AS54113' in asn_u or 'fastly' in ptr_l:
            return 'Fastly'
        if 'AS16509' in asn_u or 'AS14618' in asn_u or 'cloudfront' in ptr_l or 'awsglobal' in ptr_l:
            return 'CloudFront'
        if 'AS33438' in asn_u or 'stackpath' in ptr_l:
            return 'StackPath'
        if 'AS19551' in asn_u or 'incapsula' in ptr_l:
            return 'Incapsula'
        return 'CDN'

    @classmethod
    def _analyze_asn(cls, asn: str) -> Tuple[str, Optional[str], float]:
        if not asn:
            return "none", None, 0.0
        for provider, asn_list in cls.CDN_ASN.items():
            if any(a in asn for a in asn_list):
                return "cdn", provider, 1.0
        for provider, asn_list in cls.CLOUD_ASN.items():
            if any(a in asn for a in asn_list):
                return "cloud", provider, 0.85
        for provider, asn_list in cls.MANAGED_HOSTING.items():
            if any(a in asn for a in asn_list):
                return "managed", provider, 0.90
        for provider, asn_list in cls.SHARED_HOSTING.items():
            if any(a in asn for a in asn_list):
                return "shared", provider, 0.85
        return "generic", None, 0.0

    @classmethod
    def _analyze_rdns(cls, rdns: str) -> Tuple[str, float]:
        if not rdns:
            return "none", 0.0
        r = rdns.lower()
        for p in cls.RDNS_PATTERNS['cdn']:
            if re.search(p, r):
                return "cdn", 0.90
        for p in cls.RDNS_PATTERNS['cloud_frontend']:
            if re.search(p, r):
                return "cloud_frontend", 0.80
        for p in cls.RDNS_PATTERNS['cloud_compute']:
            if re.search(p, r):
                return "cloud_compute", 0.75
        for p in cls.RDNS_PATTERNS['shared']:
            if re.search(p, r):
                return "shared", 0.80
        return "generic", 0.0

    @classmethod
    def _analyze_ports(cls, ports: List[int]) -> Tuple[str, float]:
        if not ports:
            return "none", 0.0
        if 21 in ports and 3306 in ports:
            return "shared", 0.70
        if any(p in ports for p in [2082, 2083, 10000]):
            return "shared", 0.75
        if 22 in ports and 21 not in ports and 3306 not in ports:
            return "dedicated", 0.50
        return "generic", 0.0


# ═══════════════════════════════════════════════════════════════════════
#  ADVANCED SCANNERS
# ═══════════════════════════════════════════════════════════════════════
class BannerGrabber:
    @staticmethod
    async def grab_banner(ip: str, port: int) -> Optional[BannerInfo]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=TIMEOUT_BANNER
            )
            if port == 80:
                writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port in (21, 22):
                pass
            elif port == 25:
                writer.write(b'EHLO test\r\n')
            else:
                writer.write(b'\r\n')
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            banner = data.decode('utf-8', errors='ignore').strip()
            if banner:
                service, version = BannerGrabber._parse_banner(banner, port)
                return BannerInfo(port=port, service=service, banner=banner[:200], version=version)
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_banner(banner: str, port: int) -> Tuple[str, Optional[str]]:
        banner_lower = banner.lower()
        if port in (80, 443, 8080, 8443):
            if 'apache' in banner_lower:
                match = re.search(r'apache/([\d.]+)', banner_lower)
                return 'Apache', match.group(1) if match else None
            if 'nginx' in banner_lower:
                match = re.search(r'nginx/([\d.]+)', banner_lower)
                return 'nginx', match.group(1) if match else None
            if 'iis' in banner_lower:
                match = re.search(r'iis/([\d.]+)', banner_lower)
                return 'IIS', match.group(1) if match else None
            return 'HTTP', None
        if port == 22:
            if 'ssh' in banner_lower:
                match = re.search(r'openssh[_-]([\d.]+)', banner_lower)
                return 'OpenSSH', match.group(1) if match else None
            return 'SSH', None
        if port == 21:
            if 'ftp' in banner_lower:
                match = re.search(r'(vsftpd|proftpd|pureftpd)\s+([\d.]+)', banner_lower)
                if match:
                    return match.group(1), match.group(2)
            return 'FTP', None
        if port == 25:
            return 'SMTP', None
        return 'Unknown', None


class CVECorrelator:
    @staticmethod
    async def lookup_cves(session: aiohttp.ClientSession,
                          software: str, version: str) -> List[CVEInfo]:
        if not software or not version:
            return []
        try:
            version_clean = re.sub(r'[^\d.]', '', version)
            if not version_clean:
                return []
            url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                   f"?keywordSearch={software}+{version_clean}&resultsPerPage=3")
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status != 200:
                    return []
                data = await r.json()
                cves = []
                for vuln in data.get('vulnerabilities', [])[:3]:
                    cve_data = vuln.get('cve', {})
                    cve_id   = cve_data.get('id', 'N/A')
                    metrics  = cve_data.get('metrics', {})
                    cvss_v3  = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                    cvss_v2  = metrics.get('cvssMetricV2',  [{}])[0].get('cvssData', {})
                    severity = cvss_v3.get('baseSeverity', cvss_v2.get('severity', 'UNKNOWN'))
                    score    = cvss_v3.get('baseScore',    cvss_v2.get('baseScore', 0.0))
                    descriptions = cve_data.get('descriptions', [])
                    desc = descriptions[0].get('value', '')[:150] if descriptions else ''
                    cves.append(CVEInfo(cve_id=cve_id, severity=severity,
                                        score=float(score), description=desc))
                return cves
        except Exception:
            return []


class DefaultCredChecker:
    DEFAULT_CREDS = {
        'mysql':      [('root',''), ('root','root'), ('root','password'), ('admin','admin')],
        'ftp':        [('anonymous',''), ('admin','admin'), ('ftp','ftp')],
        'ssh':        [('root','root'), ('admin','admin'), ('ubuntu','ubuntu')],
        'cpanel':     [('admin','admin'), ('root','root')],
        'webmin':     [('admin','admin'), ('root','changeme')],
        'phpmyadmin': [('root',''), ('root','root'), ('admin','admin')],
    }

    @staticmethod
    async def test_ftp(ip: str, port: int, creds: List[Tuple[str, str]]) -> List[DefaultCredResult]:
        results = []
        for user, pwd in creds[:2]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=3
                )
                await asyncio.wait_for(reader.readline(), timeout=2)
                writer.write(f'USER {user}\r\n'.encode())
                await writer.drain()
                await asyncio.wait_for(reader.readline(), timeout=2)
                writer.write(f'PASS {pwd}\r\n'.encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.readline(), timeout=2)
                writer.close()
                await writer.wait_closed()
                if b'230' in response:
                    results.append(DefaultCredResult(service='FTP', username=user, status='SUCCESS'))
                else:
                    results.append(DefaultCredResult(service='FTP', username=user, status='FAILED'))
            except Exception:
                results.append(DefaultCredResult(service='FTP', username=user, status='ERROR'))
        return results


class WAFDetector:
    WAF_SIGNATURES = {
        'Cloudflare WAF': [r'cf-ray', r'__cfduid', r'cloudflare'],
        'AWS WAF':        [r'x-amzn-requestid', r'awselb'],
        'Akamai WAF':     [r'akamai-ghost', r'x-akamai-transformed'],
        'ModSecurity':    [r'mod_security', r'NOYB'],
        'Sucuri WAF':     [r'x-sucuri-id', r'sucuri'],
        'Imperva':        [r'visid_incap', r'incap_ses'],
        'F5 BIG-IP':      [r'bigipserver', r'f5_cspm'],
        'Barracuda':      [r'barra_counter'],
    }

    @classmethod
    def detect(cls, headers: Dict, body: str = '') -> WAFInfo:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower    = body.lower()
        for waf_name, patterns in cls.WAF_SIGNATURES.items():
            matches = 0
            for pattern in patterns:
                for header_key, header_val in headers_lower.items():
                    if re.search(pattern, header_key) or re.search(pattern, header_val):
                        matches += 1
                        break
                if re.search(pattern, body_lower):
                    matches += 1
            if matches > 0:
                confidence = min(1.0, matches / len(patterns))
                return WAFInfo(detected=True, waf_name=waf_name, confidence=confidence)
        return WAFInfo(detected=False)


class SSLScanner:
    WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'EXPORT', 'NULL', 'MD5', 'ADH']

    @staticmethod
    async def scan_ssl(ip: str, port: int = 443) -> SSLVulnerability:
        vuln   = SSLVulnerability()
        issues = []
        try:
            loop = asyncio.get_event_loop()

            def _test():
                # No gethostbyaddr — use ip directly (same fix as _get_ssl_info)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode    = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        return ssock.version(), ssock.cipher()

            version, cipher = await asyncio.wait_for(
                loop.run_in_executor(None, _test), timeout=8  # was 4s — too short
            )
            if version in ('SSLv2', 'SSLv3'):
                issues.append(f"{version} - DROWN/POODLE vulnerable")
                vuln.vulnerable = True
            elif version == 'TLSv1.0':
                issues.append("TLS 1.0 - BEAST/POODLE vulnerable")
                vuln.vulnerable = True
            elif version == 'TLSv1.1':
                issues.append("TLS 1.1 - Deprecated protocol")
            if cipher:
                cipher_name = cipher[0]
                for weak in SSLScanner.WEAK_CIPHERS:
                    if weak in cipher_name.upper():
                        issues.append(f"Weak cipher: {weak}")
                        vuln.weak_ciphers.append(weak)
                        vuln.vulnerable = True
            vuln.issues = issues
        except Exception:
            pass
        return vuln


class SensitivePathScanner:
    SENSITIVE_PATHS = [
        '/.git/config', '/.env', '/config.php', '/wp-config.php',
        '/phpinfo.php', '/adminer.php', '/phpmyadmin/',
        '/server-status', '/server-info', '/.htaccess',
        '/backup.zip', '/dump.sql', '/db.sql', '/database.sql',
        '/config.yml', '/config.json', '/.aws/credentials',
        '/.ssh/id_rsa', '/.ssh/authorized_keys',
        '/web.config', '/robots.txt', '/sitemap.xml',
        '/.git/HEAD', '/.svn/entries',
    ]

    @classmethod
    async def scan_paths(cls, session: aiohttp.ClientSession,
                         ip: str, use_https: bool = False) -> List[SensitivePathEnhanced]:
        """Scan all sensitive paths CONCURRENTLY — no serial loop, no throttle sleep."""
        protocol    = 'https' if use_https else 'http'
        base_url    = f"{protocol}://{ip}"
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode    = ssl.CERT_NONE

        async def _check(path: str):
            try:
                url = urljoin(base_url, path)
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=3)
                ) as s:
                    async with s.get(
                        url, allow_redirects=False,
                        ssl=ssl_context if use_https else False
                    ) as resp:
                        body        = await resp.read()
                        accessible  = resp.status in (200, 201, 202, 203)
                        has_content = len(body) > 0
                        return SensitivePathEnhanced(
                            path=path,
                            status_code=resp.status,
                            accessible=accessible,
                            content_type=resp.headers.get('Content-Type'),
                            response_size=len(body),
                            has_content=has_content,
                            verification=(VerificationStatus.CONFIRMED if accessible and has_content
                                          else VerificationStatus.PARTIAL if resp.status in (403, 401)
                                          else VerificationStatus.BLOCKED),
                            evidence_preview=body[:100].decode('utf-8', errors='ignore') if has_content else None,
                        )
            except Exception:
                return None

        results = await asyncio.gather(*[_check(p) for p in cls.SENSITIVE_PATHS[:10]])
        return [r for r in results if isinstance(r, SensitivePathEnhanced)]


class SubdomainEnumerator:
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'admin', 'portal', 'login', 'secure', 'vpn', 'remote',
        'dev', 'staging', 'test', 'uat', 'qa', 'demo',
        'api', 'backend', 'internal', 'private',
        'cpanel', 'whm', 'plesk', 'webmin',
        'db', 'mysql', 'pma', 'phpmyadmin',
        'direct', 'origin', 'cdn',
    ]

    @classmethod
    async def enumerate(cls, domain: str, max_subdomains: int = 15) -> List[SubdomainInfo]:
        """Resolve all subdomains concurrently instead of sequentially."""
        async def _resolve(sub: str) -> SubdomainInfo:
            subdomain = f"{sub}.{domain}"
            try:
                ip = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyname, subdomain), timeout=3
                )
                return SubdomainInfo(subdomain=subdomain, resolved=True, ip=ip)
            except Exception:
                return SubdomainInfo(subdomain=subdomain, resolved=False)

        results = await asyncio.gather(*[_resolve(s) for s in cls.COMMON_SUBDOMAINS[:max_subdomains]])
        return list(results)


class WHOISEnricher:
    @staticmethod
    async def enrich(session: aiohttp.ClientSession, ip: str) -> WHOISInfo:
        try:
            url = f"https://rdap.arin.net/registry/ip/{ip}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status != 200:
                    return WHOISInfo()
                data = await r.json()
                org   = None
                abuse = None
                entities = data.get('entities', [])
                if entities:
                    vcard = entities[0].get('vcardArray', [[]])
                    if len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry and entry[0] == 'fn':
                                org = entry[3]
                                break
                for entity in entities:
                    if 'abuse' in entity.get('roles', []):
                        abuse_vcard = entity.get('vcardArray', [[]])
                        if len(abuse_vcard) > 1:
                            for entry in abuse_vcard[1]:
                                if entry and entry[0] == 'email':
                                    abuse = entry[3]
                                    break
                return WHOISInfo(
                    network_name=data.get('name'),
                    organization=org,
                    abuse_contact=abuse,
                    net_range=f"{data.get('startAddress', '')} - {data.get('endAddress', '')}",
                    country=data.get('country')
                )
        except Exception:
            return WHOISInfo()


# ═══════════════════════════════════════════════════════════════════════
#  ASYNC CACHE
# ═══════════════════════════════════════════════════════════════════════
class AsyncCache:
    def __init__(self):
        self._asn  = {}
        self._rdns = {}
        self._lock = threading.Lock()

    def get_asn(self, ip: str) -> Optional[Dict]:
        with self._lock: return self._asn.get(ip)

    def set_asn(self, ip: str, d: Dict):
        with self._lock: self._asn[ip] = d

    def get_rdns(self, ip: str) -> Optional[str]:
        with self._lock: return self._rdns.get(ip)

    def set_rdns(self, ip: str, v: str):
        with self._lock: self._rdns[ip] = v


# ═══════════════════════════════════════════════════════════════════════
#  RED TEAM AUTOMATION v2.5
# ═══════════════════════════════════════════════════════════════════════
class Config:
    LOG_DIR = Path("spiderweb_redteam_logs")
    AUTH_PREFIX = "RT-2026-AUTHORIZED-"
    CREDENTIAL_PATTERNS = [
        r'DB_PASSWORD["\s]*[:=]["\s]*([^"\';\s]+)',
        r'API_KEY["\s]*[:=]["\s]*([^"\';\s]+)',
        r'password["\s]*[:=]["\s]*["\']([^"\']+)["\']',
    ]


class ExploitMode(Enum):
    SAFE       = "safe"
    AGGRESSIVE = "aggressive"


class AttackComplexity(Enum):
    TRIVIAL = "trivial"
    LOW     = "low"
    MEDIUM  = "medium"


@dataclass
class Credential:
    username:   str
    password:   str
    service:    str
    source:     str
    confidence: float = 0.5


@dataclass
class ChainStep:
    step_number: int
    action:      str
    technique:   str
    command:     Optional[str] = None
    result:      Optional[str] = None
    success:     bool  = False
    duration:    float = 0.0


@dataclass
class AttackChain:
    chain_id:           str
    name:               str
    target_ip:          str
    complexity:         AttackComplexity
    steps:              List[ChainStep] = field(default_factory=list)
    success:            bool = False
    credentials_found:  List[Credential] = field(default_factory=list)
    mode:               ExploitMode = ExploitMode.SAFE


@dataclass
class EntryPoint:
    type:       str
    difficulty: AttackComplexity
    description: str
    port:       Optional[int] = None
    verified:   bool = False


class AuthManager:
    def __init__(self):
        Config.LOG_DIR.mkdir(exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(Config.LOG_DIR / "audit.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('RedTeam')

    def verify(self, token: str, target: str) -> bool:
        if not token or not token.startswith(Config.AUTH_PREFIX):
            return False
        self.logger.info(f"Authorization verified for {target}")
        return True

    def require_confirmation(self, target: str) -> bool:
        print("\n" + "="*70)
        print("⚠️  AGGRESSIVE MODE AUTHORIZATION")
        print("="*70)
        print(f"Target: {target}")
        confirm = input("\nType 'I HAVE WRITTEN AUTHORIZATION': ")
        if confirm != "I HAVE WRITTEN AUTHORIZATION":
            return False
        secondary = input("Type 'PROCEED': ")
        return secondary == "PROCEED"

    def generate_token(self, target: str) -> str:
        token_data = f"{target}:{datetime.now().isoformat()}:{uuid.uuid4()}"
        token_hash = hashlib.sha256(token_data.encode()).hexdigest()[:24]
        return f"{Config.AUTH_PREFIX}{token_hash}"


class CredExtractor:
    def extract_from_text(self, text: str, source: str) -> List[Credential]:
        creds = []
        for pattern in Config.CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, text, re.I | re.M)
            for match in matches:
                username = self._guess_username(text, match)
                service  = self._guess_service(source, pattern)
                creds.append(Credential(
                    username=username, password=match,
                    service=service, source=source,
                    confidence=0.7 if '.env' in source else 0.5
                ))
        return creds

    def _guess_username(self, text: str, pwd: str) -> str:
        user_patterns = [
            r'DB_USER["\s]*[:=]["\s]*([^"\';\s]+)',
            r'username["\s]*[:=]["\s]*["\']([^"\']+)["\']',
        ]
        pwd_pos = text.find(pwd)
        window  = text[max(0, pwd_pos-300):pwd_pos+300]
        for pattern in user_patterns:
            match = re.search(pattern, window, re.I)
            if match:
                return match.group(1)
        return 'root'

    def _guess_service(self, source: str, pattern: str) -> str:
        if 'mysql' in source.lower() or 'mysql' in pattern.lower():
            return 'mysql'
        elif 'api' in pattern.lower():
            return 'api'
        return 'database'


class EntryScanner:
    def scan(self, result) -> List[EntryPoint]:
        entries = []
        if hasattr(result, 'web') and hasattr(result.web, 'sensitive_paths'):
            for path in result.web.sensitive_paths:
                if '/.git/' in path.path and path.accessible:
                    entries.append(EntryPoint(
                        type='git_exposure',
                        difficulty=AttackComplexity.TRIVIAL,
                        description='Exposed .git → source code download',
                        verified=True
                    ))
        if hasattr(result, 'tcp_ports_open'):
            db_ports = {3306: 'mysql', 5432: 'postgresql', 27017: 'mongodb'}
            for port, service in db_ports.items():
                if port in result.tcp_ports_open:
                    entries.append(EntryPoint(
                        type='exposed_database',
                        difficulty=AttackComplexity.LOW,
                        description=f'{service.upper()} exposed on port {port}',
                        port=port,
                        verified=True
                    ))
        if hasattr(result, 'default_creds'):
            for cred in result.default_creds:
                if cred.status == 'SUCCESS':
                    entries.append(EntryPoint(
                        type='default_credentials',
                        difficulty=AttackComplexity.TRIVIAL,
                        description=f'Default credentials on {cred.service}',
                        verified=True
                    ))
        return entries


class ExploitEngine:
    def __init__(self, mode: ExploitMode):
        self.mode          = mode
        self.cred_extractor = CredExtractor()
        self.temp_dir      = Path(tempfile.mkdtemp(prefix='spiderweb_'))

    def exploit_git(self, target_ip: str) -> ChainStep:
        step = ChainStep(
            step_number=1,
            action="Download .git directory",
            technique="T1213 - Data from Information Repositories",
            command=f"git-dumper http://{target_ip}/.git/ /tmp/repo"
        )
        start = time.time()
        try:
            if self.mode == ExploitMode.SAFE:
                resp = requests.head(f"http://{target_ip}/.git/config", timeout=5)
                step.success = resp.status_code == 200
                step.result  = f"Git accessible (HTTP {resp.status_code})"
            else:
                step.result  = "Download skipped in demo"
                step.success = True
        except Exception as e:
            step.result = f"Error: {e}"
        step.duration = time.time() - start
        return step

    def exploit_database(self, target_ip: str, port: int, creds: List[Credential]) -> ChainStep:
        step = ChainStep(
            step_number=2,
            action=f"Connect to database on port {port}",
            technique="T1078 - Valid Accounts",
            command=f"mysql -h {target_ip} -u <user> -p"
        )
        start = time.time()
        try:
            if self.mode == ExploitMode.SAFE:
                sock   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                step.success = result == 0
                step.result  = f"Port {port} is {'open' if result == 0 else 'closed'}"
            else:
                step.result  = "Credential testing skipped in demo"
                step.success = False
        except Exception as e:
            step.result = f"Error: {e}"
        step.duration = time.time() - start
        return step

    def cleanup(self):
        import shutil
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
        except Exception:
            pass


class RedTeamAutomation:
    def __init__(self, mode: ExploitMode = ExploitMode.SAFE,
                 auth_token: Optional[str] = None):
        self.mode           = mode
        self.auth_token     = auth_token
        self.auth_mgr       = AuthManager()
        self.entry_scanner  = EntryScanner()
        self.exploit_engine = ExploitEngine(mode)

    def analyze_target(self, result) -> List[AttackChain]:
        chains  = []
        entries = self.entry_scanner.scan(result)
        for entry in entries:
            chain = self._build_chain(entry, result)
            if chain:
                chains.append(chain)
        return chains

    def execute_chain(self, chain: AttackChain, result) -> AttackChain:
        if self.mode == ExploitMode.AGGRESSIVE:
            if not self.auth_token or not self.auth_mgr.verify(self.auth_token, result.ip):
                raise PermissionError("Invalid authorization")
            if not self.auth_mgr.require_confirmation(result.ip):
                raise PermissionError("Confirmation denied")

        self.auth_mgr.logger.info(f"Executing chain: {chain.name} on {result.ip}")
        all_creds = []
        executed  = None

        for i, step in enumerate(chain.steps):
            if step.technique.startswith("T1213"):
                executed = self.exploit_engine.exploit_git(result.ip)
                chain.steps[i] = executed
            elif step.technique.startswith("T1078"):
                db_port = next(
                    (e.port for e in self.entry_scanner.scan(result) if e.type == 'exposed_database'),
                    3306
                )
                executed = self.exploit_engine.exploit_database(result.ip, db_port, all_creds)
                chain.steps[i] = executed
            else:
                executed = step

            if executed and not executed.success:
                break

        chain.success           = any(s.success for s in chain.steps)
        chain.credentials_found = all_creds
        return chain

    def _build_chain(self, entry: EntryPoint, result) -> Optional[AttackChain]:
        if entry.type == 'git_exposure':
            has_db = any(p in result.tcp_ports_open for p in [3306, 5432, 27017])
            if has_db:
                return AttackChain(
                    chain_id=str(uuid.uuid4())[:8],
                    name="Git → Database Compromise",
                    target_ip=result.ip,
                    complexity=AttackComplexity.LOW,
                    mode=self.mode,
                    steps=[
                        ChainStep(1, "Download .git",         "T1213"),
                        ChainStep(2, "Extract credentials",   "T1552.001"),
                        ChainStep(3, "Connect to database",   "T1078"),
                    ]
                )
        elif entry.type == 'exposed_database':
            return AttackChain(
                chain_id=str(uuid.uuid4())[:8],
                name="Direct Database Access",
                target_ip=result.ip,
                complexity=AttackComplexity.MEDIUM,
                mode=self.mode,
                steps=[
                    ChainStep(1, "Test connectivity",      "T1046"),
                    ChainStep(2, "Attempt authentication", "T1078"),
                ]
            )
        return None

    def cleanup(self):
        self.exploit_engine.cleanup()


class ReportGenerator:
    @staticmethod
    def generate(chain: AttackChain) -> str:
        report = ["="*80, "RED TEAM AUTOMATION - ATTACK CHAIN REPORT", "="*80,
                  f"\nChain: {chain.name}", f"Target: {chain.target_ip}",
                  f"Mode: {chain.mode.value.upper()}", f"Complexity: {chain.complexity.value.upper()}",
                  f"\nSuccess: {'✓ YES' if chain.success else '✗ NO'}",
                  f"Credentials Found: {len(chain.credentials_found)}",
                  f"\n{'─'*80}", "ATTACK STEPS", '─'*80]
        for step in chain.steps:
            symbol = '✓' if step.success else '✗'
            report.append(f"\n[{step.step_number}] {symbol} {step.action}")
            report.append(f"  Technique: {step.technique}")
            if step.command: report.append(f"  Command: {step.command}")
            if step.result:  report.append(f"  Result: {step.result}")
            report.append(f"  Duration: {step.duration:.2f}s")
        report.append(f"\n{'='*80}")
        return '\n'.join(report)


def integrate_with_spiderweb(result, mode: ExploitMode = ExploitMode.SAFE,
                              auth_token: Optional[str] = None) -> List[AttackChain]:
    redteam = RedTeamAutomation(mode=mode, auth_token=auth_token)
    try:
        chains   = redteam.analyze_target(result)
        executed = []
        for chain in chains:
            try:
                result_chain = redteam.execute_chain(chain, result)
                executed.append(result_chain)
            except PermissionError as e:
                print(f"⚠️  {e}")
                break
        return executed
    finally:
        redteam.cleanup()


# ═══════════════════════════════════════════════════════════════════════
#  ORIGIN DISCOVERY
# ═══════════════════════════════════════════════════════════════════════
class OriginDiscovery:
    def __init__(self, api_keys: Dict = None):
        self.api_keys = api_keys or {}
        self.session  = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def discover_origins(self, hostname: str, cdn_ip: str) -> Dict:
        results = {
            'origins': [], 'methods': {}, 'confidence': 0,
            'hostname': hostname, 'cdn_ip': cdn_ip
        }
        all_origins = []

        if self.api_keys.get('securitytrails_api_key'):
            try:
                origins = self._dns_history(hostname)
                if origins:
                    results['methods']['dns_history'] = origins
                    all_origins.extend(origins)
            except Exception:
                pass

        try:
            origins = self._cert_transparency(hostname)
            if origins:
                results['methods']['cert_transparency'] = origins
                all_origins.extend(origins)
        except Exception:
            pass

        try:
            origins = self._subdomain_enum(hostname)
            if origins:
                results['methods']['subdomain_enum'] = origins
                all_origins.extend(origins)
        except Exception:
            pass

        try:
            origins = self._common_origins(hostname)
            if origins:
                results['methods']['common_patterns'] = origins
                all_origins.extend(origins)
        except Exception:
            pass

        if self.api_keys.get('shodan_api_key'):
            try:
                origins = self._cert_search_shodan(hostname)
                if origins:
                    results['methods']['cert_search'] = origins
                    all_origins.extend(origins)
            except Exception:
                pass

        unique_origins = list(set(all_origins))
        unique_origins = [ip for ip in unique_origins if ip != cdn_ip]
        unique_origins = [ip for ip in unique_origins if self._is_valid_origin(ip)]
        results['origins']    = unique_origins
        results['confidence'] = self._calculate_confidence(results['methods'])
        return results

    def _dns_history(self, hostname: str) -> List[str]:
        origins = []
        try:
            api_key = self.api_keys.get('securitytrails_api_key', '')
            url     = f'https://api.securitytrails.com/v1/history/{hostname}/dns/a'
            headers = {'APIKEY': api_key, 'Accept': 'application/json'}
            resp    = self.session.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get('records', [])[:10]:
                    for value in record.get('values', []):
                        ip = value.get('ip', '')
                        if ip and self._is_valid_ip(ip):
                            origins.append(ip)
        except Exception:
            pass
        return origins

    def _cert_transparency(self, hostname: str) -> List[str]:
        origins = []
        try:
            url  = f'https://crt.sh/?q=%25.{hostname}&output=json'
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                certs   = resp.json()
                domains = set()
                for cert in certs[:20]:
                    name = cert.get('name_value', '')
                    if name and '*' not in name:
                        domains.add(name.strip())
                for domain in list(domains)[:10]:
                    try:
                        ip = socket.gethostbyname(domain)
                        if self._is_valid_ip(ip):
                            origins.append(ip)
                    except Exception:
                        pass
        except Exception:
            pass
        return origins

    def _subdomain_enum(self, hostname: str) -> List[str]:
        origins = []
        prefixes = [
            'origin', 'direct', 'backend', 'server', 'origin-www',
            'origin-api', 'origin1', 'origin2', 'source', 'primary',
            'master', 'prod', 'production', 'app', 'web', 'www-origin'
        ]
        parts = hostname.split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
        for prefix in prefixes:
            try:
                subdomain = f"{prefix}.{base_domain}"
                ip = socket.gethostbyname(subdomain)
                if self._is_valid_ip(ip):
                    origins.append(ip)
            except Exception:
                pass
        return origins

    def _common_origins(self, hostname: str) -> List[str]:
        origins = []
        aws_patterns = [
            f"{hostname.replace('.', '-')}.s3.amazonaws.com",
            f"{hostname.split('.')[0]}.s3.amazonaws.com"
        ]
        for pattern in aws_patterns:
            try:
                ip = socket.gethostbyname(pattern)
                if self._is_valid_ip(ip):
                    origins.append(ip)
            except Exception:
                pass
        return origins

    def _cert_search_shodan(self, hostname: str) -> List[str]:
        origins = []
        try:
            api_key = self.api_keys.get('shodan_api_key', '')
            query   = f'ssl.cert.subject.cn:"{hostname}"'
            resp    = self.session.get(
                'https://api.shodan.io/shodan/host/search',
                params={'key': api_key, 'query': query}, timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get('matches', [])[:10]:
                    ip = match.get('ip_str', '')
                    if ip and self._is_valid_ip(ip):
                        origins.append(ip)
        except Exception:
            pass
        return origins

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            nums = list(map(int, parts))
            if not all(0 <= n <= 255 for n in nums):
                return False
            if nums[0] == 10:
                return False
            if nums[0] == 172 and 16 <= nums[1] <= 31:
                return False
            if nums[0] == 192 and nums[1] == 168:
                return False
            if nums[0] in (0, 127, 255):
                return False
            return True
        except Exception:
            return False

    def _is_valid_origin(self, ip: str) -> bool:
        return self._is_valid_ip(ip)

    def _calculate_confidence(self, methods: Dict) -> int:
        score   = 0
        weights = {
            'dns_history': 40, 'cert_search': 30, 'cert_transparency': 20,
            'subdomain_enum': 15, 'common_patterns': 10
        }
        for method, ips in methods.items():
            if ips:
                score += weights.get(method, 5)
        if len(methods) >= 3:
            score += 20
        elif len(methods) >= 2:
            score += 10
        return min(100, score)


# ═══════════════════════════════════════════════════════════════════════
#  DOMAIN & SUBDOMAIN RECON - DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class SMTPAnalysis:
    smtp_detected:      bool = False
    port:               Optional[int] = None
    banner:             Optional[str] = None
    supports_tls:       bool = False
    tls_version:        Optional[str] = None
    open_relay_possible: bool = False
    spf_record:         bool = False
    dkim_record:        bool = False
    dmarc_record:       bool = False
    risk_level:         str = "UNKNOWN"
    risk_factors:       List[str] = field(default_factory=list)


@dataclass
class DomainInfo:
    domain:        str
    source:        str
    resolved_ip:   Optional[str] = None
    alive:         bool = False
    technologies:  List[str] = field(default_factory=list)
    smtp_analysis: Optional[SMTPAnalysis] = None
    hosting_type:  Optional[str] = None
    risk_score:    float = 0.0
    risk_level:    str = "UNKNOWN"
    ssl_grade:     Optional[str] = None
    waf_detected:  bool = False
    vulnerabilities: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
#  SMTP SECURITY ANALYZER
# ═══════════════════════════════════════════════════════════════════════
class SMTPSecurityAnalyzer:
    SMTP_PORTS = [25, 465, 587]

    async def analyze(self, domain: str, resolved_ip: str) -> SMTPAnalysis:
        """Probe all SMTP ports simultaneously rather than sequentially."""
        analysis  = SMTPAnalysis()
        # Check all 3 SMTP ports at once — whoever responds first wins
        results   = await asyncio.gather(
            *[self._check_smtp_port(resolved_ip, p) for p in self.SMTP_PORTS],
            return_exceptions=True
        )
        for port, smtp_info in zip(self.SMTP_PORTS, results):
            if isinstance(smtp_info, Exception):
                continue
            if smtp_info.get('detected'):
                analysis.smtp_detected = True
                analysis.port          = port
                analysis.banner        = smtp_info.get('banner')
                analysis.supports_tls  = smtp_info.get('tls', False)
                analysis.tls_version   = smtp_info.get('tls_version')
                break

        if not analysis.smtp_detected:
            analysis.risk_level = "NONE"
            return analysis

        try:
            analysis.spf_record   = await self._check_spf(domain)
            analysis.dkim_record  = await self._check_dkim(domain)
            analysis.dmarc_record = await self._check_dmarc(domain)
        except Exception:
            pass

        try:
            analysis.open_relay_possible = await self._safe_relay_check(resolved_ip, analysis.port)
        except Exception:
            pass

        analysis.risk_level, analysis.risk_factors = self._calculate_smtp_risk(analysis)
        return analysis

    async def _check_smtp_port(self, ip: str, port: int) -> Dict:
        result = {'detected': False}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3   # was 10s
            )
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)  # was 5s
            result['detected'] = True
            result['banner']   = banner.decode('utf-8', errors='ignore').strip()
            if port in [25, 587]:
                writer.write(b'EHLO test\r\n')
                await writer.drain()
                response = await asyncio.wait_for(reader.read(1024), timeout=2)  # was 5s
                if b'STARTTLS' in response:
                    result['tls'] = True
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return result

    async def _check_spf(self, domain: str) -> bool:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    if b'v=spf1' in txt_string:
                        return True
        except Exception:
            pass
        return False

    async def _check_dkim(self, domain: str) -> bool:
        try:
            import dns.resolver
            for selector in ['default', 'google', 'mail', 'dkim']:
                try:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    answers     = dns.resolver.resolve(dkim_domain, 'TXT')
                    for rdata in answers:
                        for txt_string in rdata.strings:
                            if b'v=DKIM1' in txt_string:
                                return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    async def _check_dmarc(self, domain: str) -> bool:
        try:
            import dns.resolver
            dmarc_domain = f"_dmarc.{domain}"
            answers      = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    if b'v=DMARC1' in txt_string:
                        return True
        except Exception:
            pass
        return False

    async def _safe_relay_check(self, ip: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5
            )
            await asyncio.wait_for(reader.readline(), timeout=3)
            writer.write(b'EHLO test.local\r\n')
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.write(b'MAIL FROM:<test@external.com>\r\n')
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), timeout=3)
            if not response.startswith(b'250'):
                writer.write(b'QUIT\r\n')
                await writer.drain()
                writer.close()
                return False
            writer.write(b'RCPT TO:<test@another-external.com>\r\n')
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), timeout=3)
            relay_possible = response.startswith(b'250')
            writer.write(b'QUIT\r\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return relay_possible
        except Exception:
            return False

    def _calculate_smtp_risk(self, analysis: SMTPAnalysis) -> Tuple[str, List[str]]:
        risk_factors = []
        score        = 0
        if analysis.open_relay_possible:
            risk_factors.append("Potential open relay detected")
            score += 10
        if not analysis.spf_record:
            risk_factors.append("No SPF record")
            score += 3
        if not analysis.dkim_record:
            risk_factors.append("No DKIM record")
            score += 2
        if not analysis.dmarc_record:
            risk_factors.append("No DMARC record")
            score += 3
        if not analysis.supports_tls and analysis.port in [25, 587]:
            risk_factors.append("No STARTTLS support")
            score += 4
        if score >= 12:
            return "CRITICAL", risk_factors
        elif score >= 8:
            return "HIGH", risk_factors
        elif score >= 4:
            return "MEDIUM", risk_factors
        else:
            return "LOW", risk_factors


# ═══════════════════════════════════════════════════════════════════════
#  RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════
class RateLimiter:
    def __init__(self, rps: float = 8.0):
        self._interval = 1.0 / rps
        self._last     = 0.0
        self._lock     = threading.Lock()

    def wait(self):
        with self._lock:
            now     = time.time()
            elapsed = now - self._last
            if elapsed < self._interval:
                jitter = random.uniform(0, self._interval * 0.25)
                time.sleep(self._interval - elapsed + jitter)
            self._last = time.time()


# ═══════════════════════════════════════════════════════════════════════
#  MULTI-SOURCE DOMAIN GENERATOR  (FIX: all methods inside class, limit enforced)
# ═══════════════════════════════════════════════════════════════════════
class MultiSourceDomainGenerator:
    def __init__(self, rate_limiter: RateLimiter, config: DataSourceConfig):
        self._rl       = rate_limiter
        self._cfg      = config
        self._sess     = requests.Session()
        self._sess.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.domain_counter = 0
        self._cnt_lock      = threading.Lock()
        self._set_lock      = threading.Lock()

    # FIX: Proper limit enforcement - stops when target reached
    def generate(self, keywords: List[str], target: int) -> Tuple[Set[str], Dict[str, int]]:
        """
        Collect domains from ALL configured sources for ALL keywords in parallel.
        No source is skipped because another already returned enough results.
        SecurityTrails and VirusTotal always run when keys are configured.
        Results are merged and capped at *target* only after all sources finish.
        """
        source_buckets: Dict[str, Set[str]] = defaultdict(set)
        bucket_lock = threading.Lock()
        per_src = max(100, target)

        def _fetch(kw: str, source_name: str, fn) -> None:
            try:
                results = fn()
                valid = {d for d in results
                         if d and not self._is_ip_address(d) and self._valid_domain(d)}
                if valid:
                    with bucket_lock:
                        before = len(source_buckets[source_name])
                        source_buckets[source_name].update(valid)
                        added = len(source_buckets[source_name]) - before
                    if added:
                        print(f"  {Colors.GREEN}{source_name}{Colors.ENDC}"
                              f" [{kw}]: +{added} domains")
            except Exception:
                pass

        # Build full task list: every source x every keyword
        tasks = []
        for kw in keywords:
            tasks.append((kw, 'crt.sh',
                          lambda k=kw: self._crtsh(k, per_src)))
            tasks.append((kw, 'RapidDNS',
                          lambda k=kw: self._rapiddns(k, per_src)))
            if self._cfg.has_securitytrails():
                tasks.append((kw, 'SecurityTrails',
                              lambda k=kw: self._securitytrails(k, per_src)))
            if self._cfg.api_keys.get('virustotal_api_key'):
                tasks.append((kw, 'VirusTotal',
                              lambda k=kw: self._virustotal(k, per_src)))

        workers = min(len(tasks), 12)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_fetch, kw, src, fn): (kw, src)
                    for kw, src, fn in tasks}
            for f in concurrent.futures.as_completed(futs):
                try:
                    f.result()
                except Exception:
                    pass

        # Merge buckets — paid sources credited first
        stats: Dict[str, int] = {}
        all_unique: Set[str] = set()
        source_priority = ['SecurityTrails', 'VirusTotal', 'RapidDNS', 'crt.sh']
        ordered = sorted(source_buckets.keys(),
                         key=lambda s: source_priority.index(s)
                         if s in source_priority else 99)
        for src in ordered:
            new_domains = source_buckets[src] - all_unique
            if new_domains:
                all_unique.update(new_domains)
                stats[src] = len(new_domains)

        # Hard cap at target
        result_domains = set(list(all_unique)[:target])
        self.domain_counter = len(result_domains)
        return result_domains, stats

    def _crtsh(self, keyword: str, limit: int) -> Set[str]:
        domains = set()
        try:
            url  = f'https://crt.sh/?q=%25.{keyword}%25&output=json'
            resp = self._sess.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data[:limit * 2]:
                    name = entry.get('name_value', '')
                    for domain in name.split('\n'):
                        domain = domain.strip()
                        if domain and '*' not in domain and self._valid_domain(domain):
                            domains.add(domain.lower())
                            if len(domains) >= limit:
                                break
                    if len(domains) >= limit:
                        break
        except Exception:
            pass
        return domains

    def _rapiddns(self, keyword: str, limit: int) -> Set[str]:
        domains = set()
        try:
            url  = f'https://rapiddns.io/subdomain/{keyword}?full=1'
            resp = self._sess.get(url, timeout=15)
            if resp.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, 'html.parser')
                for td in soup.find_all('td'):
                    text = td.get_text().strip()
                    if '.' in text and self._valid_domain(text):
                        domains.add(text.lower())
                        if len(domains) >= limit:
                            break
        except Exception:
            pass
        return domains

    def _securitytrails(self, keyword: str, limit: int) -> Set[str]:
        domains = set()
        try:
            api_key = self._cfg.api_keys.get('securitytrails_api_key', '')
            url     = f'https://api.securitytrails.com/v1/domain/{keyword}/subdomains'
            headers = {'APIKEY': api_key, 'Accept': 'application/json'}
            resp    = self._sess.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for subdomain in data.get('subdomains', [])[:limit]:
                    full_domain = f"{subdomain}.{keyword}"
                    if self._valid_domain(full_domain):
                        domains.add(full_domain.lower())
        except Exception:
            pass
        return domains

    def _virustotal(self, keyword: str, limit: int) -> Set[str]:
        domains = set()
        try:
            api_key = self._cfg.api_keys.get('virustotal_api_key', '')
            url     = f'https://www.virustotal.com/api/v3/domains/{keyword}/subdomains'
            headers = {'x-apikey': api_key}
            resp    = self._sess.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('data', [])[:limit]:
                    domain = item.get('id', '')
                    if domain and self._valid_domain(domain):
                        domains.add(domain.lower())
        except Exception:
            pass
        return domains

    # FIX: These are now proper class methods (correctly indented)
    def _valid_domain(self, domain: str) -> bool:
        if not domain or len(domain) > 253:
            return False
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.split('/')[0].split(':')[0]
        if self._is_ip_address(domain):
            return False
        if '.' not in domain:
            return False
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        if parts[-1].isdigit():
            return False
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not all(c.isalnum() or c == '-' for c in part):
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
        return True

    def _is_ip_address(self, text: str) -> bool:
        parts = text.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False


# ═══════════════════════════════════════════════════════════════════════
#  ASYNC SCANNER  (FIX: scan_domain and scan_ip properly inside class)
# ═══════════════════════════════════════════════════════════════════════
class AsyncScanner:
    # ip-api.com free tier: 45 requests/min = 0.75 req/s.
    # Cap at 30 concurrent geo requests so we never exceed the limit even
    # when scanning 50 IPs simultaneously. Shared across all AsyncScanner
    # instances via class variable.
    _geo_sem: asyncio.Semaphore = None  # initialised lazily on first use

    def __init__(self):
        self.cache   = AsyncCache()
        self.session = None

    async def init_session(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_HTTP)
        )
        # Create the semaphore on the running event loop (once per process)
        if AsyncScanner._geo_sem is None:
            AsyncScanner._geo_sem = asyncio.Semaphore(5)  # max 5 concurrent ip-api calls

    async def close_session(self):
        if self.session:
            await self.session.close()

    # FIX: scan_domain is now properly inside AsyncScanner class
    async def scan_domain(self, domain: str) -> DomainInfo:
        """Scan a single domain — all sub-tasks run concurrently for speed."""
        info = DomainInfo(domain=domain, source="scan")

        # DNS resolution is blocking — offload to thread with timeout
        try:
            info.resolved_ip = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyname, domain), timeout=3
            )
            info.alive = True
        except Exception:
            info.alive = False
            return info

        ip = info.resolved_ip

        # ── Run all enrichment tasks in parallel ──────────────────────────
        async def _web():
            try:
                web_info = await self._get_web_info(ip)
                if web_info:
                    info.technologies = self._detect_technologies(web_info)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    headers = {'Host': domain}
                    ports   = await self._scan_ports(ip)
                    if 443 in ports or 80 in ports:
                        proto = 'https' if 443 in ports else 'http'
                        try:
                            async with aiohttp.ClientSession() as sess:
                                async with sess.get(
                                    f"{proto}://{ip}", headers=headers,
                                    allow_redirects=False, ssl=ctx,
                                    timeout=aiohttp.ClientTimeout(total=4)
                                ) as resp:
                                    server = resp.headers.get('server', '').lower()
                                    waf_h  = ['cf-ray','x-amz-cf-id','x-akamai',
                                              'x-sucuri-id','x-fw-hash']
                                    if any(h in resp.headers for h in waf_h):
                                        info.waf_detected = True
                                    if 'cloudflare' in server or 'cloudfront' in server:
                                        info.waf_detected = True
                        except Exception:
                            pass
            except Exception:
                pass

        async def _ssl():
            try:
                ssl_info = await self._get_ssl_info(ip)
                if ssl_info.get('valid'):
                    v = ssl_info.get('version', '')
                    info.ssl_grade = ("A+" if v == 'TLSv1.3' else
                                      "A"  if v == 'TLSv1.2' else
                                      "B"  if v in ('TLSv1.1','TLSv1.0') else "C")
            except Exception:
                pass

        async def _asn():
            try:
                asn_info = await self._get_asn(ip)
                org = (asn_info.get('org', '') if asn_info else '').lower()
                if   'cloudflare' in org or 'akamai' in org: info.hosting_type = "CDN"
                elif 'amazon'     in org or 'aws'    in org: info.hosting_type = "AWS"
                elif 'google'     in org or 'gcp'    in org: info.hosting_type = "GCP"
                elif 'microsoft'  in org or 'azure'  in org: info.hosting_type = "Azure"
                elif 'digitalocean' in org:                  info.hosting_type = "DigitalOcean"
                else:                                         info.hosting_type = "Dedicated/VPS"
            except Exception:
                info.hosting_type = "Unknown"

        async def _smtp():
            try:
                smtp_analyzer      = SMTPSecurityAnalyzer()
                info.smtp_analysis = await smtp_analyzer.analyze(domain, ip)
                bump = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0}
                info.risk_score   += bump.get(info.smtp_analysis.risk_level, 0.0)
            except Exception:
                pass

        await asyncio.gather(_web(), _ssl(), _asn(), _smtp(), return_exceptions=True)

        info.risk_level = ("HIGH"   if info.risk_score >= 7 else
                           "MEDIUM" if info.risk_score >= 4 else "LOW")
        return info

    # FIX: scan_ip is now properly inside AsyncScanner class
    async def scan_ip(self, ip: str,
                      keywords: List[str]    = None,
                      country_code: Optional[str] = None) -> IPAnalysisResult:
        result = IPAnalysisResult(
            ip=ip,
            source_keywords=keywords or [],
            target_country=country_code,
        )

        try:
            result.liveness = await self._check_liveness(ip)
            if result.liveness.status == "dead":
                return result

            if result.liveness.tcp_responsive:
                result.tcp_ports_open      = await self._scan_ports(ip)
                result.liveness.ports_scanned = [21, 22, 25, 80, 443, 3306, 5432,
                                                   1433, 27017, 6379, 8080, 8443, 2082, 2083, 10000]

            # geo_lookup returns BOTH asn + geo fields in one HTTP call
            tasks = [
                self._geo_lookup(ip),          # idx 0: asn+geo combined
                self._get_reverse_dns(ip),     # idx 1
                WHOISEnricher.enrich(self.session, ip),  # idx 2
            ]

            response_headers: Dict = {}
            response_body:    str  = ""

            if 443 in result.tcp_ports_open or 80 in result.tcp_ports_open:
                tasks.append(self._get_ssl_info(ip))   # idx 3
                tasks.append(self._get_web_info(ip))   # idx 4

            gathered = await asyncio.gather(*tasks, return_exceptions=True)

            geo_asn  = gathered[0] if not isinstance(gathered[0], Exception) else {}
            rdns     = gathered[1] if not isinstance(gathered[1], Exception) else None
            whois    = gathered[2] if not isinstance(gathered[2], Exception) else WHOISInfo()

            result.asn          = geo_asn.get('asn')
            result.asn_org      = geo_asn.get('org')
            result.domains.reverse_dns = rdns
            result.country      = geo_asn.get('country')
            result.country_name = geo_asn.get('country_name')
            result.city         = geo_asn.get('city')
            result.region       = geo_asn.get('region')
            result.isp          = geo_asn.get('isp')
            result.organization = geo_asn.get('org')
            result.whois        = whois

            if len(gathered) > 3 and not isinstance(gathered[3], Exception):
                ssl_info           = gathered[3]
                result.ssl.valid   = ssl_info.get('valid', False)
                result.ssl.issuer  = ssl_info.get('issuer')
                result.ssl.subject = ssl_info.get('subject')
                result.ssl.expiry  = ssl_info.get('expiry')
                result.ssl.version = ssl_info.get('version')
                result.ssl.cipher  = ssl_info.get('cipher')
                if ssl_info.get('san_domains'):
                    result.domains.tls_san_domains = ssl_info['san_domains']
                if 443 in result.tcp_ports_open:
                    result.ssl.ssl_vulnerabilities = await SSLScanner.scan_ssl(ip)

            if len(gathered) > 4 and not isinstance(gathered[4], Exception):
                web_info                   = gathered[4]
                result.web.server          = web_info.get('server')
                result.web.title           = web_info.get('title')
                result.web.powered_by      = web_info.get('powered_by')
                result.web.security_headers = web_info.get('security_headers', {})
                result.web.http_methods    = web_info.get('http_methods', [])
                response_headers           = web_info.get('headers', {})
                response_body              = web_info.get('body', '')
                result.detected_technologies = self._detect_technologies(web_info)
                result.web.waf_detected    = WAFDetector.detect(response_headers, response_body)
                use_https = 443 in result.tcp_ports_open
                result.web.sensitive_paths = await SensitivePathScanner.scan_paths(
                    self.session, ip, use_https
                )

            if result.tcp_ports_open:
                banner_tasks = [
                    BannerGrabber.grab_banner(ip, port) for port in result.tcp_ports_open[:5]
                ]
                banners = await asyncio.gather(*banner_tasks, return_exceptions=True)
                result.service_banners = [b for b in banners
                                          if not isinstance(b, Exception) and b]

            if result.service_banners:
                cve_tasks = []
                for banner in result.service_banners[:3]:
                    if banner.version:
                        cve_tasks.append(
                            CVECorrelator.lookup_cves(self.session, banner.service, banner.version)
                        )
                if cve_tasks:
                    cve_results = await asyncio.gather(*cve_tasks, return_exceptions=True)
                    for cves in cve_results:
                        if not isinstance(cves, Exception):
                            result.cve_matches.extend(cves)

            if 21 in result.tcp_ports_open:
                ftp_creds          = DefaultCredChecker.DEFAULT_CREDS.get('ftp', [])
                result.default_creds = await DefaultCredChecker.test_ftp(ip, 21, ftp_creds)

            result.hosting = ClassificationEngine.classify(
                result.asn or '', result.asn_org or '',
                result.domains.reverse_dns or '',
                result.tcp_ports_open,
                result.ssl.valid,
                result.liveness.http_responsive or result.liveness.https_responsive,
                response_headers,
            )

            result.vulnerability = VulnerabilityAssessor.assess(
                result, response_headers, response_body
            )

            if result.hosting.is_origin and not result.hosting.is_cdn:
                san = await self._get_san_domains(ip)
                result.domains.tls_san_domains = san
                all_d = set()
                if rdns:
                    all_d.add(rdns)
                all_d.update(san)
                result.domains.all_domains = sorted(all_d)
                if result.domains.all_domains:
                    primary_domain = result.domains.all_domains[0]
                    if '.' in primary_domain:
                        subdomains = await SubdomainEnumerator.enumerate(primary_domain, 10)
                        result.domains.subdomains_found = [
                            s.subdomain for s in subdomains if s.resolved
                        ]

        except Exception:
            pass

        return result

    async def _tcp_connect(self, ip: str, port: int) -> bool:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=TIMEOUT_TCP
            )
            w.close()
            await w.wait_closed()
            return True
        except Exception:
            return False

    async def _check_liveness(self, ip: str) -> LivenessStatus:
        """Probe tcp:80 and tcp:443 simultaneously instead of sequentially."""
        status = LivenessStatus()
        tcp80, tcp443 = await asyncio.gather(
            self._tcp_connect(ip, 80),
            self._tcp_connect(ip, 443),
        )
        status.log_probe('tcp_80',  'open' if tcp80  else 'closed/filtered')
        status.log_probe('tcp_443', 'open' if tcp443 else 'closed/filtered')
        status.tcp_responsive = tcp80 or tcp443

        if not status.tcp_responsive:
            status.status                   = "dead"
            status.network_reachability     = "unreachable"
            status.application_reachability = "unavailable"
            return status

        status.network_reachability = "reachable"
        checks = []
        if tcp80:  checks.append(self._http_check(ip, False))
        if tcp443: checks.append(self._http_check(ip, True))

        results = await asyncio.gather(*checks, return_exceptions=True)
        for res in results:
            if not isinstance(res, dict):
                continue
            if res.get('https'):
                success = res.get('success', False)
                status.https_responsive = success
                status.https_status     = res.get('status')
                status.tls_handshake    = res.get('tls', False)
                status.response_time    = res.get('time')
                if success:
                    status.log_probe('https', f"success_{res.get('status')}")
                elif res.get('timeout'):
                    status.log_probe('https', 'timeout')
                elif res.get('refused'):
                    status.log_probe('https', 'refused')
                else:
                    status.log_probe('https', 'failed')
            else:
                success = res.get('success', False)
                status.http_responsive = success
                status.http_status     = res.get('status')
                if not status.response_time:
                    status.response_time = res.get('time')
                if success:
                    status.log_probe('http', f"success_{res.get('status')}")
                elif res.get('timeout'):
                    status.log_probe('http', 'timeout')
                elif res.get('refused'):
                    status.log_probe('http', 'refused')
                else:
                    status.log_probe('http', 'failed')

        if status.http_responsive or status.https_responsive:
            status.status                   = "alive"
            status.application_reachability = "responsive"
        elif status.tls_handshake:
            status.status                   = "tls_only"
            status.application_reachability = "degraded"
        elif status.tcp_responsive:
            status.status                   = "filtered"
            status.application_reachability = "unavailable"
        else:
            status.status                   = "dead"
            status.application_reachability = "unavailable"

        return status

    async def _http_check(self, ip: str, https: bool) -> Dict:
        proto  = "https" if https else "http"
        result = {'https': https, 'success': False, 'status': None, 'time': None,
                  'tls': False, 'timeout': False, 'refused': False}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            conn  = aiohttp.TCPConnector(ssl=ctx if https else None)
            start = time.time()
            async with aiohttp.ClientSession(
                connector=conn, timeout=aiohttp.ClientTimeout(total=TIMEOUT_HTTP)
            ) as sess:
                async with sess.head(f"{proto}://{ip}", allow_redirects=True) as resp:
                    result['success'] = True
                    result['status']  = resp.status
                    result['time']    = time.time() - start
                    result['tls']     = https
        except asyncio.TimeoutError:
            result['timeout'] = True
        except (aiohttp.ClientConnectorError, ConnectionRefusedError):
            result['refused'] = True
        except Exception:
            pass
        return result

    async def _scan_ports(self, ip: str) -> List[int]:
        ports = [21, 22, 25, 80, 443, 3306, 5432, 1433, 27017, 6379, 8080, 8443, 2082, 2083, 10000]
        tasks = [self._tcp_connect(ip, p) for p in ports]
        res   = await asyncio.gather(*tasks)
        return [p for p, open_ in zip(ports, res) if open_]

    async def _geo_lookup(self, ip: str) -> Dict:
        """Single ip-api.com request returning BOTH geo AND ASN fields.
        
        Combines what was previously two separate HTTP calls (_get_asn +
        _get_geolocation) into one request.  Protected by a class-level
        semaphore (max 5 concurrent) and retries with back-off on HTTP 429.
        Results are cached so parallel coroutines for the same IP never
        double-request.
        """
        cached = self.cache.get_asn(ip)
        if cached:
            return cached

        FIELDS = "status,country,countryCode,region,regionName,city,isp,org,as"
        url    = f"http://ip-api.com/json/{ip}?fields={FIELDS}"

        for attempt in range(3):
            try:
                async with AsyncScanner._geo_sem:
                    async with self.session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as r:
                        if r.status == 429:
                            # ip-api sends Retry-After header; honour it
                            retry_after = float(r.headers.get('Retry-After', 2 ** attempt))
                            await asyncio.sleep(retry_after)
                            continue
                        if r.status != 200:
                            break
                        d = await r.json()
                        if d.get('status') != 'success':
                            break
                        asn_full = d.get('as', '')
                        asn_parts = asn_full.split(' ', 1)
                        result = {
                            # ASN fields (previously _get_asn)
                            'asn': asn_parts[0] if asn_parts else '',
                            'org': asn_parts[1] if len(asn_parts) > 1 else d.get('org', ''),
                            # Geo fields (previously _get_geolocation)
                            'country':      d.get('countryCode'),
                            'country_name': d.get('country'),
                            'city':         d.get('city'),
                            'region':       d.get('regionName'),
                            'isp':          d.get('isp'),
                        }
                        self.cache.set_asn(ip, result)
                        return result
            except Exception:
                await asyncio.sleep(0.5 * (attempt + 1))

        return {}

    async def _get_asn(self, ip: str) -> Dict:
        """Thin wrapper kept for backward compatibility — delegates to _geo_lookup."""
        return await self._geo_lookup(ip)

    async def _get_reverse_dns(self, ip: str) -> Optional[str]:
        cached = self.cache.get_rdns(ip)
        if cached:
            return cached
        try:
            loop = asyncio.get_event_loop()
            rdns = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=TIMEOUT_DNS
            )
            name = rdns[0]
            self.cache.set_rdns(ip, name)
            return name
        except Exception:
            return None

    async def _get_geolocation(self, ip: str) -> Dict:
        """Delegates to _geo_lookup — result includes both geo and ASN fields."""
        return await self._geo_lookup(ip)

    async def _get_ssl_info(self, ip: str) -> Dict:
        """Inspect TLS certificate on port 443.

        Key fixes vs previous version:
        - Removed blocking socket.gethostbyaddr() from inside _fetch() — that
          reverse DNS call was consuming the entire 3 s timeout before the SSL
          handshake even started, causing silent failures on every host.
        - Outer wait_for timeout raised to 8 s to allow the TCP connect (up to
          3 s) + TLS handshake (up to 5 s) to both complete.
        - server_hostname set to ip string directly so CERT_NONE context works
          without needing to resolve a hostname first.
        - Captures SAN (Subject Alternative Names) for extra intelligence.
        """
        info: Dict = {'valid': False}
        try:
            loop = asyncio.get_event_loop()

            def _fetch():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                # Use ip directly — no hostname resolution needed because we
                # disabled check_hostname and CERT_NONE skips verification.
                with socket.create_connection((ip, 443), timeout=5) as s:
                    with ctx.wrap_socket(s, server_hostname=ip) as ss:
                        return ss.getpeercert(binary_form=False), ss.version(), ss.cipher()

            cert, version, cipher = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch), timeout=8  # was TIMEOUT_TCP (3s) — too short
            )
            info['valid']  = True
            info['version'] = version
            info['cipher']  = cipher[0] if cipher else None

            if cert:
                if 'issuer' in cert:
                    issuer_d       = dict(x[0] for x in cert['issuer'])
                    info['issuer'] = issuer_d.get('organizationName') or issuer_d.get('commonName', 'Unknown')
                if 'subject' in cert:
                    subj_d          = dict(x[0] for x in cert['subject'])
                    info['subject'] = subj_d.get('commonName', 'Unknown')
                if 'notAfter' in cert:
                    info['expiry'] = cert['notAfter']
                # Collect SANs (Subject Alternative Names) for domain intel
                sans = []
                for typ, val in cert.get('subjectAltName', []):
                    if typ == 'DNS':
                        sans.append(val)
                if sans:
                    info['san_domains'] = sans[:10]  # cap at 10 to keep output clean
        except Exception:
            pass
        return info

    async def _get_web_info(self, ip: str) -> Dict:
        info: Dict = {}
        try:
            use_https = await self._tcp_connect(ip, 443)
            proto     = "https" if use_https else "http"
            # Resolve hostname in a thread with a short timeout so a slow
            # reverse-DNS lookup never blocks the entire web-info fetch.
            try:
                hostname = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyaddr, ip),
                    timeout=2
                )
                hostname = hostname[0]
            except Exception:
                hostname = ip
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            conn    = aiohttp.TCPConnector(ssl=ctx)
            headers = {'Host': hostname}
            async with aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_HTTP),
                headers=headers
            ) as sess:
                async with sess.get(f"{proto}://{ip}", allow_redirects=True) as resp:
                    info['server']     = resp.headers.get('Server')
                    info['powered_by'] = resp.headers.get('X-Powered-By')
                    info['headers']    = dict(resp.headers)
                    sec = {}
                    for h in ['Strict-Transport-Security', 'X-Frame-Options',
                              'X-Content-Type-Options', 'Content-Security-Policy',
                              'X-XSS-Protection', 'Referrer-Policy']:
                        if h in resp.headers:
                            sec[h] = resp.headers[h]
                    info['security_headers'] = sec
                    body        = await resp.text(errors='replace')
                    info['body'] = body[:4096]
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(body[:2048], 'html.parser')
                        if soup.title and soup.title.string:
                            info['title'] = soup.title.string.strip()[:100]
                    except Exception:
                        pass

                methods = []
                for method in ['OPTIONS', 'PUT', 'DELETE', 'TRACE']:
                    try:
                        async with sess.request(
                            method, f"{proto}://{ip}", timeout=aiohttp.ClientTimeout(total=2)
                        ) as r:
                            if r.status < 405:
                                methods.append(method)
                    except Exception:
                        pass
                info['http_methods'] = methods
        except Exception:
            pass
        return info

    async def _get_san_domains(self, ip: str) -> List[str]:
        domains: List[str] = []
        try:
            loop = asyncio.get_event_loop()

            def _fetch():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with socket.create_connection((ip, 443), timeout=TIMEOUT_TCP) as s:
                    with ctx.wrap_socket(s, server_hostname=ip) as ss:
                        return ss.getpeercert()

            cert = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch), timeout=TIMEOUT_TCP
            )
            if cert and 'subjectAltName' in cert:
                for tag, val in cert['subjectAltName']:
                    if tag == 'DNS':
                        d = val.replace('*.', '')
                        if d not in domains:
                            domains.append(d)
            if cert and 'subject' in cert:
                for rdn in cert['subject']:
                    for name, val in rdn:
                        if name == 'commonName':
                            d = val.replace('*.', '')
                            if d not in domains:
                                domains.append(d)
        except Exception:
            pass
        return domains[:15]

    # FIX: _detect_technologies is now properly inside AsyncScanner class
    def _detect_technologies(self, web_info: Dict) -> List[str]:
        technologies = []
        headers      = web_info.get('headers', {})
        body         = web_info.get('body', '')

        server = web_info.get('server', '') or ''
        if server:
            technologies.append(f"Server: {server}")

        powered_by = web_info.get('powered_by', '') or ''
        if powered_by:
            technologies.append(f"X-Powered-By: {powered_by}")

        framework_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'WordPress'],
            'Drupal':    ['Drupal', 'drupal'],
            'Joomla':    ['Joomla', 'joomla'],
            'Django':    ['csrfmiddlewaretoken', 'Django'],
            'Laravel':   ['laravel', 'Laravel'],
            'React':     ['react', 'React'],
            'Vue.js':    ['Vue', 'vue'],
            'Angular':   ['ng-', 'Angular'],
            'Bootstrap': ['bootstrap.min.css', 'Bootstrap'],
            'jQuery':    ['jquery', 'jQuery'],
        }
        for tech, patterns in framework_patterns.items():
            if any(p in body for p in patterns):
                if tech not in technologies:
                    technologies.append(tech)

        cdn_headers = {
            'cf-ray':       'Cloudflare',
            'x-amz-cf-id':  'CloudFront',
            'x-akamai':     'Akamai',
            'x-cache':      'Cache/CDN',
        }
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header, cdn in cdn_headers.items():
            if header in headers_lower:
                technologies.append(f"CDN: {cdn}")

        return technologies


# ═══════════════════════════════════════════════════════════════════════
#  MULTI-SOURCE IP GENERATOR  (FIX: target limit enforced)
# ═══════════════════════════════════════════════════════════════════════
class MultiSourceIPGenerator:
    def __init__(self, rate_limiter: RateLimiter, config: DataSourceConfig):
        self._rl       = rate_limiter
        self._cfg      = config
        self._sess     = requests.Session()
        self._sess.headers.update({'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )})
        self.ip_counter = 0
        self._cnt_lock  = threading.Lock()
        self._set_lock  = threading.Lock()

    # FIX: Hard stop when target reached; _add returns True when done
    def generate(self, keywords: List[str], target: int,
                 country: Optional[str] = None) -> Tuple[Set[str], Dict[str, int]]:
        """
        Collect IPs from ALL configured sources for ALL keywords in parallel.
        No source is ever skipped because another source already returned enough
        IPs — paid APIs (Shodan, Censys, FOFA, ZoomEye, SecurityTrails) always
        run and contribute their unique results.
        Results are merged and capped at *target* only after all sources finish.
        """
        # Per-source result buckets — accumulated with no quota check during collection
        source_buckets: Dict[str, Set[str]] = defaultdict(set)
        bucket_lock = threading.Lock()

        # Request generously from each source so every API can contribute fully.
        per_src = max(100, target)

        def _fetch(kw: str, source_name: str, fn) -> None:
            """Run one source for one keyword and store valid IPs in its bucket."""
            try:
                results = fn()
                valid = {ip for ip in results if self._ok(ip)}
                if valid:
                    with bucket_lock:
                        before = len(source_buckets[source_name])
                        source_buckets[source_name].update(valid)
                        added = len(source_buckets[source_name]) - before
                    if added:
                        print(f"  {Colors.GREEN}{source_name}{Colors.ENDC}"
                              f" [{kw}]: +{added} IPs")
            except Exception:
                pass

        # Build full task list: every source x every keyword
        tasks = []
        for kw in keywords:
            tasks.append((kw, 'DNS',
                          lambda k=kw: self._dns(k, per_src, country)))
            tasks.append((kw, 'URLScan',
                          lambda k=kw: self._urlscan(k, per_src, country)))
            tasks.append((kw, 'ThreatCrowd',
                          lambda k=kw: self._threatcrowd(k, per_src)))
            if self._cfg.has_shodan():
                tasks.append((kw, 'Shodan',
                              lambda k=kw: self._shodan(k, per_src, country)))
            if self._cfg.has_censys():
                tasks.append((kw, 'Censys',
                              lambda k=kw: self._censys(k, per_src, country)))
            if self._cfg.has_fofa():
                tasks.append((kw, 'FOFA',
                              lambda k=kw: self._fofa(k, per_src, country)))
            if self._cfg.has_zoomeye():
                tasks.append((kw, 'ZoomEye',
                              lambda k=kw: self._zoomeye(k, per_src, country)))
            if self._cfg.has_securitytrails():
                tasks.append((kw, 'SecurityTrails',
                              lambda k=kw: self._securitytrails(k, per_src)))

        # Run all tasks concurrently — no early cancellation based on quota
        workers = min(len(tasks), 16)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_fetch, kw, src, fn): (kw, src)
                    for kw, src, fn in tasks}
            for f in concurrent.futures.as_completed(futs):
                try:
                    f.result()
                except Exception:
                    pass

        # Merge buckets — paid sources credited first so their unique IPs show in stats
        stats: Dict[str, int] = {}
        all_unique: Set[str] = set()
        source_priority = ['Shodan', 'Censys', 'FOFA', 'ZoomEye', 'SecurityTrails',
                           'ThreatCrowd', 'URLScan', 'DNS']
        ordered = sorted(source_buckets.keys(),
                         key=lambda s: source_priority.index(s)
                         if s in source_priority else 99)
        for src in ordered:
            new_ips = source_buckets[src] - all_unique
            if new_ips:
                all_unique.update(new_ips)
                stats[src] = len(new_ips)

        # Hard cap at target
        result_ips = set(list(all_unique)[:target])
        self.ip_counter = len(result_ips)
        return result_ips, stats

    def _ok(self, ip: str) -> bool:
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            nums = list(map(int, parts))
            if not all(0 <= n <= 255 for n in nums):
                return False
            if nums[0] == 10: return False
            if nums[0] == 172 and 16 <= nums[1] <= 31: return False
            if nums[0] == 192 and nums[1] == 168: return False
            if nums[0] in (0, 127): return False
            return True
        except Exception:
            return False

    def _dns(self, kw: str, limit: int, country: Optional[str]) -> Set[str]:
        ips: Set[str] = set()
        tlds = ['com', 'net', 'org', 'io', 'ai', 'dev', 'app']
        if country:
            extras = {
                'US': ['us'], 'UK': ['uk', 'co.uk'], 'RU': ['ru'],
                'CA': ['ca'], 'AU': ['au'], 'DE': ['de'], 'FR': ['fr'],
                'IN': ['in'], 'BR': ['br'],
            }
            tlds = extras.get(country.upper(), []) + tlds

        patterns = [kw]
        for tld in tlds[:6]:
            patterns.append(f"{kw}.{tld}")
            for sub in ['www', 'mail', 'api', 'app', 'admin']:
                patterns.append(f"{sub}.{kw}.{tld}")

        for pat in patterns[:15]:
            if len(ips) >= limit:
                break
            try:
                ip = socket.gethostbyname(pat)
                if self._ok(ip):
                    ips.add(ip)
            except Exception:
                pass
        return ips

    def _urlscan(self, kw: str, limit: int, country: Optional[str]) -> Set[str]:
        ips: Set[str] = set()
        try:
            q = f'domain:{kw}' + (f' country:{country.upper()}' if country else '')
            r = self._sess.get(
                'https://urlscan.io/api/v1/search/',
                params={'q': q, 'size': min(100, limit * 5)},
                timeout=15
            )
            if r.status_code == 200:
                for item in r.json().get('results', []):
                    ip = item.get('page', {}).get('ip', '')
                    if ip and self._ok(ip):
                        ips.add(ip)
                        if len(ips) >= limit:
                            break
        except Exception:
            pass
        return ips

    def _threatcrowd(self, kw: str, limit: int) -> Set[str]:
        ips: Set[str] = set()
        try:
            r = self._sess.get(
                f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={kw}',
                timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                if data.get('response_code') == '1':
                    for res in data.get('resolutions', []):
                        ip = res.get('ip_address', '')
                        if ip and self._ok(ip):
                            ips.add(ip)
                            if len(ips) >= limit:
                                break
        except Exception:
            pass
        return ips

    def _shodan(self, kw: str, limit: int, country: Optional[str]) -> Set[str]:
        ips: Set[str] = set()
        try:
            key   = self._cfg.api_keys.get('shodan_api_key', '')
            query = f'hostname:{kw}' + (f' country:{country.upper()}' if country else '')
            r = self._sess.get(
                'https://api.shodan.io/shodan/host/search',
                params={'key': key, 'query': query, 'limit': min(100, limit)},
                timeout=15
            )
            if r.status_code == 200:
                for m in r.json().get('matches', []):
                    ip = m.get('ip_str', '')
                    if ip and self._ok(ip):
                        ips.add(ip)
                        if len(ips) >= limit:
                            break
        except Exception:
            pass
        return ips

    def _censys(self, kw: str, limit: int, country: Optional[str]) -> Set[str]:
        ips: Set[str] = set()
        try:
            api_id  = self._cfg.api_keys.get('censys_api_id', '')
            api_sec = self._cfg.api_keys.get('censys_api_secret', '')
            q = f'services.http.response.html_title:{kw}'
            if country:
                q += f' AND location.country_code:{country.upper()}'
            r = self._sess.post(
                'https://search.censys.io/api/v2/hosts/search',
                json={'q': q, 'per_page': min(100, limit)},
                auth=(api_id, api_sec),
                headers={'Accept': 'application/json'},
                timeout=15
            )
            if r.status_code == 200:
                for hit in r.json().get('result', {}).get('hits', []):
                    ip = hit.get('ip', '')
                    if ip and self._ok(ip):
                        ips.add(ip)
                        if len(ips) >= limit:
                            break
        except Exception:
            pass
        return ips

    def _fofa(self, kw: str, limit: int, country: Optional[str]) -> Set[str]:
        ips: Set[str] = set()
        try:
            email = self._cfg.api_keys.get('fofa_email', '')
            key   = self._cfg.api_keys.get('fofa_key', '')
            q     = f'domain="{kw}"'
            if country:
                q += f' && country="{country.upper()}"'
            q_b64 = base64.b64encode(q.encode()).decode()
            r = self._sess.get(
                'https://fofa.info/api/v1/search/all',
                params={'email': email, 'key': key,
                        'qbase64': q_b64, 'size': min(100, limit), 'fields': 'ip'},
                timeout=15
            )
            if r.status_code == 200:
                d = r.json()
                if not d.get('error', True):
                    for row in d.get('results', []):
                        ip = row[0] if row else ''
                        if ip and self._ok(ip):
                            ips.add(ip)
                            if len(ips) >= limit:
                                break
        except Exception:
            pass
        return ips

    def _zoomeye(self, kw: str, limit: int, country: Optional[str]) -> Set[str]:
        ips: Set[str] = set()
        try:
            key   = self._cfg.api_keys.get('zoomeye_api_key', '')
            query = f'hostname:{kw}' + (f' +country:{country.upper()}' if country else '')
            r = self._sess.get(
                'https://api.zoomeye.org/host/search',
                headers={'API-KEY': key},
                params={'query': query, 'page': 1},
                timeout=15
            )
            if r.status_code == 200:
                for m in r.json().get('matches', []):
                    ip = m.get('ip', '')
                    if ip and self._ok(ip):
                        ips.add(ip)
                        if len(ips) >= limit:
                            break
        except Exception:
            pass
        return ips

    def _securitytrails(self, kw: str, limit: int) -> Set[str]:
        ips: Set[str] = set()
        try:
            key = self._cfg.api_keys.get('securitytrails_api_key', '')
            r   = self._sess.get(
                f'https://api.securitytrails.com/v1/domain/{kw}',
                headers={'APIKEY': key, 'Accept': 'application/json'},
                timeout=15
            )
            if r.status_code == 200:
                for rec in r.json().get('current_dns', {}).get('a', {}).get('values', []):
                    ip = rec.get('ip', '')
                    if ip and self._ok(ip):
                        ips.add(ip)
                        if len(ips) >= limit:
                            break
        except Exception:
            pass
        return ips


# ═══════════════════════════════════════════════════════════════════════
#  CLI  (FIX: domain_file_scan inside class, 0=Back works everywhere)
# ═══════════════════════════════════════════════════════════════════════
class SpiderWebCLI:
    VERSION = "2.4"

    BANNER = f"""{Colors.BOLD}{Colors.GREEN}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           ╔═╗┌─┐┬┌┬┐┌─┐┬─┐╦ ╦┌─┐┌┐     ╔═╗╦═╗╔═╗             ║
║           ╚═╗├─┘│ ││├┤ ├┬┘║║║├┤ ├┴┐    ╠═╝╠╦╝║ ║             ║
║           ╚═╝┴  ┴─┴┘└─┘┴└─╚╩╝└─┘└─┘    ╩  ╩╚═╚═╝             ║
║                                                              ║
║{Colors.ENDC}      {Colors.RED}Advanced Security Intelligence v2.4 - Recon Edition{Colors.ENDC}     {Colors.GREEN}║
║{Colors.ENDC}                           {Colors.WHITE}by g33l0{Colors.ENDC}                           {Colors.GREEN}║
║                                                              ║
║ ┌──────────────────────────────────────────────────────────┐ ║
║ │ CVE Correlation | Banner Grabbing | Default Cred Testing │ ║
║ │ WAF Detection | SSL Scanning | Sensitive Path Discovery  │ ║
║ └──────────────────────────────────────────────────────────┘ ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""

    MAX_IPS = 4000

    def __init__(self):
        self.results:  List[IPAnalysisResult] = []
        self._rl       = RateLimiter(8.0)
        self.config    = DataSourceConfig()
        self.generator = MultiSourceIPGenerator(self._rl, self.config)
        signal.signal(signal.SIGINT, self._on_ctrl_c)

    def _on_ctrl_c(self, sig, frame):
        print(f"\n{Colors.YELLOW}Cancelled.{Colors.ENDC}")
        sys.exit(0)

    def print_banner(self):
        print(self.BANNER)

    # FIX: get_input - "0" always raises NavigationException when allow_back=True
    def get_input(self, prompt: str, allow_back: bool = True) -> str:
        nav = " (ESC=Exit" + (", 0=Back" if allow_back else "") + ")"
        try:
            val = input(f"{prompt}{Colors.BOLD}{nav}: {Colors.ENDC}").strip()
            if val.upper() == 'ESC':
                raise ExitException()
            if val == '0' and allow_back:
                raise NavigationException()
            return val
        except (KeyboardInterrupt, EOFError):
            raise ExitException()

    def get_yn(self, prompt: str, allow_back: bool = True) -> bool:
        """Strict yes/no prompt — loops until user types y or n (case-insensitive).
        Raises NavigationException on '0' (if allow_back), ExitException on ESC."""
        nav = " (ESC=Exit" + (", 0=Back" if allow_back else "") + ")"
        while True:
            try:
                val = input(f"{prompt} [y/n]{Colors.BOLD}{nav}: {Colors.ENDC}").strip().lower()
            except (KeyboardInterrupt, EOFError):
                raise ExitException()
            if val == 'esc':
                raise ExitException()
            if val == '0' and allow_back:
                raise NavigationException()
            if val in ('y', 'yes'):
                return True
            if val in ('n', 'no'):
                return False
            print(f"{Colors.YELLOW}  Please type 'y' or 'n'.{Colors.ENDC}")

    # FIX: prompt_input_method properly handles NavigationException from sub-menus
    def prompt_input_method(self) -> str:
        while True:
            try:
                print(f"\n{Colors.BOLD}=== SELECT INPUT METHOD ==={Colors.ENDC}\n")
                print(f"{Colors.CYAN}1.{Colors.ENDC} Keyword-based IP generation (Multi-source)")
                print(f"{Colors.CYAN}2.{Colors.ENDC} Scan IPs from file  (ips.txt)")
                print(f"{Colors.CYAN}3.{Colors.ENDC} Configure API Keys")
                print(f"{Colors.CYAN}4.{Colors.ENDC} Domain & Subdomain Recon Mode")
                choice = self.get_input("Choice (1-4)", False)
                if choice == "1": return "keyword"
                if choice == "2": return "file"
                if choice == "3":
                    self._configure_api_keys()
                    continue
                if choice == "4":
                    try:
                        self.run_domain_mode()
                    except (NavigationException, ExitException):
                        pass
                    continue
                print(f"{Colors.RED}Invalid choice.{Colors.ENDC}")
            except ExitException:
                sys.exit(0)
            except NavigationException:
                continue

    def _configure_api_keys(self):
        print(f"\n{Colors.BOLD}=== API CONFIGURATION ==={Colors.ENDC}\n")
        print(f"{Colors.YELLOW}Press Enter to skip any source.{Colors.ENDC}\n")
        try:
            fields = [
                ('Shodan API Key',         'shodan_api_key'),
                ('Censys API ID',          'censys_api_id'),
                ('Censys API Secret',      'censys_api_secret'),
                ('FOFA Email',             'fofa_email'),
                ('FOFA API Key',           'fofa_key'),
                ('ZoomEye API Key',        'zoomeye_api_key'),
                ('SecurityTrails API Key', 'securitytrails_api_key'),
                ('VirusTotal API Key',     'virustotal_api_key'),
            ]
            for label, key in fields:
                val = input(f"{label}: ").strip()
                if val:
                    self.config.api_keys[key] = val
            self.config.save()
            print(f"\n{Colors.GREEN}Configuration saved to spiderweb_config.json{Colors.ENDC}\n")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.YELLOW}Configuration cancelled.{Colors.ENDC}")

    def get_country_input(self) -> Optional[str]:
        while True:
            try:
                print(f"\n{Colors.BOLD}=== TARGET LOCATION ==={Colors.ENDC}\n")
                print(f"{Colors.CYAN}Enter 2-letter country code, 00 for worldwide, or 0 to go back.{Colors.ENDC}")
                print(f"\n{Colors.BOLD}Examples:{Colors.ENDC}")
                print("  US  UK  CA  AU  DE  FR  JP  CN  IN  BR  RU  ZA")
                country = self.get_input("Country code (or 00 for worldwide)", True).upper()
                if country == "00":
                    return None
                if len(country) == 2 and country.isalpha():
                    return country
                print(f"{Colors.RED}Invalid. Use 2 letters, 00 for worldwide, or 0 to go back.{Colors.ENDC}")
            except NavigationException:
                raise

    def get_keyword_input(self) -> Tuple[List[str], int, Optional[str]]:
        while True:
            try:
                print(f"\n{Colors.BOLD}=== KEYWORD-BASED GENERATION ==={Colors.ENDC}\n")
                print(f"{Colors.CYAN}Keywords are used as SEEDS for IP discovery across multiple sources.{Colors.ENDC}")
                print(f"{Colors.DIM}Example: 'payment-portal' finds IPs related to payment portals{Colors.ENDC}\n")

                raw = self.get_input("Keywords (comma-separated)", True)
                keywords = [k.strip() for k in raw.split(',') if k.strip()]
                if not keywords:
                    print(f"{Colors.RED}At least one keyword required.{Colors.ENDC}")
                    continue

                count_str = self.get_input(f"How many IPs? (max {self.MAX_IPS})", True)
                try:
                    count = int(count_str)
                except ValueError:
                    print(f"{Colors.RED}Invalid number.{Colors.ENDC}")
                    continue

                if not 1 <= count <= self.MAX_IPS:
                    print(f"{Colors.RED}Must be 1-{self.MAX_IPS}.{Colors.ENDC}")
                    continue

                country = self.get_country_input()
                print(f"\n{Colors.CYAN}🔍 Using keywords as discovery seeds: {', '.join(keywords)}{Colors.ENDC}\n")
                return keywords, count, country

            except NavigationException:
                # "0" pressed - go back to main menu
                raise

    def read_ips_from_file(self) -> List[str]:
        fp = Path("ips.txt")
        if not fp.exists():
            print(f"{Colors.RED}'ips.txt' not found in {os.getcwd()}{Colors.ENDC}")
            raise NavigationException()
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            ips = []
            for n, line in enumerate(lines, 1):
                ip = line.strip()
                if not ip or ip.startswith('#'):
                    continue
                if self._valid_ip(ip):
                    ips.append(ip)
                else:
                    print(f"{Colors.YELLOW}Line {n}: skipped invalid IP '{ip}'{Colors.ENDC}")
            if not ips:
                print(f"{Colors.RED}No valid IPs found.{Colors.ENDC}")
                raise NavigationException()
            unique  = list(dict.fromkeys(ips))
            removed = len(ips) - len(unique)
            if removed:
                print(f"{Colors.YELLOW}Removed {removed} duplicate IPs.{Colors.ENDC}")
            if len(unique) > self.MAX_IPS:
                print(f"{Colors.YELLOW}Trimmed to {self.MAX_IPS} IPs.{Colors.ENDC}")
                unique = unique[:self.MAX_IPS]
            return unique
        except NavigationException:
            raise
        except Exception as e:
            print(f"{Colors.RED}Error reading file: {e}{Colors.ENDC}")
            raise NavigationException()

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False

    async def _async_scan(self, ips: List[str],
                           keywords: List[str],
                           country:  Optional[str]):
        total   = len(ips)
        print(f"\n{Colors.BOLD}=== ADVANCED SECURITY SCAN: {total} IPs ==={Colors.ENDC}\n")

        scanner = AsyncScanner()
        await scanner.init_session()
        sem = asyncio.Semaphore(MAX_CONCURRENT)

        # ── Live dashboard state (thread-safe via asyncio) ─────────────────
        completed   = 0
        alive_count = 0
        vuln_count  = 0
        active: Dict[str, str] = {}   # ip -> current stage
        lock = asyncio.Lock()

        # ── Stage labels shown in the live ticker ──────────────────────────
        STAGES = {
            'liveness':   'Probing',
            'ports':      'Port scan',
            'enrich':     'Enriching',
            'web':        'Web scan',
            'paths':      'Path scan',
            'banners':    'Banners',
            'cve':        'CVE check',
            'done':       'Done',
        }

        # Detect if terminal supports ANSI cursor movement (Linux/Mac/Windows with VT enabled)
        _ansi_ok = sys.platform != 'win32' or os.environ.get('WT_SESSION') or os.environ.get('ANSICON')
        _last_lines = [0]  # mutable container so inner func can write to it

        def _render_dashboard():
            """Print a self-refreshing dashboard; degrades gracefully on Windows cmd."""
            nonlocal completed, alive_count, vuln_count
            bar_w  = 35
            filled = int(bar_w * completed / total) if total else 0
            pct    = (completed / total * 100) if total else 0
            bar    = f"{Colors.GREEN}{'█' * filled}{Colors.ENDC}" \
                     f"{Colors.WHITE}{'░' * (bar_w - filled)}{Colors.ENDC}"

            remaining     = total - completed
            summary_plain = (f"[{'█' * filled}{'░' * (bar_w - filled)}] {pct:5.1f}%  "
                             f"Done:{completed}  Remaining:{remaining}  "
                             f"Vuln:{vuln_count}  Alive:{alive_count}")
            summary_color = (f"{Colors.BOLD}[{bar}] {pct:5.1f}%{Colors.ENDC}  "
                             f"{Colors.GREEN}✓ {completed}{Colors.ENDC}  "
                             f"{Colors.YELLOW}⟳ {remaining}{Colors.ENDC}  "
                             f"{Colors.RED}☠ {vuln_count} vuln{Colors.ENDC}  "
                             f"{Colors.CYAN}♥ {alive_count} alive{Colors.ENDC}")

            active_items = list(active.items())[:4]
            ticker_lines = [
                f"  {Colors.CYAN}▶ {aip:<16}{Colors.ENDC} {Colors.YELLOW}{stage}{Colors.ENDC}"
                for aip, stage in active_items
            ]

            all_lines = [summary_color] + ticker_lines
            n = len(all_lines)

            if _ansi_ok:
                # Erase previous block and redraw in place
                if _last_lines[0]:
                    print(f"\033[{_last_lines[0]}A\033[J", end='', flush=True)
                for line in all_lines:
                    print(line, flush=True)
                _last_lines[0] = n
            else:
                # Windows fallback: single overwrite line on same row
                print(f"\r{summary_plain}", end='', flush=True)

        # Print initial blank lines only when ANSI mode is active
        if _ansi_ok:
            print("\n" * 2, end='', flush=True)

        async def _run(ip: str):
            nonlocal completed, alive_count, vuln_count

            async def _stage(name: str):
                async with lock:
                    active[ip] = STAGES.get(name, name)
                    _render_dashboard()

            async with sem:
                await _stage('liveness')

                # ── Inline scan with stage reporting ──────────────────────
                result = IPAnalysisResult(
                    ip=ip,
                    source_keywords=keywords or [],
                    target_country=country,
                )
                try:
                    result.liveness = await scanner._check_liveness(ip)

                    if result.liveness.status != "dead":
                        async with lock:
                            alive_count += 1

                        if result.liveness.tcp_responsive:
                            await _stage('ports')
                            result.tcp_ports_open = await scanner._scan_ports(ip)
                            result.liveness.ports_scanned = [21,22,25,80,443,3306,5432,
                                                              1433,27017,6379,8080,8443,2082,2083,10000]

                        await _stage('enrich')
                        # geo_lookup returns asn+geo in ONE ip-api call (fixes rate-limit)
                        tasks_enrich = [
                            scanner._geo_lookup(ip),                    # idx 0: asn+geo
                            scanner._get_reverse_dns(ip),               # idx 1
                            WHOISEnricher.enrich(scanner.session, ip),  # idx 2
                        ]
                        response_headers: Dict = {}
                        response_body:    str  = ""

                        if 443 in result.tcp_ports_open or 80 in result.tcp_ports_open:
                            tasks_enrich.append(scanner._get_ssl_info(ip))   # idx 3
                            tasks_enrich.append(scanner._get_web_info(ip))   # idx 4

                        gathered = await asyncio.gather(*tasks_enrich, return_exceptions=True)

                        geo_asn  = gathered[0] if not isinstance(gathered[0], Exception) else {}
                        rdns     = gathered[1] if not isinstance(gathered[1], Exception) else None
                        whois    = gathered[2] if not isinstance(gathered[2], Exception) else WHOISInfo()

                        result.asn          = geo_asn.get('asn')
                        result.asn_org      = geo_asn.get('org')
                        result.domains.reverse_dns = rdns
                        result.country      = geo_asn.get('country')
                        result.country_name = geo_asn.get('country_name')
                        result.city         = geo_asn.get('city')
                        result.region       = geo_asn.get('region')
                        result.isp          = geo_asn.get('isp')
                        result.organization = geo_asn.get('org')
                        result.whois        = whois

                        if len(gathered) > 3 and not isinstance(gathered[3], Exception):
                            ssl_info           = gathered[3]
                            result.ssl.valid   = ssl_info.get('valid', False)
                            result.ssl.issuer  = ssl_info.get('issuer')
                            result.ssl.subject = ssl_info.get('subject')
                            result.ssl.expiry  = ssl_info.get('expiry')
                            result.ssl.version = ssl_info.get('version')
                            result.ssl.cipher  = ssl_info.get('cipher')
                            if ssl_info.get('san_domains'):
                                result.domains.tls_san_domains = ssl_info['san_domains']
                            if 443 in result.tcp_ports_open:
                                result.ssl.ssl_vulnerabilities = await SSLScanner.scan_ssl(ip)

                        if len(gathered) > 4 and not isinstance(gathered[4], Exception):
                            await _stage('web')
                            web_info                    = gathered[4]
                            result.web.server           = web_info.get('server')
                            result.web.title            = web_info.get('title')
                            result.web.powered_by       = web_info.get('powered_by')
                            result.web.security_headers = web_info.get('security_headers', {})
                            result.web.http_methods     = web_info.get('http_methods', [])
                            response_headers            = web_info.get('headers', {})
                            response_body               = web_info.get('body', '')
                            result.detected_technologies = scanner._detect_technologies(web_info)
                            result.web.waf_detected     = WAFDetector.detect(response_headers, response_body)
                            use_https = 443 in result.tcp_ports_open

                            await _stage('paths')
                            result.web.sensitive_paths  = await SensitivePathScanner.scan_paths(
                                scanner.session, ip, use_https
                            )

                        if result.tcp_ports_open:
                            await _stage('banners')
                            banner_tasks = [
                                BannerGrabber.grab_banner(ip, port)
                                for port in result.tcp_ports_open[:5]
                            ]
                            banners = await asyncio.gather(*banner_tasks, return_exceptions=True)
                            result.service_banners = [b for b in banners
                                                      if not isinstance(b, Exception) and b]

                        if result.service_banners:
                            await _stage('cve')
                            cve_tasks = []
                            for banner in result.service_banners[:3]:
                                if banner.version:
                                    cve_tasks.append(
                                        CVECorrelator.lookup_cves(scanner.session, banner.service, banner.version)
                                    )
                            if cve_tasks:
                                cve_results = await asyncio.gather(*cve_tasks, return_exceptions=True)
                                for cves in cve_results:
                                    if not isinstance(cves, Exception):
                                        result.cve_matches.extend(cves)

                        if 21 in result.tcp_ports_open:
                            ftp_creds = DefaultCredChecker.DEFAULT_CREDS.get('ftp', [])
                            result.default_creds = await DefaultCredChecker.test_ftp(ip, 21, ftp_creds)

                        result.hosting = ClassificationEngine.classify(
                            result.asn or '', result.asn_org or '',
                            result.domains.reverse_dns or '',
                            result.tcp_ports_open,
                            result.ssl.valid,
                            result.liveness.http_responsive or result.liveness.https_responsive,
                            response_headers,
                        )

                        result.vulnerability = VulnerabilityAssessor.assess(
                            result, response_headers, response_body
                        )

                        if result.vulnerability and result.vulnerability.risk_score >= 5.0:
                            async with lock:
                                vuln_count += 1

                        if result.hosting.is_origin and not result.hosting.is_cdn:
                            san = await scanner._get_san_domains(ip)
                            result.domains.tls_san_domains = san
                            all_d = set()
                            if rdns:
                                all_d.add(rdns)
                            all_d.update(san)
                            result.domains.all_domains = sorted(all_d)
                            if result.domains.all_domains:
                                primary_domain = result.domains.all_domains[0]
                                if '.' in primary_domain:
                                    subdomains = await SubdomainEnumerator.enumerate(primary_domain, 10)
                                    result.domains.subdomains_found = [
                                        s.subdomain for s in subdomains if s.resolved
                                    ]

                except Exception:
                    pass

                await _stage('done')
                async with lock:
                    active.pop(ip, None)
                    completed += 1
                    _render_dashboard()

                return result

        try:
            scan_tasks = [_run(ip) for ip in ips]
            for coro in asyncio.as_completed(scan_tasks):
                result = await coro
                self.results.append(result)
        finally:
            await scanner.close_session()

        print(f"\n{Colors.BOLD}=== SCAN COMPLETE ==={Colors.ENDC}\n")

    def batch_scan(self, ips: List[str],
                   keywords: List[str] = None,
                   country:  Optional[str] = None):
        try:
            asyncio.run(self._async_scan(ips, keywords or [], country))
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Scan interrupted.{Colors.ENDC}")

    def display_results(self):
        if not self.results:
            print(f"{Colors.YELLOW}No results.{Colors.ENDC}")
            return

        by_cat:  Dict[str, list] = defaultdict(list)
        by_risk: Dict[str, list] = defaultdict(list)
        dead = []

        for r in self.results:
            if r.liveness.status == "dead":
                dead.append(r)
            else:
                by_cat[r.hosting.category].append(r)
                if r.vulnerability.risk_level not in ("MINIMAL", "LOW"):
                    by_risk[r.vulnerability.risk_level].append(r)

        alive     = sum(len(v) for v in by_cat.values())
        origin_ct = sum(len(v) for k, v in by_cat.items() if k != "CDN_EDGE")
        cdn_ct    = len(by_cat.get("CDN_EDGE", []))
        vuln_ct   = sum(len(v) for v in by_risk.values())
        cve_count = sum(1 for r in self.results if r.cve_matches)
        default_cred_count = sum(1 for r in self.results
                                 if any(dc.status == 'SUCCESS' for dc in r.default_creds))
        waf_count = sum(1 for r in self.results if r.web.waf_detected.detected)

        print(f"\n{Colors.BOLD}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'ADVANCED SECURITY ASSESSMENT RESULTS':^80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}\n")
        print(f"  {Colors.GREEN}Total Alive       : {alive}{Colors.ENDC}")
        print(f"  {Colors.GREEN}  Origin Servers   : {origin_ct}{Colors.ENDC}")
        print(f"  {Colors.YELLOW}  CDN / Proxies    : {cdn_ct}{Colors.ENDC}")
        print(f"  {Colors.RED}Dead / Filtered   : {len(dead)}{Colors.ENDC}")
        print(f"  {Colors.MAGENTA}Vulnerable Targets : {vuln_ct}{Colors.ENDC}")
        print(f"  {Colors.BLUE}Total Scanned     : {len(self.results)}{Colors.ENDC}\n")
        print(f"{Colors.BOLD}Advanced Features:{Colors.ENDC}")
        print(f"  {Colors.CYAN}CVE Matches Found      : {cve_count}{Colors.ENDC}")
        print(f"  {Colors.CYAN}Default Creds Accepted : {default_cred_count}{Colors.ENDC}")
        print(f"  {Colors.CYAN}WAF Detected           : {waf_count}{Colors.ENDC}")
        print()

        if by_risk:
            print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.RED}ORIGIN SERVER VULNERABILITY ASSESSMENT{Colors.ENDC}")
            print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}\n")
            for level in ('CRITICAL', 'HIGH', 'MEDIUM'):
                targets = by_risk.get(level, [])
                if not targets:
                    continue
                clr = Colors.RED if level == 'CRITICAL' else Colors.YELLOW
                print(f"{clr}{level}: {len(targets)} target(s){Colors.ENDC}\n")
                for idx, r in enumerate(targets[:3], 1):
                    print(f"{clr}[{idx}] {r.ip}{Colors.ENDC} | Risk Score: {r.vulnerability.risk_score:.1f}/10")
                    if r.country_name:
                        print(f"    Location   : {r.city or 'Unknown'}, {r.country_name}")
                    if r.vulnerability.vulnerable_services:
                        print(f"    Exposed Services:")
                        for svc in r.vulnerability.vulnerable_services[:4]:
                            print(f"      • {svc}")
                    if r.cve_matches:
                        print(f"    CVE Matches:")
                        for cve in r.cve_matches[:2]:
                            print(f"      • {cve.cve_id} [{cve.severity}] Score: {cve.score}")
                    if r.default_creds and any(dc.status == 'SUCCESS' for dc in r.default_creds):
                        print(f"    {Colors.RED}⚠ DEFAULT CREDENTIALS WORK!{Colors.ENDC}")
                        for dc in r.default_creds:
                            if dc.status == 'SUCCESS':
                                print(f"      • {dc.service}: {dc.username}")
                    if r.vulnerability.sensitive_paths_exposed:
                        print(f"    Sensitive Files:")
                        for path in r.vulnerability.sensitive_paths_exposed[:3]:
                            print(f"      • {path}")
                    if r.vulnerability.recommendations:
                        print(f"    Top Fixes:")
                        for rec in r.vulnerability.recommendations[:2]:
                            print(f"      • {rec}")
                    print()
                if len(targets) > 3:
                    print(f"{Colors.YELLOW}  ... and {len(targets)-3} more{Colors.ENDC}\n")

        cdn_targets = by_cat.get("CDN_EDGE", [])
        if cdn_targets:
            print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.CYAN}CDN DETECTION & ORIGIN DISCOVERY{Colors.ENDC}")
            print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}\n")
            print(f"{Colors.YELLOW}Found {len(cdn_targets)} CDN edge node(s){Colors.ENDC}")
            print(f"{Colors.CYAN}Attempting to discover actual origin servers...{Colors.ENDC}\n")

            origin_finder = OriginDiscovery(api_keys=self.config.api_keys)
            discovered_any = False

            for idx, r in enumerate(cdn_targets[:5], 1):
                try:
                    try:
                        hostname = socket.gethostbyaddr(r.ip)[0]
                    except Exception:
                        hostname = r.ip
                    print(f"{Colors.BOLD}[{idx}] {r.ip}{Colors.ENDC} ({hostname})")
                    print(f"    CDN Provider: {r.hosting.provider or 'Unknown'}")
                    discovery = origin_finder.discover_origins(hostname, r.ip)
                    if discovery['origins']:
                        discovered_any = True
                        print(f"    {Colors.GREEN}✓ Found {len(discovery['origins'])} potential origin(s):{Colors.ENDC}")
                        for origin_ip in discovery['origins'][:3]:
                            print(f"      {Colors.GREEN}→ {origin_ip}{Colors.ENDC}")
                            try:
                                origin_info = socket.gethostbyaddr(origin_ip)
                                print(f"        Host: {origin_info[0]}")
                            except Exception:
                                pass
                        if len(discovery['origins']) > 3:
                            print(f"      {Colors.CYAN}... and {len(discovery['origins'])-3} more{Colors.ENDC}")
                        print(f"    {Colors.CYAN}Discovery Methods:{Colors.ENDC}")
                        for method, ips in discovery['methods'].items():
                            print(f"      • {method.replace('_',' ').title()}: {len(ips)} IP(s)")
                        print(f"    {Colors.CYAN}Confidence: {discovery['confidence']}/100{Colors.ENDC}")
                    else:
                        print(f"    {Colors.YELLOW}✗ No origins discovered{Colors.ENDC}")
                        print(f"    {Colors.DIM}Tip: Configure API keys for better results{Colors.ENDC}")
                    print()
                except Exception as e:
                    print(f"    {Colors.RED}Error during discovery: {e}{Colors.ENDC}\n")

            if len(cdn_targets) > 5:
                print(f"{Colors.YELLOW}  ... and {len(cdn_targets)-5} more CDN targets{Colors.ENDC}\n")

            if discovered_any:
                print(f"{Colors.GREEN}✓ Origin discovery successful!{Colors.ENDC}")
                print(f"{Colors.CYAN}Tip: Scan discovered origin IPs directly for better results{Colors.ENDC}\n")
            else:
                print(f"{Colors.YELLOW}⚠ No origins discovered automatically{Colors.ENDC}")
                print(f"{Colors.CYAN}Recommendations:{Colors.ENDC}")
                print(f"  • Configure SecurityTrails API for DNS history")
                print(f"  • Configure Shodan API for certificate search")
                print(f"  • Manually check: origin.domain.com, direct.domain.com")
                print()

    # ══════════════════════════════════════════════════════════════════════
    #  DOMAIN & SUBDOMAIN RECON MODE
    # ══════════════════════════════════════════════════════════════════════
    def run_domain_mode(self):
        while True:
            print(f"\n{Colors.BOLD}{'='*80}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'DOMAIN & SUBDOMAIN RECON MODE':^80}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}\n")
            print(f"{Colors.YELLOW}Use only on systems you are authorized to test.{Colors.ENDC}\n")
            print(f"  {Colors.GREEN}1.{Colors.ENDC} Keyword-based domain generation")
            print(f"  {Colors.GREEN}2.{Colors.ENDC} Scan domains from file")
            print(f"  {Colors.GREEN}0.{Colors.ENDC} Back\n")
            try:
                choice = self.get_input("Choice", True)
                if choice == '1':
                    self.domain_keyword_generation()
                elif choice == '2':
                    self.domain_file_scan()
                else:
                    print(f"{Colors.RED}Invalid choice{Colors.ENDC}")
            except NavigationException:
                # "0" pressed - exit domain mode back to main menu
                return
            except ExitException:
                raise
            except KeyboardInterrupt:
                return

    def domain_keyword_generation(self):
        print(f"\n{Colors.BOLD}=== KEYWORD-BASED DOMAIN GENERATION ==={Colors.ENDC}\n")
        print(f"{Colors.CYAN}Keywords are used as SEEDS for domain discovery.{Colors.ENDC}\n")

        try:
            raw      = self.get_input("Keywords (comma-separated)", True)
            keywords = [k.strip() for k in raw.split(',') if k.strip()]
            if not keywords:
                print(f"{Colors.RED}At least one keyword required{Colors.ENDC}")
                return

            count_str = self.get_input("How many domains? (max 1000)", True)
            try:
                count = int(count_str)
                if not 1 <= count <= 1000:
                    print(f"{Colors.RED}Must be 1-1000{Colors.ENDC}")
                    return
            except ValueError:
                print(f"{Colors.RED}Invalid number{Colors.ENDC}")
                return

        except NavigationException:
            return

        print(f"\n{Colors.CYAN}Generating domains, please wait...{Colors.ENDC}\n")
        generator = MultiSourceDomainGenerator(RateLimiter(), self.config)
        domains, stats = generator.generate(keywords, count)

        print(f"\n{Colors.BOLD}=== GENERATION SUMMARY ==={Colors.ENDC}\n")
        print(f"  Requested : {count}")
        print(f"  Generated : {len(domains)}\n")
        print(f"  {Colors.BOLD}Source Breakdown:{Colors.ENDC}")
        for source, cnt in stats.items():
            print(f"    {source:20s} : {cnt}")

        # Save to domains.txt in the same directory as the script so option 2
        # ("Scan domains from file") can find it immediately without any manual steps.
        script_dir  = os.path.dirname(os.path.abspath(__file__))
        output_file = os.path.join(script_dir, 'domains.txt')
        with open(output_file, 'w') as f:
            for domain in sorted(domains):
                f.write(f"{domain}\n")
        print(f"\n{Colors.GREEN}✓ Saved {len(domains)} domains → {output_file}{Colors.ENDC}")
        print(f"{Colors.CYAN}  Tip: Use option 2 (Scan domains from file) to scan this list.{Colors.ENDC}")

        try:
            if self.get_yn(f"\nRun advanced scan on {len(domains)} domains?", True):
                asyncio.run(self.scan_domain_list(list(domains)))
        except NavigationException:
            pass

    # FIX: domain_file_scan is now properly inside SpiderWebCLI class
    def domain_file_scan(self):
        filepath = 'domains.txt'
        if not os.path.exists(filepath):
            print(f"{Colors.RED}'{filepath}' not found{Colors.ENDC}")
            return

        domains = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    domain = line.strip()
                    domain = domain.replace('http://', '').replace('https://', '')
                    domain = domain.split('/')[0]
                    if domain and '.' in domain:
                        parts = domain.split('.')
                        if len(parts) == 4 and all(p.isdigit() for p in parts):
                            continue  # Skip IPs
                        domains.append(domain.lower())

            domains = list(set(domains))
            print(f"{Colors.GREEN}Loaded {len(domains)} domains from {filepath}{Colors.ENDC}")

            os.makedirs('domain', exist_ok=True)
            with open('domain/sub-domain.txt', 'w') as f:
                for domain in sorted(domains):
                    f.write(f"{domain}\n")
            print(f"{Colors.GREEN}✓ Saved cleaned list to: domain/sub-domain.txt{Colors.ENDC}")

            try:
                if self.get_yn(f"\nScan {len(domains)} domains?", True):
                    asyncio.run(self.scan_domain_list(domains))
            except NavigationException:
                pass

        except Exception as e:
            print(f"{Colors.RED}Error reading file: {e}{Colors.ENDC}")

    async def scan_domain_list(self, domains: List[str]):
        """Scan all domains concurrently with a semaphore gate to avoid FD exhaustion."""
        total = len(domains)
        print(f"\n{Colors.BOLD}=== ADVANCED DOMAIN SCAN: {total} domains ==={Colors.ENDC}\n")

        scanner   = AsyncScanner()
        await scanner.init_session()
        results   = []
        completed = 0
        alive_c   = 0
        risk_c    = 0
        lock      = asyncio.Lock()

        # Cap concurrent domain scans: each scan uses ~6 FDs; 30×6=180, well under 512
        sem = asyncio.Semaphore(30)

        _ansi = sys.platform != 'win32' or os.environ.get('WT_SESSION') or os.environ.get('ANSICON')
        _prev = [0]

        def _render(domain_done: str = ""):
            nonlocal completed, alive_c, risk_c
            bar_w  = 35
            filled = int(bar_w * completed / total) if total else 0
            pct    = (completed / total * 100) if total else 0
            bar_c  = f"{Colors.GREEN}{'█' * filled}{Colors.ENDC}{Colors.WHITE}{'░' * (bar_w - filled)}{Colors.ENDC}"
            bar_p  = f"{'█' * filled}{'░' * (bar_w - filled)}"
            summary_c = (f"{Colors.BOLD}[{bar_c}] {pct:5.1f}%{Colors.ENDC}  "
                         f"{Colors.GREEN}✓ {completed}/{total}{Colors.ENDC}  "
                         f"{Colors.CYAN}♥ {alive_c} alive{Colors.ENDC}  "
                         f"{Colors.RED}⚠ {risk_c} risk{Colors.ENDC}")
            summary_p = f"[{bar_p}] {pct:5.1f}%  Done:{completed}/{total}  Alive:{alive_c}  Risk:{risk_c}"
            if domain_done:
                ticker = f"  {Colors.CYAN}✓ {domain_done}{Colors.ENDC}"
            else:
                ticker = ""
            if _ansi:
                if _prev[0]:
                    print(f"\033[{_prev[0]}A\033[J", end='', flush=True)
                lines = [summary_c] + ([ticker] if ticker else [])
                for l in lines:
                    print(l, flush=True)
                _prev[0] = len(lines)
            else:
                print(f"\r{summary_p}", end='', flush=True)

        print("\n" if _ansi else "", end='', flush=True)

        async def _run(domain: str):
            nonlocal completed, alive_c, risk_c
            async with sem:
                try:
                    result = await scanner.scan_domain(domain)
                except Exception:
                    result = DomainInfo(domain=domain, source="scan")
                async with lock:
                    results.append(result)
                    completed += 1
                    if result.alive:
                        alive_c += 1
                    if result.risk_level in ("HIGH", "CRITICAL"):
                        risk_c += 1
                    _render(domain)
                return result

        try:
            tasks = [_run(d) for d in domains]
            for coro in asyncio.as_completed(tasks):
                await coro
        finally:
            await scanner.close_session()

        print("\n")
        self.display_domain_results(results)
        self.export_domain_results(results)

    def display_domain_results(self, results: List[DomainInfo]):
        alive         = [r for r in results if r.alive]
        smtp_detected = [r for r in results if r.smtp_analysis and r.smtp_analysis.smtp_detected]
        high_risk     = [r for r in results if r.risk_level == "HIGH"]

        print(f"\n{Colors.BOLD}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'DOMAIN SCAN RESULTS':^80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}\n")
        print(f"  Total Scanned : {len(results)}")
        print(f"  Alive         : {len(alive)}")
        print(f"  SMTP Detected : {len(smtp_detected)}")
        print(f"  High Risk     : {len(high_risk)}\n")

        if high_risk:
            print(f"{Colors.BOLD}HIGH RISK DOMAINS:{Colors.ENDC}\n")
            for r in high_risk[:5]:
                print(f"{Colors.YELLOW}{r.domain}{Colors.ENDC}")
                print(f"  IP: {r.resolved_ip}")
                print(f"  Risk: {r.risk_score:.1f}/10")
                if r.smtp_analysis and r.smtp_analysis.smtp_detected:
                    print(f"  SMTP: Port {r.smtp_analysis.port} - {r.smtp_analysis.risk_level}")
                    if r.smtp_analysis.risk_factors:
                        print(f"  Issues: {', '.join(r.smtp_analysis.risk_factors[:2])}")
                print()

    def export_domain_results(self, results: List[DomainInfo]):
        os.makedirs('domain', exist_ok=True)
        with open('domain/domain_scan_results.csv', 'w') as f:
            f.write("domain,resolved_ip,alive,hosting_type,risk_score,risk_level,ssl_grade,"
                    "waf_detected,smtp_detected,smtp_port,smtp_risk,spf,dkim,dmarc,open_relay_flag\n")
            for r in results:
                smtp = r.smtp_analysis
                f.write(f"{r.domain},{r.resolved_ip or ''},{r.alive},{r.hosting_type or ''},")
                f.write(f"{r.risk_score},{r.risk_level},{r.ssl_grade or ''},{r.waf_detected},")
                f.write(f"{smtp.smtp_detected if smtp else False},{smtp.port if smtp else ''},")
                f.write(f"{smtp.risk_level if smtp else ''},{smtp.spf_record if smtp else False},")
                f.write(f"{smtp.dkim_record if smtp else False},{smtp.dmarc_record if smtp else False},")
                f.write(f"{smtp.open_relay_possible if smtp else False}\n")

        with open('domain/domain_scan_results.json', 'w') as f:
            data = []
            for r in results:
                item = {
                    'domain': r.domain, 'resolved_ip': r.resolved_ip,
                    'alive': r.alive, 'hosting_type': r.hosting_type,
                    'risk_score': r.risk_score, 'risk_level': r.risk_level,
                    'ssl_grade': r.ssl_grade, 'waf_detected': r.waf_detected,
                    'technologies': r.technologies, 'vulnerabilities': r.vulnerabilities,
                }
                if r.smtp_analysis:
                    item['smtp_analysis'] = {
                        'smtp_detected':      r.smtp_analysis.smtp_detected,
                        'port':               r.smtp_analysis.port,
                        'banner':             r.smtp_analysis.banner,
                        'supports_tls':       r.smtp_analysis.supports_tls,
                        'tls_version':        r.smtp_analysis.tls_version,
                        'open_relay_possible': r.smtp_analysis.open_relay_possible,
                        'spf_record':         r.smtp_analysis.spf_record,
                        'dkim_record':        r.smtp_analysis.dkim_record,
                        'dmarc_record':       r.smtp_analysis.dmarc_record,
                        'risk_level':         r.smtp_analysis.risk_level,
                        'risk_factors':       r.smtp_analysis.risk_factors,
                    }
                data.append(item)
            json.dump(data, f, indent=2)

        print(f"{Colors.GREEN}✓ Results exported to domain/ folder{Colors.ENDC}")
        print(f"  - domain/domain_scan_results.csv")
        print(f"  - domain/domain_scan_results.json")

    def export_results(self):
        if not self.results:
            print(f"{Colors.YELLOW}No results to export.{Colors.ENDC}")
            return

        ts      = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_id = self.results[0].scan_id if self.results else hashlib.md5(
            str(time.time()).encode()
        ).hexdigest()[:8]

        out_dir = Path("spiderweb_results")
        out_dir.mkdir(exist_ok=True)

        class _SafeEncoder(json.JSONEncoder):
            """Serialize Enum values and any other non-standard types safely."""
            def default(self, obj):
                if isinstance(obj, Enum):
                    return obj.value
                try:
                    return super().default(obj)
                except TypeError:
                    return str(obj)

        def _safe_asdict(r):
            """Convert dataclass to dict, coercing Enum values to their .value strings."""
            d = asdict(r)
            def _coerce(o):
                if isinstance(o, dict):
                    return {k: _coerce(v) for k, v in o.items()}
                if isinstance(o, list):
                    return [_coerce(i) for i in o]
                if isinstance(o, Enum):
                    return o.value
                return o
            return _coerce(d)

        json_path = out_dir / f"scan_{ts}_{scan_id}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'tool':             'SpiderWeb Pro',
                    'version':          self.VERSION,
                    'author':           'g33l0',
                    'scan_id':          scan_id,
                    'timestamp':        datetime.now().isoformat(),
                    'total_scanned':    len(self.results),
                    'total_alive':      sum(1 for r in self.results if r.liveness.status != 'dead'),
                    'total_vulnerable': sum(1 for r in self.results
                                           if r.vulnerability.risk_level in ('CRITICAL','HIGH','MEDIUM')),
                },
                'results': [_safe_asdict(r) for r in self.results],
            }, f, indent=2, ensure_ascii=False, cls=_SafeEncoder)

        csv_path = out_dir / f"scan_{ts}_{scan_id}.csv"
        fieldnames = [
            'ip', 'status', 'category', 'confidence', 'is_origin', 'is_cdn', 'provider',
            'country', 'city', 'region', 'isp', 'asn', 'organization',
            'open_ports', 'http_status', 'https_status', 'response_time_ms',
            'reverse_dns', 'domains', 'subdomains', 'ssl_valid', 'ssl_version', 'ssl_issuer',
            'ssl_vulnerabilities', 'web_server', 'web_title', 'powered_by', 'technologies',
            'waf_detected', 'waf_name', 'service_banners', 'cve_count', 'cves',
            'default_creds_found', 'sensitive_paths', 'dangerous_methods',
            'risk_level', 'risk_score', 'vulnerable_services', 'recommendations',
            'origin_discovery_paths', 'whois_org', 'whois_abuse_contact', 'scan_timestamp',
        ]
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in self.results:
                w.writerow({
                    'ip':                   r.ip,
                    'status':               r.liveness.status,
                    'category':             r.hosting.category,
                    'confidence':           round(r.hosting.confidence, 3),
                    'is_origin':            r.hosting.is_origin,
                    'is_cdn':               r.hosting.is_cdn,
                    'provider':             r.hosting.provider or '',
                    'country':              r.country or '',
                    'city':                 r.city or '',
                    'region':               r.region or '',
                    'isp':                  r.isp or '',
                    'asn':                  r.asn or '',
                    'organization':         r.organization or '',
                    'open_ports':           ','.join(map(str, r.tcp_ports_open)),
                    'http_status':          r.liveness.http_status or '',
                    'https_status':         r.liveness.https_status or '',
                    'response_time_ms':     (round(r.liveness.response_time * 1000, 2)
                                             if r.liveness.response_time else ''),
                    'reverse_dns':          r.domains.reverse_dns or '',
                    'domains':              ','.join(r.domains.all_domains),
                    'subdomains':           ','.join(r.domains.subdomains_found),
                    'ssl_valid':            r.ssl.valid,
                    'ssl_version':          r.ssl.version or '',
                    'ssl_issuer':           r.ssl.issuer or '',
                    'ssl_vulnerabilities':  ';'.join(r.ssl.ssl_vulnerabilities.issues),
                    'web_server':           r.web.server or '',
                    'web_title':            r.web.title or '',
                    'powered_by':           r.web.powered_by or '',
                    'technologies':         ','.join(r.detected_technologies),
                    'waf_detected':         r.web.waf_detected.detected,
                    'waf_name':             r.web.waf_detected.waf_name or '',
                    'service_banners':      ';'.join([f"{b.service}:{b.version}" for b in r.service_banners if b.version]),
                    'cve_count':            len(r.cve_matches),
                    'cves':                 ';'.join([f"{c.cve_id}[{c.severity}]" for c in r.cve_matches[:5]]),
                    'default_creds_found':  ';'.join([f"{dc.service}:{dc.username}" for dc in r.default_creds if dc.status=='SUCCESS']),
                    'sensitive_paths':      ';'.join(r.vulnerability.sensitive_paths_exposed[:5]),
                    'dangerous_methods':    ','.join(r.vulnerability.dangerous_http_methods),
                    'risk_level':           r.vulnerability.risk_level,
                    'risk_score':           r.vulnerability.risk_score,
                    'vulnerable_services':  '; '.join(r.vulnerability.vulnerable_services),
                    'recommendations':      '; '.join(r.vulnerability.recommendations[:3]),
                    'origin_discovery_paths': '; '.join(r.hosting.origin_discovery_paths),
                    'whois_org':            r.whois.organization or '',
                    'whois_abuse_contact':  r.whois.abuse_contact or '',
                    'scan_timestamp':       r.scan_timestamp,
                })

        high_risk = [r for r in self.results
                     if r.vulnerability.risk_level in ('CRITICAL', 'HIGH') and not r.hosting.is_cdn]

        vuln_path = None
        if high_risk:
            vuln_path = out_dir / f"vulnerable_{ts}_{scan_id}.txt"
            with open(vuln_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("SPIDERWEB PRO v2.4 - ADVANCED VULNERABILITY REPORT\n")
                f.write(f"Scan ID   : {scan_id}\n")
                f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("Scope     : Origin servers only (CDN edge nodes excluded)\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"HIGH-RISK ORIGIN SERVERS: {len(high_risk)}\n\n")
                for r in high_risk:
                    f.write(f"\n{'─'*80}\n")
                    f.write(f"IP         : {r.ip}\n")
                    f.write(f"Risk Level : {r.vulnerability.risk_level}\n")
                    f.write(f"Risk Score : {r.vulnerability.risk_score:.1f}/10\n")
                    f.write(f"Category   : {r.hosting.category}\n")
                    f.write(f"Provider   : {r.hosting.provider or 'Unknown'}\n")
                    f.write(f"Location   : {r.city}, {r.country_name}\n")
                    if r.whois.organization:
                        f.write(f"Owner      : {r.whois.organization}\n")
                    f.write(f"\n")
                    if r.vulnerability.vulnerable_services:
                        f.write("Vulnerable Services:\n")
                        for svc in r.vulnerability.vulnerable_services:
                            f.write(f"  ⚠ {svc}\n")
                        f.write("\n")
                    if r.cve_matches:
                        f.write(f"CVE Matches ({len(r.cve_matches)}):\n")
                        for cve in r.cve_matches[:5]:
                            f.write(f"  • {cve.cve_id} [{cve.severity}] Score: {cve.score}\n")
                            f.write(f"    {cve.description}\n")
                        f.write("\n")
                    if r.default_creds and any(dc.status == 'SUCCESS' for dc in r.default_creds):
                        f.write("DEFAULT CREDENTIALS WORK:\n")
                        for dc in r.default_creds:
                            if dc.status == 'SUCCESS':
                                f.write(f"  ⚠ {dc.service}: {dc.username}\n")
                        f.write("\n")
                    if r.service_banners:
                        f.write("Service Fingerprints:\n")
                        for banner in r.service_banners[:5]:
                            if banner.version:
                                f.write(f"  • Port {banner.port}: {banner.service} {banner.version}\n")
                        f.write("\n")
                    if r.vulnerability.sensitive_paths_exposed:
                        f.write("Sensitive Files Exposed:\n")
                        for path in r.vulnerability.sensitive_paths_exposed:
                            f.write(f"  • {path}\n")
                        f.write("\n")
                    if r.vulnerability.recommendations:
                        f.write("Remediation Steps:\n")
                        for idx, rec in enumerate(r.vulnerability.recommendations, 1):
                            f.write(f"  {idx}. {rec}\n")
                        f.write("\n")

        print(f"\n{Colors.BOLD}=== EXPORT COMPLETE ==={Colors.ENDC}\n")
        print(f"  {Colors.GREEN}Directory : {out_dir}{Colors.ENDC}")
        print(f"  {Colors.GREEN}JSON      : {json_path.name}{Colors.ENDC}")
        print(f"  {Colors.GREEN}CSV       : {csv_path.name}{Colors.ENDC}")
        if vuln_path:
            print(f"  {Colors.RED}Vuln TXT  : {vuln_path.name}{Colors.ENDC}")
        print(f"\n  {Colors.CYAN}Scan ID   : {scan_id}{Colors.ENDC}\n")


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════
def main():
    # ── Windows: use SelectorEventLoop to avoid ProactorEventLoop WinError 10054 spam ──
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        # Enable ANSI escape codes in Windows console (for colors + cursor movement)
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

    try:
        from bs4 import BeautifulSoup  # noqa
        import aiohttp                 # noqa
    except ImportError:
        print(f"{Colors.CYAN}Installing required packages...{Colors.ENDC}")
        import subprocess
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "beautifulsoup4", "aiohttp", "-q"]
        )
        print(f"{Colors.GREEN}Done.{Colors.ENDC}\n")

    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    cli = SpiderWebCLI()
    cli.print_banner()
    print(f"{Colors.YELLOW}LEGAL: Use only on systems you are authorized to test.{Colors.ENDC}\n")

    while True:
        try:
            method = cli.prompt_input_method()

            ips:      List[str]     = []
            keywords: List[str]     = []
            country:  Optional[str] = None

            if method == "keyword":
                try:
                    keywords, count, country = cli.get_keyword_input()
                except NavigationException:
                    continue

                cli.generator.ip_counter = 0

                spinner = Spinner("Generating IPs, Please wait")
                spinner.start()
                generated, stats = cli.generator.generate(keywords, count, country)
                spinner.stop()

                ips = list(generated)

                print(f"\n{Colors.BOLD}=== GENERATION SUMMARY ==={Colors.ENDC}\n")
                print(f"  {Colors.BLUE}Requested : {count}{Colors.ENDC}")
                print(f"  {Colors.GREEN}Generated : {len(ips)}{Colors.ENDC}")

                if stats:
                    print(f"\n  {Colors.BOLD}Source Breakdown:{Colors.ENDC}")
                    for src, cnt in sorted(stats.items(), key=lambda x: -x[1]):
                        print(f"    {src:20s}: {cnt}")
                print()

                if len(ips) == 0:
                    print(f"{Colors.RED}No IPs generated. Try different keywords or add API keys.{Colors.ENDC}")
                    continue

                if len(ips) < count:
                    print(f"{Colors.YELLOW}Generated {len(ips)}/{count} IPs.{Colors.ENDC}\n")
                    try:
                        if not cli.get_yn(f"Continue with {len(ips)} IPs?", True):
                            continue
                    except NavigationException:
                        continue

            else:
                try:
                    ips = cli.read_ips_from_file()
                except NavigationException:
                    continue
                print(f"\n{Colors.GREEN}Loaded {len(ips)} IPs from ips.txt{Colors.ENDC}\n")

            try:
                if not cli.get_yn(f"Start advanced scan of {len(ips)} IPs?", True):
                    continue
            except NavigationException:
                continue

            cli.results = []
            cli.batch_scan(ips, keywords, country)
            cli.display_results()

            if cli.results:
                try:
                    if cli.get_yn("Export results?", True):
                        cli.export_results()
                except NavigationException:
                    pass

            print(f"\n{Colors.GREEN}Assessment complete.{Colors.ENDC}\n")

            try:
                if not cli.get_yn("Run another scan?", False):
                    print(f"\n{Colors.WHITE}Thank you for using SpiderWeb Pro. Stay secure!{Colors.ENDC}\n")
                    break
            except ExitException:
                break

        except NavigationException:
            continue
        except ExitException:
            print(f"\n{Colors.WHITE}Goodbye!{Colors.ENDC}\n")
            break
        except Exception as e:
            print(f"\n{Colors.RED}Unexpected error: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
            try:
                if not cli.get_yn("Retry?", False):
                    break
            except Exception:
                break

    print(f"{Colors.CYAN}SpiderWeb Pro v{SpiderWebCLI.VERSION} closed.{Colors.ENDC}\n")


if __name__ == "__main__":
    main()
