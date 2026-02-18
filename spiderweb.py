#!/usr/bin/env python3
"""
SpiderWeb Pro - Enterprise Security Intelligence Platform
Author: g33l0
Version: 2.2 - Enterprise Edition
Description: Professional IP reconnaissance with multi-source intelligence,
             CDN-aware classification, vulnerability assessment, and animated UI.

Data Sources: DNS, URLScan, ThreatCrowd, Shodan, Censys, FOFA, ZoomEye, SecurityTrails

LEGAL: Use only on authorized targets. Unauthorized scanning may be illegal.
"""

import requests
import re
import time
import json
import csv
import socket
import ssl
import asyncio
import aiohttp
import concurrent.futures
from typing import Set, List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
from collections import defaultdict
import sys
import os
from pathlib import Path
import random
import threading
import signal
import hashlib
import base64


# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────
class Colors:
    GREEN   = '\033[92m'
    RED     = '\033[91m'
    WHITE   = '\033[97m'
    CYAN    = '\033[96m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'


class NavigationException(Exception):
    pass


class ExitException(Exception):
    pass


# ─────────────────────────────────────────────
#  GLOBAL CONFIG
# ─────────────────────────────────────────────
TIMEOUT_TCP  = 3
TIMEOUT_HTTP = 5
TIMEOUT_DNS  = 2
MAX_CONCURRENT = 120

# ─────────────────────────────────────────────
#  CDN / ACCELERATOR GUARDRAILS
#  Any IP whose ASN or PTR matches these is
#  FORCE-classified as CDN_EDGE and exempt
#  from vulnerability scoring.
# ─────────────────────────────────────────────
FORCE_CDN_ASN_NUMBERS = {
    # Cloudflare
    'AS13335', 'AS209242',
    # Akamai
    'AS16625', 'AS20940', 'AS21342', 'AS21357', 'AS34164',
    # Fastly
    'AS54113',
    # AWS CloudFront / Global Accelerator
    'AS16509', 'AS14618',
    # StackPath
    'AS33438',
    # Incapsula / Imperva
    'AS19551',
}

FORCE_CDN_PTR_PATTERNS = [
    r'cloudflare',
    r'cloudflare-dns',
    r'awsglobalaccelerator\.com',
    r'cloudfront\.net',
    r'akamaiedge',
    r'akamai',
    r'fastly',
    r'edgesuite',
    r'edgekey',
    r'footprint\.net',
    r'stackpath',
    r'incapsula',
]

# ─────────────────────────────────────────────
#  ANIMATED SPINNER
# ─────────────────────────────────────────────
class Spinner:
    """Animated 'Generating IPs, Please wait.. … .' spinner."""

    FRAMES = ['   ', '.  ', '.. ', '...', ' ..', '  .']

    def __init__(self, message: str = "Generating IPs, Please wait"):
        self.message  = message
        self.running  = False
        self._thread  = None
        self._idx     = 0

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
        # Clear spinner line
        print(f"\r{' ' * 60}\r", end='', flush=True)
        if final_msg:
            print(final_msg, flush=True)


# ─────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────
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
    risk_score:               float = 0.0
    risk_level:               str = "MINIMAL"
    vulnerable_services:      List[str] = field(default_factory=list)
    recommendations:          List[str] = field(default_factory=list)


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
    # Renamed from "bypass" to professional bug-bounty language
    origin_discovery_paths: List[str] = field(default_factory=list)
    signals:                ClassificationSignals = field(default_factory=ClassificationSignals)


@dataclass
class LivenessStatus:
    status:          str = "dead"
    tcp_responsive:  bool = False
    http_responsive: bool = False
    https_responsive: bool = False
    tls_handshake:   bool = False
    http_status:     Optional[int] = None
    https_status:    Optional[int] = None
    response_time:   Optional[float] = None
    ports_scanned:   List[int] = field(default_factory=list)


@dataclass
class DomainAttribution:
    reverse_dns:      Optional[str] = None
    tls_san_domains:  List[str] = field(default_factory=list)
    all_domains:      List[str] = field(default_factory=list)


@dataclass
class SSLInfo:
    valid:   bool = False
    issuer:  Optional[str] = None
    subject: Optional[str] = None
    expiry:  Optional[str] = None
    version: Optional[str] = None
    cipher:  Optional[str] = None


@dataclass
class WebInfo:
    server:           Optional[str] = None
    title:            Optional[str] = None
    powered_by:       Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class IPAnalysisResult:
    ip: str

    liveness:    LivenessStatus        = field(default_factory=LivenessStatus)
    domains:     DomainAttribution     = field(default_factory=DomainAttribution)
    hosting:     HostingClassification = field(default_factory=HostingClassification)
    vulnerability: VulnerabilityIndicators = field(default_factory=VulnerabilityIndicators)

    tcp_ports_open: List[int] = field(default_factory=list)
    asn:            Optional[str] = None
    asn_org:        Optional[str] = None

    country:      Optional[str] = None
    country_name: Optional[str] = None
    city:         Optional[str] = None
    region:       Optional[str] = None
    isp:          Optional[str] = None
    organization: Optional[str] = None

    ssl: SSLInfo = field(default_factory=SSLInfo)
    web: WebInfo = field(default_factory=WebInfo)

    detected_technologies: List[str] = field(default_factory=list)
    data_sources:          List[str] = field(default_factory=list)

    scan_timestamp:  str = field(default_factory=lambda: datetime.now().isoformat())
    source_keywords: List[str] = field(default_factory=list)
    target_country:  Optional[str] = None
    scan_id:         str = field(
        default_factory=lambda: hashlib.md5(
            str(datetime.now().timestamp()).encode()
        ).hexdigest()[:8]
    )


# ─────────────────────────────────────────────
#  API CONFIG
# ─────────────────────────────────────────────
class DataSourceConfig:
    def __init__(self):
        self.config_file = Path("spiderweb_config.json")
        self.api_keys    = self._load()

    def _load(self) -> Dict:
        defaults = {
            "shodan_api_key":       "",
            "censys_api_id":        "",
            "censys_api_secret":    "",
            "fofa_email":           "",
            "fofa_key":             "",
            "zoomeye_api_key":      "",
            "securitytrails_api_key": "",
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


# ─────────────────────────────────────────────
#  CDN FORCE-CLASSIFIER
# ─────────────────────────────────────────────
def is_force_cdn(asn: str, ptr: str) -> bool:
    """Return True if ASN or PTR matches known CDN / traffic-accelerator."""
    asn_upper = (asn or '').upper()
    for asn_num in FORCE_CDN_ASN_NUMBERS:
        if asn_num in asn_upper:
            return True

    ptr_lower = (ptr or '').lower()
    for pattern in FORCE_CDN_PTR_PATTERNS:
        if re.search(pattern, ptr_lower):
            return True

    return False


# ─────────────────────────────────────────────
#  VULNERABILITY ASSESSOR
#  Only runs on confirmed origin servers.
# ─────────────────────────────────────────────
class VulnerabilityAssessor:

    DB_PORTS = {
        3306:  'MySQL',
        5432:  'PostgreSQL',
        1433:  'MSSQL',
        27017: 'MongoDB',
        6379:  'Redis',
        5984:  'CouchDB',
        9200:  'Elasticsearch',
        11211: 'Memcached',
    }

    ADMIN_PORTS = {
        2082:  'cPanel',
        2083:  'cPanel SSL',
        8080:  'Admin Panel',
        8443:  'Admin Panel SSL',
        10000: 'Webmin',
        2086:  'WHM',
        2087:  'WHM SSL',
        8081:  'Management Console',
    }

    REQUIRED_HEADERS = [
        'Strict-Transport-Security',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Content-Security-Policy',
    ]

    OUTDATED_SIGNATURES = [
        r'Apache/2\.[0-2]',
        r'nginx/1\.[0-9]\.',
        r'PHP/5\.',
        r'PHP/7\.[0-2]',
        r'IIS/[6-8]\.',
    ]

    @classmethod
    def assess(cls, result: IPAnalysisResult,
               response_headers: Dict = None,
               response_body:    str  = None) -> VulnerabilityIndicators:
        """
        Assess ONLY if the IP is a confirmed origin server.
        CDN_EDGE IPs always get MINIMAL risk.
        """
        vuln = VulnerabilityIndicators()

        # ── CDN / accelerator guard ──────────────────────────────────────
        if result.hosting.is_cdn or result.hosting.category == "CDN_EDGE":
            vuln.risk_score = 0.0
            vuln.risk_level = "MINIMAL"
            return vuln

        risk_factors = []

        # Exposed database ports
        for port, db_name in cls.DB_PORTS.items():
            if port in result.tcp_ports_open:
                vuln.exposed_db_port = True
                vuln.sql_backend_detected = db_name
                vuln.vulnerable_services.append(f"{db_name} (Port {port})")
                risk_factors.append(3.0)
                vuln.recommendations.append(
                    f"Bind {db_name} on port {port} to localhost; block external access via firewall."
                )

        # Exposed admin ports
        for port, service in cls.ADMIN_PORTS.items():
            if port in result.tcp_ports_open:
                vuln.exposed_admin_port = True
                vuln.vulnerable_services.append(f"{service} (Port {port})")
                risk_factors.append(2.5)
                vuln.recommendations.append(
                    f"Restrict {service} (port {port}) with IP allowlist or VPN."
                )

        # Security headers
        if response_headers:
            missing = [h for h in cls.REQUIRED_HEADERS if h not in response_headers]
            if missing:
                vuln.missing_security_headers = True
                risk_factors.append(1.5)
                vuln.recommendations.append(
                    f"Add missing headers: {', '.join(missing[:3])}"
                )

        # Outdated software
        server = result.web.server or ''
        for pattern in cls.OUTDATED_SIGNATURES:
            if re.search(pattern, server, re.IGNORECASE):
                vuln.outdated_software = True
                risk_factors.append(2.0)
                vuln.recommendations.append("Update web server to latest stable version.")
                break

        # Weak TLS
        if result.ssl.valid and result.ssl.version:
            if 'TLSv1' in result.ssl.version and 'TLSv1.3' not in result.ssl.version:
                vuln.weak_ssl = True
                risk_factors.append(1.8)
                vuln.recommendations.append("Upgrade to TLS 1.2+ and disable TLS 1.0/1.1.")

        # SQL error disclosure
        if response_body:
            sql_error_patterns = [
                r'SQL syntax.*MySQL', r'Warning.*mysql_', r'valid MySQL result',
                r'MySqlClient\.', r'PostgreSQL.*ERROR', r'Warning.*pg_',
                r'valid PostgreSQL result', r'Npgsql\.',
                r'Driver.*SQL Server', r'OLE DB.*SQL Server',
                r'SQLServer JDBC Driver', r'SqlException',
            ]
            for pattern in sql_error_patterns:
                if re.search(pattern, response_body[:2000], re.IGNORECASE):
                    vuln.sql_error_disclosure = True
                    risk_factors.append(3.5)
                    vuln.vulnerable_services.append("SQL Error Disclosure in HTTP Response")
                    vuln.recommendations.append(
                        "Disable verbose database error messages in production."
                    )
                    break

        # Score & level
        vuln.risk_score = min(10.0, sum(risk_factors)) if risk_factors else 0.0

        if vuln.risk_score >= 7.0:
            vuln.risk_level = "CRITICAL"
        elif vuln.risk_score >= 5.0:
            vuln.risk_level = "HIGH"
        elif vuln.risk_score >= 3.0:
            vuln.risk_level = "MEDIUM"
        elif vuln.risk_score >= 1.0:
            vuln.risk_level = "LOW"
        else:
            vuln.risk_level = "MINIMAL"

        return vuln


# ─────────────────────────────────────────────
#  CLASSIFICATION ENGINE
# ─────────────────────────────────────────────
class ClassificationEngine:

    CDN_ASN = {
        'Cloudflare':  ['AS13335', 'AS209242'],
        'Akamai':      ['AS16625', 'AS20940', 'AS21342', 'AS21357', 'AS34164'],
        'Fastly':      ['AS54113'],
        'CloudFront':  ['AS16509', 'AS14618'],
        'StackPath':   ['AS33438'],
        'Incapsula':   ['AS19551'],
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
        'Squarespace': ['AS46652'],
        'Wix':         ['AS58182'],
        'Shopify':     ['AS55429'],
        'WordPress.com': ['AS2635'],
    }

    # IONOS (AS8560) and Newfold / Endurance (AS46606, AS26496) treated as SHARED
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

    # Origin discovery paths (professional bug-bounty language)
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

        # ── FORCE CDN check (highest priority) ──────────────────────────
        if is_force_cdn(asn, reverse_dns):
            provider = cls._detect_cdn_provider(asn, reverse_dns)
            paths    = cls.ORIGIN_DISCOVERY.get(provider, ['DNS history', 'Subdomain enumeration'])
            return HostingClassification(
                category              = "CDN_EDGE",
                provider              = provider,
                confidence            = 1.0,
                is_origin             = False,
                is_cdn                = True,
                origin_discovery_paths= paths,
                signals               = signals,
            )

        # ── ASN analysis ─────────────────────────────────────────────────
        asn_cat, asn_provider, asn_w = cls._analyze_asn(asn)
        signals.asn_signal = asn_cat
        signals.asn_weight = asn_w

        # ── Reverse DNS ──────────────────────────────────────────────────
        rdns_cat, rdns_w = cls._analyze_rdns(reverse_dns)
        signals.rdns_signal = rdns_cat
        signals.rdns_weight = rdns_w

        # ── Ports ────────────────────────────────────────────────────────
        port_cat, port_w = cls._analyze_ports(ports)
        signals.port_signal = port_cat
        signals.port_weight = port_w

        # ── SSL / HTTP ───────────────────────────────────────────────────
        if ssl_valid:
            signals.cert_signal = "valid"
            signals.cert_weight = 0.15
        if http_responsive:
            signals.http_signal = "responsive"
            signals.http_weight = 0.10

        # ── CDN header check ─────────────────────────────────────────────
        cdn_headers_present = False
        if headers:
            cdn_h = ['CF-RAY', 'X-Akamai-Request-ID', 'X-Cache', 'X-Fastly-Request-ID',
                     'X-Amz-Cf-Id']
            cdn_headers_present = any(h in headers for h in cdn_h)

        if asn_cat == "cdn" or rdns_cat == "cdn" or cdn_headers_present:
            provider = asn_provider or cls._detect_cdn_provider(asn, reverse_dns)
            conf     = min(1.0, asn_w + rdns_w + (0.2 if cdn_headers_present else 0))
            paths    = cls.ORIGIN_DISCOVERY.get(provider, ['DNS history', 'Subdomain enumeration'])
            if conf >= 0.60:
                return HostingClassification(
                    category               = "CDN_EDGE",
                    provider               = provider,
                    confidence             = conf,
                    is_origin              = False,
                    is_cdn                 = True,
                    origin_discovery_paths = paths,
                    signals                = signals,
                )

        # ── Cloud Frontend ───────────────────────────────────────────────
        if rdns_cat == "cloud_frontend":
            conf = rdns_w + signals.cert_weight + signals.http_weight
            if conf >= 0.75:
                return HostingClassification(
                    category="CLOUD_FRONTEND", provider=asn_provider,
                    confidence=conf, is_origin=True, is_cdn=False, signals=signals,
                )

        # ── Cloud Compute ────────────────────────────────────────────────
        if asn_cat == "cloud" or rdns_cat == "cloud_compute":
            pos  = asn_w + rdns_w + signals.cert_weight
            neg  = signals.port_weight * 0.3 if port_cat == "shared" else 0
            conf = pos - neg
            if conf >= 0.75:
                return HostingClassification(
                    category="CLOUD_COMPUTE", provider=asn_provider,
                    confidence=conf, is_origin=True, is_cdn=False, signals=signals,
                )

        # ── Managed Hosting ──────────────────────────────────────────────
        if asn_cat == "managed":
            conf = asn_w + signals.cert_weight + signals.http_weight
            if conf >= 0.75:
                return HostingClassification(
                    category="MANAGED_HOSTING", provider=asn_provider,
                    confidence=conf, is_origin=True, is_cdn=False, signals=signals,
                )

        # ── Shared Hosting ───────────────────────────────────────────────
        shared_signals = sum([
            asn_cat == "shared",
            rdns_cat == "shared",
            port_cat == "shared",
        ])
        if shared_signals >= 1:
            conf = min(1.0, asn_w + rdns_w + signals.port_weight)
            if conf >= 0.70 or asn_cat == "shared":
                return HostingClassification(
                    category="SHARED_HOSTING", provider=asn_provider,
                    confidence=max(conf, asn_w), is_origin=True, is_cdn=False, signals=signals,
                )

        # ── Dedicated / VPS ──────────────────────────────────────────────
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


# ─────────────────────────────────────────────
#  ASYNC CACHE
# ─────────────────────────────────────────────
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


# ─────────────────────────────────────────────
#  ASYNC SCANNER
# ─────────────────────────────────────────────
class AsyncScanner:
    def __init__(self):
        self.cache   = AsyncCache()
        self.session = None

    async def init_session(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_HTTP)
        )

    async def close_session(self):
        if self.session:
            await self.session.close()

    # ── Main entry per IP ───────────────────────────────────────────────
    async def scan_ip(self, ip: str,
                      keywords:     List[str]    = None,
                      country_code: Optional[str] = None) -> IPAnalysisResult:
        result = IPAnalysisResult(
            ip=ip,
            source_keywords=keywords or [],
            target_country=country_code,
        )

        try:
            # Phase 1: liveness
            result.liveness = await self._check_liveness(ip)
            if result.liveness.status == "dead":
                return result

            # Phase 2: port scan
            if result.liveness.tcp_responsive:
                result.tcp_ports_open = await self._scan_ports(ip)
                result.liveness.ports_scanned = [21, 22, 25, 80, 443, 3306, 5432,
                                                  1433, 27017, 6379, 8080, 8443,
                                                  2082, 2083]

            # Phase 3: concurrent data gathering
            tasks = [
                self._get_asn(ip),
                self._get_reverse_dns(ip),
                self._get_geolocation(ip),
            ]

            response_headers: Dict = {}
            response_body:    str  = ""

            if 443 in result.tcp_ports_open or 80 in result.tcp_ports_open:
                tasks.append(self._get_ssl_info(ip))
                tasks.append(self._get_web_info(ip))

            gathered = await asyncio.gather(*tasks, return_exceptions=True)

            asn_data = gathered[0] if not isinstance(gathered[0], Exception) else {}
            rdns     = gathered[1] if not isinstance(gathered[1], Exception) else None
            geo      = gathered[2] if not isinstance(gathered[2], Exception) else {}

            result.asn          = asn_data.get('asn')
            result.asn_org      = asn_data.get('org')
            result.domains.reverse_dns = rdns
            result.country      = geo.get('country')
            result.country_name = geo.get('country_name')
            result.city         = geo.get('city')
            result.region       = geo.get('region')
            result.isp          = geo.get('isp')
            result.organization = geo.get('org')

            if len(gathered) > 3 and not isinstance(gathered[3], Exception):
                ssl_info          = gathered[3]
                result.ssl.valid  = ssl_info.get('valid', False)
                result.ssl.issuer = ssl_info.get('issuer')
                result.ssl.subject= ssl_info.get('subject')
                result.ssl.expiry = ssl_info.get('expiry')
                result.ssl.version= ssl_info.get('version')
                result.ssl.cipher = ssl_info.get('cipher')

            if len(gathered) > 4 and not isinstance(gathered[4], Exception):
                web_info              = gathered[4]
                result.web.server     = web_info.get('server')
                result.web.title      = web_info.get('title')
                result.web.powered_by = web_info.get('powered_by')
                result.web.security_headers = web_info.get('security_headers', {})
                response_headers      = web_info.get('headers', {})
                response_body         = web_info.get('body', '')
                result.detected_technologies = self._detect_technologies(
                    response_body, response_headers
                )

            # Phase 4: classification (CDN force-check happens inside)
            result.hosting = ClassificationEngine.classify(
                result.asn or '',
                result.asn_org or '',
                result.domains.reverse_dns or '',
                result.tcp_ports_open,
                result.ssl.valid,
                result.liveness.http_responsive or result.liveness.https_responsive,
                response_headers,
            )

            # Phase 5: vulnerability assessment (ONLY for non-CDN origins)
            result.vulnerability = VulnerabilityAssessor.assess(
                result, response_headers, response_body
            )

            # Phase 6: domain attribution (origin only)
            if result.hosting.is_origin and not result.hosting.is_cdn:
                san = await self._get_san_domains(ip)
                result.domains.tls_san_domains = san
                all_d = set()
                if rdns:
                    all_d.add(rdns)
                all_d.update(san)
                result.domains.all_domains = sorted(all_d)

        except Exception:
            pass

        return result

    # ── TCP connect ─────────────────────────────────────────────────────
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

    # ── Liveness ────────────────────────────────────────────────────────
    async def _check_liveness(self, ip: str) -> LivenessStatus:
        status = LivenessStatus()

        tcp80  = await self._tcp_connect(ip, 80)
        tcp443 = await self._tcp_connect(ip, 443)
        status.tcp_responsive = tcp80 or tcp443

        if not status.tcp_responsive:
            status.status = "dead"
            return status

        checks = []
        if tcp80:  checks.append(self._http_check(ip, False))
        if tcp443: checks.append(self._http_check(ip, True))

        results = await asyncio.gather(*checks, return_exceptions=True)
        for res in results:
            if not isinstance(res, dict):
                continue
            if res.get('https'):
                status.https_responsive = res.get('success', False)
                status.https_status     = res.get('status')
                status.tls_handshake    = res.get('tls', False)
                status.response_time    = res.get('time')
            else:
                status.http_responsive = res.get('success', False)
                status.http_status     = res.get('status')
                if not status.response_time:
                    status.response_time = res.get('time')

        if status.http_responsive or status.https_responsive:
            status.status = "alive"
        elif status.tls_handshake:
            status.status = "tls_only"
        elif status.tcp_responsive:
            status.status = "filtered"
        else:
            status.status = "dead"

        return status

    # ── HTTP check ──────────────────────────────────────────────────────
    async def _http_check(self, ip: str, https: bool) -> Dict:
        proto  = "https" if https else "http"
        result = {'https': https, 'success': False, 'status': None, 'time': None, 'tls': False}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            conn = aiohttp.TCPConnector(ssl=ctx if https else None)
            start = time.time()
            async with aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_HTTP)
            ) as sess:
                async with sess.head(f"{proto}://{ip}", allow_redirects=True) as resp:
                    result['success'] = True
                    result['status']  = resp.status
                    result['time']    = time.time() - start
                    result['tls']     = https
        except Exception:
            pass
        return result

    # ── Port scan ────────────────────────────────────────────────────────
    async def _scan_ports(self, ip: str) -> List[int]:
        ports = [21, 22, 25, 80, 443, 3306, 5432, 1433, 27017, 6379, 8080, 8443, 2082, 2083]
        tasks = [self._tcp_connect(ip, p) for p in ports]
        res   = await asyncio.gather(*tasks)
        return [p for p, open_ in zip(ports, res) if open_]

    # ── ASN ──────────────────────────────────────────────────────────────
    async def _get_asn(self, ip: str) -> Dict:
        cached = self.cache.get_asn(ip)
        if cached:
            return cached
        try:
            url = f"http://ip-api.com/json/{ip}?fields=as"
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_DNS)) as r:
                if r.status == 200:
                    data     = await r.json()
                    asn_full = data.get('as', '')
                    if asn_full:
                        parts = asn_full.split(' ', 1)
                        d = {'asn': parts[0], 'org': parts[1] if len(parts) > 1 else ''}
                        self.cache.set_asn(ip, d)
                        return d
        except Exception:
            pass
        return {}

    # ── Reverse DNS ──────────────────────────────────────────────────────
    async def _get_reverse_dns(self, ip: str) -> Optional[str]:
        cached = self.cache.get_rdns(ip)
        if cached:
            return cached
        try:
            loop  = asyncio.get_event_loop()
            rdns  = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=TIMEOUT_DNS
            )
            name = rdns[0]
            self.cache.set_rdns(ip, name)
            return name
        except Exception:
            return None

    # ── Geolocation ──────────────────────────────────────────────────────
    async def _get_geolocation(self, ip: str) -> Dict:
        try:
            url = (f"http://ip-api.com/json/{ip}"
                   f"?fields=status,country,countryCode,region,regionName,city,isp,org")
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_DNS)) as r:
                if r.status == 200:
                    d = await r.json()
                    if d.get('status') == 'success':
                        return {
                            'country':      d.get('countryCode'),
                            'country_name': d.get('country'),
                            'city':         d.get('city'),
                            'region':       d.get('regionName'),
                            'isp':          d.get('isp'),
                            'org':          d.get('org'),
                        }
        except Exception:
            pass
        return {}

    # ── SSL info ─────────────────────────────────────────────────────────
    async def _get_ssl_info(self, ip: str) -> Dict:
        info: Dict = {'valid': False}
        try:
            loop = asyncio.get_event_loop()

            def _fetch():
                ctx = ssl.create_default_context()
                with socket.create_connection((ip, 443), timeout=TIMEOUT_TCP) as s:
                    with ctx.wrap_socket(s, server_hostname=ip) as ss:
                        return ss.getpeercert(), ss.version(), ss.cipher()

            cert, version, cipher = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch), timeout=TIMEOUT_TCP
            )
            info['valid']  = True
            info['version']= version
            info['cipher'] = cipher[0] if cipher else None

            if 'issuer' in cert:
                issuer_d = dict(x[0] for x in cert['issuer'])
                info['issuer'] = issuer_d.get('organizationName', 'Unknown')

            if 'subject' in cert:
                subj_d = dict(x[0] for x in cert['subject'])
                info['subject'] = subj_d.get('commonName', 'Unknown')

            if 'notAfter' in cert:
                info['expiry'] = cert['notAfter']
        except Exception:
            pass
        return info

    # ── Web info ─────────────────────────────────────────────────────────
    async def _get_web_info(self, ip: str) -> Dict:
        info: Dict = {}
        try:
            use_https = await self._tcp_connect(ip, 443)
            proto     = "https" if use_https else "http"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            conn = aiohttp.TCPConnector(ssl=ctx)

            async with aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_HTTP)
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

                    body       = await resp.text(errors='replace')
                    info['body'] = body[:4096]

                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(body[:2048], 'html.parser')
                        if soup.title and soup.title.string:
                            info['title'] = soup.title.string.strip()[:100]
                    except Exception:
                        pass
        except Exception:
            pass
        return info

    # ── SAN domains ──────────────────────────────────────────────────────
    async def _get_san_domains(self, ip: str) -> List[str]:
        domains: List[str] = []
        try:
            loop = asyncio.get_event_loop()

            def _fetch():
                ctx = ssl.create_default_context()
                with socket.create_connection((ip, 443), timeout=TIMEOUT_TCP) as s:
                    with ctx.wrap_socket(s, server_hostname=ip) as ss:
                        return ss.getpeercert()

            cert = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch), timeout=TIMEOUT_TCP
            )
            if 'subjectAltName' in cert:
                for tag, val in cert['subjectAltName']:
                    if tag == 'DNS':
                        d = val.replace('*.', '')
                        if d not in domains:
                            domains.append(d)
            if 'subject' in cert:
                for rdn in cert['subject']:
                    for name, val in rdn:
                        if name == 'commonName':
                            d = val.replace('*.', '')
                            if d not in domains:
                                domains.append(d)
        except Exception:
            pass
        return domains[:15]

    # ── Technology detection ─────────────────────────────────────────────
    def _detect_technologies(self, html: str, headers: Dict) -> List[str]:
        tech = []
        h    = html.lower()
        if 'wp-content' in h or 'wp-includes' in h: tech.append('WordPress')
        if 'joomla'  in h:                          tech.append('Joomla')
        if 'drupal'  in h:                          tech.append('Drupal')
        if 'data-reactroot' in h or 'react' in h:  tech.append('React')
        if 'ng-app'  in h or 'angular' in h:       tech.append('Angular')
        if 'vue'     in h:                          tech.append('Vue.js')
        if 'jquery'  in h:                          tech.append('jQuery')
        if 'bootstrap' in h:                        tech.append('Bootstrap')
        pb = headers.get('X-Powered-By', '').lower()
        sv = headers.get('Server',       '').lower()
        if 'php'     in pb or 'php'     in sv: tech.append('PHP')
        if 'asp.net' in pb or 'asp.net' in sv: tech.append('ASP.NET')
        if 'express' in pb:                    tech.append('Express')
        return tech


# ─────────────────────────────────────────────
#  RATE LIMITER
# ─────────────────────────────────────────────
class RateLimiter:
    def __init__(self, rps: float = 8.0):
        self._interval    = 1.0 / rps
        self._last        = 0.0
        self._lock        = threading.Lock()

    def wait(self):
        with self._lock:
            now     = time.time()
            elapsed = now - self._last
            if elapsed < self._interval:
                jitter = random.uniform(0, self._interval * 0.25)
                time.sleep(self._interval - elapsed + jitter)
            self._last = time.time()


# ─────────────────────────────────────────────
#  MULTI-SOURCE IP GENERATOR
# ─────────────────────────────────────────────
class MultiSourceIPGenerator:

    def __init__(self, rate_limiter: RateLimiter, config: DataSourceConfig):
        self._rl     = rate_limiter
        self._cfg    = config
        self._sess   = requests.Session()
        self._sess.headers.update({'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )})
        self.ip_counter  = 0
        self._cnt_lock   = threading.Lock()
        self._set_lock   = threading.Lock()

    # ── Public entry ────────────────────────────────────────────────────
    def generate(self, keywords: List[str], target: int,
                 country: Optional[str] = None) -> Tuple[Set[str], Dict[str, int]]:
        unique: Set[str]      = set()
        stats:  Dict[str, int] = defaultdict(int)

        per_kw = max(10, target // len(keywords))

        def _process(kw: str):
            found: Set[str] = set()

            def _add(ips: Set[str], source: str):
                with self._set_lock:
                    new = ips - unique
                if new:
                    with self._cnt_lock:
                        self.ip_counter += len(new)
                    with self._set_lock:
                        unique.update(new)
                    stats[source] = stats.get(source, 0) + len(new)
                    print(f"  {Colors.GREEN}{source}{Colors.ENDC}: "
                          f"+{len(new)} (Total: {self.ip_counter})")

            # DNS
            try:
                _add(self._dns(kw, per_kw, country), 'DNS')
            except Exception:
                pass

            # URLScan (free)
            try:
                self._rl.wait()
                _add(self._urlscan(kw, per_kw, country), 'URLScan')
            except Exception:
                pass

            # ThreatCrowd (free)
            try:
                self._rl.wait()
                _add(self._threatcrowd(kw, per_kw), 'ThreatCrowd')
            except Exception:
                pass

            # Shodan
            if self._cfg.has_shodan():
                try:
                    self._rl.wait()
                    _add(self._shodan(kw, per_kw, country), 'Shodan')
                except Exception:
                    pass

            # Censys
            if self._cfg.has_censys():
                try:
                    self._rl.wait()
                    _add(self._censys(kw, per_kw, country), 'Censys')
                except Exception:
                    pass

            # FOFA
            if self._cfg.has_fofa():
                try:
                    self._rl.wait()
                    _add(self._fofa(kw, per_kw, country), 'FOFA')
                except Exception:
                    pass

            # ZoomEye
            if self._cfg.has_zoomeye():
                try:
                    self._rl.wait()
                    _add(self._zoomeye(kw, per_kw, country), 'ZoomEye')
                except Exception:
                    pass

            # SecurityTrails
            if self._cfg.has_securitytrails():
                try:
                    self._rl.wait()
                    _add(self._securitytrails(kw, per_kw), 'SecurityTrails')
                except Exception:
                    pass

            return found

        workers = min(len(keywords), 5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_process, kw) for kw in keywords]
            for f in concurrent.futures.as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass

        return unique, dict(stats)

    # ── Helpers ──────────────────────────────────────────────────────────
    def _ok(self, ip: str) -> bool:
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            nums = list(map(int, parts))
            if not all(0 <= n <= 255 for n in nums):
                return False
            # Private ranges
            if nums[0] == 10: return False
            if nums[0] == 172 and 16 <= nums[1] <= 31: return False
            if nums[0] == 192 and nums[1] == 168: return False
            if nums[0] in (0, 127): return False
            return True
        except Exception:
            return False

    # ── DNS ──────────────────────────────────────────────────────────────
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

        for pat in patterns[:35]:
            if len(ips) >= limit:
                break
            try:
                ip = socket.gethostbyname(pat)
                if self._ok(ip):
                    ips.add(ip)
            except Exception:
                pass
            time.sleep(0.02)
        return ips

    # ── URLScan ──────────────────────────────────────────────────────────
    def _urlscan(self, kw: str, limit: int, country: Optional[str]) -> Set[str]:
        ips: Set[str] = set()
        try:
            q = f'domain:{kw}' + (f' country:{country.upper()}' if country else '')
            r = self._sess.get(
                'https://urlscan.io/api/v1/search/',
                params={'q': q, 'size': min(100, limit * 2)},
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

    # ── ThreatCrowd ──────────────────────────────────────────────────────
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

    # ── Shodan ───────────────────────────────────────────────────────────
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

    # ── Censys ───────────────────────────────────────────────────────────
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

    # ── FOFA ─────────────────────────────────────────────────────────────
    def _fofa(self, kw: str, limit: int, country: Optional[str]) -> Set[str]:
        ips: Set[str] = set()
        try:
            email = self._cfg.api_keys.get('fofa_email', '')
            key   = self._cfg.api_keys.get('fofa_key',   '')
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

    # ── ZoomEye ──────────────────────────────────────────────────────────
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

    # ── SecurityTrails ───────────────────────────────────────────────────
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


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
class SpiderWebCLI:

    VERSION = "2.2"

    BANNER = (
        f"{Colors.BOLD}{Colors.GREEN}"
        "╔═════════════════════════════════════════════════════════════════╗\n"
        "║                                                                 ║\n"
        "║         ╔═╗┌─┐┬┌┬┐┌─┐┬─┐╦ ╦┌─┐┌┐     ╔═╗╦═╗╔═╗                  ║\n"
        "║         ╚═╗├─┘│ ││├┤ ├┬┘║║║├┤ ├┴┐    ╠═╝╠╦╝║ ║                  ║\n"
        "║         ╚═╝┴  ┴─┴┘└─┘┴└─╚╩╝└─┘└─┘    ╩  ╩╚═╚═╝                  ║\n"
        "║                                                                 ║\n"
        f"║{Colors.ENDC}       {Colors.RED}Professional IP Analysis v2.2 - Enterprise Edition{Colors.ENDC}"
        f"        {Colors.GREEN}║\n"
        f"║{Colors.ENDC}                        {Colors.WHITE}by g33l0{Colors.ENDC}"
        f"                                 {Colors.GREEN}║\n"
        "║                                                                 ║\n"
        "║   ┌─────────────────────────────────────────────────────────┐   ║\n"
        "║   │  Multi-Source Intelligence | CDN-Aware Classification   │   ║\n"
        "║   │  Shodan | Censys | FOFA | ZoomEye | SecurityTrails      │   ║\n"
        "║   └─────────────────────────────────────────────────────────┘   ║\n"
        f"╚═════════════════════════════════════════════════════════════════╝{Colors.ENDC}"
    )

    MAX_IPS = 5000

    def __init__(self):
        self.results:  List[IPAnalysisResult] = []
        self._rl       = RateLimiter(8.0)
        self.config    = DataSourceConfig()
        self.generator = MultiSourceIPGenerator(self._rl, self.config)
        signal.signal(signal.SIGINT, self._on_ctrl_c)

    def _on_ctrl_c(self, sig, frame):
        print(f"\n{Colors.YELLOW}Cancelled.{Colors.ENDC}")
        sys.exit(0)

    # ── Banner ────────────────────────────────────────────────────────────
    def print_banner(self):
        print(self.BANNER)

    # ── Input helper ─────────────────────────────────────────────────────
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

    # ── Menus ─────────────────────────────────────────────────────────────
    def prompt_input_method(self) -> str:
        while True:
            try:
                print(f"\n{Colors.BOLD}=== SELECT INPUT METHOD ==={Colors.ENDC}\n")
                print(f"{Colors.CYAN}1.{Colors.ENDC} Keyword-based IP generation (Multi-source)")
                print(f"{Colors.CYAN}2.{Colors.ENDC} Scan IPs from file  (ips.txt)")
                print(f"{Colors.CYAN}3.{Colors.ENDC} Configure API Keys")
                choice = self.get_input("Choice (1-3)", False)
                if choice == "1": return "keyword"
                if choice == "2": return "file"
                if choice == "3":
                    self._configure_api_keys()
                    continue
                print(f"{Colors.RED}Invalid choice.{Colors.ENDC}")
            except ExitException:
                sys.exit(0)

    def _configure_api_keys(self):
        print(f"\n{Colors.BOLD}=== API CONFIGURATION ==={Colors.ENDC}\n")
        print(f"{Colors.YELLOW}Press Enter to skip any source.{Colors.ENDC}\n")
        try:
            fields = [
                ('Shodan API Key',        'shodan_api_key'),
                ('Censys API ID',         'censys_api_id'),
                ('Censys API Secret',     'censys_api_secret'),
                ('FOFA Email',            'fofa_email'),
                ('FOFA API Key',          'fofa_key'),
                ('ZoomEye API Key',       'zoomeye_api_key'),
                ('SecurityTrails API Key','securitytrails_api_key'),
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
        """0 = back, 00 = worldwide, XX = country code."""
        while True:
            try:
                print(f"\n{Colors.BOLD}=== TARGET LOCATION ==={Colors.ENDC}\n")
                print(f"{Colors.CYAN}Enter 2-letter country code, 00 for worldwide, or 0 to go back.{Colors.ENDC}")
                print(f"\n{Colors.BOLD}Examples:{Colors.ENDC}")
                print("  US  UK  CA  AU  DE  FR  JP  CN  IN  BR  RU  ZA")
                country = self.get_input("Country code (or 00 for worldwide)", False).upper()
                if country == "0":
                    raise NavigationException()
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
                return keywords, count, country
            except NavigationException:
                continue

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
            unique = list(dict.fromkeys(ips))
            removed = len(ips) - len(unique)
            if removed:
                print(f"{Colors.YELLOW}Removed {removed} duplicate IPs.{Colors.ENDC}")
            if len(unique) > self.MAX_IPS:
                print(f"{Colors.YELLOW}Trimmed to {self.MAX_IPS} IPs.{Colors.ENDC}")
                unique = unique[:self.MAX_IPS]
            return unique
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

    # ── Batch scan ────────────────────────────────────────────────────────
    async def _async_scan(self, ips: List[str],
                          keywords: List[str],
                          country:  Optional[str]):
        print(f"\n{Colors.BOLD}=== SCANNING {len(ips)} IPs ==={Colors.ENDC}\n")
        scanner = AsyncScanner()
        await scanner.init_session()
        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def _run(ip):
            async with sem:
                return await scanner.scan_ip(ip, keywords, country)

        tasks     = [_run(ip) for ip in ips]
        completed = 0
        total     = len(ips)

        try:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                self.results.append(result)
                completed += 1
                pct   = completed / total * 100
                filled = int(30 * completed / total)
                bar   = '█' * filled + '░' * (30 - filled)
                print(f"\r{Colors.CYAN}[{bar}] {pct:.1f}%{Colors.ENDC} | {completed}/{total}",
                      end='', flush=True)
        finally:
            await scanner.close_session()

        print(f"\n\n{Colors.BOLD}=== SCAN COMPLETE ==={Colors.ENDC}\n")

    def batch_scan(self, ips: List[str],
                   keywords: List[str] = None,
                   country:  Optional[str] = None):
        try:
            asyncio.run(self._async_scan(ips, keywords or [], country))
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Scan interrupted.{Colors.ENDC}")

    # ── Display ───────────────────────────────────────────────────────────
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

        print(f"\n{Colors.BOLD}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'SECURITY ASSESSMENT RESULTS':^80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}\n")

        print(f"  {Colors.GREEN}Total Alive     : {alive}{Colors.ENDC}")
        print(f"  {Colors.GREEN}  Origin Servers : {origin_ct}{Colors.ENDC}")
        print(f"  {Colors.YELLOW}  CDN / Proxies  : {cdn_ct}{Colors.ENDC}")
        print(f"  {Colors.RED}Dead / Filtered : {len(dead)}{Colors.ENDC}")
        print(f"  {Colors.MAGENTA}Vulnerable Targets: {vuln_ct}{Colors.ENDC}")
        print(f"  {Colors.BLUE}Total Scanned   : {len(self.results)}{Colors.ENDC}\n")

        # Vulnerability section (origin only)
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
                for idx, r in enumerate(targets[:5], 1):
                    print(f"{clr}[{idx}] {r.ip}{Colors.ENDC} | Risk Score: {r.vulnerability.risk_score:.1f}/10")
                    if r.country_name:
                        print(f"    Location  : {r.city or 'Unknown'}, {r.country_name}")
                    if r.vulnerability.vulnerable_services:
                        print(f"    Exposed Services:")
                        for svc in r.vulnerability.vulnerable_services[:4]:
                            print(f"      • {svc}")
                    if r.vulnerability.recommendations:
                        print(f"    Recommendations:")
                        for rec in r.vulnerability.recommendations[:3]:
                            print(f"      • {rec}")
                    print()
                if len(targets) > 5:
                    print(f"{Colors.YELLOW}  ... and {len(targets)-5} more{Colors.ENDC}\n")

        # Hosting categories
        cat_order = ['CDN_EDGE', 'CLOUD_FRONTEND', 'CLOUD_COMPUTE',
                     'MANAGED_HOSTING', 'SHARED_HOSTING', 'DEDICATED_VPS', 'UNKNOWN']
        print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}HOSTING CLASSIFICATION{Colors.ENDC}")
        print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}\n")

        for cat in cat_order:
            items = by_cat.get(cat, [])
            if not items:
                continue

            cat_label = cat.replace('_', ' ')
            print(f"{Colors.BOLD}{cat_label}: {len(items)}{Colors.ENDC}\n")

            for idx, r in enumerate(items[:5], 1):
                risk_icon = ('!' if r.vulnerability.risk_level == 'CRITICAL' else
                             '^' if r.vulnerability.risk_level == 'HIGH' else '-')
                print(f"  {Colors.GREEN}[{idx}] {r.ip}{Colors.ENDC} [{risk_icon}] | "
                      f"Conf: {r.hosting.confidence:.2f}")

                if r.hosting.provider:
                    print(f"      Provider       : {r.hosting.provider}")
                if r.country_name:
                    print(f"      Location       : {r.city or 'N/A'}, {r.country_name} ({r.country})")
                if r.isp:
                    print(f"      ISP            : {r.isp}")
                if r.asn:
                    print(f"      ASN            : {r.asn}")
                if r.tcp_ports_open:
                    print(f"      Open Ports     : {', '.join(map(str, r.tcp_ports_open[:10]))}")
                if r.liveness.http_status or r.liveness.https_status:
                    print(f"      HTTP / HTTPS   : {r.liveness.http_status or 'N/A'} / {r.liveness.https_status or 'N/A'}")
                if r.liveness.response_time:
                    print(f"      Response Time  : {r.liveness.response_time*1000:.1f} ms")
                if r.domains.all_domains:
                    ds = ', '.join(r.domains.all_domains[:4])
                    more = f" +{len(r.domains.all_domains)-4}" if len(r.domains.all_domains) > 4 else ""
                    print(f"      Domains        : {ds}{more}")
                elif r.domains.reverse_dns:
                    print(f"      Reverse DNS    : {r.domains.reverse_dns}")
                if r.ssl.valid:
                    print(f"      SSL            : {r.ssl.version} | Issuer: {r.ssl.issuer}")
                if r.web.server:
                    print(f"      Server         : {r.web.server}")
                if r.web.title:
                    print(f"      Title          : {r.web.title}")
                if r.detected_technologies:
                    print(f"      Tech Stack     : {', '.join(r.detected_technologies[:5])}")
                if r.web.security_headers:
                    print(f"      Sec Headers    : {len(r.web.security_headers)} present")

                # CDN origin discovery paths (professional language)
                if r.hosting.is_cdn and r.hosting.origin_discovery_paths:
                    print(f"      {Colors.CYAN}Origin Discovery Paths:{Colors.ENDC}")
                    for path in r.hosting.origin_discovery_paths[:3]:
                        print(f"        > {path}")

                print()

            if len(items) > 5:
                print(f"  {Colors.YELLOW}... and {len(items)-5} more{Colors.ENDC}\n")

    # ── Export ────────────────────────────────────────────────────────────
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

        # ── JSON ────────────────────────────────────────────────────────
        json_path = out_dir / f"scan_{ts}_{scan_id}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'tool':            'SpiderWeb Pro',
                    'version':         self.VERSION,
                    'author':          'g33l0',
                    'scan_id':         scan_id,
                    'timestamp':       datetime.now().isoformat(),
                    'total_scanned':   len(self.results),
                    'total_alive':     sum(1 for r in self.results if r.liveness.status != 'dead'),
                    'total_vulnerable':sum(1 for r in self.results
                                          if r.vulnerability.risk_level in ('CRITICAL','HIGH','MEDIUM')),
                },
                'results': [asdict(r) for r in self.results],
            }, f, indent=2, ensure_ascii=False)

        # ── CSV ─────────────────────────────────────────────────────────
        csv_path = out_dir / f"scan_{ts}_{scan_id}.csv"
        fieldnames = [
            'ip', 'status', 'category', 'confidence', 'is_origin', 'is_cdn', 'provider',
            'country', 'city', 'region', 'isp', 'asn', 'organization',
            'open_ports', 'http_status', 'https_status', 'response_time_ms',
            'reverse_dns', 'domains', 'ssl_valid', 'ssl_version', 'ssl_issuer', 'ssl_expiry',
            'web_server', 'web_title', 'powered_by', 'technologies',
            'risk_level', 'risk_score', 'vulnerable_services', 'recommendations',
            'origin_discovery_paths', 'scan_timestamp',
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
                    'ssl_valid':            r.ssl.valid,
                    'ssl_version':          r.ssl.version or '',
                    'ssl_issuer':           r.ssl.issuer or '',
                    'ssl_expiry':           r.ssl.expiry or '',
                    'web_server':           r.web.server or '',
                    'web_title':            r.web.title or '',
                    'powered_by':           r.web.powered_by or '',
                    'technologies':         ','.join(r.detected_technologies),
                    'risk_level':           r.vulnerability.risk_level,
                    'risk_score':           r.vulnerability.risk_score,
                    'vulnerable_services':  '; '.join(r.vulnerability.vulnerable_services),
                    'recommendations':      '; '.join(r.vulnerability.recommendations),
                    'origin_discovery_paths': '; '.join(r.hosting.origin_discovery_paths),
                    'scan_timestamp':       r.scan_timestamp,
                })

        # ── Vulnerability TXT (origin only) ─────────────────────────────
        high_risk = [r for r in self.results
                     if r.vulnerability.risk_level in ('CRITICAL', 'HIGH')
                     and not r.hosting.is_cdn]

        vuln_path = None
        if high_risk:
            vuln_path = out_dir / f"vulnerable_{ts}_{scan_id}.txt"
            with open(vuln_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("SPIDERWEB PRO - ORIGIN SERVER VULNERABILITY REPORT\n")
                f.write(f"Scan ID   : {scan_id}\n")
                f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("Note      : Only confirmed origin servers included.\n")
                f.write("           CDN edge nodes are excluded from this report.\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"HIGH-RISK ORIGIN SERVERS: {len(high_risk)}\n\n")
                for r in high_risk:
                    f.write(f"\nIP         : {r.ip}\n")
                    f.write(f"Risk Level : {r.vulnerability.risk_level}\n")
                    f.write(f"Risk Score : {r.vulnerability.risk_score:.1f}/10\n")
                    f.write(f"Category   : {r.hosting.category}\n")
                    f.write(f"Provider   : {r.hosting.provider or 'Unknown'}\n")
                    f.write(f"Location   : {r.city}, {r.country_name}\n")
                    if r.vulnerability.vulnerable_services:
                        f.write("Vulnerable Services:\n")
                        for svc in r.vulnerability.vulnerable_services:
                            f.write(f"  - {svc}\n")
                    if r.vulnerability.recommendations:
                        f.write("Recommendations:\n")
                        for rec in r.vulnerability.recommendations:
                            f.write(f"  - {rec}\n")
                    f.write("\n" + "-" * 80 + "\n")

        # Print summary
        print(f"\n{Colors.BOLD}=== EXPORT COMPLETE ==={Colors.ENDC}\n")
        print(f"  {Colors.GREEN}Directory : {out_dir}{Colors.ENDC}")
        print(f"  {Colors.GREEN}JSON      : {json_path.name}{Colors.ENDC}")
        print(f"  {Colors.GREEN}CSV       : {csv_path.name}{Colors.ENDC}")
        if vuln_path:
            print(f"  {Colors.RED}Vuln TXT  : {vuln_path.name}{Colors.ENDC}")
        print(f"\n  {Colors.CYAN}Scan ID   : {scan_id}{Colors.ENDC}\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    # Ensure dependencies
    try:
        from bs4 import BeautifulSoup  # noqa: F401
        import aiohttp                 # noqa: F401
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

            # ── Keyword mode ─────────────────────────────────────────────
            if method == "keyword":
                keywords, count, country = cli.get_keyword_input()
                cli.generator.ip_counter = 0

                # Animated spinner during generation
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
                    print(f"{Colors.YELLOW}Generated {len(ips)}/{count} IPs. Proceeding with available.{Colors.ENDC}\n")
                    proceed = cli.get_input(f"Continue with {len(ips)} IPs? (y/n)", True).lower()
                    if proceed != 'y':
                        continue

            # ── File mode ────────────────────────────────────────────────
            else:
                ips = cli.read_ips_from_file()
                print(f"\n{Colors.GREEN}Loaded {len(ips)} IPs from ips.txt{Colors.ENDC}\n")

            # ── Scan confirmation ────────────────────────────────────────
            confirm = cli.get_input(f"Start scan of {len(ips)} IPs? (y/n)", True).lower()
            if confirm != 'y':
                continue

            cli.results = []  # Fresh results per scan session
            cli.batch_scan(ips, keywords, country)
            cli.display_results()

            # ── Export ───────────────────────────────────────────────────
            if cli.results:
                if cli.get_input("Export results? (y/n)", True).lower() == 'y':
                    cli.export_results()

            print(f"\n{Colors.GREEN}Assessment complete.{Colors.ENDC}\n")

            if cli.get_input("Run another scan? (y/n)", False).lower() != 'y':
                print(f"\n{Colors.WHITE}Thank you for using SpiderWeb Pro. Stay secure!{Colors.ENDC}\n")
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
                if cli.get_input("Retry? (y/n)", False).lower() != 'y':
                    break
            except Exception:
                break

    print(f"{Colors.CYAN}SpiderWeb Pro v{SpiderWebCLI.VERSION} closed.{Colors.ENDC}\n")


if __name__ == "__main__":
    main()

