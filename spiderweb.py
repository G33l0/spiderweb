#!/usr/bin/env python3
"""
SpiderWeb - Advanced CLI IP Analysis Tool (Professional Edition)
Author: g33l0
Version: 7.0
Description: Professional IP reconnaissance with advanced liveness detection
"""

import requests
import re
import time
import json
import csv
import socket
import ssl
import concurrent.futures
from typing import Set, List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
from urllib.parse import quote, urlparse
from collections import defaultdict
import sys
import os
from pathlib import Path
import random
import threading
import signal
import asyncio
import aiohttp
from queue import Queue

# ANSI Color codes
class Colors:
    GREEN = '\033[92m'      # Hacker green
    RED = '\033[91m'        # Red
    WHITE = '\033[97m'      # White
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class NavigationException(Exception):
    """Exception for navigation control"""
    pass


class ExitException(Exception):
    """Exception for exit control"""
    pass


@dataclass
class DomainAttribution:
    """Domain attribution data"""
    reverse_dns: Optional[str] = None
    tls_san_domains: List[str] = field(default_factory=list)
    ct_log_domains: List[str] = field(default_factory=list)
    passive_dns_domains: List[str] = field(default_factory=list)
    all_domains: List[str] = field(default_factory=list)


@dataclass
class LivenessStatus:
    """Advanced liveness detection result"""
    status: str = "dead"  # alive, tls_only, filtered, dead
    tcp_responsive: bool = False
    http_responsive: bool = False
    https_responsive: bool = False
    tls_handshake: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    response_time: Optional[float] = None


@dataclass
class HostingClassification:
    """Hosting type classification"""
    hosting_type: str = "unknown"  # cdn, shared, vps, dedicated, load_balancer
    provider: Optional[str] = None
    confidence: float = 0.0
    is_origin: bool = False


@dataclass
class IPAnalysisResult:
    """Complete IP analysis result"""
    ip: str
    
    # Liveness
    liveness: LivenessStatus = field(default_factory=LivenessStatus)
    
    # Domain Attribution
    domains: DomainAttribution = field(default_factory=DomainAttribution)
    
    # Hosting Classification
    hosting: HostingClassification = field(default_factory=HostingClassification)
    
    # Network Info
    tcp_ports_open: List[int] = field(default_factory=list)
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    
    # Geolocation
    country: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    
    # SSL/TLS
    ssl_valid: bool = False
    ssl_issuer: Optional[str] = None
    ssl_subject: Optional[str] = None
    
    # Web
    web_server: Optional[str] = None
    web_title: Optional[str] = None
    
    # CDN Detection
    is_cdn: bool = False
    cdn_provider: Optional[str] = None
    bypass_methods: List[str] = field(default_factory=list)
    
    # Metadata
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    source_keywords: List[str] = field(default_factory=list)
    target_country: Optional[str] = None
    confidence_score: float = 0.0


class ASNCache:
    """Thread-safe ASN cache"""
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()
    
    def get(self, ip: str) -> Optional[Dict]:
        with self.lock:
            return self.cache.get(ip)
    
    def set(self, ip: str, data: Dict):
        with self.lock:
            self.cache[ip] = data


class CDNDetector:
    """Enhanced CDN/hosting detection"""
    
    CDN_ASN = {
        'Cloudflare': ['AS13335', 'AS209242'],
        'Akamai': ['AS16625', 'AS20940', 'AS21342', 'AS21357', 'AS34164'],
        'Fastly': ['AS54113'],
        'CloudFront': ['AS16509', 'AS14618'],
        'StackPath': ['AS33438'],
        'Incapsula': ['AS19551'],
        'Sucuri': ['AS30148'],
        'KeyCDN': ['AS30633'],
    }
    
    SHARED_HOSTING = {
        'GoDaddy': ['AS26496'],
        'HostGator': ['AS46606'],
        'Bluehost': ['AS46606'],
        'SiteGround': ['AS54290'],
        'Namecheap': ['AS22612'],
    }
    
    CLOUD_PROVIDERS = {
        'AWS': ['AS16509', 'AS14618'],
        'Google Cloud': ['AS15169'],
        'Azure': ['AS8075'],
        'DigitalOcean': ['AS14061'],
        'Linode': ['AS63949'],
        'Vultr': ['AS20473'],
        'OVH': ['AS16276'],
    }
    
    @staticmethod
    def classify_hosting(asn: str, asn_org: str, headers: Dict = None) -> HostingClassification:
        """Classify hosting type with confidence score"""
        classification = HostingClassification()
        
        # Check CDN
        for provider, asn_list in CDNDetector.CDN_ASN.items():
            if any(asn_num in asn for asn_num in asn_list):
                classification.hosting_type = "cdn"
                classification.provider = provider
                classification.confidence = 0.95
                classification.is_origin = False
                return classification
        
        # Check headers for CDN
        if headers:
            if 'CF-RAY' in headers:
                classification.hosting_type = "cdn"
                classification.provider = "Cloudflare"
                classification.confidence = 1.0
                classification.is_origin = False
                return classification
            
            if 'X-Akamai-Request-ID' in headers:
                classification.hosting_type = "cdn"
                classification.provider = "Akamai"
                classification.confidence = 1.0
                classification.is_origin = False
                return classification
        
        # Check shared hosting
        for provider, asn_list in CDNDetector.SHARED_HOSTING.items():
            if any(asn_num in asn for asn_num in asn_list):
                classification.hosting_type = "shared"
                classification.provider = provider
                classification.confidence = 0.85
                classification.is_origin = True
                return classification
        
        # Check cloud providers
        for provider, asn_list in CDNDetector.CLOUD_PROVIDERS.items():
            if any(asn_num in asn for asn_num in asn_list):
                classification.hosting_type = "cloud"
                classification.provider = provider
                classification.confidence = 0.75
                classification.is_origin = True
                return classification
        
        # Default to VPS/Dedicated
        classification.hosting_type = "vps_dedicated"
        classification.confidence = 0.6
        classification.is_origin = True
        
        return classification


class AdvancedScanner:
    """Advanced IP scanner with async capabilities"""
    
    def __init__(self, rate_limiter):
        self.rate_limiter = rate_limiter
        self.asn_cache = ASNCache()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def advanced_liveness_check(self, ip: str) -> LivenessStatus:
        """Advanced multi-layer liveness detection"""
        status = LivenessStatus()
        
        # Layer 1: TCP handshake on common ports
        for port in [80, 443]:
            if self._tcp_handshake(ip, port):
                status.tcp_responsive = True
                break
        
        if not status.tcp_responsive:
            status.status = "dead"
            return status
        
        # Layer 2: HTTP/HTTPS check
        http_ok, http_code, http_time = self._http_check(ip)
        https_ok, https_code, https_time, tls_ok = self._https_check_with_tls(ip)
        
        status.http_responsive = http_ok
        status.https_responsive = https_ok
        status.tls_handshake = tls_ok
        status.http_status = http_code
        status.https_status = https_code
        status.response_time = https_time or http_time
        
        # Classification
        if http_ok or https_ok:
            status.status = "alive"
        elif tls_ok:
            status.status = "tls_only"
        elif status.tcp_responsive:
            status.status = "filtered"
        else:
            status.status = "dead"
        
        return status
    
    def _tcp_handshake(self, ip: str, port: int, timeout: int = 3) -> bool:
        """Perform TCP handshake"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _http_check(self, ip: str) -> Tuple[bool, Optional[int], Optional[float]]:
        """HTTP check"""
        try:
            start = time.time()
            response = self.session.head(f"http://{ip}", timeout=5, allow_redirects=True)
            elapsed = time.time() - start
            return True, response.status_code, elapsed
        except:
            return False, None, None
    
    def _https_check_with_tls(self, ip: str) -> Tuple[bool, Optional[int], Optional[float], bool]:
        """HTTPS check with TLS handshake and SNI"""
        tls_ok = False
        
        # Try TLS handshake with SNI
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    tls_ok = True
        except:
            pass
        
        # Try HTTPS request
        try:
            start = time.time()
            response = self.session.head(f"https://{ip}", timeout=5, verify=False, allow_redirects=True)
            elapsed = time.time() - start
            return True, response.status_code, elapsed, tls_ok
        except:
            return False, None, None, tls_ok
    
    def get_domain_attribution(self, ip: str) -> DomainAttribution:
        """Get all associated domains"""
        domains = DomainAttribution()
        all_found = set()
        
        # Reverse DNS
        try:
            reverse = socket.gethostbyaddr(ip)[0]
            domains.reverse_dns = reverse
            all_found.add(reverse)
        except:
            pass
        
        # TLS certificate SAN
        try:
            san_domains = self._get_tls_san_domains(ip)
            domains.tls_san_domains = san_domains
            all_found.update(san_domains)
        except:
            pass
        
        # Certificate Transparency
        try:
            ct_domains = self._get_ct_log_domains(ip)
            domains.ct_log_domains = ct_domains
            all_found.update(ct_domains)
        except:
            pass
        
        domains.all_domains = sorted(list(all_found))
        return domains
    
    def _get_tls_san_domains(self, ip: str) -> List[str]:
        """Extract SAN domains from TLS certificate"""
        domains = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Get SAN
                    if 'subjectAltName' in cert:
                        for entry in cert['subjectAltName']:
                            if entry[0] == 'DNS':
                                domain = entry[1].replace('*.', '')
                                domains.append(domain)
                    
                    # Get CN
                    if 'subject' in cert:
                        for rdn in cert['subject']:
                            for name, value in rdn:
                                if name == 'commonName':
                                    cn = value.replace('*.', '')
                                    if cn not in domains:
                                        domains.append(cn)
        except:
            pass
        
        return domains[:20]  # Limit to 20 domains
    
    def _get_ct_log_domains(self, ip: str) -> List[str]:
        """Get domains from Certificate Transparency logs"""
        domains = []
        
        try:
            # Use crt.sh
            url = f"https://crt.sh/?q={ip}&output=json"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[:50]:  # Limit
                    name_value = entry.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip().replace('*.', '')
                        if domain and domain not in domains:
                            domains.append(domain)
        except:
            pass
        
        return domains[:20]
    
    def get_asn_info(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Get ASN and organization (with caching)"""
        cached = self.asn_cache.get(ip)
        if cached:
            return cached.get('asn'), cached.get('org')
        
        try:
            self.rate_limiter.wait()
            url = f"http://ip-api.com/json/{ip}?fields=as"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                asn_full = data.get('as', '')
                
                if asn_full:
                    parts = asn_full.split(' ', 1)
                    asn = parts[0] if parts else ''
                    org = parts[1] if len(parts) > 1 else ''
                    
                    result = {'asn': asn, 'org': org}
                    self.asn_cache.set(ip, result)
                    return asn, org
        except:
            pass
        
        return None, None
    
    def comprehensive_scan(self, ip: str, keywords: List[str] = None, 
                          country_code: Optional[str] = None) -> IPAnalysisResult:
        """Comprehensive IP analysis"""
        result = IPAnalysisResult(ip=ip, source_keywords=keywords or [], target_country=country_code)
        
        try:
            # Liveness detection
            result.liveness = self.advanced_liveness_check(ip)
            
            if result.liveness.status == "dead":
                result.confidence_score = 1.0
                return result
            
            # Port scan (limited)
            open_ports = []
            for port in [80, 443, 22, 21, 25, 3306, 8080]:
                if self._tcp_handshake(ip, port, timeout=1):
                    open_ports.append(port)
                time.sleep(0.05)
            
            result.tcp_ports_open = open_ports
            
            # ASN lookup
            asn, asn_org = self.get_asn_info(ip)
            result.asn = asn
            result.asn_org = asn_org
            
            # Geolocation
            try:
                self.rate_limiter.wait()
                geo = self._get_geolocation(ip)
                result.country = geo.get('country')
                result.country_name = geo.get('country_name')
                result.city = geo.get('city')
                result.isp = geo.get('isp')
            except:
                pass
            
            # Get headers for classification
            headers = {}
            try:
                protocol = "https" if result.liveness.https_responsive else "http"
                response = self.session.head(f"{protocol}://{ip}", timeout=5, verify=False, allow_redirects=True)
                headers = dict(response.headers)
                result.web_server = headers.get('Server', 'Unknown')
            except:
                pass
            
            # Hosting classification
            if asn:
                result.hosting = CDNDetector.classify_hosting(asn, asn_org or '', headers)
                result.is_cdn = result.hosting.hosting_type == "cdn"
                result.cdn_provider = result.hosting.provider if result.is_cdn else None
            
            # Domain attribution (only for origin servers or if explicitly needed)
            if result.hosting.is_origin or result.liveness.status == "alive":
                result.domains = self.get_domain_attribution(ip)
            
            # SSL check
            if result.liveness.tls_handshake or result.liveness.https_responsive:
                try:
                    ssl_info = self._get_ssl_info(ip)
                    result.ssl_valid = ssl_info.get('valid', False)
                    result.ssl_issuer = ssl_info.get('issuer')
                    result.ssl_subject = ssl_info.get('subject')
                except:
                    pass
            
            # Web title
            if result.liveness.status == "alive":
                try:
                    result.web_title = self._get_web_title(ip)
                except:
                    pass
            
            # Calculate confidence score
            result.confidence_score = self._calculate_confidence(result)
        
        except Exception:
            pass
        
        return result
    
    def _get_geolocation(self, ip: str) -> Dict:
        """Get geolocation"""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('countryCode'),
                        'country_name': data.get('country'),
                        'city': data.get('city'),
                        'isp': data.get('isp')
                    }
        except:
            pass
        
        return {}
    
    def _get_ssl_info(self, ip: str) -> Dict:
        """Get SSL certificate info"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['valid'] = True
                    
                    if 'issuer' in cert:
                        issuer = dict(x[0] for x in cert['issuer'])
                        ssl_info['issuer'] = issuer.get('organizationName', 'Unknown')
                    
                    if 'subject' in cert:
                        subject = dict(x[0] for x in cert['subject'])
                        ssl_info['subject'] = subject.get('commonName', 'Unknown')
        except:
            ssl_info['valid'] = False
        
        return ssl_info
    
    def _get_web_title(self, ip: str) -> Optional[str]:
        """Get web page title"""
        try:
            protocol = "https" if self._tcp_handshake(ip, 443, 1) else "http"
            response = self.session.get(f"{protocol}://{ip}", timeout=5, verify=False, stream=True)
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.content[:2048], 'html.parser')
            if soup.title and soup.title.string:
                return soup.title.string.strip()[:100]
        except:
            pass
        
        return None
    
    def _calculate_confidence(self, result: IPAnalysisResult) -> float:
        """Calculate confidence score for classification"""
        score = 0.0
        
        # Base score from hosting classification
        score = result.hosting.confidence
        
        # Boost for origin servers with domains
        if result.hosting.is_origin and result.domains.all_domains:
            score = min(1.0, score + 0.1)
        
        # Boost for valid SSL
        if result.ssl_valid:
            score = min(1.0, score + 0.05)
        
        # Penalize if CDN
        if result.is_cdn:
            score = max(0.0, score - 0.2)
        
        return round(score, 2)


class RateLimiter:
    """Thread-safe rate limiter"""
    
    def __init__(self, requests_per_second: float = 10.0):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait with jitter"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            
            if elapsed < self.min_interval:
                jitter = random.uniform(0, self.min_interval * 0.3)
                sleep_time = (self.min_interval - elapsed) + jitter
                time.sleep(sleep_time)
            
            self.last_request = time.time()


class MultiKeywordIPGenerator:
    """Multi-keyword IP generator with parallel processing"""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.ip_counter = 0
        self.counter_lock = threading.Lock()
    
    def generate_ips_multi_keyword(self, keywords: List[str], target_count: int, 
                                   country_code: Optional[str] = None) -> Tuple[Set[str], Dict[str, int]]:
        """Generate IPs from multiple keywords in parallel"""
        unique_ips = set()
        source_stats = defaultdict(int)
        ips_lock = threading.Lock()
        
        print(f"\n{Colors.BOLD}=== IP GENERATION ==={Colors.ENDC}\n")
        print(f"{Colors.BLUE}Requested IPs: {target_count}{Colors.ENDC}")
        print(f"{Colors.BLUE}Keywords: {', '.join(keywords)}{Colors.ENDC}")
        
        if country_code:
            print(f"{Colors.BLUE}Target Country: {country_code.upper()}{Colors.ENDC}")
        else:
            print(f"{Colors.BLUE}Target: Worldwide{Colors.ENDC}")
        
        print()
        
        # Calculate per-keyword target
        per_keyword = max(10, target_count // len(keywords))
        
        def process_keyword(keyword):
            """Process single keyword"""
            keyword_ips = set()
            
            # DNS discovery
            try:
                dns_ips = self._discover_dns_ips(keyword, per_keyword, country_code)
                keyword_ips.update(dns_ips)
                self._update_progress(len(dns_ips), 'DNS', ips_lock, unique_ips, dns_ips)
            except:
                pass
            
            # URLScan
            try:
                self.rate_limiter.wait()
                urlscan_ips = self._search_urlscan_ips(keyword, per_keyword, country_code)
                keyword_ips.update(urlscan_ips)
                self._update_progress(len(urlscan_ips), 'URLScan', ips_lock, unique_ips, urlscan_ips)
            except:
                pass
            
            # ThreatCrowd
            try:
                self.rate_limiter.wait()
                threat_ips = self._search_threatcrowd_ips(keyword, per_keyword)
                keyword_ips.update(threat_ips)
                self._update_progress(len(threat_ips), 'ThreatCrowd', ips_lock, unique_ips, threat_ips)
            except:
                pass
            
            return keyword_ips
        
        # Parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(keywords)) as executor:
            futures = {executor.submit(process_keyword, kw): kw for kw in keywords}
            
            for future in concurrent.futures.as_completed(futures):
                keyword = futures[future]
                try:
                    keyword_ips = future.result()
                    with ips_lock:
                        new_ips = keyword_ips - unique_ips
                        unique_ips.update(new_ips)
                        source_stats[keyword] = len(keyword_ips)
                except:
                    pass
        
        # Filter by country if needed
        if country_code and unique_ips:
            print(f"\n{Colors.CYAN}Filtering by country: {country_code.upper()}...{Colors.ENDC}")
            filtered = self._filter_by_country(unique_ips, country_code)
            print(f"{Colors.GREEN}{len(filtered)} IPs match target country{Colors.ENDC}")
            return filtered, dict(source_stats)
        
        return unique_ips, dict(source_stats)
    
    def _update_progress(self, count: int, source: str, lock, unique_ips: Set, new_ips: Set):
        """Thread-safe progress update"""
        with lock:
            added = new_ips - unique_ips
            if added:
                with self.counter_lock:
                    self.ip_counter += len(added)
                print(f"  {source}: +{len(added)} IPs (Total: {self.ip_counter})")
    
    def _filter_by_country(self, ips: Set[str], country_code: str) -> Set[str]:
        """Filter IPs by country"""
        filtered = set()
        country_upper = country_code.upper()
        
        for ip in list(ips)[:200]:  # Limit to avoid rate limiting
            try:
                self.rate_limiter.wait()
                url = f"http://ip-api.com/json/{ip}?fields=countryCode"
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('countryCode', '').upper() == country_upper:
                        filtered.add(ip)
            except:
                pass
        
        return filtered
    
    def _discover_dns_ips(self, keyword: str, limit: int, country_code: Optional[str]) -> Set[str]:
        """DNS discovery"""
        ips = set()
        
        tlds = ['com', 'net', 'org', 'io', 'ai', 'dev']
        
        if country_code:
            country_tlds = {
                'US': ['us'],
                'UK': ['uk', 'co.uk'],
                'RU': ['ru'],
                'CA': ['ca'],
                'AU': ['au'],
                'DE': ['de'],
                'FR': ['fr'],
            }
            tlds = country_tlds.get(country_code.upper(), []) + tlds[:3]
        
        subdomains = ['www', 'mail', 'api', 'app']
        
        patterns = []
        for tld in tlds[:5]:
            patterns.append(f"{keyword}.{tld}")
            for sub in subdomains[:2]:
                patterns.append(f"{sub}.{keyword}.{tld}")
        
        for pattern in patterns[:30]:
            if len(ips) >= limit:
                break
            
            try:
                ip = socket.gethostbyname(pattern)
                if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                    ips.add(ip)
            except:
                pass
            
            time.sleep(0.03)
        
        return ips
    
    def _search_urlscan_ips(self, keyword: str, limit: int, country_code: Optional[str]) -> Set[str]:
        """URLScan search"""
        ips = set()
        
        try:
            url = "https://urlscan.io/api/v1/search/"
            
            if country_code:
                query = f'domain:{keyword} country:{country_code.upper()}'
            else:
                query = f'domain:{keyword}'
            
            params = {'q': query, 'size': min(100, limit * 2)}
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    page = result.get('page', {})
                    ip = page.get('ip', '')
                    
                    if ip and self._is_valid_ip(ip) and not self._is_private_ip(ip):
                        ips.add(ip)
                        if len(ips) >= limit:
                            break
        except:
            pass
        
        return ips
    
    def _search_threatcrowd_ips(self, keyword: str, limit: int) -> Set[str]:
        """ThreatCrowd search"""
        ips = set()
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={keyword}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == '1':
                    for resolution in data.get('resolutions', []):
                        ip = resolution.get('ip_address', '')
                        if ip and self._is_valid_ip(ip) and not self._is_private_ip(ip):
                            ips.add(ip)
                            if len(ips) >= limit:
                                break
        except:
            pass
        
        return ips
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP"""
        try:
            pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(pattern, ip):
                parts = ip.split('.')
                return all(0 <= int(part) <= 255 for part in parts)
        except:
            pass
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check private IP"""
        try:
            parts = list(map(int, ip.split('.')))
            
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127 or parts[0] == 0:
                return True
        except:
            pass
        
        return False


class SpiderWebCLI:
    """SpiderWeb CLI"""
    
    VERSION = "7.0"
    BANNER = f"""
{Colors.BOLD}{Colors.GREEN}╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║         ╔═╗┌─┐┬┌┬┐┌─┐┬─┐╦ ╦┌─┐┌┐     ╔═╗╦═╗╔═╗                    ║
║         ╚═╗├─┘│ ││├┤ ├┬┘║║║├┤ ├┴┐    ╠═╝╠╦╝║ ║                    ║
║         ╚═╝┴  ┴─┴┘└─┘┴└─╚╩╝└─┘└─┘    ╩  ╩╚═╚═╝                    ║
║                                                                   ║
║{Colors.ENDC}       {Colors.RED}Professional IP Analysis v{VERSION} - Origin Detection{Colors.ENDC}         {Colors.GREEN}   ║
║{Colors.ENDC}                        {Colors.WHITE}by g33l0{Colors.ENDC}                                   {Colors.GREEN}    ║
║                                                                   ║
║   ┌─────────────────────────────────────────────────────────┐     ║
║   │  Scan | Worldwide | CDN Bypass | Advanced Detection     │     ║
║   └─────────────────────────────────────────────────────────┘     ║
╚═══════════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    
    MAX_IPS = 4000
    REQUESTS_PER_SECOND = 8.0
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.results: List[IPAnalysisResult] = []
        
        self.rate_limiter = RateLimiter(self.REQUESTS_PER_SECOND)
        self.ip_generator = MultiKeywordIPGenerator(self.rate_limiter)
        self.scanner = AdvancedScanner(self.rate_limiter)
        
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C"""
        print(f"\n{Colors.YELLOW}Operation cancelled.{Colors.ENDC}")
        sys.exit(0)
    
    def print_banner(self):
        """Display banner"""
        print(self.BANNER)
    
    def log(self, message: str, level: str = "INFO"):
        """Logging"""
        if not self.verbose:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "ERROR": Colors.RED,
            "WARNING": Colors.YELLOW,
        }
        
        color = colors.get(level, Colors.WHITE)
        print(f"{color}[{timestamp}] {message}{Colors.ENDC}")
    
    def get_input(self, prompt: str, allow_back: bool = True) -> str:
        """Get user input with navigation"""
        nav = " (ESC=Exit"
        if allow_back:
            nav += ", 0=Back"
        nav += ")"
        
        full_prompt = f"{prompt}{Colors.BOLD}{nav}: {Colors.ENDC}"
        
        try:
            user_input = input(full_prompt).strip()
            
            if user_input.upper() == 'ESC' or user_input == '\x1b':
                raise ExitException()
            
            if user_input == '0' and allow_back:
                raise NavigationException()
            
            return user_input
        
        except (KeyboardInterrupt, EOFError):
            raise ExitException()
    
    def prompt_input_method(self) -> str:
        """Input method selection"""
        while True:
            try:
                print(f"\n{Colors.BOLD}=== SELECT INPUT METHOD ==={Colors.ENDC}\n")
                print(f"{Colors.CYAN}1.{Colors.ENDC} Keyword-based IP generation")
                print(f"{Colors.CYAN}2.{Colors.ENDC} Scan IPs from file (ips.txt)")
                
                choice = self.get_input("\nEnter choice (1 or 2)", allow_back=False)
                
                if choice == "1":
                    return "keyword"
                elif choice == "2":
                    return "file"
                else:
                    print(f"{Colors.RED}Invalid choice.{Colors.ENDC}")
            
            except NavigationException:
                continue
            except ExitException:
                sys.exit(0)
    
    def get_country_input(self) -> Optional[str]:
        """Get country code"""
        while True:
            try:
                print(f"\n{Colors.BOLD}=== TARGET LOCATION ==={Colors.ENDC}\n")
                print(f"{Colors.CYAN}Enter country code or 0 for worldwide{Colors.ENDC}")
                print(f"\n{Colors.BOLD}Popular:{Colors.ENDC}")
                print("  US - United States    UK - United Kingdom    CA - Canada")
                print("  AU - Australia        DE - Germany           FR - France")
                print("  JP - Japan            CN - China             IN - India")
                print("  BR - Brazil           RU - Russia            ZA - South Africa")
                
                country = self.get_input("\nCountry code", allow_back=True).upper()
                
                if country == "0":
                    return None
                
                if len(country) == 2 and country.isalpha():
                    return country
                else:
                    print(f"{Colors.RED}Invalid code. Use 2 letters (e.g., US).{Colors.ENDC}")
            
            except NavigationException:
                raise
    
    def get_keyword_input(self) -> Tuple[List[str], int, Optional[str]]:
        """Get keywords, count, and country"""
        while True:
            try:
                print(f"\n{Colors.BOLD}=== KEYWORD-BASED IP GENERATION ==={Colors.ENDC}\n")
                
                # Keywords
                keywords_input = self.get_input("Enter keywords (comma-separated)", allow_back=True)
                
                if not keywords_input:
                    print(f"{Colors.RED}Keywords cannot be empty.{Colors.ENDC}")
                    continue
                
                keywords = [k.strip() for k in keywords_input.split(',') if k.strip()]
                
                if not keywords:
                    print(f"{Colors.RED}Please enter at least one keyword.{Colors.ENDC}")
                    continue
                
                # Count
                while True:
                    try:
                        count_input = self.get_input(f"How many IPs? (max {self.MAX_IPS})", allow_back=True)
                        count = int(count_input)
                        
                        if count <= 0:
                            print(f"{Colors.RED}Must be greater than 0.{Colors.ENDC}")
                            continue
                        
                        if count > self.MAX_IPS:
                            print(f"{Colors.RED}Maximum is {self.MAX_IPS}.{Colors.ENDC}")
                            continue
                        
                        break
                    
                    except ValueError:
                        print(f"{Colors.RED}Invalid number.{Colors.ENDC}")
                    except NavigationException:
                        raise
                
                # Country
                country = self.get_country_input()
                
                return keywords, count, country
            
            except NavigationException:
                continue
    
    def read_ips_from_file(self, filename: str = "ips.txt") -> List[str]:
        """Read IPs from file"""
        filepath = Path(filename)
        
        if not filepath.exists():
            self.log(f"File '{filename}' not found", "ERROR")
            raise NavigationException()
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            ips = []
            for line in lines:
                ip = line.strip()
                
                if not ip or ip.startswith('#'):
                    continue
                
                if self.is_valid_ip(ip):
                    ips.append(ip)
            
            if not ips:
                self.log("No valid IPs found", "ERROR")
                raise NavigationException()
            
            unique = list(dict.fromkeys(ips))
            
            if len(unique) > self.MAX_IPS:
                unique = unique[:self.MAX_IPS]
            
            self.log(f"Loaded {len(unique)} IPs", "SUCCESS")
            return unique
        
        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")
            raise NavigationException()
    
    def is_valid_ip(self, ip: str) -> bool:
        """Validate IP"""
        try:
            pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(pattern, ip):
                parts = ip.split('.')
                return all(0 <= int(part) <= 255 for part in parts)
        except:
            pass
        return False
    
    def batch_scan(self, ips: List[str], keywords: List[str] = None, country_code: Optional[str] = None):
        """Batch scan with advanced detection"""
        
        randomized = ips.copy()
        random.shuffle(randomized)
        
        self.log(f"Starting scan of {len(randomized)} IPs", "INFO")
        
        print(f"\n{Colors.BOLD}=== ADVANCED SCANNING ==={Colors.ENDC}\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(self.scanner.comprehensive_scan, ip, keywords, country_code): ip 
                      for ip in randomized}
            
            completed = 0
            total = len(randomized)
            
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    
                    completed += 1
                    progress = completed / total * 100
                    bar_length = 30
                    filled = int(bar_length * completed / total)
                    bar = '█' * filled + '░' * (bar_length - filled)
                    
                    print(f"\r{Colors.CYAN}[{bar}] {progress:.1f}%{Colors.ENDC} | "
                          f"Scanned: {completed}/{total}", end='', flush=True)
                
                except Exception:
                    self.results.append(IPAnalysisResult(ip=ip))
        
        print(f"\n\n{Colors.BOLD}=== SCAN COMPLETE ==={Colors.ENDC}\n")
        self.log(f"Scanned {len(self.results)} IPs", "SUCCESS")
    
    def display_results(self):
        """Display results"""
        if not self.results:
            self.log("No results", "WARNING")
            return
        
        alive = [r for r in self.results if r.liveness.status in ["alive", "tls_only"]]
        origin = [r for r in alive if r.hosting.is_origin]
        cdn = [r for r in alive if r.is_cdn]
        dead = [r for r in self.results if r.liveness.status == "dead"]
        
        print(f"\n{Colors.BOLD}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'RESULTS SUMMARY':^80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.GREEN}Origin Servers: {len(origin)}{Colors.ENDC}")
        print(f"{Colors.YELLOW}CDN/Proxies: {len(cdn)}{Colors.ENDC}")
        print(f"{Colors.CYAN}Total Alive: {len(alive)}{Colors.ENDC}")
        print(f"{Colors.RED}Dead: {len(dead)}{Colors.ENDC}\n")
        
        if origin:
            print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}")
            print(f"{Colors.BOLD}ORIGIN SERVERS (Top 15){Colors.ENDC}")
            print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}\n")
            
            for idx, r in enumerate(origin[:15], 1):
                print(f"{Colors.GREEN}[{idx}] {r.ip}{Colors.ENDC} | {r.hosting.hosting_type.upper()}")
                print(f"    Status: {r.liveness.status.upper()} | Confidence: {r.confidence_score}")
                
                if r.country_name:
                    print(f"    Location: {r.city or 'Unknown'}, {r.country_name}")
                
                if r.domains.all_domains:
                    domains_str = ', '.join(r.domains.all_domains[:3])
                    if len(r.domains.all_domains) > 3:
                        domains_str += f" +{len(r.domains.all_domains)-3} more"
                    print(f"    Domains: {domains_str}")
                
                if r.hosting.provider:
                    print(f"    Provider: {r.hosting.provider}")
                
                if r.tcp_ports_open:
                    print(f"    Ports: {', '.join(map(str, r.tcp_ports_open[:5]))}")
                
                print()
    
    def export_results(self):
        """Export results"""
        if not self.results:
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        json_file = f"spiderweb_{timestamp}.json"
        csv_file = f"spiderweb_{timestamp}.csv"
        
        self.export_json(json_file)
        self.export_csv(csv_file)
        
        print(f"\n{Colors.BOLD}=== EXPORT COMPLETE ==={Colors.ENDC}\n")
        print(f"{Colors.GREEN}JSON: {json_file}{Colors.ENDC}")
        print(f"{Colors.GREEN}CSV: {csv_file}{Colors.ENDC}\n")
    
    def export_json(self, filename: str):
        """Export JSON"""
        output = {
            'metadata': {
                'tool': 'SpiderWeb Pro',
                'version': self.VERSION,
                'author': 'g33l0',
                'timestamp': datetime.now().isoformat(),
                'total': len(self.results)
            },
            'results': [asdict(r) for r in self.results]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
    
    def export_csv(self, filename: str):
        """Export CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['ip', 'status', 'hosting_type', 'is_origin', 'confidence', 
                         'domains', 'country', 'city', 'provider', 'asn']
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for r in self.results:
                writer.writerow({
                    'ip': r.ip,
                    'status': r.liveness.status,
                    'hosting_type': r.hosting.hosting_type,
                    'is_origin': r.hosting.is_origin,
                    'confidence': r.confidence_score,
                    'domains': ','.join(r.domains.all_domains[:5]),
                    'country': r.country or '',
                    'city': r.city or '',
                    'provider': r.hosting.provider or '',
                    'asn': r.asn or ''
                })


def main():
    """Main entry"""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "beautifulsoup4", "-q"])
    
    try:
        import urllib3
        urllib3.disable_warnings()
    except:
        pass
    
    cli = SpiderWebCLI()
    cli.print_banner()
    
    while True:
        try:
            method = cli.prompt_input_method()
            
            ips = []
            keywords = None
            country = None
            
            if method == "keyword":
                keywords, target_count, country = cli.get_keyword_input()
                
                # Reset counter
                cli.ip_generator.ip_counter = 0
                
                generated, stats = cli.ip_generator.generate_ips_multi_keyword(keywords, target_count, country)
                ips = list(generated)
                
                print(f"\n{Colors.BOLD}=== GENERATION REPORT ==={Colors.ENDC}\n")
                print(f"{Colors.BLUE}Requested: {target_count}{Colors.ENDC}")
                print(f"{Colors.GREEN}Generated: {len(ips)}{Colors.ENDC}\n")
                
                if len(ips) < target_count:
                    print(f"{Colors.YELLOW}WARNING: Generated {len(ips)}/{target_count} IPs{Colors.ENDC}\n")
                    
                    if len(ips) > 0:
                        proceed = cli.get_input(f"Proceed with {len(ips)} IPs? (y/n)", True).lower()
                        if proceed != 'y':
                            continue
                    else:
                        print(f"{Colors.RED}No IPs generated.{Colors.ENDC}")
                        continue
            
            elif method == "file":
                ips = cli.read_ips_from_file("ips.txt")
                print(f"\n{Colors.GREEN}Loaded {len(ips)} IPs{Colors.ENDC}\n")
            
            confirm = cli.get_input(f"Scan {len(ips)} IPs? (y/n)", True).lower()
            
            if confirm != 'y':
                continue
            
            cli.batch_scan(ips, keywords, country)
            cli.display_results()
            
            if cli.results:
                export = cli.get_input("Export? (y/n)", True).lower()
                if export == 'y':
                    cli.export_results()
            
            print(f"\n{Colors.GREEN}Scan complete!{Colors.ENDC}\n")
            
            another = cli.get_input("Another scan? (y/n)", False).lower()
            if another != 'y':
                print(f"\n{Colors.WHITE}Thank you! Goodbye.{Colors.ENDC}\n")
                break
        
        except NavigationException:
            continue
        except ExitException:
            print(f"\n{Colors.WHITE}Goodbye!{Colors.ENDC}")
            break


if __name__ == "__main__":
    main()
