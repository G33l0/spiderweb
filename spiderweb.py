#!/usr/bin/env python3
"""
SpiderWeb 🕸️ - Advanced CLI IP Analysis Tool
Author: g33l0
Version: 6.0
Description: Professional, secure, and efficient IP reconnaissance framework
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
import dns.resolver
from pathlib import Path
import random
import hashlib
from threading import Lock

# Color codes for CLI
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

@dataclass
class IPAnalysisResult:
    """Complete IP analysis result"""
    ip: str
    is_live: bool = False
    
    # Liveness metrics
    ping_responsive: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    response_time: Optional[float] = None
    tcp_ports_open: List[int] = field(default_factory=list)
    
    # DNS Information
    reverse_dns: Optional[str] = None
    ptr_records: List[str] = field(default_factory=list)
    
    # SSL/TLS
    ssl_valid: Optional[bool] = None
    ssl_issuer: Optional[str] = None
    ssl_expiry: Optional[str] = None
    
    # Geolocation
    country: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    asn: Optional[str] = None
    
    # Web information
    web_server: Optional[str] = None
    web_title: Optional[str] = None
    detected_technologies: List[str] = field(default_factory=list)
    
    # Security
    security_headers: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    source_keyword: Optional[str] = None
    
    def __post_init__(self):
        if not self.scan_timestamp:
            self.scan_timestamp = datetime.now().isoformat()


class RateLimiter:
    """Adaptive rate limiter with jitter"""
    
    def __init__(self, requests_per_second: float = 5.0):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0
        self.lock = Lock()
    
    def wait(self):
        """Wait with randomized jitter to avoid patterns"""
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            
            if elapsed < self.min_interval:
                # Add jitter (±20% randomization)
                jitter = random.uniform(0.8, 1.2)
                sleep_time = (self.min_interval - elapsed) * jitter
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()


class IPGenerator:
    """Intelligent IP generation with multiple sources and retry logic"""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
    
    def generate_ips(self, keyword: str, count: int, max_retries: int = 3) -> Tuple[Set[str], Dict[str, int]]:
        """
        Generate IPs with retry logic and multiple sources
        
        Returns:
            Tuple of (unique_ips, source_stats)
        """
        ips = set()
        source_stats = defaultdict(int)
        
        print(f"\n{Colors.OKCYAN}🔍 Generating {count} IPs for keyword: '{keyword}'{Colors.ENDC}\n")
        
        # Strategy 1: Direct DNS resolution (fast, reliable)
        print(f"{Colors.OKBLUE}[1/5] Trying direct DNS resolution...{Colors.ENDC}")
        dns_ips = self._dns_resolution(keyword, count)
        ips.update(dns_ips)
        source_stats['dns'] = len(dns_ips)
        print(f"      ✓ Found {len(dns_ips)} IPs via DNS")
        
        if len(ips) >= count:
            return ips, dict(source_stats)
        
        # Strategy 2: URLScan.io (web crawling database)
        print(f"{Colors.OKBLUE}[2/5] Querying URLScan.io...{Colors.ENDC}")
        urlscan_ips = self._query_urlscan(keyword, count - len(ips))
        new_ips = urlscan_ips - ips
        ips.update(new_ips)
        source_stats['urlscan'] = len(new_ips)
        print(f"      ✓ Found {len(new_ips)} new IPs from URLScan.io")
        
        if len(ips) >= count:
            return ips, dict(source_stats)
        
        # Strategy 3: ThreatCrowd (threat intelligence)
        print(f"{Colors.OKBLUE}[3/5] Querying ThreatCrowd...{Colors.ENDC}")
        threat_ips = self._query_threatcrowd(keyword, count - len(ips))
        new_ips = threat_ips - ips
        ips.update(new_ips)
        source_stats['threatcrowd'] = len(new_ips)
        print(f"      ✓ Found {len(new_ips)} new IPs from ThreatCrowd")
        
        if len(ips) >= count:
            return ips, dict(source_stats)
        
        # Strategy 4: Certificate Transparency (crt.sh)
        print(f"{Colors.OKBLUE}[4/5] Checking Certificate Transparency logs...{Colors.ENDC}")
        crt_ips = self._query_crtsh(keyword, count - len(ips))
        new_ips = crt_ips - ips
        ips.update(new_ips)
        source_stats['crtsh'] = len(new_ips)
        print(f"      ✓ Found {len(new_ips)} new IPs from crt.sh")
        
        if len(ips) >= count:
            return ips, dict(source_stats)
        
        # Strategy 5: Expand search with variants
        print(f"{Colors.OKBLUE}[5/5] Trying keyword variations...{Colors.ENDC}")
        variant_ips = self._expand_keyword_search(keyword, count - len(ips))
        new_ips = variant_ips - ips
        ips.update(new_ips)
        source_stats['variants'] = len(new_ips)
        print(f"      ✓ Found {len(new_ips)} new IPs from variants")
        
        # Retry logic if still insufficient
        attempt = 1
        while len(ips) < count and attempt <= max_retries:
            print(f"\n{Colors.WARNING}⚠️  Only {len(ips)}/{count} IPs found. Retry attempt {attempt}/{max_retries}...{Colors.ENDC}")
            
            # Retry with more aggressive pagination
            retry_ips = self._retry_with_pagination(keyword, count - len(ips))
            new_ips = retry_ips - ips
            ips.update(new_ips)
            source_stats['retry'] = source_stats.get('retry', 0) + len(new_ips)
            print(f"      ✓ Found {len(new_ips)} additional IPs")
            
            if len(ips) >= count:
                break
            
            attempt += 1
            time.sleep(1)
        
        return ips, dict(source_stats)
    
    def _dns_resolution(self, keyword: str, limit: int) -> Set[str]:
        """DNS resolution with common patterns"""
        ips = set()
        
        # Generate domain patterns
        patterns = [
            keyword,
            f"{keyword}.com",
            f"{keyword}.net",
            f"{keyword}.org",
            f"www.{keyword}",
            f"www.{keyword}.com",
            f"www.{keyword}.net",
            f"api.{keyword}",
            f"mail.{keyword}",
            f"mail.{keyword}.com",
            f"smtp.{keyword}.com",
            f"imap.{keyword}.com",
            f"mx.{keyword}.com",
            f"ftp.{keyword}.com",
            f"sftp.{keyword}.com",
            f"files.{keyword}.com",
            f"api.{keyword}.com",
            f"app.{keyword}.com",
            f"web.{keyword}.com",
            f"portal.{keyword}.com",
            f"service.{keyword}.com",
            f"admin.{keyword}.com",
            f"panel.{keyword}.com",
            f"dashboard.{keyword}.com",
            f"manage.{keyword}.com",
            f"console.{keyword}.com",
            f"auth.{keyword}.com", 
            f"login.{keyword}.com", 
            f"sso.{keyword}.com", 
            f"secure.{keyword}.com", 
            f"vpn.{keyword}.com",
            f"gw.{keyword}.com",
            f"gateway.{keyword}.com",
            f"edge.{keyword}.com",
            f"router.{keyword}.com",
            f"lb.{keyword}.com",
            f"loadbalancer.{keyword}.com",
            f"dev.{keyword}.com",
            f"test.{keyword}.com",
            f"staging.{keyword}.com",
            f"stage.{keyword}.com",
            f"qa.{keyword}.com",
            f"uat.{keyword}.com",
            f"v1.{keyword}.com",
            f"v2.{keyword}.com",
            f"old.{keyword}.com",
            f"legacy.{keyword}.com",
            f"backup.{keyword}.com",
            f"node.{keyword}.com",
            f"nodes.{keyword}.com",
            f"cluster.{keyword}.com",
            f"docker.{keyword}.com",
            f"k8s.{keyword}.com",
            f"status.{keyword}.com",
            f"monitor.{keyword}.com",
            f"health.{keyword}.com",
            f"server.{keyword}.com",
            f"srv.{keyword}.com",
            f"host.{keyword}.com",
            f"host1.{keyword}.com",
            f"host2.{keyword}.com",
            f"ip.{keyword}.com",
            f"{keyword}.io",
            f"{keyword}.co",
            
        ]
        
        prefixes = ["api", "admin", "dev", "test", "stage", "vpn", "gw", "edge"]
        suffixes = ["1", "2", "01", "prod", "int"]

        patterns.extend(
        [f"{p}-{keyword}.com" for p in prefixes] +
        [f"{p}.{keyword}{s}.com" for p in prefixes for s in suffixes]
        )

        for pattern in patterns:
            if len(ips) >= limit:
                break
            
            try:
                ip = socket.gethostbyname(pattern)
                if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                    ips.add(ip)
                self.rate_limiter.wait()
            except:
                pass
        
        return ips
    
    def _query_urlscan(self, keyword: str, limit: int) -> Set[str]:
        """Query URLScan.io with pagination"""
        ips = set()
        
        try:
            url = "https://urlscan.io/api/v1/search/"
            params = {'q': keyword, 'size': min(limit * 2, 100)}
            
            self.rate_limiter.wait()
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    if len(ips) >= limit:
                        break
                    
                    page = result.get('page', {})
                    ip = page.get('ip', '')
                    
                    if ip and self._is_valid_ip(ip) and not self._is_private_ip(ip):
                        ips.add(ip)
        except:
            pass
        
        return ips
    
    def _query_threatcrowd(self, keyword: str, limit: int) -> Set[str]:
        """Query ThreatCrowd API"""
        ips = set()
        
        try:
            # Try as domain
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={keyword}"
            
            self.rate_limiter.wait()
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == '1':
                    for resolution in data.get('resolutions', []):
                        if len(ips) >= limit:
                            break
                        
                        ip = resolution.get('ip_address', '')
                        if ip and self._is_valid_ip(ip) and not self._is_private_ip(ip):
                            ips.add(ip)
        except:
            pass
        
        return ips
    
    def _query_crtsh(self, keyword: str, limit: int) -> Set[str]:
        """Query Certificate Transparency logs"""
        ips = set()
        
        try:
            url = "https://crt.sh/"
            params = {'q': f'%.{keyword}%', 'output': 'json'}
            
            self.rate_limiter.wait()
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                domains = set()
                
                for entry in data[:limit * 2]:
                    name_value = entry.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip().lower().replace('*.', '')
                        if domain and len(domains) < limit * 2:
                            domains.add(domain)
                
                # Resolve domains to IPs
                for domain in list(domains)[:limit]:
                    if len(ips) >= limit:
                        break
                    
                    try:
                        ip = socket.gethostbyname(domain)
                        if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                            ips.add(ip)
                        self.rate_limiter.wait()
                    except:
                        pass
        except:
            pass
        
        return ips
    
    def _expand_keyword_search(self, keyword: str, limit: int) -> Set[str]:
        """Expand search with keyword variations"""
        ips = set()
        
        # Generate variations
        variations = [
            f"{keyword}s",
            f"{keyword}-app",
            f"{keyword}-api",
            f"{keyword}-web",
            f"my{keyword}",
            f"get{keyword}",
            f"{keyword}online",
            f"{keyword}cloud",
        ]
        
        for variant in variations:
            if len(ips) >= limit:
                break
            
            # Try DNS resolution
            try:
                ip = socket.gethostbyname(f"{variant}.com")
                if self._is_valid_ip(ip) and not self._is_private_ip(ip):
                    ips.add(ip)
                self.rate_limiter.wait()
            except:
                pass
        
        return ips
    
    def _retry_with_pagination(self, keyword: str, limit: int) -> Set[str]:
        """Retry with different pagination parameters"""
        ips = set()
        
        # Try URLScan with different queries
        queries = [
            f"domain:{keyword}",
            f"page.domain:{keyword}",
            f"task.domain:{keyword}",
        ]
        
        for query in queries:
            if len(ips) >= limit:
                break
            
            try:
                url = "https://urlscan.io/api/v1/search/"
                params = {'q': query, 'size': 50}
                
                self.rate_limiter.wait()
                response = self.session.get(url, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    for result in data.get('results', []):
                        if len(ips) >= limit:
                            break
                        
                        page = result.get('page', {})
                        ip = page.get('ip', '')
                        
                        if ip and self._is_valid_ip(ip) and not self._is_private_ip(ip):
                            ips.add(ip)
            except:
                pass
        
        return ips
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved"""
        try:
            parts = [int(p) for p in ip.split('.')]
            
            # Private ranges
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:  # Loopback
                return True
            if parts[0] == 0:  # Invalid
                return True
            
            return False
        except:
            return True


class SpiderWebCLI:
    """
    SpiderWeb 🕸️ - Professional CLI IP Analysis Tool
    """
    
    VERSION = "6.0"
    BANNER = f"""
{Colors.OKCYAN}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║                ╔═╗┌─┐┬┌┬┐┌─┐┬─┐╦ ╦┌─┐┌┐                   ║
║                ╚═╗├─┘│ ││├┤ ├┬┘║║║├┤ ├┴┐                  ║
║                ╚═╝┴  ┴─┴┘└─┘┴└─╚╩╝└─┘└─┘                  ║
║                           🕸️                               ║
║             Professional IP Analysis Tool v{VERSION}            ║
║                        by g33l0                           ║
║                                                           ║
║ ┌───────────────────────────────────────────────────────┐ ║
║ │     Scan   |   Analyze   |   Report   |    Secure     │ ║
║ └───────────────────────────────────────────────────────┘ ║
╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    
    COMMON_PORTS = [80, 443, 22, 25, 3389, 3306, 5432, 27017, 6379, 445, 9200, 8443, 8000, 8080]  # Reduced for stealth
    MAX_IPS = 4000
    
    def __init__(self, verbose: bool = True, requests_per_second: float = 5.0):
        self.verbose = verbose
        self.rate_limiter = RateLimiter(requests_per_second)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results: List[IPAnalysisResult] = []
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
        self.ip_generator = IPGenerator(self.rate_limiter)
    
    def print_banner(self):
        """Display banner"""
        print(self.BANNER)
    
    def log(self, message: str, level: str = "INFO"):
        """Colored logging"""
        if not self.verbose:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        levels = {
            "INFO": (Colors.OKBLUE, "ℹ️ "),
            "SUCCESS": (Colors.OKGREEN, "✅"),
            "ERROR": (Colors.FAIL, "❌"),
            "WARNING": (Colors.WARNING, "⚠️ "),
            "SCAN": (Colors.OKCYAN, "🔍"),
            "LIVE": (Colors.OKGREEN, "🟢"),
            "DEAD": (Colors.FAIL, "🔴"),
        }
        
        color, symbol = levels.get(level, (Colors.ENDC, ""))
        print(f"{color}{symbol} [{timestamp}] {message}{Colors.ENDC}")
    
    def prompt_input_method(self) -> str:
        """Prompt user to select input method"""
        print(f"\n{Colors.BOLD}═══ SELECT INPUT METHOD ═══{Colors.ENDC}\n")
        print(f"{Colors.OKCYAN}1.{Colors.ENDC} Keyword-based IP generation")
        print(f"{Colors.OKCYAN}2.{Colors.ENDC} Scan IPs from file (ips.txt)")
        
        while True:
            try:
                choice = input(f"\n{Colors.BOLD}Enter your choice (1 or 2): {Colors.ENDC}").strip()
                
                if choice == "1":
                    return "keyword"
                elif choice == "2":
                    return "file"
                else:
                    print(f"{Colors.FAIL}❌ Invalid choice. Please enter 1 or 2.{Colors.ENDC}")
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}⚠️  Operation cancelled by user.{Colors.ENDC}")
                sys.exit(0)
    
    def get_keyword_input(self) -> Tuple[str, int]:
        """Get keyword and IP count from user"""
        print(f"\n{Colors.BOLD}═══ KEYWORD-BASED IP GENERATION ═══{Colors.ENDC}\n")
        
        # Get keyword
        while True:
            try:
                keyword = input(f"{Colors.BOLD}Enter keyword for IP generation: {Colors.ENDC}").strip()
                
                if not keyword:
                    print(f"{Colors.FAIL}❌ Keyword cannot be empty.{Colors.ENDC}")
                    continue
                
                if len(keyword) < 2:
                    print(f"{Colors.FAIL}❌ Keyword must be at least 2 characters.{Colors.ENDC}")
                    continue
                
                break
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}⚠️  Operation cancelled by user.{Colors.ENDC}")
                sys.exit(0)
        
        # Get IP count
        while True:
            try:
                count_input = input(f"{Colors.BOLD}How many IPs to generate? (max {self.MAX_IPS}): {Colors.ENDC}").strip()
                
                if not count_input:
                    print(f"{Colors.FAIL}❌ Please enter a number.{Colors.ENDC}")
                    continue
                
                count = int(count_input)
                
                if count <= 0:
                    print(f"{Colors.FAIL}❌ Count must be greater than 0.{Colors.ENDC}")
                    continue
                
                if count > self.MAX_IPS:
                    print(f"{Colors.FAIL}❌ Maximum allowed is {self.MAX_IPS} IPs.{Colors.ENDC}")
                    continue
                
                return keyword, count
            
            except ValueError:
                print(f"{Colors.FAIL}❌ Invalid number. Please enter a valid integer.{Colors.ENDC}")
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}⚠️  Operation cancelled by user.{Colors.ENDC}")
                sys.exit(0)
    
    def read_ips_from_file(self, filename: str = "ips.txt") -> List[str]:
        """Read IPs from file"""
        filepath = Path(filename)
        
        if not filepath.exists():
            self.log(f"File '{filename}' not found in current directory", "ERROR")
            self.log(f"Current directory: {os.getcwd()}", "INFO")
            sys.exit(1)
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            ips = []
            for line_num, line in enumerate(lines, 1):
                ip = line.strip()
                
                # Skip empty lines and comments
                if not ip or ip.startswith('#'):
                    continue
                
                # Validate IP format
                if self.is_valid_ip(ip):
                    ips.append(ip)
                else:
                    self.log(f"Invalid IP on line {line_num}: {ip}", "WARNING")
            
            if not ips:
                self.log(f"No valid IPs found in {filename}", "ERROR")
                sys.exit(1)
            
            if len(ips) > self.MAX_IPS:
                self.log(f"File contains {len(ips)} IPs, limiting to {self.MAX_IPS}", "WARNING")
                ips = ips[:self.MAX_IPS]
            
            # Deduplicate
            unique_ips = list(set(ips))
            if len(unique_ips) < len(ips):
                self.log(f"Removed {len(ips) - len(unique_ips)} duplicate IPs", "INFO")
            
            self.log(f"Successfully loaded {len(unique_ips)} unique IPs from {filename}", "SUCCESS")
            return unique_ips
        
        except Exception as e:
            self.log(f"Error reading file: {str(e)}", "ERROR")
            sys.exit(1)
    
    def is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def check_liveness_lightweight(self, ip: str) -> bool:
        """Lightweight liveness check (TCP connect only)"""
        # Try HTTP first (most common)
        if self.check_tcp_port(ip, 80, timeout=1):
            return True
        
        # Try HTTPS
        if self.check_tcp_port(ip, 443, timeout=1):
            return True
        
        return False
    
    def check_tcp_port(self, ip: str, port: int, timeout: int = 2) -> bool:
        """Check if TCP port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_http_status(self, ip: str) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        """Check HTTP/HTTPS status with HEAD request (lightweight)"""
        http_status = None
        https_status = None
        response_time = None
        
        # Try HTTPS first (more common now)
        try:
            start = time.time()
            response = self.session.head(f"https://{ip}", timeout=5, verify=False, allow_redirects=True)
            response_time = time.time() - start
            https_status = response.status_code
        except:
            pass
        
        # Try HTTP if HTTPS failed
        if https_status is None:
            try:
                start = time.time()
                response = self.session.head(f"http://{ip}", timeout=5, allow_redirects=True)
                response_time = time.time() - start
                http_status = response.status_code
            except:
                pass
        
        return http_status, https_status, response_time
    
    def comprehensive_scan(self, ip: str, keyword: Optional[str] = None) -> IPAnalysisResult:
        """Perform comprehensive IP analysis"""
        result = IPAnalysisResult(ip=ip, source_keyword=keyword)
        
        # Phase 1: Quick liveness check
        is_live = self.check_liveness_lightweight(ip)
        result.is_live = is_live
        
        if not is_live:
            return result
        
        # Phase 2: Detailed analysis for live IPs only
        self.rate_limiter.wait()
        
        # Check specific ports
        open_ports = []
        for port in self.COMMON_PORTS:
            if self.check_tcp_port(ip, port, timeout=2):
                open_ports.append(port)
            self.rate_limiter.wait()
        
        result.tcp_ports_open = open_ports
        
        # HTTP/HTTPS check
        http_status, https_status, response_time = self.check_http_status(ip)
        result.http_status = http_status
        result.https_status = https_status
        result.response_time = response_time
        
        # Reverse DNS
        try:
            result.reverse_dns = socket.gethostbyaddr(ip)[0]
        except:
            pass
        
        # Geolocation (rate-limited)
        self.rate_limiter.wait()
        geo_info = self.get_geolocation(ip)
        result.country = geo_info.get('country')
        result.country_name = geo_info.get('country_name')
        result.city = geo_info.get('city')
        result.region = geo_info.get('region')
        result.isp = geo_info.get('isp')
        result.organization = geo_info.get('organization')
        result.asn = geo_info.get('asn')
        
        # Web analysis (if applicable)
        if result.http_status or result.https_status:
            web_info = self.analyze_web_server(ip)
            result.web_server = web_info.get('server')
            result.web_title = web_info.get('title')
            result.detected_technologies = web_info.get('technologies', [])
            result.security_headers = web_info.get('security_headers', {})
            
            # SSL check
            if result.https_status:
                ssl_info = self.check_ssl(ip)
                result.ssl_valid = ssl_info.get('valid')
                result.ssl_issuer = ssl_info.get('issuer')
                result.ssl_expiry = ssl_info.get('expiry')
        
        return result
    
    def get_geolocation(self, ip: str) -> Dict:
        """Get IP geolocation info"""
        geo = {}
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                geo['country'] = data.get('countryCode')
                geo['country_name'] = data.get('country')
                geo['city'] = data.get('city')
                geo['region'] = data.get('regionName')
                geo['isp'] = data.get('isp')
                geo['organization'] = data.get('org')
                geo['asn'] = data.get('as')
        except:
            pass
        
        return geo
    
    def analyze_web_server(self, ip: str) -> Dict:
        """Analyze web server"""
        web_info = {}
        
        try:
            protocol = "https" if 443 in getattr(self, '_temp_ports', [443]) else "http"
            response = self.session.get(f"{protocol}://{ip}", timeout=5, verify=False)
            
            web_info['server'] = response.headers.get('Server', 'Unknown')
            
            security_headers = {}
            for header in ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']:
                if header in response.headers:
                    security_headers[header] = response.headers[header]
            web_info['security_headers'] = security_headers
            
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title:
                    web_info['title'] = soup.title.string.strip()[:100] if soup.title.string else None
            except:
                pass
            
            technologies = []
            html_lower = response.text.lower()
            
            if 'wordpress' in html_lower:
                technologies.append('WordPress')
            if 'react' in html_lower:
                technologies.append('React')
            if 'jquery' in html_lower:
                technologies.append('jQuery')
            
            web_info['technologies'] = technologies
        
        except:
            pass
        
        return web_info
    
    def check_ssl(self, ip: str) -> Dict:
        """Check SSL certificate"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['valid'] = True
                    
                    if 'issuer' in cert:
                        issuer = dict(x[0] for x in cert['issuer'])
                        ssl_info['issuer'] = issuer.get('organizationName', 'Unknown')
                    
                    if 'notAfter' in cert:
                        ssl_info['expiry'] = cert['notAfter']
        except:
            ssl_info['valid'] = False
        
        return ssl_info
    
    def batch_scan(self, ips: List[str], keyword: Optional[str] = None):
        """Scan multiple IPs with randomization and adaptive pacing"""
        self.log(f"Starting batch scan of {len(ips)} IPs", "SCAN")
        
        # Randomize IP order to avoid sequential subnet scanning
        randomized_ips = ips.copy()
        random.shuffle(randomized_ips)
        
        self.log("IPs randomized for stealth scanning", "INFO")
        
        live_count = 0
        dead_count = 0
        
        print(f"\n{Colors.BOLD}═══ SCANNING PROGRESS ═══{Colors.ENDC}\n")
        print(f"{Colors.OKBLUE}Phase 1: Quick liveness checks{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Phase 2: Comprehensive scans on live IPs only{Colors.ENDC}\n")
        
        # Phase 1: Quick liveness screening
        live_ips = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.check_liveness_lightweight, ip): ip for ip in randomized_ips}
            
            for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
                ip = futures[future]
                try:
                    is_live = future.result()
                    if is_live:
                        live_ips.append(ip)
                        live_count += 1
                    else:
                        dead_count += 1
                        # Still add dead result
                        self.results.append(IPAnalysisResult(ip=ip, is_live=False, source_keyword=keyword))
                    
                    progress = idx / len(randomized_ips) * 100
                    bar_length = 30
                    filled = int(bar_length * idx / len(randomized_ips))
                    bar = '█' * filled + '░' * (bar_length - filled)
                    
                    print(f"\r{Colors.OKCYAN}Phase 1 [{bar}] {progress:.1f}%{Colors.ENDC} | "
                          f"{Colors.OKGREEN}Live: {live_count}{Colors.ENDC} | "
                          f"{Colors.FAIL}Dead: {dead_count}{Colors.ENDC}", end='', flush=True)
                
                except Exception as e:
                    dead_count += 1
                    self.results.append(IPAnalysisResult(ip=ip, is_live=False, source_keyword=keyword))
        
        print(f"\n\n{Colors.OKGREEN}✓ Phase 1 complete: {live_count} live IPs identified{Colors.ENDC}\n")
        
        # Phase 2: Comprehensive scan of live IPs only
        if live_ips:
            print(f"{Colors.OKBLUE}Phase 2: Deep scanning {len(live_ips)} live IPs...{Colors.ENDC}\n")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(self.comprehensive_scan, ip, keyword): ip for ip in live_ips}
                
                for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    ip = futures[future]
                    try:
                        result = future.result()
                        self.results.append(result)
                        
                        progress = idx / len(live_ips) * 100
                        bar_length = 30
                        filled = int(bar_length * idx / len(live_ips))
                        bar = '█' * filled + '░' * (bar_length - filled)
                        
                        print(f"\r{Colors.OKCYAN}Phase 2 [{bar}] {progress:.1f}%{Colors.ENDC} | "
                              f"Scanned: {idx}/{len(live_ips)}", end='', flush=True)
                    
                    except Exception as e:
                        self.log(f"Error in deep scan of {ip}: {str(e)}", "ERROR")
        
        print(f"\n\n{Colors.BOLD}═══ SCAN COMPLETE ═══{Colors.ENDC}\n")
        self.log(f"Final results: {live_count} live, {dead_count} dead/unreachable", "SUCCESS")
    
    def display_results(self):
        """Display scan results"""
        if not self.results:
            self.log("No results to display", "WARNING")
            return
        
        live_results = [r for r in self.results if r.is_live]
        dead_results = [r for r in self.results if not r.is_live]
        
        print(f"\n{Colors.BOLD}{'═'*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'SCAN RESULTS SUMMARY':^80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'═'*80}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}🟢 Live IPs: {len(live_results)}{Colors.ENDC}")
        print(f"{Colors.FAIL}🔴 Dead/Unreachable IPs: {len(dead_results)}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}📊 Total Scanned: {len(self.results)}{Colors.ENDC}")
        
        if len(self.results) > 0:
            success_rate = len(live_results) / len(self.results) * 100
            print(f"{Colors.OKCYAN}📈 Success Rate: {success_rate:.1f}%{Colors.ENDC}\n")
        
        if live_results:
            print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}")
            print(f"{Colors.BOLD}LIVE IP DETAILS (showing first 20){Colors.ENDC}")
            print(f"{Colors.BOLD}{'─'*80}{Colors.ENDC}\n")
            
            for idx, result in enumerate(live_results[:20], 1):
                print(f"{Colors.OKGREEN}[{idx}] {result.ip}{Colors.ENDC}")
                
                if result.country_name:
                    print(f"    ├─ Location: {result.city or 'Unknown'}, {result.country_name} ({result.country})")
                
                if result.isp:
                    print(f"    ├─ ISP: {result.isp}")
                
                if result.organization:
                    print(f"    ├─ Organization: {result.organization}")
                
                if result.reverse_dns:
                    print(f"    ├─ Reverse DNS: {result.reverse_dns}")
                
                if result.tcp_ports_open:
                    print(f"    ├─ Open Ports: {', '.join(map(str, result.tcp_ports_open))}")
                
                if result.http_status or result.https_status:
                    print(f"    ├─ HTTP: {result.http_status or 'N/A'} | HTTPS: {result.https_status or 'N/A'}")
                
                if result.web_server:
                    print(f"    ├─ Web Server: {result.web_server}")
                
                if result.web_title:
                    print(f"    ├─ Title: {result.web_title}")
                
                if result.detected_technologies:
                    print(f"    ├─ Technologies: {', '.join(result.detected_technologies)}")
                
                if result.ssl_valid:
                    print(f"    ├─ SSL: Valid ✓ ({result.ssl_issuer})")
                
                if result.response_time:
                    print(f"    └─ Response Time: {result.response_time*1000:.0f}ms")
                else:
                    print(f"    └─")
                
                print()
            
            if len(live_results) > 20:
                print(f"{Colors.WARNING}... and {len(live_results) - 20} more live IPs (see export files for full list){Colors.ENDC}\n")
    
    def export_results(self):
        """Export results to files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        json_file = f"spiderweb_results_{timestamp}.json"
        self.export_json(json_file)
        
        csv_file = f"spiderweb_results_{timestamp}.csv"
        self.export_csv(csv_file)
        
        txt_file = f"spiderweb_report_{timestamp}.txt"
        self.export_txt(txt_file)
        
        print(f"\n{Colors.BOLD}═══ EXPORT COMPLETE ═══{Colors.ENDC}\n")
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} JSON: {json_file}")
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} CSV: {csv_file}")
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} TXT: {txt_file}\n")
    
    def export_json(self, filename: str):
        """Export to JSON"""
        output = {
            'metadata': {
                'tool': 'SpiderWeb CLI',
                'version': self.VERSION,
                'author': 'g33l0',
                'timestamp': datetime.now().isoformat(),
                'total_scanned': len(self.results),
                'live_count': sum(1 for r in self.results if r.is_live),
                'dead_count': sum(1 for r in self.results if not r.is_live)
            },
            'results': [asdict(r) for r in self.results]
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
    
    def export_csv(self, filename: str):
        """Export to CSV"""
        with open(filename, 'w', newline='') as f:
            fieldnames = ['ip', 'is_live', 'country', 'city', 'isp', 'organization',
                         'reverse_dns', 'open_ports', 'http_status', 'https_status',
                         'web_server', 'ssl_valid', 'response_time_ms']
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.results:
                writer.writerow({
                    'ip': result.ip,
                    'is_live': result.is_live,
                    'country': result.country,
                    'city': result.city,
                    'isp': result.isp,
                    'organization': result.organization,
                    'reverse_dns': result.reverse_dns,
                    'open_ports': ','.join(map(str, result.tcp_ports_open)),
                    'http_status': result.http_status,
                    'https_status': result.https_status,
                    'web_server': result.web_server,
                    'ssl_valid': result.ssl_valid,
                    'response_time_ms': round(result.response_time * 1000) if result.response_time else None
                })
    
    def export_txt(self, filename: str):
        """Export detailed text report"""
        with open(filename, 'w') as f:
            f.write("="*80 + "\n")
            f.write("SpiderWeb 🕸️ - IP Analysis Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Author: g33l0\n")
            f.write("="*80 + "\n\n")
            
            live = [r for r in self.results if r.is_live]
            dead = [r for r in self.results if not r.is_live]
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*80 + "\n")
            f.write(f"Total IPs Scanned: {len(self.results)}\n")
            f.write(f"Live IPs: {len(live)}\n")
            f.write(f"Dead/Unreachable IPs: {len(dead)}\n")
            
            if len(self.results) > 0:
                f.write(f"Success Rate: {len(live)/len(self.results)*100:.1f}%\n")
            f.write("\n")
            
            f.write("LIVE IP DETAILED ANALYSIS\n")
            f.write("="*80 + "\n\n")
            
            for idx, result in enumerate(live, 1):
                f.write(f"[{idx}] {result.ip}\n")
                f.write("-"*80 + "\n")
                f.write(f"Location: {result.city or 'Unknown'}, {result.country_name or 'Unknown'}\n")
                f.write(f"ISP: {result.isp or 'Unknown'}\n")
                f.write(f"Organization: {result.organization or 'Unknown'}\n")
                f.write(f"ASN: {result.asn or 'Unknown'}\n")
                
                if result.reverse_dns:
                    f.write(f"Reverse DNS: {result.reverse_dns}\n")
                
                f.write(f"Open Ports: {result.tcp_ports_open or 'None detected'}\n")
                f.write(f"HTTP Status: {result.http_status or 'N/A'}\n")
                f.write(f"HTTPS Status: {result.https_status or 'N/A'}\n")
                
                if result.web_server:
                    f.write(f"Web Server: {result.web_server}\n")
                
                if result.web_title:
                    f.write(f"Page Title: {result.web_title}\n")
                
                if result.detected_technologies:
                    f.write(f"Technologies: {', '.join(result.detected_technologies)}\n")
                
                if result.ssl_valid is not None:
                    f.write(f"SSL Valid: {'Yes' if result.ssl_valid else 'No'}\n")
                    if result.ssl_valid and result.ssl_issuer:
                        f.write(f"SSL Issuer: {result.ssl_issuer}\n")
                
                if result.response_time:
                    f.write(f"Response Time: {result.response_time*1000:.2f}ms\n")
                
                f.write("\n")


def main():
    """Main CLI entry point"""
    try:
        import dns.resolver
        from bs4 import BeautifulSoup
    except ImportError:
        print("📦 Installing required packages...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "dnspython", "beautifulsoup4", "-q"])
        import dns.resolver
        from bs4 import BeautifulSoup
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    cli = SpiderWebCLI()
    cli.print_banner()
    
    try:
        method = cli.prompt_input_method()
        
        ips = []
        keyword = None
        
        if method == "keyword":
            keyword, requested_count = cli.get_keyword_input()
            
            print(f"\n{Colors.BOLD}{'═'*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}IP GENERATION SUMMARY{Colors.ENDC}")
            print(f"{Colors.BOLD}{'═'*70}{Colors.ENDC}\n")
            print(f"{Colors.OKBLUE}Requested IPs: {requested_count}{Colors.ENDC}")
            
            # Generate IPs with retry logic
            ip_set, source_stats = cli.ip_generator.generate_ips(keyword, requested_count)
            ips = list(ip_set)
            
            print(f"\n{Colors.BOLD}{'─'*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}GENERATION RESULTS{Colors.ENDC}")
            print(f"{Colors.BOLD}{'─'*70}{Colors.ENDC}\n")
            
            print(f"{Colors.OKGREEN}✓ Generated IPs: {len(ips)}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}  Requested: {requested_count}{Colors.ENDC}")
            
            if len(ips) < requested_count:
                shortfall = requested_count - len(ips)
                print(f"\n{Colors.WARNING}⚠️  WARNING: Could only generate {len(ips)}/{requested_count} IPs{Colors.ENDC}")
                print(f"{Colors.WARNING}   Shortfall: {shortfall} IPs ({shortfall/requested_count*100:.1f}%){Colors.ENDC}\n")
                print(f"{Colors.OKBLUE}Reasons:{Colors.ENDC}")
                print(f"  • Limited public data available for keyword '{keyword}'")
                print(f"  • DNS resolution failures for generated domains")
                print(f"  • Private/reserved IP addresses filtered out")
                print(f"  • Duplicate IPs removed across all sources\n")
                
                print(f"{Colors.OKBLUE}Sources used:{Colors.ENDC}")
                for source, count in source_stats.items():
                    print(f"  • {source}: {count} IPs")
                
                print(f"\n{Colors.OKBLUE}Suggestions:{Colors.ENDC}")
                print(f"  • Try a more common keyword (e.g., 'google', 'amazon', 'microsoft')")
                print(f"  • Use a company/brand name with known infrastructure")
                print(f"  • Reduce the requested count")
                print(f"  • Use file input method with known IPs\n")
                
                proceed = input(f"{Colors.BOLD}Proceed with {len(ips)} IPs? (y/n): {Colors.ENDC}").strip().lower()
                if proceed != 'y':
                    print(f"\n{Colors.WARNING}⚠️  Scan cancelled by user.{Colors.ENDC}")
                    sys.exit(0)
            else:
                print(f"{Colors.OKGREEN}✓ Successfully generated all requested IPs{Colors.ENDC}\n")
                print(f"{Colors.OKBLUE}Sources used:{Colors.ENDC}")
                for source, count in source_stats.items():
                    print(f"  • {source}: {count} IPs")
            
            if not ips:
                cli.log("Could not generate any IPs from keyword", "ERROR")
                sys.exit(1)
        
        elif method == "file":
            ips = cli.read_ips_from_file("ips.txt")
            
            print(f"\n{Colors.BOLD}{'═'*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}FILE INPUT SUMMARY{Colors.ENDC}")
            print(f"{Colors.BOLD}{'═'*70}{Colors.ENDC}\n")
            print(f"{Colors.OKGREEN}✓ Loaded IPs: {len(ips)}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}  Source: ips.txt{Colors.ENDC}\n")
        
        # Display scan configuration
        print(f"{Colors.BOLD}{'═'*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}SCAN CONFIGURATION{Colors.ENDC}")
        print(f"{Colors.BOLD}{'═'*70}{Colors.ENDC}\n")
        print(f"{Colors.OKBLUE}Total IPs to scan: {len(ips)}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Rate limit: 5 requests/second{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Scan strategy: Two-phase (liveness → deep scan){Colors.ENDC}")
        print(f"{Colors.OKBLUE}IP order: Randomized for stealth{Colors.ENDC}\n")
        
        # Perform batch scan
        cli.batch_scan(ips, keyword)
        
        # Display results
        cli.display_results()
        
        # Export results
        export = input(f"\n{Colors.BOLD}Export results to files? (y/n): {Colors.ENDC}").strip().lower()
        if export == 'y':
            cli.export_results()
        
        print(f"\n{Colors.OKGREEN}✅ SpiderWeb scan completed successfully!{Colors.ENDC}\n")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}⚠️  Scan interrupted by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}❌ Fatal error: {str(e)}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()