#!/usr/bin/env python3
"""
██╗  ██╗ █████╗ ██████╗ ███╗   ███╗ █████╗ ███████╗    ██╗███╗   ██╗███████╗ ██████╗
██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝    ██║████╗  ██║██╔════╝██╔═══██╗
█████╔╝ ███████║██████╔╝██╔████╔██║███████║███████╗    ██║██╔██╗ ██║█████╗  ██║   ██║
██╔═██╗ ██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║╚════██║    ██║██║╚██╗██║██╔══╝  ██║   ██║
██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║███████║    ██║██║ ╚████║██║     ╚██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝

kArmas_info — The Strongest Web OSINT & Intelligence Crawler Ever Built
Version  : 2.0.0
Author   : kArmas
License  : MIT

Features:
  - Deep recursive web crawling with multithreading
  - URL/link extraction (internal + external)
  - Email harvesting
  - Phone number detection
  - Social media profile discovery
  - JavaScript file analysis
  - Subdomain enumeration from page content
  - Secret/API key pattern detection
  - File download discovery (.pdf, .doc, .xls, .zip, etc.)
  - Form & input field extraction
  - Comment extraction from HTML/JS
  - DNS information gathering
  - Whois lookup
  - IP geolocation
  - HTTP header analysis
  - Technology fingerprinting
  - Robots.txt / sitemap.xml parsing
  - Wayback Machine (archived URLs)
  - Export to JSON, CSV, TXT
  - Beautiful colored terminal output
  - Progress bar with live stats
"""

import argparse
import csv
import json
import os
import re
import socket
import sys
import time
import threading
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue, Empty

# ──────────────────────────────────────────────
# Dependency check & graceful install hints
# ──────────────────────────────────────────────
def check_dep(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False

MISSING = []
for pkg in ["requests", "bs4", "colorama", "tqdm", "dns"]:
    if not check_dep(pkg):
        MISSING.append(pkg)

if MISSING:
    print(f"\n[!] Missing dependencies: {', '.join(MISSING)}")
    print(f"    Run:  pip install {' '.join(MISSING).replace('bs4','beautifulsoup4').replace('dns','dnspython')}\n")
    sys.exit(1)

import requests
import dns.resolver
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# ──────────────────────────────────────────────
# ANSI Banner
# ──────────────────────────────────────────────
BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║  {Fore.YELLOW}██╗  ██╗ █████╗ ██████╗ ███╗   ███╗ █████╗ ███████╗{Fore.RED}       ║
║  {Fore.YELLOW}██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝{Fore.RED}       ║
║  {Fore.YELLOW}█████╔╝ ███████║██████╔╝██╔████╔██║███████║███████╗ {Fore.RED}       ║
║  {Fore.YELLOW}██╔═██╗ ██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║╚════██║{Fore.RED}       ║
║  {Fore.YELLOW}██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║███████║{Fore.RED}       ║
║  {Fore.YELLOW}╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝{Fore.RED}       ║
║         {Fore.CYAN}██╗███╗   ██╗███████╗ ██████╗ {Fore.RED}                        ║
║         {Fore.CYAN}██║████╗  ██║██╔════╝██╔═══██╗{Fore.RED}                        ║
║         {Fore.CYAN}██║██╔██╗ ██║█████╗  ██║   ██║{Fore.RED}                        ║
║         {Fore.CYAN}██║██║╚██╗██║██╔══╝  ██║   ██║{Fore.RED}                        ║
║         {Fore.CYAN}██║██║ ╚████║██║     ╚██████╔╝{Fore.RED}                        ║
║         {Fore.CYAN}╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ {Fore.RED}                        ║
║  {Fore.WHITE}The Strongest Web OSINT & Intelligence Crawler Ever Built{Fore.RED}  ║
║  {Fore.GREEN}v2.0.0  |  github: kArmas  |  MIT License{Fore.RED}                    ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ──────────────────────────────────────────────
# Regex Patterns
# ──────────────────────────────────────────────
PATTERNS = {
    "emails": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE
    ),
    "phones": re.compile(
        r"(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}"
    ),
    "subdomains": re.compile(r"(?:[a-z0-9\-]+\.)+[a-z]{2,}", re.IGNORECASE),
    "social_facebook": re.compile(r"facebook\.com/[A-Za-z0-9._\-/]+"),
    "social_twitter": re.compile(r"(?:twitter|x)\.com/[A-Za-z0-9._\-]+"),
    "social_instagram": re.compile(r"instagram\.com/[A-Za-z0-9._\-]+"),
    "social_linkedin": re.compile(r"linkedin\.com/(?:in|company)/[A-Za-z0-9._\-]+"),
    "social_github": re.compile(r"github\.com/[A-Za-z0-9._\-]+"),
    "social_youtube": re.compile(r"youtube\.com/(?:channel|user|c)/[A-Za-z0-9._\-]+"),
    "social_tiktok": re.compile(r"tiktok\.com/@[A-Za-z0-9._\-]+"),
    "api_keys_google": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "api_keys_aws": re.compile(r"AKIA[0-9A-Z]{16}"),
    "api_keys_github": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "api_keys_stripe": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "api_keys_slack": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]+"),
    "api_keys_jwt": re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"),
    "api_keys_generic": re.compile(r"(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?", re.IGNORECASE),
    "passwords_generic": re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]", re.IGNORECASE),
    "ip_addresses": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "files_interesting": re.compile(
        r"https?://[^\s\"'<>]+\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz|7z|rar|sql|bak|env|config|cfg|conf|log|key|pem|crt|csv|xml|json|yaml|yml)\b",
        re.IGNORECASE,
    ),
    "html_comments": re.compile(r"<!--(.*?)-->", re.DOTALL),
    "js_comments": re.compile(r"(?://[^\n]*|/\*.*?\*/)", re.DOTALL),
    "js_files": re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE),
    "s3_buckets": re.compile(r"[a-z0-9\-\.]+\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com", re.IGNORECASE),
    "internal_paths": re.compile(r'(?:href|src|action|data\-url)=["\']([/][^"\'<>\s]{2,})["\']', re.IGNORECASE),
}

# Technologies to fingerprint (header + body patterns)
TECH_SIGNATURES = {
    "WordPress": [re.compile(r"wp-content|wp-includes|wordpress", re.I)],
    "Drupal": [re.compile(r"Drupal|drupal\.org|/sites/default/", re.I)],
    "Joomla": [re.compile(r"joomla|/components/com_|/modules/mod_", re.I)],
    "React": [re.compile(r"react\.production|__react|ReactDOM", re.I)],
    "Angular": [re.compile(r"ng-version|angular\.min\.js|ng-app", re.I)],
    "Vue.js": [re.compile(r"vue\.min\.js|__vue__|vue\.runtime", re.I)],
    "jQuery": [re.compile(r"jquery[\.\-][\d]+|jQuery\s*\(", re.I)],
    "Bootstrap": [re.compile(r"bootstrap\.min\.css|bootstrap\.bundle", re.I)],
    "Next.js": [re.compile(r"__NEXT_DATA__|_next/static", re.I)],
    "Laravel": [re.compile(r"laravel_session|Laravel", re.I)],
    "Django": [re.compile(r"csrfmiddlewaretoken|django", re.I)],
    "Flask": [re.compile(r"Werkzeug|flask", re.I)],
    "Express.js": [re.compile(r"Express|connect\.sid", re.I)],
    "Nginx": [re.compile(r"nginx", re.I)],
    "Apache": [re.compile(r"Apache", re.I)],
    "IIS": [re.compile(r"IIS|ASP\.NET", re.I)],
    "Cloudflare": [re.compile(r"cloudflare|__cfduid|cf-ray", re.I)],
    "Google Analytics": [re.compile(r"google-analytics\.com|ga\.js|gtag", re.I)],
    "Facebook Pixel": [re.compile(r"connect\.facebook\.net|fbevents\.js", re.I)],
    "Shopify": [re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I)],
    "Wix": [re.compile(r"wix\.com|_wix_browser_sess", re.I)],
}

FILE_TYPES = {
    "documents": r"\.(pdf|doc|docx|ppt|pptx|xls|xlsx|odt|rtf|txt)(\?.*)?$",
    "archives": r"\.(zip|tar|gz|tgz|7z|rar|bz2)(\?.*)?$",
    "data": r"\.(json|xml|csv|sql|db|sqlite)(\?.*)?$",
    "config": r"\.(env|cfg|conf|config|ini|yaml|yml|toml)(\?.*)?$",
    "certs": r"\.(pem|crt|cer|key|p12|pfx)(\?.*)?$",
    "images": r"\.(jpg|jpeg|png|gif|svg|webp|ico|bmp)(\?.*)?$",
    "media": r"\.(mp4|mp3|wav|avi|mov|mkv|webm)(\?.*)?$",
}

# ──────────────────────────────────────────────
# Utility helpers
# ──────────────────────────────────────────────
def log(msg, level="info", verbose=True):
    if not verbose and level == "debug":
        return
    colors = {
        "info":    Fore.CYAN    + "[*] ",
        "ok":      Fore.GREEN   + "[+] ",
        "warn":    Fore.YELLOW  + "[!] ",
        "error":   Fore.RED     + "[-] ",
        "debug":   Fore.MAGENTA + "[~] ",
        "section": Fore.WHITE   + Style.BRIGHT + "\n[■] ",
    }
    prefix = colors.get(level, "[?] ")
    print(f"{prefix}{msg}{Style.RESET_ALL}")

def normalize_url(url, base):
    url = url.strip()
    if not url or url.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
        return None
    if url.startswith("//"):
        scheme = urllib.parse.urlparse(base).scheme
        return f"{scheme}:{url}"
    if url.startswith("/"):
        parsed = urllib.parse.urlparse(base)
        return f"{parsed.scheme}://{parsed.netloc}{url}"
    if not url.startswith("http"):
        return urllib.parse.urljoin(base, url)
    return url

def same_domain(url, base_domain):
    try:
        return urllib.parse.urlparse(url).netloc.rstrip("/").endswith(base_domain.lstrip("www.").lstrip("."))
    except Exception:
        return False

def extract_domain(url):
    return urllib.parse.urlparse(url).netloc

def get_base_domain(url):
    netloc = urllib.parse.urlparse(url).netloc
    parts = netloc.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return netloc

def classify_file(url):
    url_lower = url.lower()
    for ftype, pattern in FILE_TYPES.items():
        if re.search(pattern, url_lower):
            return ftype
    return None

# ──────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

def fetch(url, timeout=10, proxies=None, cookies=None, headers=None):
    try:
        h = {**DEFAULT_HEADERS, **(headers or {})}
        r = requests.get(
            url, timeout=timeout, verify=False,
            headers=h, proxies=proxies, cookies=cookies,
            allow_redirects=True,
        )
        return r
    except requests.exceptions.RequestException:
        return None

# ──────────────────────────────────────────────
# Intelligence Extractors
# ──────────────────────────────────────────────
def extract_all(text, url=""):
    results = defaultdict(set)
    for key, pattern in PATTERNS.items():
        found = pattern.findall(text)
        for item in found:
            if isinstance(item, tuple):
                item = item[0]
            item = item.strip()
            if item:
                results[key].add(item)
    return results

def fingerprint_tech(response):
    found = set()
    body = (response.text or "").lower() if response else ""
    headers_str = " ".join(f"{k}: {v}" for k, v in (response.headers or {}).items()).lower()
    combined = body + " " + headers_str
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if pattern.search(combined):
                found.add(tech)
                break
    return found

def analyze_headers(response):
    info = {}
    if not response:
        return info
    h = response.headers
    interesting = [
        "Server", "X-Powered-By", "X-Frame-Options", "X-XSS-Protection",
        "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
        "Access-Control-Allow-Origin", "Set-Cookie", "X-AspNet-Version",
        "X-Generator", "X-Drupal-Cache", "CF-Ray", "Via", "X-Cache",
    ]
    for h_key in interesting:
        val = h.get(h_key)
        if val:
            info[h_key] = val
    return info

def parse_robots(base_url, proxies=None):
    paths = set()
    url = f"{base_url.rstrip('/')}/robots.txt"
    r = fetch(url, proxies=proxies)
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    paths.add(parts[1].strip())
    return paths

def parse_sitemap(base_url, proxies=None):
    urls = set()
    url = f"{base_url.rstrip('/')}/sitemap.xml"
    r = fetch(url, proxies=proxies)
    if r and r.status_code == 200:
        found = re.findall(r"<loc>(.*?)</loc>", r.text, re.IGNORECASE)
        urls.update(found)
    return urls

def dns_recon(domain):
    info = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            info[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return info

def ip_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def wayback_urls(domain, limit=50):
    urls = set()
    api = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&collapse=urlkey&limit={limit}"
    r = fetch(api, timeout=15)
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            line = line.strip()
            if line:
                urls.add(line)
    return urls

def get_js_content(js_url, proxies=None):
    r = fetch(js_url, proxies=proxies)
    if r and r.status_code == 200:
        return r.text
    return ""

# ──────────────────────────────────────────────
# Core Crawler
# ──────────────────────────────────────────────
class KArmasInfo:
    def __init__(self, args):
        self.target      = args.url.rstrip("/")
        self.depth       = args.depth
        self.threads     = args.threads
        self.timeout     = args.timeout
        self.output_dir  = args.output
        self.verbose      = args.verbose
        self.cookies_str = args.cookies
        self.proxy       = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        self.delay       = args.delay
        self.include_ext = args.include_ext
        self.exclude_ext = args.exclude_ext

        self.base_domain  = get_base_domain(self.target)
        self.start_time   = datetime.now()

        # Data stores
        self.visited        = set()
        self.queue          = Queue()
        self.lock           = threading.Lock()

        self.results = {
            "target":           self.target,
            "scan_time":        "",
            "urls_internal":    set(),
            "urls_external":    set(),
            "emails":           set(),
            "phones":           set(),
            "social_facebook":  set(),
            "social_twitter":   set(),
            "social_instagram": set(),
            "social_linkedin":  set(),
            "social_github":    set(),
            "social_youtube":   set(),
            "social_tiktok":    set(),
            "api_keys_google":  set(),
            "api_keys_aws":     set(),
            "api_keys_github":  set(),
            "api_keys_stripe":  set(),
            "api_keys_slack":   set(),
            "api_keys_jwt":     set(),
            "api_keys_generic": set(),
            "passwords_generic":set(),
            "ip_addresses":     set(),
            "subdomains":       set(),
            "files":            defaultdict(set),
            "js_files":         set(),
            "html_comments":    set(),
            "js_comments":      set(),
            "s3_buckets":       set(),
            "internal_paths":   set(),
            "technologies":     set(),
            "headers":          {},
            "dns":              {},
            "robots_paths":     set(),
            "sitemap_urls":     set(),
            "wayback_urls":     set(),
        }

        self.cookies = {}
        if self.cookies_str:
            for pair in self.cookies_str.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self.cookies[k.strip()] = v.strip()

        os.makedirs(self.output_dir, exist_ok=True)

    # ── Merge extracted data into global results ──
    def _merge(self, extracted):
        with self.lock:
            for key, values in extracted.items():
                if key in self.results and isinstance(self.results[key], set):
                    self.results[key].update(values)

    # ── Crawl a single URL ──
    def _crawl(self, url, depth):
        if depth < 0:
            return
        with self.lock:
            if url in self.visited:
                return
            self.visited.add(url)

        if self.delay > 0:
            time.sleep(self.delay)

        r = fetch(url, timeout=self.timeout, proxies=self.proxy, cookies=self.cookies)
        if not r:
            return

        # Header analysis (first page only)
        with self.lock:
            if not self.results["headers"]:
                self.results["headers"] = analyze_headers(r)
                self.results["technologies"].update(fingerprint_tech(r))

        content_type = r.headers.get("Content-Type", "")
        if "text" not in content_type and "javascript" not in content_type and "json" not in content_type:
            return

        text = r.text
        extracted = extract_all(text, url)

        # Classify files found in URLs
        for file_url in extracted.get("files_interesting", set()):
            ftype = classify_file(file_url)
            if ftype:
                with self.lock:
                    self.results["files"][ftype].add(file_url)

        self._merge(extracted)

        # Parse HTML for links
        try:
            soup = BeautifulSoup(text, "html.parser")
        except Exception:
            return

        tags = soup.find_all(["a", "link", "script", "img", "form", "iframe", "area"])
        new_urls = set()
        for tag in tags:
            for attr in ["href", "src", "action", "data-url", "data-href"]:
                raw = tag.get(attr)
                if raw:
                    norm = normalize_url(raw, url)
                    if norm:
                        ftype = classify_file(norm)
                        if ftype:
                            with self.lock:
                                self.results["files"][ftype].add(norm)
                        if same_domain(norm, self.base_domain):
                            with self.lock:
                                self.results["urls_internal"].add(norm)
                            if norm not in self.visited:
                                new_urls.add(norm)
                        else:
                            with self.lock:
                                self.results["urls_external"].add(norm)

        # Extract subdomain candidates
        with self.lock:
            for sd in extracted.get("subdomains", set()):
                if self.base_domain in sd and sd != self.base_domain:
                    self.results["subdomains"].add(sd)

        # Analyze inline JS files
        js_links = set()
        for tag in soup.find_all("script", src=True):
            js_url = normalize_url(tag["src"], url)
            if js_url:
                js_links.add(js_url)
                with self.lock:
                    self.results["js_files"].add(js_url)

        for js_url in js_links:
            js_text = get_js_content(js_url, self.proxy)
            if js_text:
                js_extracted = extract_all(js_text, js_url)
                self._merge(js_extracted)

        # Queue next URLs
        for next_url in new_urls:
            self.queue.put((next_url, depth - 1))

    # ── Worker thread ──
    def _worker(self, pbar):
        while True:
            try:
                url, depth = self.queue.get(timeout=3)
                self._crawl(url, depth)
                pbar.update(1)
                pbar.set_postfix({
                    "visited": len(self.visited),
                    "emails":  len(self.results["emails"]),
                    "files":   sum(len(v) for v in self.results["files"].values()),
                })
                self.queue.task_done()
            except Empty:
                break
            except Exception as e:
                self.queue.task_done()

    # ── Pre-scan reconnaissance ──
    def _recon(self):
        log("Starting reconnaissance phase...", "section")
        domain = extract_domain(self.target)

        log(f"Resolving IP for {domain}", "info")
        ip = ip_lookup(domain)
        if ip:
            log(f"IP Address: {Fore.GREEN}{ip}", "ok")
            with self.lock:
                self.results["ip_addresses"].add(ip)

        log("Running DNS enumeration...", "info")
        dns_data = dns_recon(domain)
        with self.lock:
            self.results["dns"] = dns_data
        for rtype, records in dns_data.items():
            log(f"DNS {rtype}: {', '.join(records[:3])}", "ok")

        log("Fetching robots.txt...", "info")
        robots = parse_robots(self.target, self.proxy)
        with self.lock:
            self.results["robots_paths"].update(robots)
        if robots:
            log(f"robots.txt paths: {len(robots)} entries", "ok")

        log("Fetching sitemap.xml...", "info")
        sitemap = parse_sitemap(self.target, self.proxy)
        with self.lock:
            self.results["sitemap_urls"].update(sitemap)
            for u in sitemap:
                self.queue.put((u, self.depth))
        if sitemap:
            log(f"Sitemap URLs found: {len(sitemap)}", "ok")

        log("Querying Wayback Machine...", "info")
        wb = wayback_urls(domain)
        with self.lock:
            self.results["wayback_urls"].update(wb)
        if wb:
            log(f"Wayback Machine archived URLs: {len(wb)}", "ok")

    # ── Main run ──
    def run(self):
        print(BANNER)
        log(f"Target  : {Fore.YELLOW}{self.target}", "info")
        log(f"Depth   : {self.depth}  |  Threads: {self.threads}  |  Timeout: {self.timeout}s", "info")
        log(f"Output  : {self.output_dir}", "info")
        print()

        # Recon
        self._recon()

        # Seed the queue
        self.queue.put((self.target, self.depth))

        # Crawl
        log("Starting deep crawl...", "section")
        pbar = tqdm(
            desc=f"{Fore.CYAN}Crawling{Style.RESET_ALL}",
            unit="pages",
            dynamic_ncols=True,
            colour="cyan",
        )

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._worker, pbar) for _ in range(self.threads)]
            for f in as_completed(futures):
                pass

        pbar.close()

        self.results["scan_time"] = str(datetime.now() - self.start_time)

        # Print summary
        self._print_summary()

        # Export
        self._export()

    # ── Summary ──
    def _print_summary(self):
        r = self.results
        print()
        log("═" * 60, "section")
        log(f"SCAN COMPLETE in {r['scan_time']}", "ok")
        log("═" * 60, "info")

        cats = [
            ("Internal URLs",     len(r["urls_internal"])),
            ("External URLs",     len(r["urls_external"])),
            ("Emails",            len(r["emails"])),
            ("Phone Numbers",     len(r["phones"])),
            ("Subdomains",        len(r["subdomains"])),
            ("JS Files",          len(r["js_files"])),
            ("S3 Buckets",        len(r["s3_buckets"])),
            ("HTML Comments",     len(r["html_comments"])),
            ("Social Profiles",   sum(len(r[k]) for k in r if k.startswith("social_"))),
            ("API Keys/Secrets",  sum(len(r[k]) for k in r if k.startswith("api_keys_"))),
            ("Passwords Found",   len(r["passwords_generic"])),
            ("Files (docs)",      len(r["files"].get("documents", set()))),
            ("Files (archives)",  len(r["files"].get("archives", set()))),
            ("Files (config)",    len(r["files"].get("config", set()))),
            ("Files (certs)",     len(r["files"].get("certs", set()))),
            ("Technologies",      len(r["technologies"])),
            ("Wayback URLs",      len(r["wayback_urls"])),
            ("Robots paths",      len(r["robots_paths"])),
        ]
        for name, count in cats:
            color = Fore.GREEN if count > 0 else Fore.WHITE
            print(f"  {Fore.CYAN}{name:<25}{color}{count}{Style.RESET_ALL}")

        if r["technologies"]:
            print(f"\n  {Fore.YELLOW}Technologies detected:{Style.RESET_ALL}")
            for tech in sorted(r["technologies"]):
                print(f"    {Fore.GREEN}✓ {tech}{Style.RESET_ALL}")

        if r["emails"]:
            print(f"\n  {Fore.YELLOW}Emails:{Style.RESET_ALL}")
            for e in sorted(r["emails"])[:10]:
                print(f"    {Fore.GREEN}{e}{Style.RESET_ALL}")
            if len(r["emails"]) > 10:
                print(f"    ... and {len(r['emails']) - 10} more")

        # Warn about secrets
        secrets_total = sum(len(r[k]) for k in r if k.startswith("api_keys_")) + len(r["passwords_generic"])
        if secrets_total > 0:
            print(f"\n  {Fore.RED}⚠  POTENTIAL SECRETS FOUND: {secrets_total} — check output files!{Style.RESET_ALL}")

    # ── Export ──
    def _sets_to_lists(self, obj):
        if isinstance(obj, set):
            return sorted(obj)
        if isinstance(obj, dict):
            return {k: self._sets_to_lists(v) for k, v in obj.items()}
        if isinstance(obj, defaultdict):
            return {k: self._sets_to_lists(v) for k, v in obj.items()}
        return obj

    def _export(self):
        log("Exporting results...", "section")
        domain_safe = re.sub(r"[^\w\-]", "_", self.base_domain)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(self.output_dir, f"kArmas_{domain_safe}_{ts}")

        # JSON
        json_path = f"{base}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self._sets_to_lists(self.results), f, indent=2, ensure_ascii=False)
        log(f"JSON  → {json_path}", "ok")

        # TXT summary
        txt_path = f"{base}.txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"kArmas_info Report\n")
            f.write(f"Target : {self.results['target']}\n")
            f.write(f"Time   : {self.results['scan_time']}\n\n")
            for key, val in self.results.items():
                if isinstance(val, (set, list)) and val:
                    f.write(f"\n== {key.upper()} ==\n")
                    items = sorted(val) if isinstance(val, set) else val
                    for item in items:
                        f.write(f"  {item}\n")
                elif isinstance(val, (dict, defaultdict)) and val:
                    f.write(f"\n== {key.upper()} ==\n")
                    for k2, v2 in val.items():
                        if isinstance(v2, (set, list)):
                            for item in sorted(v2):
                                f.write(f"  [{k2}] {item}\n")
                        else:
                            f.write(f"  {k2}: {v2}\n")
        log(f"TXT   → {txt_path}", "ok")

        # CSV (flat key=value for spreadsheet import)
        csv_path = f"{base}.csv"
        rows = []
        for key, val in self.results.items():
            if isinstance(val, (set, list)):
                for item in val:
                    rows.append({"category": key, "value": str(item)})
            elif isinstance(val, (dict, defaultdict)):
                for k2, v2 in val.items():
                    if isinstance(v2, (set, list)):
                        for item in v2:
                            rows.append({"category": f"{key}_{k2}", "value": str(item)})
                    else:
                        rows.append({"category": f"{key}_{k2}", "value": str(v2)})
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["category", "value"])
            writer.writeheader()
            writer.writerows(rows)
        log(f"CSV   → {csv_path}", "ok")

        log(f"All results saved to: {Fore.YELLOW}{self.output_dir}", "ok")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="kArmas_info",
        description="The Strongest Web OSINT & Intelligence Crawler — kArmas_info",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python kArmas_info.py -u https://example.com
  python kArmas_info.py -u https://example.com -d 3 -t 20
  python kArmas_info.py -u https://example.com --proxy http://127.0.0.1:8080
  python kArmas_info.py -u https://example.com -o results/ -v
        """,
    )
    p.add_argument("-u",  "--url",         required=True,  help="Target URL (e.g. https://example.com)")
    p.add_argument("-d",  "--depth",       type=int,  default=2, help="Crawl depth (default: 2)")
    p.add_argument("-t",  "--threads",     type=int,  default=10, help="Number of threads (default: 10)")
    p.add_argument(       "--timeout",     type=int,  default=10, help="HTTP request timeout in seconds (default: 10)")
    p.add_argument("-o",  "--output",      default="kArmas_output", help="Output directory (default: kArmas_output)")
    p.add_argument(       "--proxy",       default=None, help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument(       "--cookies",     default=None, help='Cookies string (e.g. "session=abc; token=xyz")')
    p.add_argument(       "--delay",       type=float, default=0, help="Delay between requests in seconds (default: 0)")
    p.add_argument(       "--include-ext", default=None, help="Only crawl URLs with these extensions (comma-separated)")
    p.add_argument(       "--exclude-ext", default=None, help="Skip URLs with these extensions (comma-separated)")
    p.add_argument("-v",  "--verbose",     action="store_true", help="Enable verbose/debug output")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate URL
    parsed = urllib.parse.urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        log("Invalid URL — include scheme (e.g. https://example.com)", "error")
        sys.exit(1)

    try:
        tool = KArmasInfo(args)
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
