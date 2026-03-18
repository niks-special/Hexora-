#!/usr/bin/env python3
# ============================================================
#   HEXORA - Advanced Vulnerability Intelligence Engine
#   Author  : Nikhil Patil
#   Platform: Kali Linux
#   Version : 1.0.0
# ============================================================

import sys
import os
import socket
import ssl
import re
import json
import time
import argparse
import threading
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────
#  ANSI COLOUR PALETTE
# ─────────────────────────────────────────────
class C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    CYAN  = "\033[38;2;0;255;220m"
    PINK  = "\033[38;2;255;0;128m"
    PURP  = "\033[38;2;180;0;255m"
    GOLD  = "\033[38;2;255;200;0m"
    RED   = "\033[38;2;255;50;50m"
    GRN   = "\033[38;2;0;255;100m"
    WHT   = "\033[38;2;230;230;230m"
    GREY  = "\033[38;2;100;100;120m"


def gradient_line(text, start=(0, 255, 220), end=(255, 0, 128)):
    out = ""
    n = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        t = i / n
        r = int(start[0] + (end[0] - start[0]) * t)
        g = int(start[1] + (end[1] - start[1]) * t)
        b = int(start[2] + (end[2] - start[2]) * t)
        out += f"\033[38;2;{r};{g};{b}m{ch}"
    return out + C.RST


# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER_LINES = [
    r"  ██╗  ██╗███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ",
    r"  ██║  ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗██╔══██╗",
    r"  ███████║█████╗   ╚███╔╝ ██║   ██║██████╔╝███████║",
    r"  ██╔══██║██╔══╝   ██╔██╗ ██║   ██║██╔══██╗██╔══██║",
    r"  ██║  ██║███████╗██╔╝ ██╗╚██████╔╝██║  ██║██║  ██║",
    r"  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
]

GRADIENT_STEPS = [
    (0, 255, 220),
    (30, 220, 255),
    (80, 150, 255),
    (140, 80, 255),
    (200, 30, 255),
    (255, 0, 160),
]


def print_banner():
    os.system("clear" if os.name != "nt" else "cls")
    for i, line in enumerate(BANNER_LINES):
        col = GRADIENT_STEPS[i % len(GRADIENT_STEPS)]
        print(f"\033[38;2;{col[0]};{col[1]};{col[2]}m{C.BOLD}{line}{C.RST}")

    tagline = "  ⬡  Advanced  Vulnerability  Intelligence  Engine  ⬡"
    print(gradient_line(tagline))
    print()

    bar = (
        f"  {C.GREY}[{C.RST}{C.CYAN}v1.0.0{C.RST}{C.GREY}]{C.RST}"
        f"  {C.GREY}|{C.RST}"
        f"  {C.GREY}by {C.RST}{C.PINK}hexora-team{C.RST}"
        f"  {C.GREY}|{C.RST}"
        f"  {C.GREY}{datetime.now().strftime('%Y-%m-%d  %H:%M')}{C.RST}"
        f"  {C.GREY}|{C.RST}"
        f"  {C.GRN}ARMED & READY{C.RST}"
    )
    print(bar)
    print(f"\n  {C.GREY}{'─' * 62}{C.RST}\n")


# ─────────────────────────────────────────────
#  LOGGER
# ─────────────────────────────────────────────
class Logger:
    @staticmethod
    def _ts():
        return f"{C.GREY}[{datetime.now().strftime('%H:%M:%S')}]{C.RST}"

    @staticmethod
    def info(msg):
        print(f"  {Logger._ts()} {C.CYAN}[*]{C.RST} {C.WHT}{msg}{C.RST}")

    @staticmethod
    def ok(msg):
        print(f"  {Logger._ts()} {C.GRN}[+]{C.RST} {C.GRN}{msg}{C.RST}")

    @staticmethod
    def warn(msg):
        print(f"  {Logger._ts()} {C.GOLD}[!]{C.RST} {C.GOLD}{msg}{C.RST}")

    @staticmethod
    def vuln(msg):
        print(f"  {Logger._ts()} {C.RED}[VULN]{C.RST} {C.RED}{C.BOLD}{msg}{C.RST}")

    @staticmethod
    def fail(msg):
        print(f"  {Logger._ts()} {C.PINK}[-]{C.RST} {C.GREY}{msg}{C.RST}")

    @staticmethod
    def section(title):
        bar = "─" * 58
        print(f"\n  {C.PURP}┌{bar}┐{C.RST}")
        print(f"  {C.PURP}│{C.RST}  {C.BOLD}{C.CYAN}{title:<56}{C.RST}{C.PURP}  │{C.RST}")
        print(f"  {C.PURP}└{bar}┘{C.RST}\n")


log = Logger()


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def make_request(url, timeout=8, headers=None):
    req_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers=req_headers)
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return resp, body
    except Exception as e:
        return None, str(e)


def save_report(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log.ok(f"Report saved -> {filename}")


# ─────────────────────────────────────────────
#  MODULE 1 — PORT SCANNER
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 5900: "VNC",
    11211: "Memcached", 9200: "Elasticsearch",
}


def scan_port(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            try:
                s.settimeout(0.5)
                banner = s.recv(256).decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            return port, True, banner
    except Exception:
        return port, False, ""


def port_scan(host, ports=None, threads=100):
    log.section("PORT SCANNER")
    ip = resolve_host(host)
    if not ip:
        log.fail(f"Cannot resolve {host}")
        return {}
    log.info(f"Target: {host}  ({ip})")
    port_list = ports or list(COMMON_PORTS.keys())
    log.info(f"Scanning {len(port_list)} ports ...")
    results = {}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in port_list}
        for fut in as_completed(futures):
            port, open_, banner = fut.result()
            if open_:
                svc = COMMON_PORTS.get(port, "unknown")
                results[port] = {"service": svc, "banner": banner}
                bstr = f"  banner={banner[:40]!r}" if banner else ""
                log.ok(f"Port {port:>5}/tcp  OPEN  {svc:<14}{bstr}")

    if not results:
        log.fail("No open ports found.")
    return results


# ─────────────────────────────────────────────
#  MODULE 2 — URL VULNERABILITY SCANNER
# ─────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
]

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "\" OR \"1\"=\"1", "1' ORDER BY 1--",
    "1 UNION SELECT NULL--", "' AND SLEEP(2)--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-01756",
    "unclosed quotation", "odbc drivers", "sqlite3",
    "pg_query", "warning: pg_", "syntax error",
    "microsoft ole db", "incorrect syntax",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com",
    "//evil.com/%2F..", "///evil.com",
]


def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return parsed, params


def inject_param(parsed, params, key, value):
    new_params = dict(params)
    new_params[key] = [value]
    new_query = urllib.parse.urlencode(new_params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def test_xss(url, params, parsed):
    findings = []
    for key in params:
        for payload in XSS_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            _, body = make_request(test_url, timeout=6)
            if payload in body:
                findings.append({"type": "XSS", "param": key, "payload": payload, "url": test_url})
                log.vuln(f"XSS -> param={key}  payload={payload[:40]}")
    return findings


def test_sqli(url, params, parsed):
    findings = []
    for key in params:
        for payload in SQLI_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            _, body = make_request(test_url, timeout=8)
            body_lower = body.lower()
            for err in SQLI_ERRORS:
                if err in body_lower:
                    findings.append({"type": "SQLi", "param": key, "payload": payload,
                                     "error_keyword": err, "url": test_url})
                    log.vuln(f"SQL Injection -> param={key}  trigger={err!r}")
                    break
    return findings


def test_lfi(url, params, parsed):
    findings = []
    for key in params:
        for payload in LFI_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            _, body = make_request(test_url, timeout=6)
            if "root:x:" in body or "bin/bash" in body or "daemon:" in body:
                findings.append({"type": "LFI", "param": key, "payload": payload, "url": test_url})
                log.vuln(f"LFI -> param={key}  payload={payload}")
    return findings


def test_open_redirect(url, params, parsed):
    findings = []
    for key in params:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            resp, _ = make_request(test_url, timeout=6)
            if resp:
                loc = resp.headers.get("Location", "")
                if "evil.com" in loc:
                    findings.append({"type": "OpenRedirect", "param": key,
                                     "payload": payload, "url": test_url})
                    log.vuln(f"Open Redirect -> param={key}  Location={loc}")
    return findings


def test_security_headers(url):
    log.info("Checking HTTP security headers ...")
    resp, _ = make_request(url)
    if not resp:
        log.fail("Could not fetch URL for header analysis.")
        return {}
    headers = {k.lower(): v for k, v in dict(resp.headers).items()}
    EXPECTED = {
        "Strict-Transport-Security": "HSTS missing — protocol downgrade risk",
        "X-Content-Type-Options":    "X-Content-Type-Options missing — MIME sniff risk",
        "X-Frame-Options":           "X-Frame-Options missing — clickjacking risk",
        "Content-Security-Policy":   "CSP missing — XSS / injection risk",
        "Referrer-Policy":           "Referrer-Policy missing — info leakage risk",
        "Permissions-Policy":        "Permissions-Policy missing — feature abuse risk",
    }
    issues = {}
    for h, msg in EXPECTED.items():
        if h.lower() not in headers:
            log.warn(msg)
            issues[h] = msg
        else:
            log.ok(f"  {h} OK")
    return issues


def test_ssl_tls(host, port=443):
    log.info("Checking SSL/TLS configuration ...")
    issues = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert   = tls.getpeercert()
                proto  = tls.version()
                cipher = tls.cipher()
                log.ok(f"TLS version : {proto}")
                log.ok(f"Cipher      : {cipher[0]}")
                exp = cert.get("notAfter", "")
                if exp:
                    exp_dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
                    days = (exp_dt - datetime.utcnow()).days
                    if days < 30:
                        log.warn(f"Certificate expires in {days} days!")
                        issues.append(f"Cert expiry in {days} days")
                    else:
                        log.ok(f"Cert valid for {days} more days")
                if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    log.vuln(f"Weak TLS version in use: {proto}")
                    issues.append(f"Weak TLS: {proto}")
    except Exception as e:
        log.fail(f"SSL check failed: {e}")
    return issues


def scan_url(url):
    log.section("URL VULNERABILITY SCAN")
    log.info(f"Target URL: {url}")
    parsed, params = extract_params(url)
    all_findings = []

    if not params:
        log.warn("No query parameters found. Injecting ?id=1 for demonstration.")
        url += ("&" if "?" in url else "?") + "id=1"
        parsed, params = extract_params(url)

    log.info(f"Parameters detected: {list(params.keys())}")
    print()

    log.info("Testing Cross-Site Scripting (XSS) ...")
    all_findings += test_xss(url, params, parsed)

    log.info("Testing SQL Injection ...")
    all_findings += test_sqli(url, params, parsed)

    log.info("Testing Local File Inclusion (LFI) ...")
    all_findings += test_lfi(url, params, parsed)

    log.info("Testing Open Redirect ...")
    all_findings += test_open_redirect(url, params, parsed)

    print()
    host = parsed.hostname
    test_security_headers(url)
    print()
    if parsed.scheme == "https":
        test_ssl_tls(host)

    return all_findings


# ─────────────────────────────────────────────
#  MODULE 3 — SUBDOMAIN ENUMERATOR
# ─────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "beta",
    "app", "portal", "vpn", "remote", "secure", "mx", "ns", "ns1", "ns2",
    "blog", "shop", "store", "forum", "support", "help", "status", "cdn",
    "media", "img", "images", "assets", "static", "docs", "wiki", "git",
    "jenkins", "ci", "jira", "gitlab", "auth", "login", "sso", "dashboard",
    "panel", "manage", "monitor", "metrics", "grafana", "kibana", "es",
]


def enumerate_subdomains(domain, threads=50):
    log.section("SUBDOMAIN ENUMERATOR")
    log.info(f"Domain: {domain}  |  wordlist: {len(SUBDOMAIN_WORDLIST)} entries")
    found = []

    def check(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return fqdn, ip
        except Exception:
            return None, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, s): s for s in SUBDOMAIN_WORDLIST}
        for fut in as_completed(futures):
            fqdn, ip = fut.result()
            if fqdn:
                log.ok(f"  {fqdn:<40} -> {ip}")
                found.append({"subdomain": fqdn, "ip": ip})

    if not found:
        log.fail("No subdomains resolved.")
    return found


# ─────────────────────────────────────────────
#  MODULE 4 — NETWORK VULNERABILITY SCANNER
# ─────────────────────────────────────────────
DANGEROUS_PORTS = {
    21:    "FTP  — anonymous login often enabled",
    23:    "Telnet — plaintext credential exposure",
    445:   "SMB  — EternalBlue / ransomware target",
    3389:  "RDP  — BlueKeep / brute-force risk",
    5900:  "VNC  — no auth / weak password risk",
    6379:  "Redis — unauthenticated by default",
    27017: "MongoDB — unauthenticated by default",
    11211: "Memcached — DDoS amplification risk",
    9200:  "Elasticsearch — no auth by default",
}


def check_anonymous_ftp(host):
    try:
        import ftplib
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(host, 21)
        ftp.login("anonymous", "anonymous@")
        ftp.quit()
        return True
    except Exception:
        return False


def check_redis_unauth(host):
    try:
        with socket.create_connection((host, 6379), timeout=3) as s:
            s.send(b"PING\r\n")
            resp = s.recv(64).decode("utf-8", errors="replace")
            return "+PONG" in resp
    except Exception:
        return False


def network_vuln_scan(host, open_ports):
    log.section("NETWORK VULNERABILITY ANALYSIS")
    vulns = []
    for port, info in open_ports.items():
        if port in DANGEROUS_PORTS:
            msg = DANGEROUS_PORTS[port]
            log.warn(f"High-risk port {port} open — {msg}")
            entry = {"port": port, "risk": msg}
            if port == 21 and check_anonymous_ftp(host):
                log.vuln(f"Anonymous FTP login ACCEPTED on {host}:21")
                entry["critical"] = "Anonymous FTP enabled"
            if port == 6379 and check_redis_unauth(host):
                log.vuln(f"Redis is UNAUTHENTICATED on {host}:6379")
                entry["critical"] = "Unauthenticated Redis"
            vulns.append(entry)
    if not vulns:
        log.ok("No critical network-level vulnerabilities in open ports.")
    return vulns


# ─────────────────────────────────────────────
#  MODULE 5 — DNS RECON
# ─────────────────────────────────────────────
def dns_recon(domain):
    log.section("DNS RECONNAISSANCE")
    records = {}

    def query(rtype):
        try:
            result = subprocess.check_output(
                ["dig", "+short", rtype, domain],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip().splitlines()
            return [r.strip() for r in result if r.strip()]
        except Exception:
            return []

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        vals = query(rtype)
        if vals:
            records[rtype] = vals
            for v in vals:
                log.ok(f"  {rtype:<8} {v}")
        else:
            log.fail(f"  {rtype:<8} (none)")

    # zone transfer attempt
    for ns in records.get("NS", [])[:2]:
        ns = ns.rstrip(".")
        try:
            out = subprocess.check_output(
                ["dig", "AXFR", domain, f"@{ns}"],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode()
            if "Transfer failed" not in out and "XFR size" in out:
                log.vuln(f"Zone Transfer POSSIBLE via {ns}!")
                records["zone_transfer"] = ns
        except Exception:
            pass

    return records


# ─────────────────────────────────────────────
#  MODULE 6 — DIRECTORY BRUTEFORCE
# ─────────────────────────────────────────────
DIR_WORDLIST = [
    "admin", "login", "dashboard", "api", "config", "backup", ".git",
    "wp-admin", "phpmyadmin", "manager", "console", "shell", "cmd",
    "upload", "uploads", "files", "db", "database", "server-status",
    "robots.txt", "sitemap.xml", ".env", "web.config", "readme.txt",
    "info.php", "test.php", "phpinfo.php", "install", "setup",
    "cgi-bin", "scripts", "includes", "src", "vendor", "node_modules",
    ".htaccess", "crossdomain.xml", "security.txt", "changelog",
]

SENSITIVE_PATHS = {".git", ".env", "web.config", "backup", "config", "phpinfo.php"}


def dir_bruteforce(base_url, threads=30):
    log.section("DIRECTORY BRUTEFORCE")
    log.info(f"Base URL: {base_url}  |  paths: {len(DIR_WORDLIST)}")
    base_url = base_url.rstrip("/")
    found = []

    def check(path):
        url = f"{base_url}/{path}"
        resp, body = make_request(url, timeout=5)
        if resp and resp.status in (200, 201, 301, 302, 403):
            return path, resp.status, len(body)
        return None, None, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, p): p for p in DIR_WORDLIST}
        for fut in as_completed(futures):
            path, code, length = fut.result()
            if path:
                colour = C.GRN if code == 200 else C.GOLD if code == 403 else C.CYAN
                log.ok(f"  [{colour}{code}{C.RST}]  /{path:<30}  ({length} bytes)")
                found.append({"path": path, "status": code, "bytes": length})
                if path in SENSITIVE_PATHS:
                    log.vuln(f"Sensitive path exposed: /{path}")

    if not found:
        log.fail("No interesting paths found.")
    return found


# ─────────────────────────────────────────────
#  MODULE 7 — TECHNOLOGY FINGERPRINT
# ─────────────────────────────────────────────
TECH_SIGNATURES = {
    "WordPress":  ["wp-content", "wp-includes", "WordPress"],
    "Joomla":     ["Joomla!", "/components/com_"],
    "Drupal":     ["Drupal.settings", "/sites/default/"],
    "PHP":        ["X-Powered-By: PHP", ".php"],
    "ASP.NET":    ["X-Powered-By: ASP.NET", "ASP.NET_SessionId"],
    "Django":     ["csrftoken", "django"],
    "Laravel":    ["laravel_session", "XSRF-TOKEN"],
    "jQuery":     ["jquery.min.js", "jQuery v"],
    "Bootstrap":  ["bootstrap.min.css", "Bootstrap"],
    "React":      ["react.development.js", "__reactFiber"],
    "Vue.js":     ["vue.min.js", "Vue.js"],
    "nginx":      ["Server: nginx"],
    "Apache":     ["Server: Apache"],
    "IIS":        ["Server: Microsoft-IIS"],
    "Cloudflare": ["CF-RAY", "cloudflare"],
}


def tech_fingerprint(url):
    log.section("TECHNOLOGY FINGERPRINT")
    resp, body = make_request(url)
    if not resp:
        log.fail("Cannot reach URL for fingerprinting.")
        return {}
    combined = str(dict(resp.headers)) + body
    detected = {}
    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined.lower():
                detected[tech] = sig
                log.ok(f"  Detected: {C.CYAN}{tech}{C.RST}  (via {sig!r})")
                break
    if not detected:
        log.fail("No known technologies identified.")
    return detected


# ─────────────────────────────────────────────
#  FULL SCAN ORCHESTRATOR
# ─────────────────────────────────────────────
def full_scan(target, url=None):
    report = {
        "target": target,
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "findings": {},
    }
    is_url   = target.startswith("http")
    host     = urllib.parse.urlparse(target).hostname if is_url else target
    scan_url_ = url or (target if is_url else f"http://{target}")

    open_ports = port_scan(host)
    report["findings"]["open_ports"] = open_ports

    tech = tech_fingerprint(scan_url_)
    report["findings"]["technologies"] = tech

    url_findings = scan_url(scan_url_)
    report["findings"]["url_vulnerabilities"] = url_findings

    net_vulns = network_vuln_scan(host, open_ports)
    report["findings"]["network_vulnerabilities"] = net_vulns

    log.section("SECURITY HEADER AUDIT")
    hdr_issues = test_security_headers(scan_url_)
    report["findings"]["header_issues"] = hdr_issues

    dir_findings = dir_bruteforce(scan_url_)
    report["findings"]["directories"] = dir_findings

    domain = host if host and "." in host else None
    if domain:
        subs = enumerate_subdomains(domain)
        report["findings"]["subdomains"] = subs
        dns  = dns_recon(domain)
        report["findings"]["dns"] = dns

    log.section("SCAN SUMMARY")
    print(f"  {C.BOLD}{C.CYAN}Open Ports{C.RST}     : {len(open_ports)}")
    print(f"  {C.BOLD}{C.RED}URL Vulns{C.RST}      : {len(url_findings)}")
    print(f"  {C.BOLD}{C.RED}Network Vulns{C.RST}  : {len(net_vulns)}")
    print(f"  {C.BOLD}{C.GOLD}Header Issues{C.RST}  : {len(hdr_issues)}")
    print(f"  {C.BOLD}{C.GRN}Technologies{C.RST}   : {', '.join(tech.keys()) or 'none'}")

    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"hexora_report_{ts}.json"
    save_report(report, fname)
    print(f"\n  {C.PURP}{'─' * 58}{C.RST}\n")
    return report


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        description="HEXORA — Advanced Vulnerability Intelligence Engine",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = p.add_subparsers(dest="command")

    fs = sub.add_parser("full",  help="Full automated scan (ports + URL + network + dirs + DNS)")
    fs.add_argument("target",    help="IP / hostname / URL")
    fs.add_argument("--url",     help="Override base URL for web checks")

    ps = sub.add_parser("ports", help="Port scan only")
    ps.add_argument("host",      help="IP or hostname")
    ps.add_argument("--range",   help="Port range e.g. 1-1024")

    us = sub.add_parser("url",   help="URL vulnerability scan (XSS / SQLi / LFI / Redirect)")
    us.add_argument("url",       help="Target URL")

    ss = sub.add_parser("subs",  help="Subdomain enumeration")
    ss.add_argument("domain",    help="Domain name")

    ds = sub.add_parser("dns",   help="DNS recon + zone transfer check")
    ds.add_argument("domain",    help="Domain name")

    drs = sub.add_parser("dirs", help="Directory / path bruteforce")
    drs.add_argument("url",      help="Base URL")

    fps = sub.add_parser("tech", help="Technology fingerprint")
    fps.add_argument("url",      help="Target URL")

    return p


def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        print(
            f"\n  {C.GREY}Examples:{C.RST}\n"
            f"  {C.CYAN}python3 hexora.py full http://testphp.vulnweb.com{C.RST}\n"
            f"  {C.CYAN}python3 hexora.py ports 192.168.1.1 --range 1-1024{C.RST}\n"
            f"  {C.CYAN}python3 hexora.py url \"http://example.com/page?id=1\"{C.RST}\n"
            f"  {C.CYAN}python3 hexora.py subs example.com{C.RST}\n"
            f"  {C.CYAN}python3 hexora.py dns example.com{C.RST}\n"
            f"  {C.CYAN}python3 hexora.py dirs http://example.com{C.RST}\n"
            f"  {C.CYAN}python3 hexora.py tech http://example.com{C.RST}\n"
        )
        sys.exit(0)

    try:
        if args.command == "full":
            full_scan(args.target, getattr(args, "url", None))
        elif args.command == "ports":
            ports = None
            if args.range:
                lo, hi = map(int, args.range.split("-"))
                ports  = list(range(lo, hi + 1))
            port_scan(args.host, ports)
        elif args.command == "url":
            scan_url(args.url)
        elif args.command == "subs":
            enumerate_subdomains(args.domain)
        elif args.command == "dns":
            dns_recon(args.domain)
        elif args.command == "dirs":
            dir_bruteforce(args.url)
        elif args.command == "tech":
            tech_fingerprint(args.url)

    except KeyboardInterrupt:
        print(f"\n\n  {C.GOLD}[!] Scan interrupted by user.{C.RST}\n")
        sys.exit(0)
    except Exception as e:
        log.fail(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
