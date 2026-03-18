# ⬡ HEXORA — Advanced Vulnerability Intelligence Engine

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![License](https://img.shields.io/badge/License-MIT-green)

A powerful CLI vulnerability scanner for URLs and networks, built for Kali Linux.

## Features
- Port Scanner (threaded, with banner grabbing)
- URL Vulnerability Scanner (XSS, SQLi, LFI, Open Redirect)
- Security Header Audit
- SSL/TLS Inspector
- Network Vulnerability Analysis
- Directory Bruteforce
- Subdomain Enumerator
- DNS Recon + Zone Transfer check
- Technology Fingerprinting
- Auto JSON report generation

## Usage
```bash
python3 hexora.py full http://target.com
python3 hexora.py ports 192.168.1.1 --range 1-1024
python3 hexora.py url "http://site.com/page?id=1"
python3 hexora.py subs example.com
python3 hexora.py dns example.com
python3 hexora.py dirs http://example.com
python3 hexora.py tech http://example.com
```

## ⚠️ Disclaimer
For educational purposes and authorized testing only.
