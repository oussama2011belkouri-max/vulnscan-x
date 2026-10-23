# 🛡️ VULNSCAN-X

> A fast, lightweight, template-based vulnerability scanner written entirely in Python 3. Designed as a scriptable, zero-dependency alternative to Nuclei.

---

## 🚀 Features

- **Zero External Dependencies:** Built strictly using Python's standard library (`urllib`, `concurrent.futures`, `argparse`, etc.). No need to run `pip install`.
- **Smart Template Engine:** Supports multiple matcher types including Status codes, Substrings, Regular Expressions (`regex`), and HTTP Headers.
- **Built-in Fuzzing:** Automated payload testing for common injections and vulnerabilities (SQLi, XSS, RCE, SSTI, Path Traversal, LFI).
- **Automated Recon:** Passive subdomain enumeration built-in via `crt.sh`.
- **High Concurrency:** Fast multi-threaded scanning using `ThreadPoolExecutor`.
- **Extensible:** Easily load and run your own custom JSON templates.
- **Structured Reporting:** Export findings directly into a clean JSON report.

---

## 📥 Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/oussama2011belkouri-max/vulnscan-x.git
cd vulnscan-x
chmod +x vulnscan.py
python3 vulnscanx.py
