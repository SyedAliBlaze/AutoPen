# AutoPen — Automated Penetration Testing Tool

> **Version 1.0** | For Authorized Security Testing Only

AutoPen is a modular, automated penetration testing framework written in Python. It performs multi-phase security assessments against target systems — encompassing network reconnaissance, web application vulnerability scanning, directory enumeration, and risk scoring — then produces executive-grade PDF and HTML reports with CVSS v3.1 scoring and remediation roadmaps.

AutoPen is built entirely from scratch with its own detection logic, payload libraries, and scoring engine. It does **not** wrap external vulnerability scanners — every module implements its own analysis.

---

## Table of Contents

- [Features](#features)
- [Project Architecture](#project-architecture)
- [Directory Structure](#directory-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scan Phases](#scan-phases)
  - [Phase 1 — Reconnaissance (Nmap)](#phase-1--reconnaissance-nmap)
  - [Phase 2 — Directory Brute-Forcing](#phase-2--directory-brute-forcing)
  - [Phase 3 — Web Crawling (Shared Pre-Scan)](#phase-3--web-crawling-shared-pre-scan)
  - [Phase 4 — SQL Injection Detection](#phase-4--sql-injection-detection)
  - [Phase 5 — Cross-Site Scripting (XSS)](#phase-5--cross-site-scripting-xss)
  - [Phase 6 — Cross-Site Request Forgery (CSRF)](#phase-6--cross-site-request-forgery-csrf)
  - [Phase 7 — Server-Side Request Forgery (SSRF) & LFI](#phase-7--server-side-request-forgery-ssrf--lfi)
  - [Phase 8 — OS Command Injection](#phase-8--os-command-injection)
  - [Phase 9 — Brute Force Vulnerability Detection](#phase-9--brute-force-vulnerability-detection)
- [CVSS v3.1 Scoring Engine](#cvss-v31-scoring-engine)
- [Reporting](#reporting)
- [Safety & Compliance](#safety--compliance)
- [Dependencies](#dependencies)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

| Category | Capabilities |
|---|---|
| **Reconnaissance** | Nmap service discovery, version fingerprinting, CVE mapping against known vulnerable signatures, high-risk port flagging |
| **Web Crawling** | Breadth-first spider that auto-discovers pages, forms (including `<textarea>` and `<select>` fields), and GET parameters — shared across all web modules |
| **SQL Injection** | Error-based, boolean-based, and blind (boolean-based) SQLi detection with custom payload library and DB error signature matching |
| **XSS** | Reflected and stored XSS detection across GET parameters and POST forms with context-aware payloads |
| **CSRF** | Missing CSRF token detection, form exploitability verification, and session cookie security auditing (SameSite, Secure, HttpOnly) |
| **SSRF / LFI** | Server-Side Request Forgery and Local File Inclusion detection via URL parameter probing and internal network scanning payloads |
| **Command Injection** | OS command injection with baseline-aware diff analysis to eliminate false positives; uses unique echo tokens for reliable confirmation |
| **Brute Force** | Detection of missing brute force protections — tests for account lockout, rate limiting, and CAPTCHA presence |
| **Directory Enumeration** | Built-in 90+ entry wordlist covering admin panels, config files, backups, dev artifacts, CMS paths, API endpoints, and sensitive directories |
| **CVSS Scoring** | Industry-standard CVSS v3.1 base score calculation using FIRST specification formulas with per-finding vector justification |
| **Reporting** | Dual-format output: professional PDF (via ReportLab) and styled HTML reports with cover page, executive summary, detailed findings, and remediation roadmap |
| **Audit Logging** | Append-only audit trail recording every scan action, finding, scope violation, and consent confirmation |
| **Scope Validation** | Pre-scan target validation supporting IP addresses, CIDR subnets, and hostnames with excluded path enforcement |

---

## Project Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        main.py (Entry Point)                 │
│  Banner → Config → Target Input → Consent → Scan Phases     │
└──────────┬───────────────────────────────────────────────────┘
           │
           ├── config/config.yaml          ← Scan configuration
           ├── core/scope_validator.py     ← Pre-scan scope enforcement
           ├── audit/logger.py             ← Append-only audit trail
           │
           ├── modules/recon/
           │   ├── nmap_scanner.py         ← Phase 1: Service discovery
           │   └── crawler.py             ← Shared web crawler
           │
           ├── modules/bruteforce/
           │   └── dir_bruteforce.py       ← Phase 2: Directory enumeration
           │
           ├── modules/web/
           │   ├── sqli_scanner.py         ← Phase 3: SQL injection
           │   ├── xss_scanner.py          ← Phase 4: Cross-site scripting
           │   ├── csrf_scanner.py         ← Phase 5: CSRF detection
           │   ├── ssrf_scanner.py         ← Phase 6: SSRF / LFI
           │   ├── cmd_injection_scanner.py← Phase 7: Command injection
           │   └── bruteforce_scanner.py   ← Phase 8: Brute force vuln detection
           │
           ├── scoring/cvss_engine.py      ← CVSS v3.1 score calculation
           └── reporting/pdf_generator.py  ← PDF + HTML report generation
```

---

## Directory Structure

```
autopen/
├── main.py                          # Application entry point & orchestrator
├── autopen                          # Bash launcher script (venv + deps + run)
├── config/
│   └── config.yaml                  # Scan configuration (target, modules, scope)
├── core/
│   └── scope_validator.py           # Target validation & scope enforcement
├── audit/
│   ├── logger.py                    # Audit logging engine
│   ├── autopen_audit.log            # Persistent audit trail
│   └── test.log                     # Test log output
├── modules/
│   ├── recon/
│   │   ├── nmap_scanner.py          # Nmap service/version scanner
│   │   └── crawler.py               # Breadth-first web crawler
│   ├── bruteforce/
│   │   └── dir_bruteforce.py        # Directory brute-forcer (built-in wordlist)
│   └── web/
│       ├── sqli_scanner.py          # SQL injection scanner (error/boolean/blind)
│       ├── xss_scanner.py           # XSS scanner (reflected/stored)
│       ├── csrf_scanner.py          # CSRF & cookie security scanner
│       ├── ssrf_scanner.py          # SSRF & LFI scanner
│       ├── cmd_injection_scanner.py # OS command injection scanner
│       └── bruteforce_scanner.py    # Brute force protection detector
├── scoring/
│   └── cvss_engine.py               # CVSS v3.1 base score calculator
├── reporting/
│   └── pdf_generator.py             # PDF & HTML report generator
├── requirements.txt                 # Python dependencies
└── readme.md                        # This file
```

---

## Installation

### Prerequisites

- **Python 3.8+**
- **Nmap** installed and accessible in `$PATH` (required for the recon module)
- **Linux/macOS** recommended (the tool targets Linux-based vulnerable VMs)

### Quick Start (Using the Launcher Script)

```bash
# Make the launcher executable
chmod +x autopen

# Run — automatically creates venv, installs deps, and starts the scan
./autopen
```

The `autopen` bash script will:
1. Create a Python virtual environment (`venv/`) if one doesn't exist
2. Install all dependencies from `requirements.txt`
3. Launch `main.py`

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

---

## Configuration

All scan parameters are defined in `config/config.yaml`:

```yaml
# Target Configuration
target:
  host: "127.0.0.1"                  # Target IP address
  url: "http://127.0.0.1"           # Target base URL
  username: "admin"                 # Optional login credentials
  password: "password"

# Scope Enforcement
scope:
  allowed_hosts:
    - "192.168.220.11"              # Whitelisted targets (supports CIDR)
  excluded_paths:
    - "/logout.php"                 # Paths the crawler must skip
  max_requests_per_second: 10       # Rate limiting
  consent_confirmed: true           # Must be true before any scan runs

# Scan Module Selection
scan:
  modules:
    - recon                         # Nmap reconnaissance
    - sqli                          # SQL injection
    - xss                           # Cross-site scripting
    - bruteforce                    # Directory brute-forcing
    - csrf                          # Cross-site request forgery
    - ssrf                          # Server-side request forgery / LFI
    - cmd_injection                 # OS command injection
    - brute_vuln                    # Brute force protection detection
  timeout: 10                       # Request timeout in seconds
  user_agent: "AutoPen-Scanner/1.0 (Authorized Security Testing)"

# Report Output
reporting:
  output_dir: "reports"
  formats:
    - pdf
    - html
  company_name: "AutoPen Security"
  classification: "CONFIDENTIAL"

# Audit Trail
audit:
  log_file: "audit/autopen_audit.log"
  log_level: "INFO"
```

### Key Configuration Notes

- **`consent_confirmed`** must be set to `true` in the config, AND the user must type `AGREE` at the interactive consent prompt before any scanning begins.
- **`allowed_hosts`** supports both individual IPs and CIDR notation (e.g., `192.168.1.0/24`).
- **`excluded_paths`** prevents the crawler and scanners from hitting sensitive endpoints like logout pages.
- **Modules** can be selectively enabled/disabled by adding or removing entries from the `modules` list.

---

## Usage

### Interactive Workflow

1. **Launch** — Run `./autopen` or `python main.py`
2. **Target Input** — Enter the target in any format:
   - `192.168.43.54` (raw IP)
   - `http://192.168.43.54` (with scheme)
   - `http://192.168.43.54/app/` (with path)
   - The smart parser auto-detects and normalizes the input
3. **Review Configuration** — A formatted table displays all scan settings
4. **Legal Consent** — Type `AGREE` to confirm you have written authorization
5. **Automated Scan** — All enabled modules run sequentially through each phase
6. **Results** — Findings summary table displayed in the terminal
7. **Report** — PDF and HTML reports saved to `reports/` directory

### Example Terminal Output

```
░█████╗░██╗░░░██╗████████╗░█████╗░██████╗░███████╗███╗░░██╗
██╔══██╗██║░░░██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝████╗░██║
███████║██║░░░██║░░░██║░░░██║░░██║██████╔╝█████╗░░██╔██╗██║
██╔══██║██║░░░██║░░░██║░░░██║░░██║██╔═══╝░██╔══╝░░██║╚████║
██║░░██║╚██████╔╝░░░██║░░░╚█████╔╝██║░░░░░███████╗██║░╚███║
╚═╝░░╚═╝░╚═════╝░░░╚═╝░░░░╚════╝░╚═╝░░░░░╚══════╝╚═╝░░╚══╝

Enter target IP or URL: 192.168.220.11
✓ Target parsed successfully
✓ Configuration loaded
Type AGREE to confirm authorization: AGREE
✓ Scan started...
```

---

## Scan Phases

### Phase 1 — Reconnaissance (Nmap)

**Module:** `modules/recon/nmap_scanner.py`

Performs network-level service discovery and version fingerprinting using Nmap with the following scan arguments:

```
-sV -sC --open -T4 --host-timeout <timeout>
```

**Detection capabilities:**
- **Vulnerable service matching** against a built-in database of 8 known vulnerable signatures:
  - vsftpd 2.3.4 (CVE-2011-2523 — backdoor, CRITICAL)
  - UnrealIRCd (CVE-2010-2075 — backdoor, CRITICAL)
  - Samba 3.0.20 (CVE-2007-2447 — command injection, CRITICAL)
  - ProFTPD 1.3.1 (CVE-2010-4221 — buffer overflow, HIGH)
  - Apache 2.2.8 (CVE-2011-3192 — Range DoS, HIGH)
  - OpenSSH 4.7 (CVE-2008-0166 — weak PRNG, HIGH)
  - MySQL 5.0 (CVE-2012-2122 — auth bypass, HIGH)
  - PostgreSQL 8.3 (CVE-2013-1899 — privilege escalation, MEDIUM)

- **High-risk port flagging** for inherently dangerous services:
  - Telnet (23), rexec (512), rlogin (513), rsh (514), Bindshell (1524), X11 (6000), NFS (2049)

**Output:** Professional tables showing open ports, services, versions, and flagged risks.

---

### Phase 2 — Directory Brute-Forcing

**Module:** `modules/bruteforce/dir_bruteforce.py`

Discovers hidden directories and sensitive files using a built-in curated wordlist of **90+ entries** organized by category:

| Category | Examples |
|---|---|
| Admin panels | `admin`, `dashboard`, `controlpanel`, `webadmin` |
| Authentication | `login`, `signup`, `register`, `auth` |
| Config/sensitive | `.env`, `.htaccess`, `config.php`, `web.config` |
| Backup files | `backup.zip`, `backup.sql`, `db_backup` |
| Dev artifacts | `phpinfo.php`, `test.php`, `debug`, `staging` |
| CMS paths | `wp-admin`, `phpmyadmin`, `joomla` |
| API endpoints | `api/v1`, `swagger`, `graphql` |
| Version control | `.git`, `.git/HEAD`, `.svn` |
| Server info | `server-status`, `robots.txt`, `sitemap.xml` |

**Response classification:**
- `200` → FOUND (HIGH severity)
- `301/302` → REDIRECT (MEDIUM — resource exists)
- `401` → AUTH REQUIRED (MEDIUM — resource exists)
- `403` → FORBIDDEN (LOW — protected but exists)

Includes rate limiting (50ms between requests) to avoid overwhelming the target.

---

### Phase 3 — Web Crawling (Shared Pre-Scan)

**Module:** `modules/recon/crawler.py`

A breadth-first web crawler that runs **once** and shares its results with all subsequent web vulnerability scanners. This avoids redundant crawling and ensures consistent test coverage.

**How it works:**
1. Starts from the configured `url` and crawls up to 100 pages
3. Uses a custom `HTMLParser` to extract:
   - All `<a href>` links
   - All `<form>` elements with their `<input>`, `<select>`, and `<textarea>` fields
4. Deduplicates discovered GET parameters and forms
5. Never leaves the target host (strict same-origin enforcement)

**Output shared with scanners:**
- `urls` — All discovered page URLs
- `forms` — Deduplicated forms with action URLs, methods, and input fields
- `get_params` — Deduplicated URL parameters with original values

---

### Phase 4 — SQL Injection Detection

**Module:** `modules/web/sqli_scanner.py`

Tests all crawler-discovered GET parameters and form fields for SQL injection using three detection techniques:

**1. Error-Based SQLi** (14 payloads)
- Injects SQL syntax-breaking payloads (`'`, `' OR '1'='1`, `UNION SELECT`, etc.)
- Checks response body against 17 database error signatures covering MySQL, PostgreSQL, MSSQL, and Oracle

**2. Boolean-Based SQLi** (4 payload pairs)
- Sends true/false condition pairs (`' AND '1'='1` vs `' AND '1'='2`)
- Detects injection when response length differs by >50 bytes

**3. Blind SQLi (Boolean-Based)** (4 payload pairs)
- Uses response length differential to confirm blind injection

**Safety features:**
- Filters out non-injectable targets (phpinfo, static files, logout pages)
- Validates all URLs belong to the authorized target IP
- Validates all URLs belong to the authorized target IP

---

### Phase 5 — Cross-Site Scripting (XSS)

**Module:** `modules/web/xss_scanner.py`

Detects both reflected and stored XSS across the entire web application surface.

**Reflected XSS** (15 payloads)
- Sends payloads via GET parameters: `<script>alert('XSS')</script>`, `<img src=x onerror=alert('XSS')>`, `<svg onload=...>`, event handler injections, and filter evasion payloads
- Checks if payload appears unmodified in the response using 12 XSS signatures

**Stored XSS** (4 payloads)
- Submits payloads via POST forms
- Fetches the display page to verify payload persistence
- Supports separate submit/display URLs (e.g., Mutillidae blog)

- Scans all discovered form fields for persistence

**Deduplication:** Maintains a `tested_targets` set to prevent duplicate findings from the same parameter/URL combination.

---

### Phase 6 — Cross-Site Request Forgery (CSRF)

**Module:** `modules/web/csrf_scanner.py`

Performs a two-stage CSRF analysis on all discovered forms:

**Stage 1 — Token Analysis:**
- Checks each form for CSRF token fields against 15 common token field names (`csrf_token`, `_csrf`, `nonce`, `authenticity_token`, etc.)
- Identifies state-changing forms using 30+ sensitive keyword patterns (`password`, `transfer`, `delete`, `admin`, etc.)

**Stage 2 — Exploitability Verification:**
- For forms missing CSRF tokens, attempts to submit the form without any token
- Compares response against baseline to confirm the submission was accepted
- Checks for success indicators (`success`, `updated`, `saved`, etc.)

**Cookie Security Audit:**
- Inspects all session cookies for missing security attributes:
  - `SameSite` attribute
  - `Secure` flag (HTTPS-only)
  - `HttpOnly` flag (prevents JavaScript access)

---

### Phase 7 — Server-Side Request Forgery (SSRF) & LFI

**Module:** `modules/web/ssrf_scanner.py`

Tests for SSRF and Local File Inclusion through URL-accepting parameters.

**SSRF Payloads** (16 entries)
- Internal network probing: `http://127.0.0.1/`, `http://10.0.0.1/`, `http://192.168.0.1/`
- Cloud metadata: `http://169.254.169.254/latest/meta-data/`, `http://metadata.google.internal/`
- Protocol abuse: `file:///etc/passwd`, `dict://`, `gopher://`

**Detection:**
- Matches response against 12 SSRF signatures (`root:x:0:0`, `127.0.0.1 localhost`, `ami-id`, etc.)
- Baseline-aware response diff analysis (>500 byte change with internal content indicators)
- Identifies URL-accepting parameters by name (28 common URL parameter names) and value pattern

- Scans URL parameters for path traversal and remote URL fetching

**Finding differentiation:** Automatically classifies findings as either SSRF or LFI based on payload type.

---

### Phase 8 — OS Command Injection

**Module:** `modules/web/cmd_injection_scanner.py`

Detects command injection vulnerabilities using a **baseline-aware diff approach** that eliminates false positives.

**Payload library** (13 payloads):
- Echo unique token: `;echo <unique_token>`, `|echo <unique_token>`, `` `echo <unique_token>` ``
- System commands: `;id` (checks for `uid=`), `;whoami` (checks for `www-data`)
- Ping: `;ping -c 1 127.0.0.1` (checks for `bytes from 127.0.0.1`)

**Baseline-aware detection (key innovation):**
1. First sends a clean request (`127.0.0.1`) to establish baseline response content
2. Then sends payload-injected requests
3. A signature is only flagged if it appears in the payload response **but NOT in the baseline**
4. This prevents false positives from `www-data`, `root`, or `apache` appearing in normal page HTML

- Tests crawler-discovered forms with command-like field names (`ip`, `host`, `cmd`, `exec`, `ping`, `target`)

---

### Phase 9 — Brute Force Vulnerability Detection

**Module:** `modules/web/bruteforce_scanner.py`

Detects **missing brute force protections** rather than performing actual password cracking.

**What it tests:**
1. **Target form testing** — Submits safe credential pairs and monitors for:
   - Account lockout indicators (`locked`, `too many`, `blocked`, `suspended`)
   - Rate limiting (HTTP 429 or response time >3 seconds)
   - CAPTCHA presence (`captcha`, `recaptcha`, `verify`)

**Safe by design:** Uses only a minimal, predetermined credential set — not a dictionary attack.

---

## CVSS v3.1 Scoring Engine

**Module:** `scoring/cvss_engine.py`

Implements the official CVSS v3.1 Base Score calculation formula from the [FIRST specification](https://www.first.org/cvss/v3.1/specification-document).

**Vector components calculated:**
| Metric | Values |
|---|---|
| Attack Vector (AV) | Network (0.85), Adjacent (0.62), Local (0.55), Physical (0.20) |
| Attack Complexity (AC) | Low (0.77), High (0.44) |
| Privileges Required (PR) | None (0.85), Low (0.62/0.50), High (0.27/0.50) |
| User Interaction (UI) | None (0.85), Required (0.62) |
| Scope (S) | Unchanged, Changed |
| CIA Impact | None (0.00), Low (0.22), High (0.56) |

**Pre-defined vectors for finding types:**

| Finding Type | CVSS Vector | Base Score |
|---|---|---|
| SQL Injection | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| Stored XSS | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N` | 9.1 |
| Reflected XSS | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 |
| Command Injection | Same as SQLi vector | 9.8 |
| Vulnerable Service | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| High Risk Port | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | 6.5 |
| Directory Exposure | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 |

**Severity mapping:** None (0.0), LOW (0.1–3.9), MEDIUM (4.0–6.9), HIGH (7.0–8.9), CRITICAL (9.0–10.0)

All findings are enriched with CVSS scores, vectors, severity ratings, and justifications before report generation.

---

## Reporting

**Module:** `reporting/pdf_generator.py`

Generates two report formats simultaneously:

### PDF Report (via ReportLab)
- **Cover page** with target details, assessment date, tool version, classification, and overall risk badge
- **Executive summary** with risk score (0–100), severity breakdown table, and action timelines
- **Detailed findings** — each finding includes: title, severity badge, CVSS score/vector, target URL, description, evidence block, and remediation steps
- **Remediation roadmap** — findings sorted by severity with fix-by timelines:
  - CRITICAL → 24 hours
  - HIGH → 7 days
  - MEDIUM → 30 days
  - LOW → 90 days

### HTML Report
- Same content as PDF but in a styled, self-contained HTML file
- Professional CSS styling with severity-colored finding cards
- Always generated as a fallback if PDF generation encounters issues

### Risk Scoring Formula

```
Risk Score = min(100, (Critical × 25) + (High × 10) + (Medium × 5) + (Low × 1))
```

| Score Range | Risk Level |
|---|---|
| 75–100 | CRITICAL |
| 50–74 | HIGH |
| 25–49 | MEDIUM |
| 0–24 | LOW |

Reports are saved to the `reports/` directory with timestamped filenames:
```
reports/autopen_report_192_168_220_11_20260513_143052.pdf
reports/autopen_report_192_168_220_11_20260513_143052.html
```

---

## Safety & Compliance

AutoPen implements multiple layers of safety controls to ensure responsible use:

### Pre-Scan Safeguards
1. **Configuration consent** — `consent_confirmed: true` must be set in `config.yaml`
2. **Interactive consent** — User must type `AGREE` at the legal warning prompt before any scanning begins
3. **Scope validation** — Target must be explicitly listed in `allowed_hosts`; out-of-scope targets are blocked
4. **Excluded paths** — Sensitive endpoints (e.g., logout pages) are never touched

### Runtime Safety
5. **Same-host enforcement** — The web crawler never follows links outside the target host
6. **URL validation** — Every scanner verifies that test URLs belong to the authorized target IP
7. **Rate limiting** — Configurable request throttling to prevent target overload
8. **Append-only audit log** — Every action is recorded with timestamps for forensic accountability

### Audit Log Format
```
2026-05-13 14:30:52 | INFO | SCAN STARTED | Target: 192.168.220.11 | Modules: ['recon', 'sqli', 'xss']
2026-05-13 14:30:53 | INFO | CONSENT | Confirmed: True | Operator: unknown
2026-05-13 14:31:05 | INFO | REQUEST | GET | http://127.0.0.1/ | Status: 200
2026-05-13 14:31:10 | WARNING | FINDING | Error-Based SQLi | Target: ... | Severity: HIGH
2026-05-13 14:35:22 | INFO | SCAN COMPLETED | Target: 192.168.220.11 | Findings: 12
```

---

## Dependencies

Listed in `requirements.txt`:

| Package | Purpose |
|---|---|
| `pyyaml` | YAML configuration file parsing |
| `rich` | Terminal UI — styled tables, panels, progress bars, and prompts |
| `python-nmap` | Python interface to the Nmap port scanner |
| `requests` | HTTP client for web scanning modules |
| `reportlab` | Professional PDF report generation |

**System requirement:** Nmap must be installed separately and available in `$PATH`.

---

## Legal Disclaimer

> ⚠️ **WARNING:** AutoPen performs active security testing including network reconnaissance, port scanning, web vulnerability probing (SQLi, XSS, CSRF, SSRF, command injection), directory enumeration, and brute force analysis.
>
> **Unauthorized use against systems you do not own or have explicit written permission to test is ILLEGAL and may result in criminal prosecution.**
>
> This tool is intended for:
> - Authorized penetration testing engagements
> - Security research in controlled lab environments
> - Educational purposes with dedicated vulnerable VMs (e.g., Metasploitable 2)
>
> The developers assume no liability for misuse of this tool. **Always obtain written authorization before testing any system.**
