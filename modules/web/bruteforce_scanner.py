# AutoPen Brute Force Vulnerability Scanner
# Detects MISSING brute force protections
# Tests for account lockout, rate limiting, CAPTCHA
# Uses only a small safe credential set
# For authorized security testing only

import requests
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Small safe credential list for detection only
# Not for actual password cracking
SAFE_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('admin', 'admin123'),
    ('test', 'test'),
]

# Common weak passwords to test
COMMON_PASSWORDS = [
    'password', 'admin', '123456',
    'admin123', 'letmein', 'qwerty'
]


class BruteForceScannerVuln:
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
        """Main brute force vulnerability detection"""
        console.print(Panel(
            "[bold yellow]PHASE 8: BRUTE FORCE VULNERABILITY "
            "DETECTION[/bold yellow]\n"
            f"Target: [bold white]{self.target_ip}[/bold white]\n"
            "Checking for missing brute force protections...",
            style="yellow"
        ))

        if not self.validator.is_host_in_scope(self.target_ip):
            console.print("[bold red]Out of scope.[/bold red]")
            return []

        # Authentication is handled by the shared session in main.py if provided

        # Test target URL for brute force vulnerabilities if it looks like a login/form
        self._test_protection(self.target_url)

        self._display_results()
        return self.findings

    # DVWA specific methods removed

    def _test_protection(self, url: str):
        """
        Test a URL for brute force vulnerability.
        Checks if application allows unlimited
        login attempts without lockout or rate limiting.
        """
        console.print(
            f"\n[cyan]Testing:[/cyan] {url}"
        )

        failed_responses = []
        locked = False
        rate_limited = False

        console.print(
            f"  [yellow]→ Testing {len(SAFE_CREDENTIALS)} "
            f"credential pairs for lockout detection[/yellow]"
        )

        for username, password in SAFE_CREDENTIALS:
            try:
                start = time.time()
                response = self.session.get(
                    url,
                    params={
                        'username': username,
                        'password': password,
                        'Login': 'Login'
                    },
                    timeout=self.timeout
                )
                elapsed = time.time() - start

                self.logger.log_request(
                    'GET', url, response.status_code
                )

                response_lower = response.text.lower()

                # Check for lockout indicators
                if any(term in response_lower for term in [
                    'locked', 'too many', 'blocked',
                    'suspended', 'temporarily'
                ]):
                    locked = True
                    console.print(
                        f"  [green]✓ Account lockout detected "
                        f"after {len(failed_responses)} "
                        f"attempts[/green]"
                    )
                    break

                # Check for rate limiting
                if response.status_code == 429 or \
                   elapsed > 3.0:
                    rate_limited = True
                    console.print(
                        "  [green]✓ Rate limiting detected"
                        "[/green]"
                    )
                    break

                # Check for CAPTCHA
                if any(term in response_lower for term in [
                    'captcha', 'recaptcha', 'verify'
                ]):
                    console.print(
                        "  [green]✓ CAPTCHA protection "
                        "detected[/green]"
                    )
                    break

                failed_responses.append(response)
                time.sleep(0.2)

            except Exception as e:
                self.logger.log_error('bf_test', str(e))

        # If no protection found after all attempts
        if not locked and not rate_limited and \
           len(failed_responses) >= len(SAFE_CREDENTIALS):
            finding = {
                'title': 'Missing Brute Force Protection',
                'type': 'bruteforce',
                'vuln_type': 'Missing Rate Limiting',
                'target': url,
                'parameter': 'username/password',
                'payload': 'Multiple credential attempts',
                'severity': 'MEDIUM',
                'cvss_score': 7.5,
                'cvss_vector': (
                    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/'
                    'S:U/C:H/I:N/A:N'
                ),
                'description': (
                    "No brute force protection detected. "
                    "Application allows unlimited login attempts "
                    "without account lockout, rate limiting, "
                    "or CAPTCHA. Attacker can attempt thousands "
                    "of passwords automatically."
                ),
                'evidence': (
                    f"Tested {len(failed_responses)} credential "
                    f"pairs.\n"
                    f"No lockout triggered.\n"
                    f"No rate limiting detected.\n"
                    f"No CAPTCHA present.\n"
                    f"Application accepts unlimited attempts."
                ),
                'remediation': (
                    "1. Implement account lockout after 5 "
                    "failed attempts.\n"
                    "2. Add rate limiting on login endpoints.\n"
                    "3. Implement CAPTCHA after 3 failures.\n"
                    "4. Add login attempt logging and alerting.\n"
                    "5. Consider multi-factor authentication."
                ),
                'references': [
                    'https://owasp.org/www-community/controls/'
                    'Blocking_Brute_Force_Attacks',
                    'CWE-307: Improper Restriction of Excessive '
                    'Authentication Attempts'
                ],
                'discovered_at': datetime.now().isoformat()
            }
            self.findings.append(finding)
            self.logger.log_finding(
                'Missing Brute Force Protection',
                url, 'MEDIUM'
            )
            console.print(
                f"  [bold red]✗ VULNERABLE[/bold red] — "
                f"No brute force protection!\n"
                f"  [red]Tested:[/red] "
                f"{len(failed_responses)} attempts, "
                f"no lockout triggered"
            )

    # Single protection test used

    def _display_results(self):
        console.print(
            f"\n[bold white]Brute Force Scan Complete."
            f"[/bold white]"
        )
        if not self.findings:
            console.print(
                "[bold green]✓ Brute force protections "
                "appear present.[/bold green]"
            )
            return

        table = Table(
            title="Brute Force Findings",
            box=box.ROUNDED,
            style="yellow"
        )
        table.add_column("Type", style="bold white", width=30)
        table.add_column("Target", style="cyan", width=35)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("CVSS", style="bold", width=6)

        for f in self.findings:
            table.add_row(
                f['vuln_type'],
                f['target'][-35:],
                f['severity'],
                str(f['cvss_score'])
            )

        console.print(table)
        console.print(
            f"[bold yellow]Total Brute Force Findings: "
            f"{len(self.findings)}[/bold yellow]"
        )
