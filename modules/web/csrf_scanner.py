# AutoPen CSRF Scanner
# Detects Cross-Site Request Forgery vulnerabilities
# Checks for missing CSRF tokens and weak cookie attributes
# Own detection logic - no external tools

import requests
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from modules.recon.crawler import WebCrawler

console = Console()

# Forms that should always have CSRF protection
# These perform state-changing operations
SENSITIVE_FORM_KEYWORDS = [
    'password', 'passwd', 'pwd',
    'transfer', 'payment', 'pay',
    'delete', 'remove', 'update',
    'email', 'username', 'user',
    'settings', 'profile', 'account',
    'admin', 'config', 'submit',
    'register', 'signup', 'login',
    'confirm', 'change', 'edit',
    'post', 'comment', 'message',
    'upload', 'import', 'export',
]

# CSRF token field names commonly used
CSRF_TOKEN_NAMES = [
    'csrf', 'csrf_token', 'csrftoken',
    'csrf-token', '_csrf', '_token',
    'token', 'authenticity_token',
    'nonce', 'xsrf', 'xsrf_token',
    '__requestverificationtoken',
    'user_token', 'form_token',
    'security_token', 'anti_csrf',
]

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

class CSRFScanner:
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
        self.tested_forms = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['scan']['user_agent']
        })
        self.config = config

    def run(self, crawl_results=None) -> list:
        """Main CSRF scan function"""
        console.print(Panel(
            "[bold blue]PHASE 5: CSRF DETECTION[/bold blue]\n"
            f"Target: [bold white]{self.target_ip}[/bold white]\n"
            "Checking forms for missing CSRF protection...",
            style="blue"
        ))

        if not self.validator.is_host_in_scope(self.target_ip):
            console.print("[bold red]Target out of scope.[/bold red]")
            return []

        # Login to DVWA
        if not self._login_to_dvwa():
            console.print("[bold red]✗ Could not login to DVWA.[/bold red]")
            return []

        console.print("[bold green]✓[/bold green] Logged into DVWA")

        # Crawl to discover forms
        if crawl_results is None:
            console.print("\n[cyan]Crawling for forms...[/cyan]")
            crawler = WebCrawler(self.config, self.logger, self.session)
            crawl_results = crawler.run()
        else:
            console.print("\n[cyan]Using shared crawler results.[/cyan]")
        forms = crawl_results['forms']

        if not forms:
            console.print("[yellow]No forms discovered.[/yellow]")
            return []

        console.print(
            f"\n[cyan]Analysing {len(forms)} forms for CSRF protection...[/cyan]"
        )

        for form in forms:
            self._analyse_form(form)

        # Check cookie security
        self._check_cookie_security()

        self._display_results()
        return self.findings

    def _login_to_dvwa(self) -> bool:
        """Login to DVWA"""
        try:
            login_url = f"{self.base_url}/dvwa/login.php"
            login_data = {
                'username': self.username,
                'password': self.password,
                'Login': 'Login'
            }
            response = self.session.post(
                login_url,
                data=login_data,
                timeout=self.timeout,
                allow_redirects=True
            )
            self.session.post(
                f"{self.base_url}/dvwa/security.php",
                data={'security': 'low', 'seclev_submit': 'Submit'},
                timeout=self.timeout
            )
            test = self.session.get(
                f"{self.base_url}/dvwa/",
                timeout=self.timeout
            )
            if 'login' in test.url.lower():
                return False
            self.logger.log_request('POST', login_url, response.status_code)
            return True
        except Exception as e:
            self.logger.log_error('csrf_login', str(e))
            return False

    def _analyse_form(self, form: dict):        
        """
        Analyse a single form for CSRF protection.

        Detection logic:
        1. Check if form is state-changing (POST or sensitive GET)
        2. Check if form has a CSRF token field
        3. If no token found — check if form is exploitable
        4. Try submitting without token — if succeeds = CSRF confirmed
        """
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        found_on = form.get('found_on', '')

        form_key = f"{action}_{method}"
        if form_key in self.tested_forms:
            return
        self.tested_forms.add(form_key)
        
        # Skip GET forms that don't change state
        if method == 'GET':
            if not self._is_sensitive_form(inputs, action):
                return

        # Skip login forms — CSRF on login is different issue
        if 'login' in action.lower():
            return

        # Skip external URLs
        if self.target_ip not in action:
            return

        # Get all input field names
        input_names = [
            i['name'].lower() for i in inputs
            if i.get('name')
        ]

        # Check for CSRF token
        has_csrf_token = False
        token_field = None

        for name in input_names:
            for csrf_name in CSRF_TOKEN_NAMES:
                if csrf_name in name:
                    has_csrf_token = True
                    token_field = name
                    break
            if has_csrf_token:
                break

        if has_csrf_token:
            console.print(
                f"  [green]✓ CSRF token found[/green] "
                f"({token_field}) → {action[-50:]}"
            )
            return

        # No CSRF token found — this is suspicious
        # Now verify by attempting to submit without token
        console.print(
            f"\n  [yellow]⚠ No CSRF token in form[/yellow]\n"
            f"  [cyan]Action:[/cyan] {action[-60:]}\n"
            f"  [cyan]Method:[/cyan] {method}\n"
            f"  [cyan]Fields:[/cyan] "
            f"{', '.join(input_names[:5])}"
        )

        # Try to submit the form without any CSRF token
        is_exploitable = self._verify_csrf(form, inputs)

        if is_exploitable:
            finding = {
                'title': f"CSRF Vulnerability — {action.split('/')[-1]}",
                'type': 'csrf',
                'vuln_type': 'CSRF',
                'target': action,
                'parameter': 'N/A',
                'severity': 'MEDIUM',
                'cvss_score': 6.5,
                'cvss_vector': (
                    'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N'
                ),
                'description': (
                    f"The form at {action} does not implement "
                    f"CSRF token protection. An attacker can trick "
                    f"authenticated users into submitting malicious "
                    f"requests without their knowledge."
                ),
                'evidence': (
                    f"Form URL: {action}\n"
                    f"Method: {method}\n"
                    f"Fields: {', '.join(input_names)}\n"
                    f"CSRF Token: NOT FOUND\n"
                    f"Form submitted without token: SUCCESS\n"
                    f"Found on page: {found_on}"
                ),
                'remediation': (
                    "1. Implement synchronizer token pattern — "
                    "generate unique token per session.\n"
                    "2. Validate CSRF token on every state-changing "
                    "request server-side.\n"
                    "3. Set SameSite=Strict or SameSite=Lax on "
                    "session cookies.\n"
                    "4. Use double submit cookie pattern as "
                    "additional defense.\n"
                    "5. Verify Origin and Referer headers for "
                    "cross-origin requests."
                ),
                'references': [
                    'https://owasp.org/www-community/attacks/csrf',
                    'CWE-352: Cross-Site Request Forgery'
                ],
                'discovered_at': datetime.now().isoformat()
            }
            self.findings.append(finding)
            self.logger.log_finding('CSRF', action, 'MEDIUM')
            console.print(
                f"  [bold red]✗ VULNERABLE — CSRF confirmed![/bold red]\n"
                f"  [red]Form submitted without token successfully[/red]"
            )
        else:
            console.print(
                f"  [green]✓ Form rejected without token "
                f"— protected by other means[/green]"
            )

    def _verify_csrf(self, form: dict, inputs: list) -> bool:
        """
        Try to submit form without CSRF token.
        If submission succeeds — form is CSRF vulnerable.
        """
        try:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()

            # Build form data with test values
            form_data = {}
            for inp in inputs:
                name = inp.get('name', '')
                inp_type = inp.get('type', 'text')
                if not name:
                    continue
                # Skip CSRF token fields if somehow present
                if any(csrf in name.lower() for csrf in CSRF_TOKEN_NAMES):
                    continue
                # Use safe test values
                if inp_type == 'password':
                    form_data[name] = 'TestPassword123!'
                elif inp_type == 'email':
                    form_data[name] = 'test@test.com'
                elif inp_type == 'number':
                    form_data[name] = '1'
                else:
                    form_data[name] = 'csrf_test_value'

            # Get baseline response first
            baseline = self.session.get(
                action,
                timeout=self.timeout
            )
            baseline_len = len(baseline.text)

            # Submit without CSRF token
            if method == 'POST':
                response = self.session.post(
                    action,
                    data=form_data,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                response = self.session.get(
                    action,
                    params=form_data,
                    timeout=self.timeout
                )

            self.logger.log_request(method, action, response.status_code)

            # If response is 200 and content changed
            # Form accepted submission without token
            if response.status_code == 200:
                response_len = len(response.text)
                # Meaningful response change indicates processing
                if abs(response_len - baseline_len) > 100:
                    return True
                # Or if response contains success indicators
                response_lower = response.text.lower()
                success_indicators = [
                    'success', 'updated', 'saved',
                    'changed', 'submitted', 'thank you',
                    'welcome', 'logged in'
                ]
                for indicator in success_indicators:
                    if indicator in response_lower:
                        return True

            time.sleep(0.2)
            return False

        except Exception as e:
            self.logger.log_error('csrf_verify', str(e))
            return False

    def _is_sensitive_form(self, inputs: list, action: str) -> bool:
        """
        Check if a GET form performs sensitive operations.
        """
        action_lower = action.lower()
        input_names = [
            i.get('name', '').lower()
            for i in inputs
        ]

        # Check action URL for sensitive keywords
        for keyword in SENSITIVE_FORM_KEYWORDS:
            if keyword in action_lower:
                return True

        # Check input field names
        for name in input_names:
            for keyword in SENSITIVE_FORM_KEYWORDS:
                if keyword in name:
                    return True

        return False

    def _check_cookie_security(self):
        """
        Check session cookie security attributes.
        Missing SameSite makes CSRF easier.
        """
        console.print(
            "\n[cyan]Checking cookie security attributes...[/cyan]"
        )

        try:
            response = self.session.get(
                self.dvwa_url,
                timeout=self.timeout
            )

            cookies = self.session.cookies

            for cookie in cookies:
                issues = []

                # Check SameSite
                if not hasattr(cookie, 'same_site') or \
                   not cookie._rest.get('SameSite'):
                    issues.append('SameSite attribute missing')

                # Check Secure flag
                if not cookie.secure:
                    issues.append('Secure flag missing')

                # Check HttpOnly
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('HttpOnly flag missing')

                if issues:
                    finding = {
                        'title': f"Insecure Cookie: {cookie.name}",
                        'type': 'csrf',
                        'vuln_type': 'Insecure Cookie',
                        'target': self.dvwa_url,
                        'parameter': cookie.name,
                        'severity': 'LOW',
                        'cvss_score': 4.3,
                        'cvss_vector': (
                            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/'
                            'S:U/C:L/I:N/A:N'
                        ),
                        'description': (
                            f"Session cookie '{cookie.name}' is "
                            f"missing security attributes: "
                            f"{', '.join(issues)}"
                        ),
                        'evidence': (
                            f"Cookie: {cookie.name}\n"
                            f"Issues: {', '.join(issues)}\n"
                            f"Value length: {len(cookie.value)} chars"
                        ),
                        'remediation': (
                            "1. Set SameSite=Strict on all session "
                            "cookies.\n"
                            "2. Set Secure flag — HTTPS only.\n"
                            "3. Set HttpOnly flag — prevents JS "
                            "access.\n"
                            "4. Set appropriate cookie expiry.\n"
                            "5. Use __Host- prefix for strongest "
                            "protection."
                        ),
                        'references': [
                            'https://owasp.org/www-community/'
                            'controls/SecureCookieAttribute',
                            'CWE-614: Sensitive Cookie in HTTPS '
                            'Session Without Secure Attribute'
                        ],
                        'discovered_at': datetime.now().isoformat()
                    }
                    self.findings.append(finding)
                    self.logger.log_finding(
                        'Insecure Cookie',
                        self.dvwa_url,
                        'LOW'
                    )
                    console.print(
                        f"  [yellow]⚠ Cookie issue:[/yellow] "
                        f"{cookie.name} — "
                        f"{', '.join(issues)}"
                    )
                else:
                    console.print(
                        f"  [green]✓ Cookie secure:[/green] "
                        f"{cookie.name}"
                    )

        except Exception as e:
            self.logger.log_error('cookie_check', str(e))

    def _display_results(self):
        """Display CSRF findings"""
        console.print(f"\n[bold white]CSRF Scan Complete.[/bold white]")

        if not self.findings:
            console.print(
                "[bold green]✓ No CSRF vulnerabilities found."
                "[/bold green]"
            )
            return

        table = Table(
            title="CSRF Findings",
            box=box.ROUNDED,
            style="blue"
        )
        table.add_column("Type", style="bold white", width=25)
        table.add_column("Target", style="cyan", width=40)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("CVSS", style="bold", width=6)

        severity_colors = {
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }

        for f in self.findings:
            color = severity_colors.get(f['severity'], 'white')
            table.add_row(
                f['vuln_type'],
                f['target'][-40:],
                f"[{color}]{f['severity']}[/{color}]",
                str(f['cvss_score'])
            )

        console.print(table)
        console.print(
            f"[bold blue]Total CSRF Findings: "
            f"{len(self.findings)}[/bold blue]"
        )
