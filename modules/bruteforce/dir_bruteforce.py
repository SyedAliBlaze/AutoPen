# AutoPen Directory Brute-forcer
# Discovers hidden directories and files
# Uses own wordlist - no external tools
# Finds admin panels, backup files, config files

import requests
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

# ─────────────────────────────────────────────
# OUR OWN WORDLIST
# Carefully selected common directories
# Organized by category
# ─────────────────────────────────────────────

WORDLIST = [
    # Admin panels
    "admin", "administrator", "admin.php", "admin.html",
    "admin/login", "admin/index", "adminpanel", "admin_area",
    "backend", "manage", "management", "manager", "controlpanel",
    "cp", "dashboard", "webadmin", "siteadmin",

    # Authentication
    "login", "login.php", "signin", "signup", "register",
    "auth", "authentication", "logout", "user", "users",
    "account", "accounts", "profile", "members",

    # Configuration and sensitive files
    "config", "config.php", "configuration", "settings",
    "setup", "install", "installer", "web.config",
    ".htaccess", ".htpasswd", ".env", "env",
    "database", "db", "db.php", "database.php",

    # Backup files
    "backup", "backups", "bak", "old", "temp", "tmp",
    "backup.zip", "backup.tar.gz", "backup.sql",
    "db_backup", "site_backup", "www_backup",

    # Development artifacts
    "test", "testing", "dev", "development", "debug",
    "staging", "demo", "sandbox", "beta",
    "phpinfo.php", "info.php", "test.php",

    # Common CMS paths
    "wp-admin", "wp-login.php", "wp-config.php",
    "wordpress", "joomla", "drupal", "cms",
    "phpmyadmin", "pma", "myadmin", "mysql",

    # API endpoints
    "api", "api/v1", "api/v2", "rest", "graphql",
    "swagger", "docs", "documentation",

    # Logs and data
    "logs", "log", "error_log", "access_log",
    "data", "files", "uploads", "upload",
    "images", "img", "static", "assets",
    "private", "secret", "hidden", "confidential",

    # Server info
    "server-status", "server-info",
    "status", "health", "metrics",
    ".git", ".git/HEAD", ".svn",
    "robots.txt", "sitemap.xml",
]

# Response codes that indicate found resources
INTERESTING_CODES = {
    200: ('FOUND', 'HIGH', 'Directory/file accessible'),
    201: ('FOUND', 'HIGH', 'Resource created/accessible'),
    301: ('REDIRECT', 'MEDIUM', 'Permanent redirect - resource exists'),
    302: ('REDIRECT', 'MEDIUM', 'Temporary redirect - resource exists'),
    401: ('AUTH REQUIRED', 'MEDIUM', 'Requires authentication - resource exists'),
    403: ('FORBIDDEN', 'LOW', 'Access denied - resource exists but protected'),
}


class DirBruteforcer:
    def __init__(self, config: dict, logger, validator):
        self.target_ip = config['target']['host']
        self.base_url = f"http://{self.target_ip}"
        self.timeout = config['scan']['timeout']
        self.logger = logger
        self.validator = validator
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['scan']['user_agent']
        })

    def run(self) -> list:
        """Main brute-force function"""
        console.print(Panel(
            "[bold magenta]PHASE 4: DIRECTORY BRUTE-FORCING[/bold magenta]\n"
            f"Target: [bold white]{self.base_url}[/bold white]\n"
            f"Wordlist size: [bold white]{len(WORDLIST)}[/bold white] entries\n"
            "Discovering hidden directories and sensitive files...",
            style="magenta"
        ))

        if not self.validator.is_host_in_scope(self.target_ip):
            console.print("[bold red]Target out of scope. Scan blocked.[/bold red]")
            return []

        self._run_bruteforce()
        self._display_results()
        return self.findings

    def _run_bruteforce(self):
        """
        Send requests for each word in wordlist.
        Check response codes to identify existing resources.
        """
        console.print(
            f"[magenta]Scanning {len(WORDLIST)} paths...[/magenta]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[magenta]{task.description}[/magenta]"),
            BarColumn(),
            TextColumn("[white]{task.completed}/{task.total}[/white]"),
            transient=False
        ) as progress:
            task = progress.add_task(
                "Brute-forcing directories...",
                total=len(WORDLIST)
            )

            for word in WORDLIST:
                url = f"{self.base_url}/{word}"

                try:
                    response = self.session.get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=False
                    )

                    self.logger.log_request(
                        'GET', url, response.status_code
                    )

                    # Check if response code is interesting
                    if response.status_code in INTERESTING_CODES:
                        status_info = INTERESTING_CODES[response.status_code]
                        status_label = status_info[0]
                        severity = status_info[1]
                        reason = status_info[2]

                        # Get content length for evidence
                        content_length = len(response.content)

                        # Get redirect location if applicable
                        redirect_to = response.headers.get(
                            'Location', 'N/A'
                        )

                        finding = {
                            'title': f"Hidden Path Discovered: /{word}",
                            'type': 'directory',
                            'status': status_label,
                            'target': url,
                            'path': f"/{word}",
                            'status_code': response.status_code,
                            'severity': severity,
                            'cvss_score': (
                                7.5 if severity == 'HIGH'
                                else 5.0 if severity == 'MEDIUM'
                                else 3.1
                            ),
                            'description': (
                                f"Hidden resource discovered at /{word}.\n"
                                f"Status: {response.status_code} "
                                f"({status_label}) — {reason}"
                            ),
                            'evidence': (
                                f"URL: {url}\n"
                                f"Status Code: {response.status_code}\n"
                                f"Response Size: {content_length} bytes\n"
                                f"Redirect: {redirect_to}"
                            ),
                            'remediation': (
                                "1. Remove or restrict access to sensitive "
                                "directories.\n"
                                "2. Implement proper access controls.\n"
                                "3. Use robots.txt to hide from search engines "
                                "(security through obscurity only).\n"
                                "4. Audit web server configuration.\n"
                                "5. Remove development and backup files "
                                "from production."
                            ),
                            'references': [
                                'https://owasp.org/www-project-web-security'
                                '-testing-guide/',
                                'CWE-538: File and Directory Information '
                                'Exposure'
                            ],
                            'discovered_at': datetime.now().isoformat()
                        }

                        self.findings.append(finding)
                        self.logger.log_finding(
                            f"Directory {status_label}",
                            url,
                            severity
                        )

                        # Show finding immediately
                        severity_colors = {
                            'HIGH': 'bold red',
                            'MEDIUM': 'yellow',
                            'LOW': 'green'
                        }
                        color = severity_colors.get(severity, 'white')
                        console.print(
                            f"  [{color}][{response.status_code}] "
                            f"{status_label}[/{color}] "
                            f"→ /{word}"
                        )

                    # Rate limiting
                    time.sleep(0.05)

                except requests.exceptions.Timeout:
                    pass
                except requests.exceptions.ConnectionError:
                    pass
                except Exception as e:
                    self.logger.log_error('dir_bruteforce', str(e))

                progress.advance(task)

    def _display_results(self):
        """Display brute-force results"""
        console.print(
            f"\n[bold white]Directory Scan Complete.[/bold white]"
        )

        if not self.findings:
            console.print(
                "[bold green]✓ No hidden directories found.[/bold green]"
            )
            return

        table = Table(
            title="Directory Findings",
            box=box.ROUNDED,
            style="magenta"
        )
        table.add_column("Status", style="bold", width=15)
        table.add_column("Path", style="cyan", width=35)
        table.add_column("Code", style="white", width=6)
        table.add_column("Severity", style="bold", width=10)

        severity_colors = {
            'HIGH': 'red',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }

        for f in self.findings:
            color = severity_colors.get(f['severity'], 'white')
            table.add_row(
                f['status'],
                f['path'],
                str(f['status_code']),
                f"[{color}]{f['severity']}[/{color}]"
            )

        console.print(table)
        console.print(
            f"[bold magenta]"
            f"Total Directory Findings: {len(self.findings)}"
            f"[/bold magenta]"
        )
