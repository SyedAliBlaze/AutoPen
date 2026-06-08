# AutoPen - Automated Penetration Testing Tool
# Version 1.0
# For authorized security testing only

import yaml
import os
import sys
import re
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box
from scoring.cvss_engine import CVSSEngine
from reporting.pdf_generator import PDFReportGenerator
from modules.web.csrf_scanner import CSRFScanner
from modules.web.ssrf_scanner import SSRFScanner
from modules.web.cmd_injection_scanner import CmdInjectionScanner
from modules.web.bruteforce_scanner import BruteForceScannerVuln


from audit.logger import AuditLogger
from core.scope_validator import ScopeValidator
from modules.recon.nmap_scanner import NmapScanner
from modules.web.sqli_scanner import SQLiScanner
from modules.web.xss_scanner import XSSScanner
from modules.bruteforce.dir_bruteforce import DirBruteforcer


console = Console()


def load_config(config_path: str) -> dict:
    """Load configuration from yaml file"""
    with open(os.path.expanduser(config_path), 'r') as f:
        return yaml.safe_load(f)


def print_banner():
    """Print professional AutoPen banner"""
    banner = """
    ░█████╗░██╗░░░██╗████████╗░█████╗░██████╗░███████╗███╗░░██╗
    ██╔══██╗██║░░░██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝████╗░██║
    ███████║██║░░░██║░░░██║░░░██║░░██║██████╔╝█████╗░░██╔██╗██║
    ██╔══██║██║░░░██║░░░██║░░░██║░░██║██╔═══╝░██╔══╝░░██║╚████║
    ██║░░██║╚██████╔╝░░░██║░░░╚█████╔╝██║░░░░░███████╗██║░╚███║
    ╚═╝░░╚═╝░╚═════╝░░░╚═╝░░░░╚════╝░╚═╝░░░░░╚══════╝╚═╝░░╚══╝
    """
    console.print(banner, style="bold red")
    console.print(
        Panel(
            "[bold white]Automated Penetration Testing Tool[/bold white]\n"
            "[yellow]Version 1.0[/yellow] | "
            "[red]For Authorized Security Testing Only[/red]",
            box=box.DOUBLE,
            style="bold blue"
        )
    )


def parse_target_input(user_input: str) -> dict:
    """
    Smart target parser.
    Accepts any format the user provides:
      - 192.168.43.54
      - http://192.168.1.100/
      - http://192.168.1.100/app/
      - https://192.168.1.100/login.php

    Returns a clean dict with ip, base_url, target_url
    """
    user_input = user_input.strip()

    # If no scheme provided, add http:// so urlparse works correctly
    if not user_input.startswith('http://') and not user_input.startswith('https://'):
        # Check if it looks like just an IP
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, user_input):
            # Pure IP — add scheme
            user_input = f"http://{user_input}"
        else:
            # Could be a hostname or partial URL
            user_input = f"http://{user_input}"

    # Now parse properly
    parsed = urlparse(user_input)
    host = parsed.hostname
    scheme = parsed.scheme or 'http'

    # Validate IP format
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, host):
        return None

    # Validate each octet is 0-255
    octets = host.split('.')
    for octet in octets:
        if not 0 <= int(octet) <= 255:
            return None

    base_url = f"{scheme}://{host}"
    
    # Extract path if present
    path = parsed.path
    if path and not path.endswith('/'):
        # If it's a file, get the directory
        if '.' in path.split('/')[-1]:
            path = '/'.join(path.split('/')[:-1]) + '/'
    
    target_url = f"{scheme}://{host}{path}" if path else base_url

    return {
        'ip': host,
        'base_url': base_url,
        'url': target_url,
        'scheme': scheme
    }


def get_target_from_user() -> dict:
    """
    Ask user for target.
    Accepts IP or full URL.
    Validates and returns parsed target info.
    """
    console.print(Panel(
        "[bold cyan]Target Configuration[/bold cyan]\n\n"
        "[white]Enter target in any format:[/white]\n"
        "[green]  192.168.1.100[/green]\n"
        "[green]  http://192.168.1.100[/green]\n"
        "[green]  http://192.168.1.100/app/[/green]\n\n"
        "[yellow]You must have explicit authorization to test this target.[/yellow]",
        style="cyan"
    ))

    while True:
        user_input = Prompt.ask("[bold yellow]Enter target IP or URL[/bold yellow]")

        target = parse_target_input(user_input)

        if target:
            console.print(f"\n[bold green]✓ Target parsed successfully[/bold green]")
            console.print(f"  [white]IP Address :[/white] [bold cyan]{target['ip']}[/bold cyan]")
            console.print(f"  [white]Base URL   :[/white] [bold cyan]{target['base_url']}[/bold cyan]")
            console.print(f"  [white]Target URL :[/white] [bold cyan]{target['url']}[/bold cyan]\n")
            return target
        else:
            console.print("[bold red]✗ Invalid format. Please enter a valid IP address or URL.[/bold red]")
            console.print("[yellow]Example: 192.168.1.100 or http://192.168.1.100/app/[/yellow]\n")


def print_scan_config(config: dict):
    """Display scan configuration in a professional table"""
    table = Table(
        title="Scan Configuration",
        box=box.ROUNDED,
        style="cyan"
    )
    table.add_column("Setting", style="bold white")
    table.add_column("Value", style="green")

    table.add_row("Target Host", config['target']['host'])
    table.add_row("Target URL", config['target']['url'])
    table.add_row("Allowed Hosts", ", ".join(config['scope']['allowed_hosts']))
    table.add_row("Modules", ", ".join(config['scan']['modules']))
    table.add_row("Timeout", f"{config['scan']['timeout']} seconds")
    table.add_row("Max Requests/sec", str(config['scope']['max_requests_per_second']))
    table.add_row("Report Format", ", ".join(config['reporting']['formats']))

    console.print(table)


def consent_banner(config: dict) -> bool:
    """
    Display legal consent banner.
    User must explicitly type AGREE before any scan starts.
    """
    console.print(
        Panel(
            "[bold red]⚠  LEGAL WARNING ⚠[/bold red]\n\n"
            "[white]AutoPen performs active security testing including:\n"
            "• Network reconnaissance and port scanning\n"
            "• Web vulnerability probing (SQLi, XSS)\n"
            "• Directory enumeration\n\n"
            "[bold yellow]Unauthorized use against systems you do not own\n"
            "or have explicit written permission to test is ILLEGAL\n"
            "and may result in criminal prosecution.[/bold yellow]\n\n"
            f"[white]Target: [bold red]{config['target']['host']}[/bold red]\n"
            "Ensure you have written authorization before proceeding.[/white]",
            box=box.DOUBLE,
            style="red"
        )
    )

    response = Prompt.ask(
        "\n[bold yellow]Type AGREE to confirm you have authorization to test this target[/bold yellow]"
    )

    if response.strip().upper() != "AGREE":
        console.print("\n[bold red]Consent not confirmed. Exiting.[/bold red]")
        return False

    return True


def display_findings_summary(findings: list):
    """Display all findings in a final professional summary table"""
    if not findings:
        console.print("\n[bold green]No vulnerabilities found.[/bold green]")
        return

    table = Table(
        title="Final Findings Summary",
        box=box.ROUNDED,
        style="white"
    )
    table.add_column("#", style="white", width=4)
    table.add_column("Vulnerability", style="bold white")
    table.add_column("Target", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("CVSS", style="bold")

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "blue"
    }

    for i, finding in enumerate(findings, 1):
        severity = finding.get('severity', 'INFO')
        color = severity_colors.get(severity, 'white')
        table.add_row(
            str(i),
            finding.get('title', 'Unknown'),
            finding.get('target', 'Unknown'),
            f"[{color}]{severity}[/{color}]",
            str(finding.get('cvss_score', 'N/A'))
        )

    console.print(table)
    console.print(f"\n[bold red]Total Findings: {len(findings)}[/bold red]")


def main():
    # Step 1 - Banner
    print_banner()

    # Step 2 - Load config
    try:
        config = load_config('config/config.yaml')
        console.print("[bold green]✓[/bold green] Configuration loaded successfully")
    except FileNotFoundError:
        console.print("[bold red]✗ config/config.yaml not found[/bold red]")
        sys.exit(1)
    except yaml.YAMLError as e:
        console.print(f"[bold red]✗ Config file error: {e}[/bold red]")
        sys.exit(1)

    # Step 3 - Smart target input
    # Accepts IP, URL, or full path - any format
    target = get_target_from_user()

    # Update config with parsed target
    config['target']['host'] = target['ip']
    config['target']['url'] = target['url']
    config['scope']['allowed_hosts'] = [target['ip']]

    # Step 4 - Show scan configuration
    print_scan_config(config)

    # Step 5 - Consent confirmation
    if not consent_banner(config):
        sys.exit(0)

    # Step 6 - Initialize logger
    logger = AuditLogger(config['audit']['log_file'])
    console.print("[bold green]✓[/bold green] Audit logger initialized")

    # Step 7 - Initialize scope validator
    validator = ScopeValidator(config, logger)
    if not validator.validate_target(config['target']['host']):
        console.print("[bold red]✗ Target validation failed. Exiting.[/bold red]")
        sys.exit(1)
    console.print("[bold green]✓[/bold green] Scope validation passed")

    # Step 8 - Log scan start
    logger.log_scan_start(
        config['target']['host'],
        config['scan']['modules']
    )

    console.print(
        Panel(
            "[bold green]All checks passed. Starting scan modules.[/bold green]",
            style="green"
        )
    )

    # All findings collected here
    all_findings = []

    # Phase 1 - Recon
    if 'recon' in config['scan']['modules']:
        scanner = NmapScanner(config, logger, validator)
        recon_findings = scanner.run()
        all_findings.extend(recon_findings)

    # Phase 2 - Directory Brute-forcing
    # Runs BEFORE crawling so crawler has more paths
    if 'bruteforce' in config['scan']['modules']:
        brute = DirBruteforcer(config, logger, validator)
        brute_findings = brute.run()
        all_findings.extend(brute_findings)

    # Pre-scan — Crawl ONCE share with all web modules
    console.print(Panel(
        "[bold cyan]WEB CRAWLER — Shared Pre-Scan[/bold cyan]\n"
        "Running once for all web vulnerability modules...",
        style="cyan"
    ))

    import requests as req
    shared_session = req.Session()
    shared_session.headers.update({
        'User-Agent': config['scan']['user_agent']
    })

    # Optional: Authentication can be added here if needed for generic targets
    # For now, we proceed with the provided credentials if any

    from modules.recon.crawler import WebCrawler
    shared_crawler = WebCrawler(config, logger, shared_session)
    shared_crawl_results = shared_crawler.run()
    console.print(
        f"[bold green]✓ Crawl complete —[/bold green] "
        f"[white]{len(shared_crawl_results['urls'])} pages | "
        f"{len(shared_crawl_results['get_params'])} parameters | "
        f"{len(shared_crawl_results['forms'])} forms[/white]"
    )

    # Phase 3 - SQLi using shared results
    if 'sqli' in config['scan']['modules']:
        sqli = SQLiScanner(config, logger, validator)
        sqli.session = shared_session
        sqli_findings = sqli.run(shared_crawl_results)
        all_findings.extend(sqli_findings)

    # Phase 4 - XSS using shared results
    if 'xss' in config['scan']['modules']:
        xss = XSSScanner(config, logger, validator)
        xss.session = shared_session
        xss_findings = xss.run(shared_crawl_results)
        all_findings.extend(xss_findings)

    # Phase 5 - CSRF using shared results
    if 'csrf' in config['scan']['modules']:
        csrf = CSRFScanner(config, logger, validator)
        csrf.session = shared_session
        csrf_findings = csrf.run(shared_crawl_results)
        all_findings.extend(csrf_findings)

    # Phase 6 - SSRF using shared results
    if 'ssrf' in config['scan']['modules']:
        ssrf = SSRFScanner(config, logger, validator)
        ssrf.session = shared_session
        ssrf_findings = ssrf.run(shared_crawl_results)
        all_findings.extend(ssrf_findings)
    
    # Phase 7 - Command Injection
    if 'cmd_injection' in config['scan']['modules']:
        cmd = CmdInjectionScanner(config, logger, validator)
        cmd.session = shared_session
        cmd_findings = cmd.run(shared_crawl_results)
        all_findings.extend(cmd_findings)

    # Phase 8 - Brute Force Vulnerability Detection
    if 'brute_vuln' in config['scan']['modules']:
        bf = BruteForceScannerVuln(config, logger, validator)
        bf.session = shared_session
        bf_findings = bf.run(shared_crawl_results)
        all_findings.extend(bf_findings)
    
    # Enrich findings with CVSS scores
    console.print("\n[bold white]Calculating CVSS scores...[/bold white]")
    cvss_engine = CVSSEngine()
    all_findings = cvss_engine.enrich_findings(all_findings)

    # Final summary
    console.print(f"\n[bold white]Scan Complete.[/bold white]")
    display_findings_summary(all_findings)

    # Generate PDF report
    reporter = PDFReportGenerator(config)
    report_path = reporter.generate(all_findings, config['target']['host'])

    # Log completion
    logger.log_scan_end(config['target']['host'], len(all_findings))

    console.print(
        f"\n[bold green]✓ Assessment complete.[/bold green]\n"
        f"[white]Report saved to:[/white] [cyan]{report_path}[/cyan]"
    )


if __name__ == "__main__":
    main()

