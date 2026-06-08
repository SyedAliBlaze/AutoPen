# AutoPen Nmap Recon Module
# Performs service discovery and version fingerprinting
# Maps discovered services to known vulnerability patterns

import nmap
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

# Known vulnerable service signatures
# This is our own basic CVE mapping - not a tool wrapper
VULNERABLE_SERVICES = {
    'vsftpd 2.3.4': {
        'cve': 'CVE-2011-2523',
        'description': 'vsftpd 2.3.4 backdoor vulnerability - remote root shell',
        'severity': 'CRITICAL',
        'cvss': 10.0
    },
    'unreal': {
        'cve': 'CVE-2010-2075',
        'description': 'UnrealIRCd backdoor allows remote command execution',
        'severity': 'CRITICAL',
        'cvss': 10.0
    },
    'samba 3.0.20': {
        'cve': 'CVE-2007-2447',
        'description': 'Samba username map script command injection',
        'severity': 'CRITICAL',
        'cvss': 9.3
    },
    'proftpd 1.3.1': {
        'cve': 'CVE-2010-4221',
        'description': 'ProFTPD 1.3.3c backdoor via EXPLOIT buffer overflow',
        'severity': 'HIGH',
        'cvss': 7.5
    },
    'apache 2.2.8': {
        'cve': 'CVE-2011-3192',
        'description': 'Apache Range header DoS vulnerability',
        'severity': 'HIGH',
        'cvss': 7.8
    },
    'openssh 4.7': {
        'cve': 'CVE-2008-0166',
        'description': 'Debian OpenSSL predictable random number generator',
        'severity': 'HIGH',
        'cvss': 7.8
    },
    'mysql 5.0': {
        'cve': 'CVE-2012-2122',
        'description': 'MySQL authentication bypass vulnerability',
        'severity': 'HIGH',
        'cvss': 7.5
    },
    'postgresql 8.3': {
        'cve': 'CVE-2013-1899',
        'description': 'PostgreSQL privilege escalation vulnerability',
        'severity': 'MEDIUM',
        'cvss': 6.5
    }
}

# High risk ports that should never be open on production
HIGH_RISK_PORTS = {
    23: {'service': 'Telnet', 'reason': 'Plaintext protocol - credentials transmitted unencrypted', 'severity': 'HIGH'},
    512: {'service': 'rexec', 'reason': 'Remote execution service - legacy insecure protocol', 'severity': 'HIGH'},
    513: {'service': 'rlogin', 'reason': 'Remote login - no encryption', 'severity': 'HIGH'},
    514: {'service': 'rsh', 'reason': 'Remote shell - no authentication', 'severity': 'HIGH'},
    1524: {'service': 'Bindshell', 'reason': 'Open root shell - direct system access', 'severity': 'CRITICAL'},
    6000: {'service': 'X11', 'reason': 'X11 display server exposed - GUI capture possible', 'severity': 'HIGH'},
    2049: {'service': 'NFS', 'reason': 'Network File System exposed - file system access', 'severity': 'HIGH'},
}

class NmapScanner:
    def __init__(self, config: dict, logger, validator):
        self.target = config['target']['host']
        self.timeout = config['scan']['timeout']
        self.logger = logger
        self.validator = validator
        self.findings = []
        self.raw_results = {}

    def run(self) -> list:
        """
        Main scan function.
        Returns list of findings from recon.
        """
        console.print(Panel(
            "[bold cyan]PHASE 1: RECONNAISSANCE[/bold cyan]\n"
            f"Target: [bold white]{self.target}[/bold white]\n"
            "Running service discovery and version fingerprinting...",
            style="cyan"
        ))

        # Validate scope before scanning
        if not self.validator.is_host_in_scope(self.target):
            console.print("[bold red]Target out of scope. Scan blocked.[/bold red]")
            return []

        # Run the scan
        scan_results = self._run_nmap_scan()

        if not scan_results:
            console.print("[bold red]Nmap scan failed or returned no results.[/bold red]")
            return []

        # Parse results
        self._parse_results(scan_results)

        # Display results
        self._display_results()

        return self.findings

    def _run_nmap_scan(self) -> dict:
        """Run Nmap scan and return raw results"""
        try:
            nm = nmap.PortScanner()

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Scanning {task.description}[/bold cyan]"),
                transient=True
            ) as progress:
                progress.add_task(f"{self.target}...", total=None)

                # -sV = service version detection
                # -sC = default scripts
                # --open = only show open ports
                # -T4 = aggressive timing
                nm.scan(
                    hosts=self.target,
                    arguments=f'-sV -sC --open -T4 --host-timeout {self.timeout*10}s'
                )

            self.logger.log_request('NMAP', self.target, 0)
            return nm

        except Exception as e:
            self.logger.log_error('nmap_scanner', str(e))
            console.print(f"[bold red]Nmap error: {e}[/bold red]")
            return None

    def _parse_results(self, nm):
        """
        Parse Nmap results into structured findings.
        This is our own parsing logic.
        """
        for host in nm.all_hosts():
            self.raw_results['host'] = host
            self.raw_results['hostname'] = nm[host].hostname()
            self.raw_results['state'] = nm[host].state()
            self.raw_results['ports'] = []

            # Parse each open port
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()

                for port in sorted(ports):
                    service_info = nm[host][proto][port]

                    port_data = {
                        'port': port,
                        'protocol': proto,
                        'state': service_info['state'],
                        'service': service_info['name'],
                        'version': service_info.get('version', ''),
                        'product': service_info.get('product', ''),
                        'extrainfo': service_info.get('extrainfo', ''),
                    }

                    self.raw_results['ports'].append(port_data)

                    # Check for vulnerable services
                    self._check_vulnerable_service(port, service_info)

                    # Check for high risk ports
                    self._check_high_risk_port(port, service_info)

    def _check_vulnerable_service(self, port: int, service_info: dict):
        """
        Check if detected service version matches known vulnerable versions.
        This is our own vulnerability mapping logic.
        """
        product = service_info.get('product', '').lower()
        version = service_info.get('version', '').lower()
        full_version = f"{product} {version}".strip()

        for signature, vuln_data in VULNERABLE_SERVICES.items():
            if signature.lower() in full_version:
                finding = {
                    'title': f"Vulnerable Service: {product} {version}",
                    'type': 'vulnerable_service',
                    'target': self.target,
                    'port': port,
                    'service': service_info.get('name', ''),
                    'cve': vuln_data['cve'],
                    'description': vuln_data['description'],
                    'severity': vuln_data['severity'],
                    'cvss_score': vuln_data['cvss'],
                    'evidence': f"Port {port} running {product} {version}",
                    'remediation': f"Update {product} to latest stable version immediately. "
                                   f"Apply vendor patches for {vuln_data['cve']}.",
                    'discovered_at': datetime.now().isoformat()
                }
                self.findings.append(finding)
                self.logger.log_finding(
                    f"Vulnerable Service {vuln_data['cve']}",
                    f"{self.target}:{port}",
                    vuln_data['severity']
                )

    def _check_high_risk_port(self, port: int, service_info: dict):
        """
        Flag inherently dangerous open ports.
        These are risky regardless of version.
        """
        if port in HIGH_RISK_PORTS:
            risk = HIGH_RISK_PORTS[port]
            finding = {
                'title': f"High Risk Port Open: {port}/{risk['service']}",
                'type': 'high_risk_port',
                'target': self.target,
                'port': port,
                'service': risk['service'],
                'cve': 'N/A',
                'description': risk['reason'],
                'severity': risk['severity'],
                'cvss_score': 7.5 if risk['severity'] == 'HIGH' else 9.0,
                'evidence': f"Port {port} ({risk['service']}) is open and accessible",
                'remediation': f"Disable {risk['service']} if not required. "
                               f"If required, restrict access with firewall rules.",
                'discovered_at': datetime.now().isoformat()
            }
            self.findings.append(finding)
            self.logger.log_finding(
                f"High Risk Port {port}",
                self.target,
                risk['severity']
            )

    def _display_results(self):
        """Display scan results in professional tables"""

        # Port table
        port_table = Table(
            title=f"Open Ports — {self.target}",
            box=box.ROUNDED,
            style="cyan"
        )
        port_table.add_column("Port", style="bold white", width=8)
        port_table.add_column("Service", style="cyan", width=12)
        port_table.add_column("Product", style="white", width=20)
        port_table.add_column("Version", style="yellow", width=15)
        port_table.add_column("Risk", style="bold", width=10)

        for port_data in self.raw_results.get('ports', []):
            port = port_data['port']
            risk = "⚠ HIGH" if port in HIGH_RISK_PORTS else ""
            risk_style = "red" if port in HIGH_RISK_PORTS else "green"

            port_table.add_row(
                str(port),
                port_data['service'],
                port_data['product'],
                port_data['version'],
                f"[{risk_style}]{risk}[/{risk_style}]"
            )

        console.print(port_table)

        # Findings summary
        if self.findings:
            findings_table = Table(
                title="Recon Findings",
                box=box.ROUNDED,
                style="red"
            )
            findings_table.add_column("Severity", style="bold", width=10)
            findings_table.add_column("Finding", style="white", width=40)
            findings_table.add_column("CVE", style="yellow", width=16)
            findings_table.add_column("CVSS", style="bold white", width=6)

            severity_colors = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green"
            }

            for f in self.findings:
                color = severity_colors.get(f['severity'], 'white')
                findings_table.add_row(
                    f"[{color}]{f['severity']}[/{color}]",
                    f['title'],
                    f['cve'],
                    str(f['cvss_score'])
                )

            console.print(findings_table)
            console.print(f"\n[bold red]Total Recon Findings: {len(self.findings)}[/bold red]")
        else:
            console.print("[bold green]No vulnerable services detected.[/bold green]")
