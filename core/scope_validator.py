# AutoPen Scope Validator
# This runs BEFORE any scan module
# If target is not in scope - everything stops
# This is what separates a professional tool from a hacking script

import ipaddress
from urllib.parse import urlparse
from audit.logger import AuditLogger

class ScopeValidator:
    def __init__(self, config: dict, logger: AuditLogger):
        self.allowed_hosts = config['scope']['allowed_hosts']
        self.excluded_paths = config['scope']['excluded_paths']
        self.consent_confirmed = config['scope']['consent_confirmed']
        self.logger = logger

    def validate_consent(self) -> bool:
        """
        Consent must be confirmed in config before any scan runs.
        Professional tools never scan without explicit authorization.
        """
        if not self.consent_confirmed:
            print("\n[!] CONSENT NOT CONFIRMED")
            print("[!] Set consent_confirmed: true in config/config.yaml")
            print("[!] This confirms you have authorization to test this target")
            print("[!] Scanning without authorization is illegal\n")
            self.logger.log_consent(False)
            return False
        self.logger.log_consent(True)
        return True

    def is_host_in_scope(self, host: str) -> bool:
        """
        Check if target host is in allowed scope.
        Supports both IP addresses and hostnames.
        """
        # Direct match
        if host in self.allowed_hosts:
            return True

        # Check if host falls within any allowed subnet
        try:
            target_ip = ipaddress.ip_address(host)
            for allowed in self.allowed_hosts:
                try:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if target_ip in network:
                        return True
                except ValueError:
                    # allowed is a hostname not a subnet
                    if host == allowed:
                        return True
        except ValueError:
            # host is a hostname not an IP
            if host in self.allowed_hosts:
                return True

        # Host not in scope - log the violation
        self.logger.log_scope_violation(host)
        return False

    def is_url_in_scope(self, url: str) -> bool:
        """
        Check if a full URL is within scope.
        Checks host and excluded paths.
        """
        parsed = urlparse(url)
        host = parsed.hostname
        path = parsed.path

        # Check host
        if not self.is_host_in_scope(host):
            return False

        # Check excluded paths
        for excluded in self.excluded_paths:
            if path.startswith(excluded):
                self.logger.log_scope_violation(url)
                return False

        return True

    def validate_target(self, target: str) -> bool:
        """
        Master validation function.
        Call this before any module runs.
        Returns True only if everything is safe to proceed.
        """
        # First check consent
        if not self.validate_consent():
            return False

        # Then check scope
        if not self.is_host_in_scope(target):
            print(f"\n[!] TARGET OUT OF SCOPE: {target}")
            print(f"[!] Allowed targets: {self.allowed_hosts}")
            print(f"[!] Scan blocked.\n")
            return False

        return True
