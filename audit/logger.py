# AutoPen Audit Logger
# Every action the tool takes is recorded here
# Logs are append-only - professional requirement

import logging
import os
from datetime import datetime

class AuditLogger:
    def __init__(self, log_file: str):
        # Expand path if ~ is used
        self.log_file = os.path.expanduser(log_file)
        
        # Create audit directory if it doesn't exist
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Setup logger
        self.logger = logging.getLogger("AutoPen")
        self.logger.setLevel(logging.INFO)
        
        # File handler - append only, never overwrite
        handler = logging.FileHandler(self.log_file, mode='a')
        handler.setLevel(logging.INFO)
        
        # Professional log format
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
    def log_scan_start(self, target: str, modules: list):
        self.logger.info(f"SCAN STARTED | Target: {target} | Modules: {modules}")
        
    def log_scan_end(self, target: str, findings_count: int):
        self.logger.info(f"SCAN COMPLETED | Target: {target} | Findings: {findings_count}")
        
    def log_request(self, method: str, url: str, status_code: int):
        self.logger.info(f"REQUEST | {method} | {url} | Status: {status_code}")
        
    def log_finding(self, vuln_type: str, target: str, severity: str):
        self.logger.warning(f"FINDING | {vuln_type} | Target: {target} | Severity: {severity}")
        
    def log_scope_violation(self, target: str):
        self.logger.error(f"SCOPE VIOLATION BLOCKED | Target: {target}")
        
    def log_error(self, module: str, error: str):
        self.logger.error(f"ERROR | Module: {module} | {error}")
        
    def log_consent(self, confirmed: bool, operator: str = "unknown"):
        self.logger.info(f"CONSENT | Confirmed: {confirmed} | Operator: {operator}")
