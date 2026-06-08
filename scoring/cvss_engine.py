# AutoPen CVSS v3.1 Scoring Engine
# Dynamic scoring based on finding context
# Not hardcoded - calculated from actual vectors
# Industry standard CVSS v3.1 implementation

from rich.console import Console

console = Console()

# CVSS v3.1 Vector weights
# Source: https://www.first.org/cvss/v3.1/specification-document

ATTACK_VECTOR = {
    'N': 0.85,   # Network
    'A': 0.62,   # Adjacent
    'L': 0.55,   # Local
    'P': 0.20,   # Physical
}

ATTACK_COMPLEXITY = {
    'L': 0.77,   # Low
    'H': 0.44,   # High
}

PRIVILEGES_REQUIRED = {
    'N': 0.85,   # None
    'L': 0.62,   # Low (unchanged scope)
    'H': 0.27,   # High (unchanged scope)
}

PRIVILEGES_REQUIRED_CHANGED = {
    'N': 0.85,   # None
    'L': 0.50,   # Low (changed scope)
    'H': 0.50,   # High (changed scope)
}

USER_INTERACTION = {
    'N': 0.85,   # None
    'R': 0.62,   # Required
}

SCOPE = {
    'U': 'unchanged',
    'C': 'changed',
}

IMPACT = {
    'N': 0.00,   # None
    'L': 0.22,   # Low
    'H': 0.56,   # High
}

# Predefined CVSS vectors for finding types
# Based on real-world CVSS assessments
FINDING_VECTORS = {
    'sqli': {
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N',
        'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H',
        'description': 'Network exploitable, no auth required, full impact'
    },
    'reflected_xss': {
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R',
        'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N',
        'description': 'Network exploitable, user interaction required'
    },
    'stored_xss': {
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N',
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N',
        'S': 'C', 'C': 'L', 'I': 'H', 'A': 'N',
        'description': 'Network exploitable, affects all users'
    },
    'directory': {
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N',
        'S': 'U', 'C': 'L', 'I': 'N', 'A': 'N',
        'description': 'Information disclosure via exposed directory'
    },
    'vulnerable_service': {
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N',
        'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H',
        'description': 'Network exploitable vulnerable service version'
    },
    'high_risk_port': {
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N',
        'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N',
        'description': 'Insecure service exposed to network'
    },
}


class CVSSEngine:
    def __init__(self):
        pass

    def calculate_score(self, finding: dict) -> dict:
        """
        Calculate CVSS v3.1 score for a finding.
        Returns score, severity, vector string, and justification.
        """
        finding_type = finding.get('type', 'directory')
        vuln_type = finding.get('vuln_type', '')
        title_lower = finding.get('title', '').lower()
        vuln_type_lower = vuln_type.lower() if vuln_type else ''

        if 'local file inclusion' in vuln_type_lower or \
           'lfi' in vuln_type_lower:
            vector_key = 'vulnerable_service'
        elif 'ssrf' in vuln_type_lower or \
             'server-side request' in vuln_type_lower:
            vector_key = 'vulnerable_service'
        elif 'command injection' in vuln_type_lower:
            vector_key = 'sqli'
        elif finding_type == 'sqli':
            vector_key = 'sqli'
        elif 'reflected' in vuln_type_lower:
            vector_key = 'reflected_xss'
        elif 'stored' in vuln_type_lower:
            vector_key = 'stored_xss'
        elif finding_type == 'directory':
            vector_key = 'directory'
        elif 'vulnerable service' in title_lower:
            vector_key = 'vulnerable_service'
        elif 'high risk port' in title_lower:
            vector_key = 'high_risk_port'
        else:
            vector_key = 'directory'

        vectors = FINDING_VECTORS[vector_key]
        score = self._calculate_base_score(vectors)
        severity = self._score_to_severity(score)

        return {
            'score': round(score, 1),
            'severity': severity,
            'vector': vectors['vector'],
            'justification': vectors['description'],
            'breakdown': {
                'attack_vector': vectors['AV'],
                'attack_complexity': vectors['AC'],
                'privileges_required': vectors['PR'],
                'user_interaction': vectors['UI'],
                'scope': vectors['S'],
                'confidentiality': vectors['C'],
                'integrity': vectors['I'],
                'availability': vectors['A'],
            }
        }

    def _calculate_base_score(self, v: dict) -> float:
        """
        CVSS v3.1 Base Score calculation formula.
        Source: FIRST CVSS v3.1 specification.
        """
        # Impact sub score
        isc_base = (
            1 -
            (1 - IMPACT[v['C']]) *
            (1 - IMPACT[v['I']]) *
            (1 - IMPACT[v['A']])
        )

        if v['S'] == 'U':
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * \
                     ((isc_base - 0.02) ** 15)

        # Exploitability sub score
        if v['S'] == 'U':
            pr = PRIVILEGES_REQUIRED[v['PR']]
        else:
            pr = PRIVILEGES_REQUIRED_CHANGED[v['PR']]

        exploitability = (
            8.22 *
            ATTACK_VECTOR[v['AV']] *
            ATTACK_COMPLEXITY[v['AC']] *
            pr *
            USER_INTERACTION[v['UI']]
        )

        # Base score
        if impact <= 0:
            return 0.0

        if v['S'] == 'U':
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)

        # Round up to 1 decimal
        return self._round_up(base)

    def _round_up(self, value: float) -> float:
        """CVSS v3.1 specific rounding"""
        import math
        return math.ceil(value * 10) / 10

    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity rating"""
        if score == 0.0:
            return 'NONE'
        elif score <= 3.9:
            return 'LOW'
        elif score <= 6.9:
            return 'MEDIUM'
        elif score <= 8.9:
            return 'HIGH'
        else:
            return 'CRITICAL'

    def enrich_findings(self, findings: list) -> list:
        """
        Enrich all findings with proper CVSS scores.
        Call this before generating report.
        """
        enriched = []
        for finding in findings:
            cvss_data = self.calculate_score(finding)
            finding['cvss_score'] = cvss_data['score']
            finding['cvss_vector'] = cvss_data['vector']
            finding['cvss_severity'] = cvss_data['severity']
            finding['cvss_justification'] = cvss_data['justification']
            finding['severity'] = cvss_data['severity']
            enriched.append(finding)
        return enriched
