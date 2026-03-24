"""
Regex Detection Engine
Scans text for sensitive patterns: emails, API keys, passwords, tokens,
secrets, stack traces, and more.
"""

import re
import logging
from typing import List, Tuple, Pattern
from models.schemas import Finding, RiskLevel

logger = logging.getLogger(__name__)


class RegexEngine:
    """
    Static pattern-based detection engine.
    Each pattern has: (compiled_regex, risk_level, description, recommendation)
    """

    # Ordered from most specific → least specific to avoid false positives
    PATTERNS: dict[str, Tuple[str, RiskLevel, str]] = {
        # CRITICAL — Hardcoded secrets & passwords
        "password": (
            r"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*['\"]?([^\s'\"]{3,})['\"]?",
            RiskLevel.CRITICAL,
            "Hardcoded password detected"
        ),
        "private_key": (
            r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            RiskLevel.CRITICAL,
            "Private key detected in content"
        ),
        "connection_string": (
            r"(?i)(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s]+:[^\s]+@[^\s]+",
            RiskLevel.CRITICAL,
            "Database connection string with credentials"
        ),

        # HIGH — API keys & tokens
        "api_key": (
            r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
            RiskLevel.HIGH,
            "API key exposed"
        ),
        "openai_key": (
            r"sk-[a-zA-Z0-9]{20,}",
            RiskLevel.HIGH,
            "OpenAI-style API key detected"
        ),
        "aws_key": (
            r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
            RiskLevel.HIGH,
            "AWS access key detected"
        ),
        "bearer_token": (
            r"(?i)(?:bearer|token|auth)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-.]{20,})['\"]?",
            RiskLevel.HIGH,
            "Authentication token detected"
        ),
        "jwt_token": (
            r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-]+",
            RiskLevel.HIGH,
            "JWT token detected"
        ),
        "github_token": (
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
            RiskLevel.HIGH,
            "GitHub personal access token detected"
        ),

        # MEDIUM — Error leaks & security issues
        "stack_trace": (
            r"(?i)(?:Traceback \(most recent call last\)|Exception in thread|"
            r"at\s+[\w.$]+\.\w+\([\w.]+:\d+\)|"
            r"(?:java|python|node|php)\.\w+\.\w+Exception|"
            r"stack\s*trace|NullPointerException|StackOverflowError)",
            RiskLevel.MEDIUM,
            "Stack trace or error leak detected"
        ),
        "sql_injection": (
            r"(?i)(?:SELECT\s+.+\s+FROM\s+.+\s+WHERE|"
            r"UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO\s+.+\s+VALUES|"
            r";\s*DELETE\s+FROM)",
            RiskLevel.MEDIUM,
            "Potential SQL injection pattern"
        ),
        "ip_address": (
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            RiskLevel.MEDIUM,
            "IP address detected"
        ),

        # LOW — PII & identifiers
        "email": (
            r"[\w.+-]+@[\w-]+\.[\w.-]+",
            RiskLevel.LOW,
            "Email address detected"
        ),
        "phone": (
            r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
            RiskLevel.LOW,
            "Phone number detected"
        ),
        "ssn": (
            r"\b\d{3}-\d{2}-\d{4}\b",
            RiskLevel.HIGH,
            "Possible SSN detected"
        ),
        "credit_card": (
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
            RiskLevel.HIGH,
            "Credit card number detected"
        ),
    }

    def __init__(self):
        """Pre-compile all regex patterns for performance."""
        self._compiled: dict[str, Tuple[Pattern, RiskLevel, str]] = {}
        for name, (pattern, risk, desc) in self.PATTERNS.items():
            try:
                self._compiled[name] = (re.compile(pattern), risk, desc)
            except re.error as e:
                logger.error(f"Failed to compile pattern '{name}': {e}")

        logger.info(f"RegexEngine initialized with {len(self._compiled)} patterns")

    def scan_text(self, text: str) -> List[Finding]:
        """Scan full text, tracking line numbers."""
        findings = []
        lines = text.splitlines()

        for line_num, line in enumerate(lines, start=1):
            line_findings = self.scan_line(line, line_num)
            findings.extend(line_findings)

        logger.info(f"RegexEngine found {len(findings)} findings across {len(lines)} lines")
        return findings

    def scan_line(self, line: str, line_num: int) -> List[Finding]:
        """Scan a single line against all compiled patterns."""
        findings = []
        for name, (compiled, risk, desc) in self._compiled.items():
            for match in compiled.finditer(line):
                value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                col = match.start() + 1

                findings.append(Finding(
                    type=name,
                    line=line_num,
                    column=col,
                    risk=risk,
                    value=value,
                    context=line.strip()[:200],
                    recommendation=self._get_recommendation(name)
                ))
        return findings

    @staticmethod
    def _get_recommendation(finding_type: str) -> str:
        """Return remediation advice based on finding type."""
        recommendations = {
            "password": "Remove hardcoded passwords. Use environment variables or a secrets manager.",
            "api_key": "Rotate this API key immediately. Store keys in a vault (e.g., AWS Secrets Manager).",
            "openai_key": "Revoke and regenerate this OpenAI key. Never commit API keys to source control.",
            "aws_key": "Rotate this AWS key via IAM. Enable key rotation policies.",
            "bearer_token": "Ensure tokens are short-lived and not logged. Implement token rotation.",
            "jwt_token": "Verify JWT expiration claims. Do not log full tokens.",
            "github_token": "Revoke this GitHub token immediately via Settings > Developer settings.",
            "private_key": "Remove private keys from codebase. Use a certificate manager.",
            "connection_string": "Move database credentials to environment variables or a secrets manager.",
            "email": "Consider if this email exposure is necessary. Anonymize where possible.",
            "phone": "Review if phone number exposure is compliant with data protection policies.",
            "ssn": "CRITICAL: Remove SSN immediately. This is a regulatory compliance violation.",
            "credit_card": "CRITICAL: Remove card numbers. This violates PCI-DSS compliance.",
            "stack_trace": "Suppress detailed error messages in production. Log internally only.",
            "sql_injection": "Use parameterized queries. Never concatenate user input into SQL.",
            "ip_address": "Consider if IP logging is compliant with your privacy policy.",
        }
        return recommendations.get(finding_type, "Review this finding and apply appropriate security controls.")