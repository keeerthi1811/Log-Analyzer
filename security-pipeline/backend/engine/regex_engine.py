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
    """

    PATTERNS: dict[str, Tuple[str, RiskLevel, str]] = {

        # ---------------- CRITICAL ----------------

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

        # ---------------- HIGH ----------------

        "api_key": (
            r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{6,})['\"]?",
            RiskLevel.HIGH,
            "API key exposed"
        ),

        # ✅ FIXED HERE
        "openai_key": (
            r"\bsk-[a-zA-Z0-9\-]{6,}\b",
            RiskLevel.HIGH,
            "OpenAI-style API key detected"
        ),

        "aws_key": (
            r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
            RiskLevel.HIGH,
            "AWS access key detected"
        ),

        "bearer_token": (
            r"(?i)(?:bearer|token|auth)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-.]{10,})['\"]?",
            RiskLevel.HIGH,
            "Authentication token detected"
        ),

        "jwt_token": (
            r"eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_\-]+",
            RiskLevel.HIGH,
            "JWT token detected"
        ),

        "github_token": (
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}",
            RiskLevel.HIGH,
            "GitHub personal access token detected"
        ),

        # ---------------- MEDIUM ----------------

        "stack_trace": (
            r"(?i)(?:Traceback \(most recent call last\)|"
            r"Exception in thread|"
            r"at\s+[\w.$]+\.\w+\([\w.]+:\d+\)|"
            r"NullPointerException|StackOverflowError|stack\s*trace)",
            RiskLevel.MEDIUM,
            "Stack trace or error leak detected"
        ),

        "sql_injection": (
            r"(?i)(SELECT\s+.+\s+FROM|UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO)",
            RiskLevel.MEDIUM,
            "Potential SQL injection pattern"
        ),

        "ip_address": (
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            RiskLevel.MEDIUM,
            "IP address detected"
        ),

        # ---------------- LOW ----------------

        "email": (
            r"[\w.+-]+@[\w-]+\.[\w.-]+",
            RiskLevel.LOW,
            "Email address detected"
        ),

        "phone": (
            r"(?:\+?\d{1,3}[-.\s]?)?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}",
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

        self._compiled: dict[str, Tuple[Pattern, RiskLevel, str]] = {}

        for name, (pattern, risk, desc) in self.PATTERNS.items():

            try:
                self._compiled[name] = (
                    re.compile(pattern),
                    risk,
                    desc
                )

            except re.error as e:
                logger.error(f"Failed to compile {name}: {e}")

        logger.info(
            f"RegexEngine initialized with {len(self._compiled)} patterns"
        )

    # -----------------------------

    def scan_text(self, text: str) -> List[Finding]:

        findings = []

        lines = text.splitlines()

        for line_num, line in enumerate(lines, start=1):

            findings.extend(
                self.scan_line(line, line_num)
            )

        logger.info(
            f"RegexEngine found {len(findings)} findings "
            f"across {len(lines)} lines"
        )

        return findings

    # -----------------------------

    def scan_line(self, line: str, line_num: int) -> List[Finding]:

        findings = []

        for name, (compiled, risk, desc) in self._compiled.items():

            for match in compiled.finditer(line):

                value = (
                    match.group(1)
                    if match.lastindex
                    else match.group(0)
                )

                findings.append(

                    Finding(
                        type=name,
                        line=line_num,
                        column=match.start() + 1,
                        risk=risk,
                        value=value,
                        context=line.strip()[:200],
                        recommendation=desc,
                    )

                )

        return findings