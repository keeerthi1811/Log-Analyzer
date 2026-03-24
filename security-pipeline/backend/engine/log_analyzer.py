"""
Log Analyzer Module
Handles line-by-line and chunked analysis of log files.
Optimized for large file processing with memory-efficient chunking.
"""

import re
import logging
from typing import List, Generator, Tuple
from models.schemas import Finding, RiskLevel

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """
    Specialized log file analyzer with:
    - Line-by-line scanning
    - Chunked processing for large files
    - Log-format-aware pattern detection
    - Temporal anomaly detection
    """

    # Log-specific patterns (beyond what RegexEngine handles)
    LOG_PATTERNS = {
        "api_key": {
            "pattern": r"(?i)(?:api[_\-]?key|sk-[a-zA-Z0-9]{20,})",
            "risk": RiskLevel.HIGH,
            "score": 4,
            "description": "API key detected in log"
        },
        "openai_key_log": {
            "pattern": r"sk-[a-zA-Z0-9]{10,}",
            "risk": RiskLevel.HIGH,
            "score": 4,
            "description": "OpenAI-style key in log"
        },
        "email": {
            "pattern": r"[\w.+-]+@[\w-]+\.[\w.-]+",
            "risk": RiskLevel.LOW,
            "score": 1,
            "description": "Email address in log"
        },
        "password": {
            "pattern": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*([^\s,;'\"]+)",
            "risk": RiskLevel.CRITICAL,
            "score": 5,
            "description": "Password detected in log"
        },
        "stack_trace": {
            "pattern": (
                r"(?i)(?:Exception|Traceback|stack\s*trace|Error:|FATAL|"
                r"at\s+[\w.$]+\.[\w]+\([\w.]+:\d+\)|NullPointerException|"
                r"java\.lang\.\w+Exception)"
            ),
            "risk": RiskLevel.MEDIUM,
            "score": 2,
            "description": "Stack trace or exception in log"
        },
        "bearer_token_log": {
            "pattern": r"(?i)(?:bearer|token|auth[_\-]?token)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-.]{20,})",
            "risk": RiskLevel.HIGH,
            "score": 4,
            "description": "Authentication token in log"
        },
        "secret_log": {
            "pattern": r"(?i)(?:secret|client_secret|app_secret)\s*[=:]\s*['\"]?([^\s'\"]{8,})",
            "risk": RiskLevel.CRITICAL,
            "score": 5,
            "description": "Secret key in log"
        },
        "failed_login": {
            "pattern": r"(?i)(?:failed\s+(?:login|auth)|authentication\s+failed|invalid\s+credentials|access\s+denied|unauthorized)",
            "risk": RiskLevel.MEDIUM,
            "score": 2,
            "description": "Failed authentication attempt"
        },
        "error_level": {
            "pattern": r"(?:^|\s)(?:ERROR|FATAL|CRITICAL)(?:\s|:|\])",
            "risk": RiskLevel.MEDIUM,
            "score": 2,
            "description": "Error-level log entry"
        },
    }

    def __init__(self):
        """Pre-compile log patterns."""
        self._compiled = {}
        for name, cfg in self.LOG_PATTERNS.items():
            try:
                self._compiled[name] = {
                    "regex": re.compile(cfg["pattern"]),
                    "risk": cfg["risk"],
                    "score": cfg["score"],
                    "description": cfg["description"]
                }
            except re.error as e:
                logger.error(f"LogAnalyzer: failed to compile '{name}': {e}")

        logger.info(f"LogAnalyzer initialized with {len(self._compiled)} log-specific patterns")

    def analyze(self, text: str, chunk_size: int = 500) -> List[Finding]:
        """
        Main analysis entry point.
        Automatically switches between direct and chunked processing.
        """
        lines = text.splitlines()
        total_lines = len(lines)

        logger.info(f"LogAnalyzer: processing {total_lines} lines (chunk_size={chunk_size})")

        if total_lines <= chunk_size:
            # Direct line-by-line for small files
            return self._scan_lines(lines, offset=0)
        else:
            # Chunked processing for large files
            return self._scan_chunked(lines, chunk_size)

    def _scan_lines(self, lines: List[str], offset: int = 0) -> List[Finding]:
        """Scan a list of lines, with offset for chunk-aware line numbering."""
        findings = []
        multiline_buffer = []
        multiline_start = -1

        for idx, line in enumerate(lines):
            line_num = offset + idx + 1

            # Handle multi-line stack traces
            if self._is_stack_trace_continuation(line):
                multiline_buffer.append(line)
                continue
            elif multiline_buffer:
                # Process the accumulated stack trace
                if multiline_start > 0:
                    stack_text = "\n".join(multiline_buffer)
                    findings.append(Finding(
                        type="stack_trace",
                        line=multiline_start,
                        risk=RiskLevel.MEDIUM,
                        value=f"Stack trace ({len(multiline_buffer)} lines)",
                        context=multiline_buffer[0][:200],
                        recommendation="Suppress detailed stack traces in production logs."
                    ))
                multiline_buffer = []
                multiline_start = -1

            # Scan current line
            line_findings = self.scan_line(line, line_num)
            findings.extend(line_findings)

            # Check if this starts a stack trace
            if any(f.type == "stack_trace" for f in line_findings):
                multiline_buffer = [line]
                multiline_start = line_num

        return findings

    def _scan_chunked(self, lines: List[str], chunk_size: int) -> List[Finding]:
        """Process large files in chunks to manage memory."""
        all_findings = []

        for chunk_start, chunk_lines in self._chunk_generator(lines, chunk_size):
            logger.debug(f"Processing chunk starting at line {chunk_start + 1}")
            chunk_findings = self._scan_lines(chunk_lines, offset=chunk_start)
            all_findings.extend(chunk_findings)

        logger.info(f"Chunked analysis complete: {len(all_findings)} findings from {len(lines)} lines")
        return all_findings

    @staticmethod
    def _chunk_generator(lines: List[str], chunk_size: int) -> Generator[Tuple[int, List[str]], None, None]:
        """Yield (offset, chunk_lines) tuples."""
        for i in range(0, len(lines), chunk_size):
            yield i, lines[i:i + chunk_size]

    def scan_line(self, line: str, line_num: int) -> List[Finding]:
        """Scan a single log line against all log-specific patterns."""
        findings = []
        seen_types = set()

        for name, cfg in self._compiled.items():
            if name in seen_types:
                continue

            match = cfg["regex"].search(line)
            if match:
                # Determine the type for dedup (normalize similar types)
                base_type = self._normalize_type(name)
                if base_type in seen_types:
                    continue
                seen_types.add(base_type)

                value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

                findings.append(Finding(
                    type=base_type,
                    line=line_num,
                    column=match.start() + 1,
                    risk=cfg["risk"],
                    value=value.strip(),
                    context=line.strip()[:200],
                    recommendation=cfg["description"]
                ))

        return findings

    @staticmethod
    def _normalize_type(name: str) -> str:
        """Normalize pattern names to base types for deduplication."""
        type_map = {
            "openai_key_log": "api_key",
            "bearer_token_log": "bearer_token",
            "secret_log": "secret",
            "failed_login": "auth_failure",
            "error_level": "error_level",
        }
        return type_map.get(name, name)

    @staticmethod
    def _is_stack_trace_continuation(line: str) -> bool:
        """Check if a line is a continuation of a stack trace."""
        stripped = line.strip()
        return bool(
            stripped.startswith("at ") or
            stripped.startswith("Caused by:") or
            stripped.startswith("...") or
            re.match(r"^\s+at\s+", line) or
            re.match(r"^\s+\.\.\.\s+\d+\s+more", line)
        )

    def get_stats(self) -> dict:
        """Return analyzer statistics."""
        return {
            "patterns_loaded": len(self._compiled),
            "pattern_names": list(self._compiled.keys())
        }