"""
AI Insights Engine — Generative AI integration for contextual analysis.
Uses Gemini API with fallback if API key missing.
"""

import os
import json
import logging
from typing import List

from models.schemas import Finding, AIInsights, InputType, RiskLevel

logger = logging.getLogger(__name__)


class AIInsightsEngine:

    def __init__(self):

        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

        self._gemini_available = False

        if self.api_key:
            try:
                from google import genai

                self.client = genai.Client(api_key=self.api_key)
                self._gemini_available = True

                logger.info(f"AI Engine: Gemini configured ({self.model})")

            except Exception as e:
                logger.warning(f"Gemini not available: {e}")
        else:
            logger.info("No Gemini key found, using fallback")

    # -------------------------
    # STATUS
    # -------------------------

    def get_status(self):

        if self._gemini_available:
            return f"Gemini ({self.model})"

        return "Local fallback analysis"

    # -------------------------
    # MAIN ENTRY
    # -------------------------

    async def generate_insights(
        self,
        content: str,
        findings: List[Finding],
        input_type: InputType
    ) -> AIInsights:

        if self._gemini_available:
            try:
                return await self._gemini_analysis(content, findings, input_type)
            except Exception as e:
                logger.error(f"Gemini failed: {e}")

        return self._fallback_analysis(content, findings, input_type)

    # -------------------------
    # GEMINI
    # -------------------------

    async def _gemini_analysis(
        self,
        content: str,
        findings: List[Finding],
        input_type: InputType
    ) -> AIInsights:

        findings_summary = []
        for f in findings[:50]:
            findings_summary.append({
                "type": f.type,
                "line": f.line,
                "risk": f.risk.value,
                "value": f.value[:50] if f.value else ""
            })

        prompt = f"""
You are a senior security analyst. Analyze this {input_type.value} content.

Return ONLY valid JSON in exactly this format, no markdown, no extra text:
{{
  "summary": "Brief summary of what the content contains and key security issues found",
  "anomalies": ["anomaly 1", "anomaly 2"],
  "security_warnings": ["specific warning 1", "specific warning 2"],
  "risk_assessment": "Overall risk narrative with recommended actions"
}}

Rules:
- anomalies: unusual patterns, repeated failures, brute force, suspicious behavior
- security_warnings: specific issues like exposed credentials, API keys, PII, stack traces
- Be specific to the actual findings, not generic
- risk_assessment: summarize severity and what to do

Content (first 2000 chars):
{content[:2000]}

Findings detected:
{json.dumps(findings_summary)}
"""

        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
        )

        text = response.text.strip()

        # Strip markdown code blocks if Gemini wraps in ```json
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()

        try:
            data = json.loads(text)
            return AIInsights(
                summary=data.get("summary", "Analysis complete"),
                anomalies=data.get("anomalies", []),
                security_warnings=data.get("security_warnings", []),
                risk_assessment=data.get("risk_assessment", "")
            )

        except Exception as e:
            logger.warning(f"Gemini returned invalid JSON: {e}")
            return self._fallback_analysis(content, findings, input_type)

    # -------------------------
    # FALLBACK
    # -------------------------

    def _fallback_analysis(
        self,
        content: str,
        findings: List[Finding],
        input_type: InputType
    ) -> AIInsights:

        logger.info("Using fallback analysis")

        # Build summary
        summary = f"Analyzed {len(content)} characters"
        if findings:
            summary += f", found {len(findings)} issues"

        critical = [f for f in findings if f.risk == RiskLevel.CRITICAL]
        high     = [f for f in findings if f.risk == RiskLevel.HIGH]
        medium   = [f for f in findings if f.risk == RiskLevel.MEDIUM]

        # Build anomalies
        anomalies = []
        auth_failures = [f for f in findings if f.type == "auth_failure"]
        if len(auth_failures) >= 2:
            anomalies.append(
                f"Multiple failed login attempts detected ({len(auth_failures)} occurrences) — possible brute force attack"
            )
        if any(f.type == "stack_trace" for f in findings):
            anomalies.append(
                "Stack trace reveals internal system details — debug information exposed in production"
            )
        if any(f.type == "error_level" for f in findings):
            anomalies.append(
                "Error-level log entries detected — system instability or attack may be in progress"
            )
        if len(set(f.line for f in findings if f.line)) > 5:
            anomalies.append(
                f"Security issues spread across {len(set(f.line for f in findings if f.line))} different lines — widespread exposure"
            )

        # Build security warnings
        warnings = []
        if any(f.type == "password" for f in findings):
            warnings.append("Plaintext password found in logs — reset credentials and audit authentication systems immediately")
        if any(f.type in ("api_key", "openai_key") for f in findings):
            warnings.append("API key exposed in logs — rotate immediately and audit all access logs")
        if any(f.type == "email" for f in findings):
            warnings.append("PII (email addresses) detected in logs — review data retention and logging policies")
        if any(f.type == "ip_address" for f in findings):
            warnings.append("IP addresses logged — ensure compliance with data privacy regulations")
        for f in critical:
            warnings.append(
                f"CRITICAL: {f.type} at line {f.line} — {f.recommendation or 'Immediate action required'}"
            )
        for f in high:
            warnings.append(
                f"HIGH: {f.type} at line {f.line} — {f.recommendation or 'Review and remediate'}"
            )

        # Build risk assessment
        if critical:
            risk_assessment = (
                f"CRITICAL risk level. {len(critical)} critical finding(s) require immediate remediation. "
                "Rotate all exposed credentials and review access logs without delay."
            )
        elif high:
            risk_assessment = (
                f"HIGH risk level. {len(high)} high-severity finding(s) detected. "
                "Review and remediate exposed secrets within 24 hours."
            )
        elif medium:
            risk_assessment = (
                f"MEDIUM risk level. {len(medium)} medium-severity finding(s) found. "
                "Schedule remediation and improve secure logging practices."
            )
        else:
            risk_assessment = (
                "LOW risk level. Minor issues detected. "
                "Review findings and apply secure logging best practices."
            )

        return AIInsights(
            summary=summary,
            anomalies=anomalies,
            security_warnings=warnings,
            risk_assessment=risk_assessment
        )