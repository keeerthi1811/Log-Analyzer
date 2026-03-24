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
                return await self._gemini_analysis(
                    content,
                    findings,
                    input_type
                )

            except Exception as e:
                logger.error(f"Gemini failed: {e}")

        return self._fallback_analysis(
            content,
            findings,
            input_type
        )

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
                "value": f.value[:50]
            })

        prompt = f"""
You are a senior security analyst.

Return ONLY valid JSON.

Format:
{{
  "summary": "...",
  "risk_levels": ["LOW","MEDIUM","HIGH"],
  "recommendations": ["..."]
}}

Input type: {input_type.value}

Content:
{content[:2000]}

Findings:
{json.dumps(findings_summary)}
"""

        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
        )

        text = response.text.strip()

        try:
            data = json.loads(text)

            return AIInsights(**data)

        except Exception as e:

            logger.warning(f"Gemini returned invalid JSON: {e}")

            return self._fallback_analysis(
                content,
                findings,
                input_type
            )

    # -------------------------
    # FALLBACK (VERY IMPORTANT)
    # -------------------------

    def _fallback_analysis(
        self,
        content: str,
        findings: List[Finding],
        input_type: InputType
    ) -> AIInsights:

        logger.info("Using fallback analysis")

        summary = f"Analyzed {len(content)} characters"

        if findings:
            summary += f", found {len(findings)} issues"

        risks = []

        for f in findings:
            r = f.risk.value
            if r not in risks:
                risks.append(r)

        if not risks:
            risks.append(RiskLevel.LOW.value)

        return AIInsights(
            summary=summary,
            risk_levels=risks,
            recommendations=[
                "Review detected issues",
                "Validate inputs",
                "Check logs carefully",
                "Follow security best practices"
            ]
        )