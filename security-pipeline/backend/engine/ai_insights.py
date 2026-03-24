"""
AI Insights Engine — Generative AI integration for contextual analysis.
Uses OpenAI API with a robust fallback for environments without API keys.
"""

import os
import json
import logging
from typing import List, Optional

from models.schemas import Finding, AIInsights, InputType, RiskLevel

logger = logging.getLogger(__name__)


class AIInsightsEngine:
    """
    Generates meaningful, context-aware insights from analyzed content.
    Primary: OpenAI GPT-4o-mini / GPT-4
    Fallback: Rule-based local analysis engine
    """

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self._openai_available = False

        if self.api_key and self.api_key.startswith("sk-"):
            try:
                import openai
                self.client = openai.AsyncOpenAI(api_key=self.api_key)
                self._openai_available = True
                logger.info(f"AI Engine: OpenAI configured (model={self.model})")
            except ImportError:
                logger.warning("openai package not installed, using fallback")
        else:
            logger.info("AI Engine: No API key found, using intelligent fallback analysis")

    def get_status(self) -> str:
        if self._openai_available:
            return f"OpenAI ({self.model})"
        return "Local fallback analysis"

    async def generate_insights(
        self,
        content: str,
        findings: List[Finding],
        input_type: InputType
    ) -> AIInsights:
        """
        Generate AI-powered insights from content and findings.
        Falls back to rule-based analysis if OpenAI is unavailable.
        """
        if self._openai_available:
            try:
                return await self._openai_analysis(content, findings, input_type)
            except Exception as e:
                logger.error(f"OpenAI analysis failed, using fallback: {e}")

        return self._fallback_analysis(content, findings, input_type)

    async def _openai_analysis(
        self,
        content: str,
        findings: List[Finding],
        input_type: InputType
    ) -> AIInsights:
        """Generate insights using OpenAI API."""
        # Prepare findings summary for the prompt
        findings_summary = []
        for f in findings[:50]:  # Limit to avoid token overflow
            findings_summary.append({
                "type": f.type,
                "line": f.line,
                "risk": f.risk.value,
                "value": f.value[:50] + "..." if len(f.value) > 50 else f.value
            })

        # Truncate content for context (keep first and last portions)
        max_content_chars = 3000
        if len(content) > max_content_chars:
            half = max_content_chars // 2
            truncated_content = content[:half] + "\n... [truncated] ...\n" + content[-half:]
        else:
            truncated_content = content

        prompt = f"""You are a senior security analyst reviewing {input_type.value} data.

CONTENT (may be truncated):