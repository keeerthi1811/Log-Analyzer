"""
Risk & Policy Engine — Stage 4 of the pipeline.
Classifies findings, computes risk scores, and enforces policies (masking, blocking).
"""

import re
import logging
from typing import List, Optional

from models.schemas import (
    Finding, RiskLevel, RiskBreakdown, AnalyzeResponse,
    AIInsights, AnalysisOptions, InputType
)

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Computes aggregate risk scores and enforces security policies.

    Risk Point Values:
        Critical = 5 points
        High     = 4 points
        Medium   = 2 points
        Low      = 1 point
        Info     = 0 points
    """

    RISK_SCORES = {
        RiskLevel.CRITICAL: 5,
        RiskLevel.HIGH: 4,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 1,
        RiskLevel.INFO: 0,
    }

    def evaluate(
        self,
        content: str,
        findings: List[Finding],
        options: AnalysisOptions,
        ai_insights: Optional[AIInsights],
        input_type: InputType,
        total_lines: int
    ) -> AnalyzeResponse:
        """
        Final pipeline stage:
        1. Deduplicate findings
        2. Calculate risk breakdown and total score
        3. Apply masking if requested
        4. Determine if content should be blocked
        5. Assemble the complete response
        """
        # 1. Deduplicate findings (same type + line + value)
        deduped = self._deduplicate(findings)

        # 2. Calculate risk breakdown
        breakdown = self._calculate_breakdown(deduped)

        # 3. Calculate total risk score
        risk_score = breakdown.total_score

        # 4. Apply masking if requested
        masked_content = None
        if options.mask:
            masked_content = self._mask_content(content, deduped)
            deduped = self._mask_finding_values(deduped)

        # 5. Determine blocking
        blocked = False
        if options.block_high_risk:
            blocked = breakdown.critical > 0 or breakdown.high > 0
            if blocked:
                logger.warning(
                    f"Content BLOCKED: {breakdown.critical} critical, "
                    f"{breakdown.high} high-risk findings"
                )

        # 6. Assemble response
        response = AnalyzeResponse(
            status="warning" if blocked else ("success" if risk_score < 10 else "warning"),
            input_type=input_type,
            total_lines=total_lines,
            findings=deduped,
            risk_breakdown=breakdown,
            risk_score=risk_score,
            masked_content=masked_content,
            ai_insights=ai_insights if ai_insights else AIInsights(),
            blocked=blocked,
            metadata={
                "deduplicated_count": len(findings) - len(deduped),
                "masking_applied": options.mask,
                "blocking_applied": options.block_high_risk,
            }
        )

        logger.info(
            f"RiskEngine: score={risk_score}, findings={len(deduped)}, "
            f"blocked={blocked}, breakdown=C:{breakdown.critical}/H:{breakdown.high}/"
            f"M:{breakdown.medium}/L:{breakdown.low}"
        )

        return response

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings (same type, line, and value)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.type, f.line, f.value)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _calculate_breakdown(self, findings: List[Finding]) -> RiskBreakdown:
        """Calculate risk breakdown with counts and total score."""
        breakdown = RiskBreakdown()
        total = 0

        for f in findings:
            points = self.RISK_SCORES.get(f.risk, 0)
            total += points

            if f.risk == RiskLevel.CRITICAL:
                breakdown.critical += 1
            elif f.risk == RiskLevel.HIGH:
                breakdown.high += 1
            elif f.risk == RiskLevel.MEDIUM:
                breakdown.medium += 1
            elif f.risk == RiskLevel.LOW:
                breakdown.low += 1
            elif f.risk == RiskLevel.INFO:
                breakdown.info += 1

        breakdown.total_score = total
        return breakdown

    @staticmethod
    def _mask_content(content: str, findings: List[Finding]) -> str:
        """
        Replace sensitive values in the content with masked versions.
        Preserves structure while hiding actual values.
        """
        masked = content

        # Sort findings by value length (longest first) to avoid partial replacements
        sorted_findings = sorted(findings, key=lambda f: len(f.value), reverse=True)

        for f in sorted_findings:
            if f.value and len(f.value) > 2:
                if f.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    # Full mask for critical/high
                    mask = "*" * len(f.value)
                elif f.risk == RiskLevel.MEDIUM:
                    # Partial mask for medium
                    mask = f.value[:2] + "*" * (len(f.value) - 2)
                else:
                    # Show first/last for low
                    if len(f.value) > 4:
                        mask = f.value[0] + "*" * (len(f.value) - 2) + f.value[-1]
                    else:
                        mask = f.value[0] + "***"

                # Use exact replacement (not regex) to avoid issues with special chars
                masked = masked.replace(f.value, mask)

        return masked

    @staticmethod
    def _mask_finding_values(findings: List[Finding]) -> List[Finding]:
        """Mask the values stored in finding objects themselves."""
        masked_findings = []
        for f in findings:
            masked_f = f.model_copy()
            if f.value and len(f.value) > 4:
                masked_f.value = f.value[:3] + "*" * (len(f.value) - 3)
            elif f.value:
                masked_f.value = f.value[0] + "***"
            masked_findings.append(masked_f)
        return masked_findings