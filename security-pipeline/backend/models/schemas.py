"""
Pydantic models for request validation and response serialization.
These enforce the API contract between frontend and backend.
"""

from __future__ import annotations
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Literal
from enum import Enum


class InputType(str, Enum):
    TEXT = "text"
    FILE = "file"
    SQL = "sql"
    CHAT = "chat"
    LOG = "log"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnalysisOptions(BaseModel):
    """Options that control how the analysis pipeline behaves."""
    mask: bool = Field(default=False, description="Mask sensitive values in output")
    block_high_risk: bool = Field(default=False, description="Flag critical/high risk for blocking")
    log_analysis: bool = Field(default=True, description="Enable line-by-line log analysis")
    ai_insights: bool = Field(default=True, description="Enable AI-powered analysis")
    chunk_size: int = Field(default=500, ge=50, le=5000, description="Lines per chunk for large files")


class AnalyzeRequest(BaseModel):
    """Primary request payload for the /analyze endpoint."""
    input_type: InputType
    content: str = Field(..., min_length=1, max_length=5_000_000, description="Raw content to analyze")
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)

    @validator("content")
    def content_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Content cannot be empty or whitespace only")
        return v


class Finding(BaseModel):
    """A single detected security finding."""
    type: str = Field(..., description="Category: email, api_key, password, stack_trace, token, secret")
    line: int = Field(..., ge=0, description="Line number where finding was detected")
    column: Optional[int] = Field(None, description="Column offset within the line")
    risk: RiskLevel
    value: str = Field(..., description="The matched value (may be masked)")
    context: Optional[str] = Field(None, description="Surrounding text for context")
    recommendation: Optional[str] = Field(None, description="Remediation suggestion")


class RiskBreakdown(BaseModel):
    """Summary counts by risk level."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total_score: int = 0


class AIInsights(BaseModel):
    """AI-generated analysis results."""
    summary: str = Field(default="", description="Overall log activity summary")
    anomalies: List[str] = Field(default_factory=list, description="Detected anomalies")
    security_warnings: List[str] = Field(default_factory=list, description="Security recommendations")
    risk_assessment: str = Field(default="", description="Overall risk assessment narrative")


class AnalyzeResponse(BaseModel):
    """Complete response from the analysis pipeline."""
    status: Literal["success", "error", "warning"] = "success"
    input_type: InputType
    total_lines: int = 0
    findings: List[Finding] = Field(default_factory=list)
    risk_breakdown: RiskBreakdown = Field(default_factory=RiskBreakdown)
    risk_score: int = 0
    masked_content: Optional[str] = Field(None, description="Content with sensitive data masked")
    ai_insights: AIInsights = Field(default_factory=AIInsights)
    blocked: bool = Field(default=False, description="Whether content was blocked due to policy")
    processing_time_ms: float = 0.0
    metadata: dict = Field(default_factory=dict)


class FileUploadResponse(BaseModel):
    """Response after file upload and analysis."""
    filename: str
    file_size_bytes: int
    analysis: AnalyzeResponse


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "1.0.0"
    modules: dict = Field(default_factory=dict)