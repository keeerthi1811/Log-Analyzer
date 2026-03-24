"""
API route handlers. 
This is the Ingestion & Validation stage of the pipeline.
"""

import time
import logging
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from models.schemas import (
    AnalyzeRequest, AnalyzeResponse, FileUploadResponse,
    HealthResponse, InputType, AnalysisOptions
)
from engine.extraction_parser import ExtractionParser
from engine.log_analyzer import LogAnalyzer
from engine.regex_engine import RegexEngine
from engine.ai_insights import AIInsightsEngine
from engine.risk_engine import RiskEngine

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize pipeline components (singleton pattern)
extraction_parser = ExtractionParser()
log_analyzer = LogAnalyzer()
regex_engine = RegexEngine()
ai_engine = AIInsightsEngine()
risk_engine = RiskEngine()


async def run_pipeline(content: str, input_type: InputType, options: AnalysisOptions) -> AnalyzeResponse:
    """
    Execute the full modular security pipeline:
    1. Extract & normalize text
    2. Run regex detection
    3. Run log analysis (line-by-line or chunked)
    4. Generate AI insights
    5. Apply risk scoring & policy enforcement
    """
    start_time = time.time()

    # STAGE 2: Extraction — normalize to plain text
    normalized_text = extraction_parser.normalize(content, input_type)
    lines = normalized_text.splitlines()
    total_lines = len(lines)

    # STAGE 3A: Regex Engine — pattern-based detection
    findings = regex_engine.scan_text(normalized_text)

    # STAGE 3B: Log Analyzer — line-by-line with chunking support
    if options.log_analysis:
        log_findings = log_analyzer.analyze(
            normalized_text,
            chunk_size=options.chunk_size
        )
        # Merge, avoiding duplicates
        existing_keys = {(f.type, f.line, f.value) for f in findings}
        for lf in log_findings:
            key = (lf.type, lf.line, lf.value)
            if key not in existing_keys:
                findings.append(lf)
                existing_keys.add(key)

    # Sort findings by line number
    findings.sort(key=lambda f: (f.line, f.risk.value))

    # STAGE 3C: AI Insights
    ai_insights = None
    if options.ai_insights:
        ai_insights = await ai_engine.generate_insights(
            content=normalized_text,
            findings=findings,
            input_type=input_type
        )

    # STAGE 4: Risk & Policy Engine
    response = risk_engine.evaluate(
        content=normalized_text,
        findings=findings,
        options=options,
        ai_insights=ai_insights,
        input_type=input_type,
        total_lines=total_lines
    )

    response.processing_time_ms = round((time.time() - start_time) * 1000, 2)
    return response


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """System health and module status check."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        modules={
            "extraction_parser": "active",
            "regex_engine": f"{len(regex_engine.PATTERNS)} patterns loaded",
            "log_analyzer": "active",
            "ai_engine": ai_engine.get_status(),
            "risk_engine": "active"
        }
    )


@router.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_content(request: AnalyzeRequest):
    """
    Primary analysis endpoint.
    Accepts text, SQL, chat, or log content as a JSON payload.
    Runs the full security pipeline and returns findings + AI insights.
    """
    try:
        logger.info(f"Analyze request: input_type={request.input_type}, content_length={len(request.content)}")
        response = await run_pipeline(
            content=request.content,
            input_type=request.input_type,
            options=request.options
        )
        return response

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Pipeline error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


@router.post("/upload", response_model=FileUploadResponse, tags=["Analysis"])
async def upload_file(
    file: UploadFile = File(..., description="File to analyze (PDF, DOC, DOCX, TXT, LOG)"),
    mask: bool = Form(default=False),
    block_high_risk: bool = Form(default=False),
    log_analysis: bool = Form(default=True),
    ai_insights: bool = Form(default=True),
    chunk_size: int = Form(default=500),
):
    """
    File upload endpoint.
    Supports PDF, DOC, DOCX, TXT, and LOG files.
    Extracts text and runs the full security pipeline.
    """
    # Validate file extension
    allowed_extensions = {".pdf", ".doc", ".docx", ".txt", ".log"}
    file_ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""

    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{file_ext}'. Allowed: {', '.join(allowed_extensions)}"
        )

    # Read file content
    try:
        raw_bytes = await file.read()
        file_size = len(raw_bytes)

        # Size limit: 50MB
        max_size = 50 * 1024 * 1024
        if file_size > max_size:
            raise HTTPException(status_code=413, detail=f"File too large. Maximum size: {max_size // (1024*1024)}MB")

        # Extract text based on file type
        content = extraction_parser.extract_from_bytes(raw_bytes, file_ext, file.filename)

        if not content.strip():
            raise HTTPException(status_code=422, detail="Could not extract any text from the uploaded file")

        # Determine input type
        input_type = InputType.LOG if file_ext in {".log", ".txt"} else InputType.FILE

        # Build options
        options = AnalysisOptions(
            mask=mask,
            block_high_risk=block_high_risk,
            log_analysis=log_analysis,
            ai_insights=ai_insights,
            chunk_size=chunk_size
        )

        # Run pipeline
        analysis = await run_pipeline(content=content, input_type=input_type, options=options)

        return FileUploadResponse(
            filename=file.filename,
            file_size_bytes=file_size,
            original_content=content,   # ✅ ADD THIS LINE
            analysis=analysis
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"File processing error: {str(e)}")