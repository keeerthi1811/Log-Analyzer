"""
End-to-end pipeline tests.
Validates the provided app.log use case and risk scoring.
"""

import pytest
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from httpx import AsyncClient, ASGITransport
from main import app

SAMPLE_LOG = """2024-01-15 10:23:45 INFO Application started successfully
2024-01-15 10:23:46 INFO Loading configuration from /etc/app/config.yml
2024-01-15 10:24:12 DEBUG Connecting to database at db-host:5432
2024-01-15 10:24:15 INFO Database connection established
2024-01-15 10:25:01 INFO User login attempt: admin@company.com
2024-01-15 10:25:03 ERROR Authentication config: password = admin123
2024-01-15 10:26:15 WARN API call using key: sk-prod-xyz-abc123defg456hijklmno
2024-01-15 10:27:30 ERROR java.lang.NullPointerException
    at com.app.service.UserService.java:142
    at com.app.controller.AuthController.java:89
2024-01-15 10:28:00 INFO Processing batch job #4521 complete
2024-01-15 10:28:30 INFO Application shutdown gracefully"""


@pytest.mark.asyncio
async def test_analyze_sample_log():
    """
    Test the provided app.log use case:
    - admin@company.com (email → Low risk → 1 point)
    - admin123 (password → Critical risk → 5 points)
    - sk-prod-xyz... (API key → High risk → 4 points)
    - Stack trace (Medium risk → 2 points)
    Total expected risk score: 12
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/analyze", json={
            "input_type": "log",
            "content": SAMPLE_LOG,
            "options": {
                "mask": False,
                "block_high_risk": False,
                "log_analysis": True,
                "ai_insights": False  # Skip AI for deterministic testing
            }
        })

    assert response.status_code == 200
    data = response.json()

    print(f"\n{'='*60}")
    print(f"Total findings: {len(data['findings'])}")
    print(f"Risk score: {data['risk_score']}")
    print(f"Risk breakdown: {data['risk_breakdown']}")
    print(f"{'='*60}")
    for f in data["findings"]:
        print(f"  Line {f['line']}: [{f['risk'].upper():8s}] {f['type']:15s} → {f['value'][:50]}")
    print(f"{'='*60}\n")

    # Verify specific detections
    finding_types = {f["type"] for f in data["findings"]}
    finding_risks = {f["risk"] for f in data["findings"]}

    # Must detect email
    email_findings = [f for f in data["findings"] if f["type"] == "email"]
    assert len(email_findings) >= 1, "Should detect admin@company.com"
    assert any(f["risk"] == "low" for f in email_findings), "Email should be Low risk"

    # Must detect password
    password_findings = [f for f in data["findings"] if f["type"] == "password"]
    assert len(password_findings) >= 1, "Should detect password = admin123"
    assert any(f["risk"] == "critical" for f in password_findings), "Password should be Critical risk"

    # Must detect API key
    api_findings = [f for f in data["findings"] if f["type"] == "api_key" or "key" in f["type"]]
    assert len(api_findings) >= 1, "Should detect sk-prod-xyz API key"
    assert any(f["risk"] == "high" for f in api_findings), "API key should be High risk"

    # Must detect stack trace
    stack_findings = [f for f in data["findings"] if f["type"] == "stack_trace"]
    assert len(stack_findings) >= 1, "Should detect stack trace"
    assert any(f["risk"] == "medium" for f in stack_findings), "Stack trace should be Medium risk"

    # Verify risk score = 12
    # Score: Critical(5) + High(4) + Medium(2) + Low(1) = 12
    assert data["risk_score"] == 12, f"Expected risk score 12, got {data['risk_score']}"


@pytest.mark.asyncio
async def test_masking():
    """Test that sensitive values are properly masked."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/analyze", json={
            "input_type": "text",
            "content": "My password = SuperSecret123 and email is test@example.com",
            "options": {"mask": True, "ai_insights": False}
        })

    assert response.status_code == 200
    data = response.json()

    assert data["masked_content"] is not None
    assert "SuperSecret123" not in data["masked_content"]
    assert "***" in data["masked_content"] or "****" in data["masked_content"]


@pytest.mark.asyncio
async def test_blocking():
    """Test that high-risk content is flagged for blocking."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/analyze", json={
            "input_type": "text",
            "content": "Config: password = admin123",
            "options": {"block_high_risk": True, "ai_insights": False}
        })

    assert response.status_code == 200
    data = response.json()
    assert data["blocked"] is True


@pytest.mark.asyncio
async def test_health_check():
    """Test health endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_empty_content_rejected():
    """Test that empty content is rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/analyze", json={
            "input_type": "text",
            "content": "   ",
        })

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_large_log_chunking():
    """Test chunked processing for large logs."""
    # Generate a large log
    large_log_lines = []
    for i in range(1200):
        if i == 500:
            large_log_lines.append(f"2024-01-15 10:25:01 ERROR password = secret{i}")
        elif i == 1000:
            large_log_lines.append(f"2024-01-15 10:26:15 WARN API key: sk-testkey-{'x'*20}")
        else:
            large_log_lines.append(f"2024-01-15 10:{i//60:02d}:{i%60:02d} INFO Normal log entry #{i}")

    large_log = "\n".join(large_log_lines)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/analyze", json={
            "input_type": "log",
            "content": large_log,
            "options": {
                "log_analysis": True,
                "ai_insights": False,
                "chunk_size": 500
            }
        })

    assert response.status_code == 200
    data = response.json()
    assert data["total_lines"] == 1200
    assert len(data["findings"]) >= 2  # At least password + API key
    print(f"Large log test: {len(data['findings'])} findings in {data['total_lines']} lines")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])