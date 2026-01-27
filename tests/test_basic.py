import pytest
from pathlib import Path
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.sast.secrets import scan_file_for_secrets
from aegisaudit.sast.static import scan_python_ast

# Fixtures
@pytest.fixture
def mock_artifact():
    return ScanArtifact(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={"Server": "nginx"},
        content=b"<html><body><script>alert(1)</script></body></html>",
        start_time=1.0,
        end_time=2.0
    )

# SAST Tests
def test_secrets_detection_aws(tmp_path):
    # Create file with fake AWS key
    p = tmp_path / "creds.txt"
    p.write_text("aws_key = AKIAIOSFODNN7EXAMPLE")
    
    findings = scan_file_for_secrets(p)
    assert len(findings) == 1
    assert findings[0].id == "sast-secret-aws-access-key"
    assert findings[0].severity == Severity.HIGH

def test_static_analysis_eval(tmp_path):
    p = tmp_path / "bad.py"
    p.write_text("x = eval('1+1')")
    
    findings = scan_python_ast(p)
    assert len(findings) == 1
    assert findings[0].id == "eval-detected"

def test_static_analysis_blind_except(tmp_path):
    p = tmp_path / "bad.py"
    p.write_text("try:\n    pass\nexcept:\n    pass")
    
    findings = scan_python_ast(p)
    assert len(findings) == 1
    assert findings[0].id == "blind-except"
