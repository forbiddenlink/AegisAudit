import pytest
import json
from pathlib import Path
from aegisaudit.models import ScanResult, ScanSummary, Finding, Severity
from aegisaudit.reporters.json_report import generate_json_report
from aegisaudit.reporters.sarif_report import generate_sarif_report
from aegisaudit.reporters.html_report import generate_html_report


@pytest.fixture
def sample_scan_result():
    """Create a sample scan result for testing."""
    return ScanResult(
        tool_version="0.1.0",
        targets=["https://example.com"],
        findings=[
            Finding(
                id="missing-hsts",
                severity=Severity.HIGH,
                title="Missing HSTS Header",
                description="HTTP Strict Transport Security header is missing.",
                url="https://example.com",
                remediation="Add 'Strict-Transport-Security' header.",
                tags=["headers", "hsts"]
            ),
            Finding(
                id="missing-csp",
                severity=Severity.MEDIUM,
                title="Missing Content Security Policy",
                description="CSP header is missing.",
                url="https://example.com",
                remediation="Implement CSP.",
                tags=["headers", "csp"]
            ),
            Finding(
                id="info-leak",
                severity=Severity.LOW,
                title="Server Header Disclosure",
                description="Server header reveals technology details.",
                url="https://example.com",
                remediation="Suppress server header.",
                tags=["headers", "info-leak"]
            ),
        ],
        summary=ScanSummary(
            total_findings=3,
            critical_count=0,
            high_count=1,
            medium_count=1,
            low_count=1,
            info_count=0,
            overall_score=65.0
        )
    )


class TestJSONReport:
    """Tests for JSON report generation."""
    
    def test_json_report_created(self, sample_scan_result, tmp_path):
        """JSON report file should be created."""
        output_file = tmp_path / "report.json"
        generate_json_report(sample_scan_result, output_file)
        
        assert output_file.exists()
    
    def test_json_report_valid_json(self, sample_scan_result, tmp_path):
        """JSON report should be valid JSON."""
        output_file = tmp_path / "report.json"
        generate_json_report(sample_scan_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert isinstance(data, dict)
    
    def test_json_report_contains_findings(self, sample_scan_result, tmp_path):
        """JSON report should contain all findings."""
        output_file = tmp_path / "report.json"
        generate_json_report(sample_scan_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert "findings" in data
        assert len(data["findings"]) == 3
    
    def test_json_report_contains_summary(self, sample_scan_result, tmp_path):
        """JSON report should contain summary."""
        output_file = tmp_path / "report.json"
        generate_json_report(sample_scan_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert "summary" in data
        assert data["summary"]["total_findings"] == 3
        assert abs(data["summary"]["overall_score"] - 65.0) < 0.01


class TestSARIFReport:
    """Tests for SARIF report generation."""
    
    def test_sarif_report_created(self, sample_scan_result, tmp_path):
        """SARIF report file should be created."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)
        
        assert output_file.exists()
    
    def test_sarif_report_valid_json(self, sample_scan_result, tmp_path):
        """SARIF report should be valid JSON."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert isinstance(data, dict)
    
    def test_sarif_report_version(self, sample_scan_result, tmp_path):
        """SARIF report should have correct version."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert "version" in data
        assert data["version"] == "2.1.0"
    
    def test_sarif_report_contains_runs(self, sample_scan_result, tmp_path):
        """SARIF report should contain runs array."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert "runs" in data
        assert len(data["runs"]) >= 1
    
    def test_sarif_report_contains_results(self, sample_scan_result, tmp_path):
        """SARIF report should contain results."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        results = data["runs"][0]["results"]
        assert len(results) == 3
    
    def test_sarif_severity_mapping(self, sample_scan_result, tmp_path):
        """SARIF report should map severity levels correctly."""
        output_file = tmp_path / "report.sarif"
        generate_sarif_report(sample_scan_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        results = data["runs"][0]["results"]
        # HIGH -> error, MEDIUM -> warning, LOW -> note
        levels = [r["level"] for r in results]
        assert "error" in levels  # HIGH finding
        assert "warning" in levels  # MEDIUM finding
        assert "note" in levels  # LOW finding


class TestHTMLReport:
    """Tests for HTML report generation."""
    
    def test_html_report_created(self, sample_scan_result, tmp_path):
        """HTML report file should be created."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)
        
        assert output_file.exists()
    
    def test_html_report_not_empty(self, sample_scan_result, tmp_path):
        """HTML report should have content."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)
        
        content = output_file.read_text()
        assert len(content) > 100
    
    def test_html_report_contains_title(self, sample_scan_result, tmp_path):
        """HTML report should contain title."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)
        
        content = output_file.read_text()
        assert "<title>" in content
        assert "AegisAudit" in content or "Report" in content
    
    def test_html_report_contains_findings(self, sample_scan_result, tmp_path):
        """HTML report should display findings."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)
        
        content = output_file.read_text()
        assert "Missing HSTS" in content
        assert "Content Security Policy" in content
    
    def test_html_report_contains_score(self, sample_scan_result, tmp_path):
        """HTML report should display overall score."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)
        
        content = output_file.read_text()
        assert "65" in content or "score" in content.lower()
    
    def test_html_report_valid_html(self, sample_scan_result, tmp_path):
        """HTML report should have basic HTML structure."""
        output_file = tmp_path / "report.html"
        generate_html_report(sample_scan_result, output_file)
        
        content = output_file.read_text()
        assert "<html" in content.lower()
        assert "</html>" in content.lower()
        assert "<body" in content.lower()
        assert "</body>" in content.lower()


class TestReportWithNoFindings:
    """Tests for reports with clean scan results."""
    
    def test_empty_findings_json(self, tmp_path):
        """JSON report should handle empty findings."""
        clean_result = ScanResult(
            tool_version="0.1.0",
            targets=["https://secure-example.com"],
            findings=[],
            summary=ScanSummary(
                total_findings=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                overall_score=100.0
            )
        )
        
        output_file = tmp_path / "clean.json"
        generate_json_report(clean_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert data["summary"]["total_findings"] == 0
        assert abs(data["summary"]["overall_score"] - 100.0) < 0.01
    
    def test_empty_findings_html(self, tmp_path):
        """HTML report should handle empty findings gracefully."""
        clean_result = ScanResult(
            tool_version="0.1.0",
            targets=["https://secure-example.com"],
            findings=[],
            summary=ScanSummary(
                total_findings=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                overall_score=100.0
            )
        )
        
        output_file = tmp_path / "clean.html"
        generate_html_report(clean_result, output_file)
        
        content = output_file.read_text()
        assert "100" in content or "perfect" in content.lower() or "no findings" in content.lower()
