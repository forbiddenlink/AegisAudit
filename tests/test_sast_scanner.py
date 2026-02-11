import pytest
from pathlib import Path
from aegisaudit.sast.scanner import SASTScanner
from aegisaudit.models import Severity


@pytest.fixture
def scanner():
    """Create SAST scanner instance."""
    return SASTScanner()


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project directory structure."""
    # Create subdirectories
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "config").mkdir()
    return tmp_path


class TestSecretsDetection:
    """Tests for secrets detection across different file types."""
    
    def test_aws_access_key_detection(self, scanner, temp_project):
        """Should detect AWS access keys."""
        credentials_file = temp_project / "config" / "aws.txt"
        credentials_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        
        results = scanner.scan(temp_project)
        aws_findings = [f for f in results.findings if "aws" in f.id.lower() or "aws" in f.title.lower()]
        assert len(aws_findings) >= 1
        assert any(f.severity == Severity.HIGH for f in aws_findings)
    
    def test_aws_secret_key_detection(self, scanner, temp_project):
        """Should detect AWS secret access keys."""
        credentials_file = temp_project / "config" / ".env"
        credentials_file.write_text("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
        
        results = scanner.scan(temp_project)
        secret_findings = [f for f in results.findings if "secret" in f.description.lower()]
        assert len(secret_findings) >= 1
    
    def test_google_api_key_detection(self, scanner, temp_project):
        """Should detect Google API keys."""
        config_file = temp_project / "src" / "config.py"
        # Fake API key with valid format, used for testing secret detection
        config_file.write_text('GOOGLE_API_KEY = "AIzaSyFAKEKEY_TEST_EXAMPLE_123456789012"\n')  # nosec
        
        results = scanner.scan(temp_project)
        google_findings = [f for f in results.findings if "google" in f.title.lower() or "api" in f.description.lower()]
        assert len(google_findings) >= 1
    
    def test_private_key_detection(self, scanner, temp_project):
        """Should detect private keys."""
        key_file = temp_project / "id_rsa"
        key_file.write_text("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n")
        
        results = scanner.scan(temp_project)
        key_findings = [f for f in results.findings if "private key" in f.title.lower() or "private key" in f.description.lower()]
        assert len(key_findings) >= 1
        assert any(f.severity in [Severity.HIGH, Severity.CRITICAL] for f in key_findings)
    
    def test_no_secrets_in_clean_code(self, scanner, temp_project):
        """Clean code without secrets should have no secret findings."""
        clean_file = temp_project / "src" / "utils.py"
        clean_file.write_text("""
def greet(name):
    return f"Hello, {name}!"

class Calculator:
    def add(self, a, b):
        return a + b
""")
        
        results = scanner.scan(temp_project)
        secret_findings = [f for f in results.findings if "secret" in f.id.lower() or "key" in f.description.lower()]
        # Should have no secret findings
        assert len(secret_findings) == 0


class TestPythonStaticAnalysis:
    """Tests for Python AST-based static analysis."""
    
    def test_eval_detection(self, scanner, temp_project):
        """Should detect use of eval()."""
        bad_file = temp_project / "src" / "bad.py"
        bad_file.write_text("result = eval('2 + 2')\n")
        
        results = scanner.scan(temp_project)
        eval_findings = [f for f in results.findings if "eval" in f.id.lower()]
        assert len(eval_findings) >= 1
        assert any(f.severity in [Severity.HIGH, Severity.CRITICAL] for f in eval_findings)
    
    def test_exec_detection(self, scanner, temp_project):
        """Should detect use of exec()."""
        bad_file = temp_project / "src" / "dangerous.py"
        bad_file.write_text("exec('print(\"hello\")')\n")
        
        results = scanner.scan(temp_project)
        exec_findings = [f for f in results.findings if "exec" in f.id.lower()]
        assert len(exec_findings) >= 1
    
    def test_blind_except_detection(self, scanner, temp_project):
        """Should detect bare except clauses."""
        bad_file = temp_project / "src" / "error_handling.py"
        bad_file.write_text("""
try:
    risky_operation()
except:
    pass
""")
        
        results = scanner.scan(temp_project)
        except_findings = [f for f in results.findings if "except" in f.id.lower()]
        assert len(except_findings) >= 1
    
    def test_clean_python_code(self, scanner, temp_project):
        """Clean Python code should have no static analysis findings."""
        clean_file = temp_project / "src" / "safe.py"
        clean_file.write_text("""
def process_data(data):
    try:
        return int(data)
    except ValueError as e:
        logging.error(f"Invalid data: {e}")
        return None
""")
        
        results = scanner.scan(temp_project)
        static_findings = [f for f in results.findings if "eval" in f.id.lower() or "exec" in f.id.lower()]
        assert len(static_findings) == 0


class TestDependencyScanning:
    """Tests for dependency vulnerability scanning."""
    
    def test_python_requirements_scanning(self, scanner, temp_project):
        """Should check Python dependencies if requirements.txt exists."""
        req_file = temp_project / "requirements.txt"
        req_file.write_text("""
# This would normally trigger safety check
# For testing, we just verify the file is picked up
requests==2.25.0
flask==1.0.0
""")
        
        results = scanner.scan(temp_project)
        # Dependency scanning may or may not find issues depending on safety DB
        # Just verify it runs without crashing
        assert isinstance(results.findings, list)
    
    def test_pyproject_toml_scanning(self, scanner, temp_project):
        """Should check Python dependencies from pyproject.toml."""
        pyproject = temp_project / "pyproject.toml"
        pyproject.write_text("""
[project]
name = "test-project"
dependencies = [
    "requests>=2.25.0",
]
""")
        
        results = scanner.scan(temp_project)
        assert isinstance(results.findings, list)
    
    def test_package_json_scanning(self, scanner, temp_project):
        """Should check Node.js dependencies if package.json exists."""
        package_json = temp_project / "package.json"
        package_json.write_text("""
{
  "name": "test-app",
  "dependencies": {
    "express": "^4.0.0"
  }
}
""")
        
        results = scanner.scan(temp_project)
        # npm audit runs if npm is available
        assert isinstance(results.findings, list)


class TestFileFiltering:
    """Tests for file filtering and exclusions."""
    
    def test_ignores_git_directory(self, scanner, temp_project):
        """Should not scan .git directory."""
        git_dir = temp_project / ".git"
        git_dir.mkdir()
        config_file = git_dir / "config"
        config_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        
        results = scanner.scan(temp_project)
        # Should not find secrets in .git directory
        git_findings = [f for f in results.findings if ".git" in f.url]
        assert len(git_findings) == 0
    
    def test_ignores_venv_directory(self, scanner, temp_project):
        """Should not scan virtual environment directories."""
        venv_dir = temp_project / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        lib_file = venv_dir / "pkg.py"
        lib_file.write_text("SECRET_KEY='AKIAIOSFODNN7EXAMPLE'\n")
        
        results = scanner.scan(temp_project)
        # Should not scan venv
        venv_findings = [f for f in results.findings if ".venv" in f.url or "venv" in f.url]
        assert len(venv_findings) == 0
    
    def test_scans_source_directories(self, scanner, temp_project):
        """Should scan src/ directory."""
        src_file = temp_project / "src" / "app.py"
        src_file.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        
        results = scanner.scan(temp_project)
        # Should find secrets in src/
        src_findings = [f for f in results.findings if "src" in f.url and "api" in f.description.lower()]
        assert len(src_findings) >= 1


class TestScanResultStructure:
    """Tests for scan result structure and metadata."""
    
    def test_scan_result_contains_metadata(self, scanner, temp_project):
        """Scan result should have proper metadata."""
        results = scanner.scan(temp_project)
        
        assert results.tool_version is not None
        assert results.summary is not None
        assert hasattr(results, 'findings')
        assert isinstance(results.findings, list)
    
    def test_empty_directory_scan(self, scanner, tmp_path):
        """Scanning empty directory should not crash."""
        results = scanner.scan(tmp_path)
        assert isinstance(results.findings, list)
        assert results.summary.total_findings == len(results.findings)
