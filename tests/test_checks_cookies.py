import pytest
from aegisaudit.models import ScanArtifact, Severity
from aegisaudit.checks.cookies import check_cookies
from aegisaudit.config import AegisConfig


@pytest.fixture
def base_config():
    return AegisConfig(allowlist_urls=[], probe_files=False)


@pytest.fixture
def https_artifact():
    """Artifact from HTTPS site."""
    return ScanArtifact(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
        content=b"<html><body>Test</body></html>",
        start_time=1.0,
        end_time=2.0
    )


@pytest.fixture
def http_artifact():
    """Artifact from HTTP site."""
    return ScanArtifact(
        url="http://example.com",
        final_url="http://example.com",
        status_code=200,
        headers={},
        content=b"<html><body>Test</body></html>",
        start_time=1.0,
        end_time=2.0
    )


class TestSecureFlag:
    """Tests for Secure cookie attribute."""
    
    def test_no_cookies(self, https_artifact, base_config):
        """No cookies set should result in no findings."""
        findings = check_cookies(https_artifact, base_config)
        assert len(findings) == 0
    
    def test_secure_flag_missing_on_https(self, https_artifact, base_config):
        """Cookie without Secure flag on HTTPS should trigger finding."""
        https_artifact.headers["set-cookie"] = "sessionid=abc123; Path=/"
        findings = check_cookies(https_artifact, base_config)
        secure_findings = [f for f in findings if "secure" in f.description.lower()]
        assert len(secure_findings) >= 1
        assert any(f.severity in [Severity.MEDIUM, Severity.HIGH] for f in secure_findings)
    
    def test_secure_flag_present(self, https_artifact, base_config):
        """Cookie with Secure flag should not trigger finding."""
        https_artifact.headers["set-cookie"] = "sessionid=abc123; Path=/; Secure"
        findings = check_cookies(https_artifact, base_config)
        secure_findings = [f for f in findings if "secure" in f.description.lower() and "missing" in f.description.lower()]
        # Should not complain about missing Secure flag
        assert len([f for f in secure_findings if "missing" in f.description.lower()]) == 0


class TestHttpOnlyFlag:
    """Tests for HttpOnly cookie attribute."""
    
    def test_httponly_missing(self, https_artifact, base_config):
        """Session cookie without HttpOnly should trigger finding."""
        https_artifact.headers["set-cookie"] = "sessionid=abc123; Path=/; Secure"
        findings = check_cookies(https_artifact, base_config)
        httponly_findings = [f for f in findings if "httponly" in f.description.lower()]
        assert len(httponly_findings) >= 1
        assert any(f.severity in [Severity.MEDIUM, Severity.HIGH] for f in httponly_findings)
    
    def test_httponly_present(self, https_artifact, base_config):
        """Cookie with HttpOnly should not trigger finding."""
        https_artifact.headers["set-cookie"] = "sessionid=abc123; Path=/; Secure; HttpOnly"
        findings = check_cookies(https_artifact, base_config)
        httponly_findings = [f for f in findings if "httponly" in f.description.lower() and "missing" in f.description.lower()]
        assert len(httponly_findings) == 0


class TestSameSiteAttribute:
    """Tests for SameSite cookie attribute."""
    
    def test_samesite_missing(self, https_artifact, base_config):
        """Cookie without SameSite should trigger finding."""
        https_artifact.headers["set-cookie"] = "sessionid=abc123; Path=/; Secure; HttpOnly"
        findings = check_cookies(https_artifact, base_config)
        samesite_findings = [f for f in findings if "samesite" in f.description.lower()]
        assert len(samesite_findings) >= 1
        assert any(f.severity in [Severity.MEDIUM, Severity.HIGH] for f in samesite_findings)
    
    def test_samesite_lax(self, https_artifact, base_config):
        """Cookie with SameSite=Lax should not trigger finding."""
        https_artifact.headers["set-cookie"] = "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
        findings = check_cookies(https_artifact, base_config)
        samesite_findings = [f for f in findings if "samesite" in f.description.lower() and "missing" in f.description.lower()]
        assert len(samesite_findings) == 0
    
    def test_samesite_strict(self, https_artifact, base_config):
        """Cookie with SameSite=Strict should not trigger finding."""
        https_artifact.headers["set-cookie"] = "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"
        findings = check_cookies(https_artifact, base_config)
        samesite_findings = [f for f in findings if "samesite" in f.description.lower() and "missing" in f.description.lower()]
        assert len(samesite_findings) == 0
    
    def test_samesite_none_requires_secure(self, https_artifact, base_config):
        """SameSite=None without Secure should trigger finding."""
        https_artifact.headers["set-cookie"] = "sessionid=abc123; Path=/; HttpOnly; SameSite=None"
        findings = check_cookies(https_artifact, base_config)
        # Should warn about SameSite=None without Secure
        secure_findings = [f for f in findings if ("secure" in f.description.lower() or "samesite" in f.description.lower())]
        assert len(secure_findings) >= 1


class TestMultipleCookies:
    """Tests for handling multiple cookies."""
    
    def test_multiple_cookies_in_header(self, https_artifact, base_config):
        """Should handle multiple Set-Cookie headers."""
        # In HTTP, multiple Set-Cookie headers are sent separately
        # For testing, we'll simulate with comma-separated (though not spec-compliant)
        https_artifact.headers["set-cookie"] = "session=abc; Secure, tracking=xyz"
        findings = check_cookies(https_artifact, base_config)
        # Should find issues with the tracking cookie
        assert len(findings) >= 1
    
    def test_all_cookies_secure(self, https_artifact, base_config):
        """All cookies with proper attributes should minimize findings."""
        https_artifact.headers["set-cookie"] = "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict"
        findings = check_cookies(https_artifact, base_config)
        # Should have minimal or no findings
        critical_findings = [f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
        assert len(critical_findings) == 0


class TestHTTPContext:
    """Tests for cookies on HTTP (not HTTPS) sites."""
    
    def test_http_site_secure_flag_not_expected(self, http_artifact, base_config):
        """On HTTP site, Secure flag is not applicable."""
        http_artifact.headers["set-cookie"] = "session=abc; Path=/"
        findings = check_cookies(http_artifact, base_config)
        # Implementation detail: may or may not warn about Secure on HTTP
        # At minimum, should warn about other attributes
        assert isinstance(findings, list)
    
    def test_http_site_should_still_check_other_attributes(self, http_artifact, base_config):
        """Even on HTTP, should check HttpOnly and SameSite."""
        http_artifact.headers["set-cookie"] = "session=abc; Path=/"
        findings = check_cookies(http_artifact, base_config)
        # Should still have findings for missing HttpOnly and SameSite
        assert len(findings) >= 1


class TestEdgeCases:
    """Tests for edge cases and malformed cookies."""
    
    def test_empty_set_cookie_header(self, https_artifact, base_config):
        """Empty Set-Cookie header should not crash."""
        https_artifact.headers["set-cookie"] = ""
        findings = check_cookies(https_artifact, base_config)
        assert isinstance(findings, list)
    
    def test_malformed_cookie(self, https_artifact, base_config):
        """Malformed cookie should be handled gracefully."""
        https_artifact.headers["set-cookie"] = ";;;invalid;;;"
        findings = check_cookies(https_artifact, base_config)
        assert isinstance(findings, list)
    
    def test_cookie_with_unusual_attributes(self, https_artifact, base_config):
        """Cookie with Domain and Max-Age should still be checked."""
        https_artifact.headers["set-cookie"] = "session=abc; Domain=.example.com; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
        findings = check_cookies(https_artifact, base_config)
        # Should have no critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
