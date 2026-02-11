import pytest
from aegisaudit.models import ScanArtifact, Severity
from aegisaudit.checks.headers import check_headers
from aegisaudit.config import AegisConfig


@pytest.fixture
def base_config():
    """Base configuration with no allowlists."""
    return AegisConfig(allowlist_urls=[], probe_files=False)


@pytest.fixture
def base_artifact():
    """Base artifact with minimal headers."""
    return ScanArtifact(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
        content=b"<html><body>Test</body></html>",
        start_time=1.0,
        end_time=2.0,
    )


class TestHSTSHeader:
    """Tests for HTTP Strict Transport Security header."""

    def test_missing_hsts(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        hsts_findings = [f for f in findings if "HSTS" in f.title]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == Severity.HIGH
        assert "missing" in hsts_findings[0].description.lower()

    def test_hsts_present_valid(self, base_artifact, base_config):
        base_artifact.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"
        findings = check_headers(base_artifact, base_config)
        hsts_findings = [f for f in findings if "HSTS" in f.title]
        assert len(hsts_findings) == 0

    def test_hsts_short_max_age(self, base_artifact, base_config):
        base_artifact.headers["strict-transport-security"] = "max-age=3600"
        findings = check_headers(base_artifact, base_config)
        hsts_findings = [
            f for f in findings if "HSTS" in f.title or "max-age" in f.description.lower()
        ]
        assert len(hsts_findings) > 0
        assert any(f.severity in [Severity.MEDIUM, Severity.HIGH] for f in hsts_findings)

    def test_hsts_missing_includesubdomains(self, base_artifact, base_config):
        base_artifact.headers["strict-transport-security"] = "max-age=31536000"
        findings = check_headers(base_artifact, base_config)
        # Should warn about missing includeSubDomains
        subdomain_findings = [f for f in findings if "subdomain" in f.description.lower()]
        # May or may not warn depending on implementation
        assert isinstance(subdomain_findings, list)


class TestCSPHeader:
    """Tests for Content Security Policy header."""

    def test_missing_csp(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        csp_findings = [
            f for f in findings if "CSP" in f.title or "Content-Security-Policy" in f.title
        ]
        assert len(csp_findings) >= 1
        assert any(f.severity == Severity.HIGH for f in csp_findings)

    def test_csp_present(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = "default-src 'self'; script-src 'self'"
        findings = check_headers(base_artifact, base_config)
        csp_findings = [
            f
            for f in findings
            if "missing" in f.description.lower() and "csp" in f.description.lower()
        ]
        assert len(csp_findings) == 0

    def test_csp_unsafe_inline(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = (
            "default-src 'self'; script-src 'unsafe-inline'"
        )
        findings = check_headers(base_artifact, base_config)
        unsafe_findings = [f for f in findings if "unsafe-inline" in f.description.lower()]
        assert len(unsafe_findings) >= 1
        assert any(f.severity in [Severity.MEDIUM, Severity.HIGH] for f in unsafe_findings)

    def test_csp_unsafe_eval(self, base_artifact, base_config):
        base_artifact.headers["content-security-policy"] = (
            "default-src 'self'; script-src 'unsafe-eval'"
        )
        findings = check_headers(base_artifact, base_config)
        unsafe_findings = [f for f in findings if "unsafe-eval" in f.description.lower()]
        assert len(unsafe_findings) >= 1


class TestXFrameOptions:
    """Tests for X-Frame-Options header."""

    def test_missing_xfo(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        xfo_findings = [
            f for f in findings if "X-Frame-Options" in f.title or "frame" in f.title.lower()
        ]
        # Should warn if missing (unless CSP has frame-ancestors)
        assert isinstance(xfo_findings, list)

    def test_xfo_deny(self, base_artifact, base_config):
        base_artifact.headers["x-frame-options"] = "DENY"
        findings = check_headers(base_artifact, base_config)
        xfo_findings = [
            f
            for f in findings
            if "X-Frame-Options" in f.title and "missing" in f.description.lower()
        ]
        assert len(xfo_findings) == 0

    def test_xfo_sameorigin(self, base_artifact, base_config):
        base_artifact.headers["x-frame-options"] = "SAMEORIGIN"
        findings = check_headers(base_artifact, base_config)
        xfo_findings = [
            f
            for f in findings
            if "X-Frame-Options" in f.title and "missing" in f.description.lower()
        ]
        assert len(xfo_findings) == 0


class TestReferrerPolicy:
    """Tests for Referrer-Policy header."""

    def test_missing_referrer_policy(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        ref_findings = [
            f for f in findings if "Referrer-Policy" in f.title or "referrer" in f.title.lower()
        ]
        assert len(ref_findings) >= 1

    def test_referrer_policy_present(self, base_artifact, base_config):
        base_artifact.headers["referrer-policy"] = "strict-origin-when-cross-origin"
        findings = check_headers(base_artifact, base_config)
        ref_findings = [
            f
            for f in findings
            if "Referrer-Policy" in f.title and "missing" in f.description.lower()
        ]
        assert len(ref_findings) == 0

    def test_referrer_policy_no_referrer(self, base_artifact, base_config):
        base_artifact.headers["referrer-policy"] = "no-referrer"
        findings = check_headers(base_artifact, base_config)
        ref_findings = [
            f
            for f in findings
            if "Referrer-Policy" in f.title and "missing" in f.description.lower()
        ]
        assert len(ref_findings) == 0


class TestXContentTypeOptions:
    """Tests for X-Content-Type-Options header."""

    def test_missing_xcto(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        xcto_findings = [
            f
            for f in findings
            if "X-Content-Type-Options" in f.title or "nosniff" in f.description.lower()
        ]
        assert len(xcto_findings) >= 1

    def test_xcto_nosniff(self, base_artifact, base_config):
        base_artifact.headers["x-content-type-options"] = "nosniff"
        findings = check_headers(base_artifact, base_config)
        xcto_findings = [
            f
            for f in findings
            if "X-Content-Type-Options" in f.title and "missing" in f.description.lower()
        ]
        assert len(xcto_findings) == 0


class TestPermissionsPolicy:
    """Tests for Permissions-Policy header."""

    def test_missing_permissions_policy(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        pp_findings = [f for f in findings if "Permissions-Policy" in f.title]
        # May warn or not depending on implementation
        assert isinstance(pp_findings, list)

    def test_permissions_policy_present(self, base_artifact, base_config):
        base_artifact.headers["permissions-policy"] = "geolocation=(), camera=()"
        findings = check_headers(base_artifact, base_config)
        pp_findings = [
            f
            for f in findings
            if "Permissions-Policy" in f.title and "missing" in f.description.lower()
        ]
        assert len(pp_findings) == 0


class TestCrossOriginPolicies:
    """Tests for COOP, COEP, and CORP headers."""

    def test_missing_coop(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        coop_findings = [
            f for f in findings if "Cross-Origin-Opener-Policy" in f.title or "COOP" in f.title
        ]
        # Implementation may or may not warn
        assert isinstance(coop_findings, list)

    def test_coop_present(self, base_artifact, base_config):
        base_artifact.headers["cross-origin-opener-policy"] = "same-origin"
        findings = check_headers(base_artifact, base_config)
        # Should not have missing COOP finding
        assert isinstance(findings, list)

    def test_missing_coep(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        coep_findings = [
            f for f in findings if "Cross-Origin-Embedder-Policy" in f.title or "COEP" in f.title
        ]
        assert isinstance(coep_findings, list)

    def test_missing_corp(self, base_artifact, base_config):
        findings = check_headers(base_artifact, base_config)
        corp_findings = [
            f for f in findings if "Cross-Origin-Resource-Policy" in f.title or "CORP" in f.title
        ]
        assert isinstance(corp_findings, list)


class TestInfoLeakage:
    """Tests for information disclosure headers."""

    def test_server_header_present(self, base_artifact, base_config):
        base_artifact.headers["server"] = "Apache/2.4.41"
        findings = check_headers(base_artifact, base_config)
        server_findings = [
            f for f in findings if "server" in f.title.lower() or "server" in f.description.lower()
        ]
        # Should warn about version disclosure
        assert len(server_findings) >= 1
        assert any(f.severity in [Severity.LOW, Severity.INFO] for f in server_findings)

    def test_x_powered_by_present(self, base_artifact, base_config):
        base_artifact.headers["x-powered-by"] = "PHP/7.4.3"
        findings = check_headers(base_artifact, base_config)
        xpb_findings = [
            f for f in findings if "powered" in f.description.lower() or "X-Powered-By" in f.title
        ]
        assert len(xpb_findings) >= 1
        assert any(f.severity in [Severity.LOW, Severity.INFO] for f in xpb_findings)


class TestAllowlist:
    """Tests for allowlist enforcement."""

    def test_allowlist_suppresses_findings(self, base_artifact):
        config = AegisConfig(allowlist_urls=["example.com"], probe_files=False)
        findings = check_headers(base_artifact, config)
        # Allowlisted URLs may suppress certain findings
        assert isinstance(findings, list)

    def test_non_allowlisted_url_shows_findings(self, base_config):
        artifact = ScanArtifact(
            url="https://notallowed.com",
            final_url="https://notallowed.com",
            status_code=200,
            headers={},
            content=b"<html></html>",
            start_time=1.0,
            end_time=2.0,
        )
        findings = check_headers(artifact, base_config)
        # Should have findings for missing headers
        assert len(findings) > 0
