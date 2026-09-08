import logging
from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from aegisaudit.checks.dns import check_dns
from aegisaudit.config import AegisConfig
from aegisaudit.models import ScanArtifact


def artifact():
    return ScanArtifact(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
        cookies={},
        body_snippet="",
        content_type="text/html",
    )


@pytest.mark.parametrize("failure", [dns.exception.Timeout(), dns.resolver.NoNameservers()])
def test_spf_lookup_failure_is_not_a_missing_record(monkeypatch, caplog, failure):
    def resolve(domain, record_type):
        if domain == "example.com" and record_type == "TXT":
            raise failure
        return []

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    with caplog.at_level(logging.INFO):
        findings = check_dns(artifact(), AegisConfig())
    assert not any(f.id == "missing-spf" for f in findings)
    assert "SPF lookup failed" in caplog.text


@pytest.mark.parametrize("response", [[], dns.resolver.NoAnswer(), dns.resolver.NXDOMAIN()])
def test_confirmed_absent_spf_is_reported(monkeypatch, response):
    def resolve(domain, record_type):
        if domain == "example.com" and record_type == "TXT":
            if isinstance(response, Exception):
                raise response
            return response
        return []

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    assert any(f.id == "missing-spf" for f in check_dns(artifact(), AegisConfig()))


@pytest.mark.parametrize("policy, weak", [("v=spf1 -all", False), ("v=spf1 +all", True)])
def test_existing_spf_policy_still_checked(monkeypatch, policy, weak):
    record = Mock()
    record.to_text.return_value = '"' + policy + '"'
    monkeypatch.setattr(dns.resolver, "resolve", lambda *_: [record])
    findings = check_dns(artifact(), AegisConfig())
    assert not any(f.id == "missing-spf" for f in findings)
    assert any(f.id == "spf-allow-all" for f in findings) is weak
