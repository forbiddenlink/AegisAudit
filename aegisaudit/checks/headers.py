from typing import List
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig

def check_headers(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings = []
    headers = {k.lower(): v for k, v in artifact.headers.items()}
    policy = config.policy.get("required_headers", {})

    # HSTS
    hsts_policy = policy.get("strict-transport-security", {})
    if "strict-transport-security" not in headers:
        findings.append(Finding(
            id="missing-hsts",
            severity=Severity.HIGH,
            title="Missing HSTS Header",
            description="HTTP Strict Transport Security (HSTS) header is missing.",
            url=artifact.url,
            remediation="Add 'Strict-Transport-Security' header with a max-age of at least 6 months.",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
            tags=["headers", "hsts"]
        ))
    
    # CSP
    if "content-security-policy" not in headers:
         if policy.get("content-security-policy", {}).get("required", True):
            findings.append(Finding(
                id="missing-csp",
                severity=Severity.MEDIUM,
                title="Missing Content Security Policy",
                description="Content-Security-Policy header is missing, allowing potential XSS.",
                url=artifact.url,
                remediation="Implement a Content Security Policy to restrict resource loading.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                tags=["headers", "csp"]
            ))

    # X-Content-Type-Options
    if "x-content-type-options" not in headers:
        findings.append(Finding(
            id="missing-xcto",
            severity=Severity.LOW,
            title="Missing X-Content-Type-Options",
            description="X-Content-Type-Options header is missing.",
            url=artifact.url,
            remediation="Set 'X-Content-Type-Options: nosniff'.",
            tags=["headers"]
        ))
    elif headers["x-content-type-options"].lower() != "nosniff":
         findings.append(Finding(
            id="bad-xcto",
            severity=Severity.LOW,
            title="Invalid X-Content-Type-Options",
            description=f"Expected 'nosniff', got '{headers['x-content-type-options']}'",
            evidence=headers["x-content-type-options"],
            url=artifact.url,
            remediation="Set 'X-Content-Type-Options: nosniff'.",
            tags=["headers"]
        ))

    # Info Disclosure (Server headers)
    for banned in config.policy.get("banned_headers", []):
        if banned in headers:
             findings.append(Finding(
                id=f"leaked-{banned}",
                severity=Severity.INFO,
                title=f"Information Leakage: {banned}",
                description=f"Server is disclosing technology details via the '{banned}' header.",
                evidence=f"{banned}: {headers[banned]}",
                url=artifact.url,
                remediation=f"Configure the server to suppress the '{banned}' header.",
                tags=["headers", "info-leak"]
            ))

    return findings
