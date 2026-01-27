from typing import List
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig

def check_security_txt(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings = []
    
    # Simple check: If we (the fetcher) specially fetched /.well-known/security.txt we would check it.
    # But the current artifact is just the main page.
    # Limitation: The current scanner model fetches one URL and runs checks on it.
    # To check security.txt properly, we should ideally fetch it separately.
    # For MVP: If the user scans `/.well-known/security.txt` explicitly, check it.
    # OR: Just warn if the main page headers don't link to it (optional check)?
    # Better: Scan logic should probably try to fetch security.txt if it's the root domain.
    # Since checks are pure functions of *one* artifact, we can only check *that* artifact.
    
    # Compromise for "Pure Check" model:
    # 1. If the artifact URL ends in security.txt, validate the content.
    # 2. If it's a regular page, check if we can see a Link header (unlikely for security.txt).
    
    if artifact.url.endswith("security.txt"):
        if "Contact:" not in artifact.body_snippet:
             findings.append(Finding(
                id="sectxt-no-contact",
                severity=Severity.HIGH,
                title="Invalid security.txt",
                description="security.txt is missing the mandatory 'Contact:' field.",
                url=artifact.url,
                remediation="Add 'Contact: ...' to provide variable disclosure contact.",
                references=["https://securitytxt.org/"],
                tags=["security.txt"]
            ))
        if "Expires:" not in artifact.body_snippet:
             findings.append(Finding(
                id="sectxt-no-expires",
                severity=Severity.MEDIUM,
                title="Missing Expires Field",
                description="security.txt must have an 'Expires:' field.",
                url=artifact.url,
                remediation="Add 'Expires: <date>' to the file.",
                tags=["security.txt"]
            ))

    return findings
