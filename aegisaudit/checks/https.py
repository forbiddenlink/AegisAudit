from typing import List
import re
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig

def check_https(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings = []
    
    # Check 1: Final URL must be HTTPS
    if not artifact.final_url.startswith("https://"):
        findings.append(Finding(
            id="not-https",
            severity=Severity.HIGH,
            title="Not Using HTTPS",
            description="The final URL is not served over HTTPS.",
            url=artifact.final_url,
            remediation="Enforce HTTPS redirection.",
            tags=["https"]
        ))
    
    # Check 2: Mixed Content (Passive body scan)
    if "text/html" in artifact.content_type:
        # Regex for http:// sources in script/img/link/iframe
        mixed_pattern = re.compile(r'<(script|img|iframe|link)[^>]+(src|href)=["\'\s]*http://', re.IGNORECASE)
        matches = mixed_pattern.findall(artifact.body_snippet)
        if matches:
             findings.append(Finding(
                id="mixed-content",
                severity=Severity.MEDIUM,
                title="Mixed Content Detected",
                description="HTML contains references to resources over plain HTTP.",
                evidence=f"Found {len(matches)} instances",
                url=artifact.url,
                remediation="Change all resource links to use 'https://' or relative paths.",
                tags=["https", "mixed-content"]
            ))

    return findings
