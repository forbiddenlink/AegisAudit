from typing import List
import re
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig

def check_secrets(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    findings = []
    
    # Analyze body content only
    content = artifact.body_snippet

    # Regex Patterns for Secrets/PII
    patterns = {
        "AWS Access Key": {
            "regex": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])", 
            "severity": Severity.HIGH,
            "description": "Possible AWS Access Key ID found in HTML.",
            "tags": ["secrets", "aws"]
        },
        "Google API Key": {
            "regex": r"AIza[0-9A-Za-z-_]{35}",
            "severity": Severity.MEDIUM, 
            "description": "Google API Key found. Ensure it is restricted by referrer.",
            "tags": ["secrets", "google"]
        },
        "Email Address": {
            # Simple regex to avoid false positives in complex JS
            "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "severity": Severity.INFO,
            "description": "Email address exposed in source code. Can lead to scraping/spam.",
            "tags": ["pii", "email"]
        },
        "Internal IP": {
             "regex": r"192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}",
             "severity": Severity.LOW,
             "description": "Internal IP address revealed in source code.",
             "tags": ["info-leak", "network"]
        }
    }

    for name, rule in patterns.items():
        matches = re.finditer(rule["regex"], content)
        count = 0
        example = ""
        for m in matches:
            count += 1
            if not example:
                example = m.group(0)
            # Limit matches to avoid perf issues on huge files
            if count > 5: break
        
        if count > 0:
            # Special case for Email: If it's a contact page, it's expected.
            # But we flag it as INFO regardless for awareness.
            findings.append(Finding(
                id=f"leak-{name.lower().replace(' ', '-')}",
                severity=rule["severity"],
                title=f"{name} Detected",
                description=f"{rule['description']} (Found {count} instance(s)).",
                evidence=f"Example: {example}...",
                url=artifact.url,
                remediation="Remove sensitive data from client-side code. For emails, use obfuscation or forms.",
                tags=rule["tags"]
            ))

    return findings
