import re
from pathlib import Path
from typing import List
from aegisaudit.models import Finding, Severity

# Reuse some patterns from checks/secrets.py but optimized for file scanning
PATTERNS = {
    "AWS Access Key": {
        "regex": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])", 
        "severity": Severity.HIGH,
        "tags": ["secrets", "aws"]
    },
    "Google API Key": {
        "regex": r"AIza[0-9A-Za-z-_]{35}",
        "severity": Severity.MEDIUM,
        "tags": ["secrets", "google"]
    },
    "Generic Private Key": {
        "regex": r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "tags": ["secrets", "crypto"]
    },
    "Slack Token": {
        "regex": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "severity": Severity.HIGH,
        "tags": ["secrets", "slack"]
    }
}

def scan_file_for_secrets(path: Path) -> List[Finding]:
    findings = []
    try:
        # Read file safely
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return [] # Skip binary files

        for name, rule in PATTERNS.items():
            matches = re.finditer(rule["regex"], content)
            for m in matches:
                # Get line number
                line_no = content[:m.start()].count('\n') + 1
                
                findings.append(Finding(
                    id=f"sast-secret-{name.lower().replace(' ', '-')}",
                    severity=rule["severity"],
                    title=f"Hardcoded {name}",
                    description=f"Found potential {name} in source code.",
                    evidence=f"File: {path.name}:{line_no} - Match: {m.group(0)[:10]}...",
                    url=str(path), # Overloading URL field for file path
                    remediation="Use environment variables or a secret manager. Do not commit secrets.",
                    tags=rule["tags"] + ["sast"]
                ))
                # Stop after one match per type per file to reduce noise
                break
                
    except Exception as e:
        pass
        
    return findings
