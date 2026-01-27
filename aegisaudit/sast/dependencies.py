import subprocess
import json
from pathlib import Path
from typing import List
from aegisaudit.models import Finding, Severity

def check_python_dependencies(path: Path) -> List[Finding]:
    findings = []
    # Check for requirements.txt or pyproject.toml
    if not (path / "requirements.txt").exists() and not (path / "pyproject.toml").exists():
        return []

    try:
        # Run safety check
        # We assume safety is installed in the same env
        result = subprocess.run(
            ["safety", "check", "--json"], 
            cwd=str(path),
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            try:
                vulns = json.loads(result.stdout)
                # Parse safety JSON output (structure varies by version, handling common 2.x/3.x)
                if isinstance(vulns, dict) and "vulnerabilities" in vulns:
                    vulns = vulns["vulnerabilities"]
                
                for v in vulns:
                    # Safety format handling
                    pkg = v.get("package_name") or v.get("name", "unknown")
                    ver = v.get("installed_version") or v.get("version", "unknown")
                    desc = v.get("vulnerability_spec", "") or v.get("description", "")
                    
                    findings.append(Finding(
                        id=f"vuln-pypi-{pkg}",
                        severity=Severity.HIGH,
                        title=f"Vulnerable Python Package: {pkg}",
                        description=f"Package {pkg} ({ver}) has known vulnerabilities: {desc}",
                        url=str(path / "requirements.txt"),
                        remediation="Upgrade the package to a safe version.",
                        tags=["sast", "dependency", "python"]
                    ))
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        pass # Safety not installed

    return findings

def check_node_dependencies(path: Path) -> List[Finding]:
    findings = []
    # Check for package.json
    if not (path / "package.json").exists():
        return []

    try:
        # Run npm audit
        result = subprocess.run(
            ["npm", "audit", "--json"], 
            cwd=str(path),
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            try:
                report = json.loads(result.stdout)
                if "advisories" in report: # Older npm
                    advisories = report["advisories"]
                    vulns = advisories.values()
                elif "vulnerabilities" in report: # Newer npm
                     # This structure is complex (nested), simple flat parsing for MVP
                     vulns = [] # TODO: implement full recursive parse if needed
                     pass 
                
                # Simplified parsing for 'advisories' style or 'metadata' summary
                metadata = report.get("metadata", {}).get("vulnerabilities", {})
                if metadata:
                    for severity, count in metadata.items():
                        if count > 0:
                            sev_enum = Severity.LOW
                            if severity == "high": sev_enum = Severity.HIGH
                            elif severity == "critical": sev_enum = Severity.CRITICAL
                            elif severity == "moderate": sev_enum = Severity.MEDIUM
                            
                            findings.append(Finding(
                                id=f"vuln-npm-{severity}",
                                severity=sev_enum,
                                title=f"NPM Vulnerabilities ({severity})",
                                description=f"Found {count} {severity} vulnerabilities in Node.js dependencies.",
                                url=str(path / "package.json"),
                                remediation="Run 'npm audit fix' to resolve vulnerabilities.",
                                tags=["sast", "dependency", "node"]
                            ))

            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
         pass # npm not installed

    return findings
