import json
from pathlib import Path
from aegisaudit.models import ScanResult, Severity


def generate_sarif_report(result: ScanResult, output_path: Path):
    """Generate a SARIF 2.1.0 compatible report."""

    rules = []
    # Deduplicate rules from findings for the valid rules array
    seen_rules = set()

    # Map for rules
    for finding in result.findings:
        if finding.id not in seen_rules:
            rules.append(
                {
                    "id": finding.id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": f"{finding.description}\n\nRemediation: {finding.remediation}",
                        "markdown": f"**{finding.description}**\n\n### Remediation\n{finding.remediation}\n\n### References\n{', '.join(finding.references)}",
                    },
                    "properties": {"tags": finding.tags, "precision": "high"},
                }
            )
            seen_rules.add(finding.id)

    sarif_results = []
    for finding in result.findings:
        level = "warning"
        if finding.severity == Severity.HIGH:
            level = "error"
        elif finding.severity == Severity.INFO:
            level = "note"

        sarif_results.append(
            {
                "ruleId": finding.id,
                "level": level,
                "message": {"text": finding.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.url}}}],
            }
        )

    sarif_log = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": result.tool_name,
                        "version": result.tool_version,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    with open(output_path, "w") as f:
        json.dump(sarif_log, f, indent=2)
