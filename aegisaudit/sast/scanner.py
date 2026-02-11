import os
from pathlib import Path
from aegisaudit.models import ScanResult
from aegisaudit.sast.secrets import scan_file_for_secrets
from aegisaudit.sast.static import scan_python_ast
from aegisaudit.sast.dependencies import check_python_dependencies, check_node_dependencies
from aegisaudit.scoring import calculate_score


class SASTScanner:
    def __init__(self):
        pass

    def scan(self, root_path: Path) -> ScanResult:
        all_findings = []

        # 1. Dependency Checks (Root level primarily)
        all_findings.extend(check_python_dependencies(root_path))
        all_findings.extend(check_node_dependencies(root_path))

        # 2. Walk files
        for root, _, files in os.walk(root_path):
            for file in files:
                file_path = Path(root) / file

                # Skip .git, .venv, node_modules, caches
                if any(
                    p in file_path.parts
                    for p in [
                        ".git",
                        "node_modules",
                        "venv",
                        ".venv",
                        "__pycache__",
                        ".pytest_cache",
                    ]
                ):
                    continue

                # Secrets Scan (All text files)
                all_findings.extend(scan_file_for_secrets(file_path))

                # Static Analysis (Python)
                if file_path.suffix == ".py":
                    all_findings.extend(scan_python_ast(file_path))

        # Post-process findings to filter duplicates
        unique = {}
        for f in all_findings:
            key = (f.id, f.url)
            if key not in unique:
                unique[key] = f

        all_findings = list(unique.values())

        summary = calculate_score(all_findings)

        return ScanResult(
            targets=[str(root_path)], findings=all_findings, summary=summary, config_snapshot={}
        )
