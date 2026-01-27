import os
from pathlib import Path
from typing import List
from aegisaudit.models import Finding
from aegisaudit.sast.secrets import scan_file_for_secrets
from aegisaudit.sast.static import scan_python_ast
from aegisaudit.sast.dependencies import check_python_dependencies, check_node_dependencies

class SASTScanner:
    def __init__(self, root_path: Path):
        self.root_path = root_path

    def scan(self) -> List[Finding]:
        all_findings = []
        
        # 1. Dependency Checks (Root level primarily)
        all_findings.extend(check_python_dependencies(self.root_path))
        all_findings.extend(check_node_dependencies(self.root_path))

        # 2. Walk files
        for root, _, files in os.walk(self.root_path):
            for file in files:
                file_path = Path(root) / file
                
                # Skip .git, .env (we handle envs as findings if they exist separately?), node_modules
                if any(p in file_path.parts for p in [".git", "node_modules", "venv", "__pycache__"]):
                    continue

                # Secrets Scan (All text files)
                all_findings.extend(scan_file_for_secrets(file_path))

                # Static Analysis (Python)
                if file_path.suffix == ".py":
                    all_findings.extend(scan_python_ast(file_path))

        return all_findings

```
