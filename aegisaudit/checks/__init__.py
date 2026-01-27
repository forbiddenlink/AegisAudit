from typing import List, Protocol
from aegisaudit.models import ScanArtifact, Finding, Severity
from aegisaudit.config import AegisConfig

class Check(Protocol):
    def run(self, artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
        """Run the check against the artifact and return findings."""
        ...
