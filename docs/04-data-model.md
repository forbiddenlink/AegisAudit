# Data Model

Finding fields:

- id: stable identifier (e.g., "missing-hsts")
- severity: info | low | medium | high
- title: human headline
- description: what it means
- evidence: exact observed values (header/cookie snippet)
- url: affected resource
- remediation: actionable fix guidance
- references: list of strings (OWASP cheat sheet name, MDN topic)
- tags: ["headers", "cookies", "csp", "https", "info-leak"]

ScanResult:

- started_at: datetime
- finished_at: datetime
- tool_version: string
- targets: list of scanned URLs
- findings: list[Finding]
- summary:
  - counts_by_severity: dict[str, int]
  - category_scores: dict[str, float]
  - overall_score: float
- config_snapshot: redacted config used for scan (no secrets)
