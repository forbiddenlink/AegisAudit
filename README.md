# AegisAudit

**Tagline:** Security posture reports for modern web apps.

# AegisAudit 🛡️

A modern, full-stack security posture scanner for both **Web Applications** (DAST-like) and **Source Code** (SAST).

## Features

- **Web Scan (`scan`)**:
  - **Headers**: Checks for HSTS, CSP, X-Frame-Options, etc.
  - **DNS**: Analyzes SPF, DMARC, CAA records.
  - **Content**: Passively detects PII (Emails) and exposed secrets (API Keys) in HTML.
  - **Crypto**: Checks SSL/TLS certificate expiration and versions.
  - **Probing**: Optionally checks for exposed files (`.env`, `.git`).
  
- **Code Audit (`audit`)**:
  - **Secrets**: Scans files for hardcoded AWS keys, Google API keys, and private keys.
  - **Dependencies**: Checks for vulnerable Python packages (`safety`) and Node.js code (`npm audit`).
  - **Static Analysis**: Detects dangerous Python patterns like `eval()` and `exec()`.

- **Operational Excellence**:
  - **History**: Tracks scan scores over time in a local SQLite database.
  - **Alerts**: Sends results to Slack/Discord Webhooks.
  - **Reports**: Generates JSON, SARIF (GitHub Security), and rich HTML reports with trend charts.

## Installation

```bash
git clone https://github.com/your-username/aegisaudit.git
cd aegisaudit
pip install -e .
```

## Usage

### 1. Web Scan

Scan a live website for security issues.

```bash
# Basic scan
aegis scan --url https://example.com

# Deep scan (with file probing) and HTML report
aegis scan --url https://example.com --probe --format html

# Send alert to Discord
aegis scan --url https://example.com --webhook "https://discord.com/api/webhooks/..."
```

### 2. Code Audit

Audit a local directory for secrets and vulnerabilities.

```bash
# Audit current directory
aegis audit .

# Audit specific folder and output report
aegis audit ./src --out ./audit-reports
```

### 3. View History

See how your security score improves over time.

```bash
aegis history
```

## Docker Usage

Run AegisAudit without installing Python dependencies manually.

```bash
docker build -t aegis .
docker run --rm aegis scan --url https://example.com
```

## Contributing

Run tests with `pytest`:

```bash
pytest tests/
```

## Example Output

### Terminal

![Terminal Output](https://via.placeholder.com/800x400?text=Terminal+Output+Screenshot)
*(Example: Findings table with High/Medium/Low severity and overall score)*

### HTML Report

![HTML Report](https://via.placeholder.com/800x600?text=HTML+Report+Screenshot)
*(Example: detailed remediation guidance)*

## Documentation

- [Vision](docs/00-vision.md)
- [Check Catalog](docs/07-check-catalog.md)
- [CLI Spec](docs/05-cli-spec.md)
