# Requirements

Functional (MVP):

- CLI command: `aegis scan`
- Input: list of URLs OR sitemap URL OR a local file of URLs
- Hard scope allowlist (domains) required
- Fetch pages with redirects enabled and capture:
  - final URL, status, headers, cookies, content-type
  - (HTML only) truncated body for analysis
- Run checks and produce Findings:
  - security headers presence + basic quality
  - cookie flags (Secure/HttpOnly/SameSite)
  - HTTPS enforcement (http -> https redirect behavior)
  - mixed content references in HTML
  - CSP presence + basic anti-footgun checks
  - basic info leakage signals (server header exposure, debug headers)
- Output:
  - terminal summary (counts by severity)
  - JSON report (full machine-readable)
  - HTML report (human friendly)

Non-functional:

- Deterministic output (same input => same results)
- Fast: small sites in under ~60s
- Safe defaults: rate limit, timeouts, truncation
- Easy install: pipx / uv / poetry
