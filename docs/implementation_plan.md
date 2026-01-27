# AegisAudit Implementation Plan

## Goal Description

Create **AegisAudit**, a defensive website security posture auditor. It passively checks for risky defaults and misconfigurations (headers, cookies, HTTPS hygiene, CSP quality) and generates clean, actionable reports.
Key Principles: Safe-by-design (no exploits), Actionable (remediation guidance), and Professional Quality (modern Python stack).

## User Review Required
>
> [!IMPORTANT]
> **Enhancements Proposed**:
>
> - **SARIF Output**: Native support for SARIF 2.1.0 JSON output to integrate with GitHub Advanced Security.
> - **RFC 9116 Support**: Passive check for `/.well-known/security.txt` presence and validity (expiration, contact).
> - **SRI & Supply Chain**: Passive check for `integrity` attributes on external scripts/styles.
> - Added **Permissions-Policy**, **COOP**, **COEP**, and **CORP** to the Header Checks checks based on modern OWASP recommendations.
> - Added **SSL Certificate Expiration** check (passive) to the HTTPS sufficiency checks.
> - Confirmed **httpx** is suitable for async fetching and basic SSL validation.
> - Proposed **content-security-policy** library for robust CSP parsing (optional, can start with regex/string analysis for MVP).

## Proposed Changes

### Documentation Layout

We will establish the `docs/` folder with the "spine" documents provided by the user, enhanced with the researched findings.

#### [NEW] Documentation Files

- [NEW] [README.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/README.md) - Project entry point.
- [NEW] [docs/00-vision.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/00-vision.md)
- [NEW] [docs/01-ethics-scope.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/01-ethics-scope.md)
- [NEW] [docs/02-requirements.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/02-requirements.md)
- [NEW] [docs/03-architecture.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/03-architecture.md)
- [NEW] [docs/04-data-model.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/04-data-model.md)
- [NEW] [docs/05-cli-spec.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/05-cli-spec.md)
- [NEW] [docs/06-config-policy.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/06-config-policy.md)
- [NEW] [docs/07-check-catalog.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/07-check-catalog.md) (Enhanced with OWASP findings)
- [NEW] [docs/08-reporting.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/08-reporting.md)
- [NEW] [docs/09-testing.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/09-testing.md)
- [NEW] [docs/10-roadmap.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/10-roadmap.md)
- [NEW] [docs/11-security-of-tool.md](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/docs/11-security-of-tool.md)

### Project Scaffolding (Day 1)

- [NEW] [pyproject.toml](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/pyproject.toml) - Dependencies: `httpx`, `typer`, `pydantic`, `rich`, `jinja2`, `pytest`, `ruff`, `mypy`.
- [NEW] [aegisaudit/**init**.py](file:///Users/elizabethstein/.gemini/antigravity/brain/b498d960-4ecb-441e-978a-60c9d21f5863/aegisaudit/__init__.py)

## Verification Plan

### Automated Tests

1. **Documentation Check**: Verify all MD files exist and contain the required sections.
2. **Scaffolding Check**: Verify `pyproject.toml` is valid and dependencies can be installed (simulated or dry-run).
3. **Linter Check**: Run `ruff check .` on the generated python files (if any).

### Manual Verification

1. Review the generated markdown files to ensuring the content matches the "User's Vote" + "Deep Research Enhancements".
