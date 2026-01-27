# Security of AegisAudit

Threats:

- SSRF: scanner being used to hit internal IPs
- Data leakage: reports storing sensitive response data
- Abuse: scanning third-party sites without permission

Mitigations:

- enforce allowlist on hostname + resolved IP rules (later)
- block private IP ranges by default (optional advanced)
- truncate bodies; never store auth headers; redact cookies if needed
- safe defaults: rate limit, timeouts
- clear ethics + permission requirement
