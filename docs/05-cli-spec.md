# CLI Spec

Command:

- aegis scan [OPTIONS]

Options (MVP):

- --urls FILE            Path to newline-delimited URL list
- --sitemap URL          Sitemap to expand (optional)
- --allow DOMAIN         Repeatable allowlist entries (required)
- --out DIR              Output directory (default: ./aegis-report)
- --format [json|html|all]  Output formats (default: all)
- --rate FLOAT           Requests/sec (default: 2.0)
- --timeout FLOAT        Seconds (default: 10)
- --max-bytes INT        Max bytes of HTML to analyze (default: 200000)

Exit codes:

- 0 success (no high findings)
- 2 completed with high findings
- 3 config/scope error
- 4 runtime error
