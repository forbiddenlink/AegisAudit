# Config & Policy

Config file (aegis.yml) example:

scope:
  allow:
    - "staging.myapp.com"
    - "myapp.com"

targets:
  urls_file: "urls.txt"
  sitemap: null

limits:
  rate_per_sec: 2.0
  timeout_sec: 10
  max_html_bytes: 200000

policy:
  required_headers:
    strict-transport-security:
      min_max_age: 15552000
    content-security-policy:
      required: true
    permissions-policy:
      required: true
    cross-origin-opener-policy:
      required: true
    referrer-policy:
      required: true
  server_header:
    allow_present: false
