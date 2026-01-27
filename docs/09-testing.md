# Testing Strategy

Unit tests:

- checks: feed synthetic headers/cookies/html => expect findings
- policy: required headers rules behave correctly

Integration tests:

- spin up a tiny local test server with known headers/cookies
- run scanner against localhost and validate report outputs

Golden files:

- keep a sample JSON output in tests/fixtures and compare stable fields

Quality gates:

- ruff + mypy + pytest in CI
