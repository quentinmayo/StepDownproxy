# Initial validation — October 12, 2026

Validated locally with Go 1.27.2 in Docker, OPA 1.21.2, and generated demonstration credentials. No real upstream token or infrastructure password was needed for these tests.

- Go race tests and `go vet`: passed for the gateway and standard-library Knox client.
- Eight Rego tests: passed, covering exact repository access, denied writes, duplicate/unknown query parameters, identity separation, and constrained JSON writes.
- Docker build and nine smoke checks: passed for token injection, policy denial, caller/admin separation, and decision simulation.
- Real Knox integration: passed against commit `61dd58235016fe07c1a63aa8afda1be3e00fbea9` in the companion's test harness. Verified ACL restrictions/revocation, Primary rotation, verified TLS, and a running proxy fetching the new credential without restart.
- Browser checks: console login, asset validation/persistence, policy simulation, and mobile-width overflow checks passed.
- `govulncheck`: no vulnerabilities found in the checked code/dependency graph.
- Publication checks: generated `.env` files and local artifacts excluded; Git history scanned with Gitleaks before push.

Security tests include ambiguous/encoded paths, duplicate JSON keys, unsupported body encodings, request/response limits, failed/undefined/non-boolean OPA decisions, redirects, credential echoes, unsafe headers, duplicate Authorization headers, and cross-origin management requests.

These tests establish the implemented behaviors; they do not constitute an independent security audit or validation of a production GitHub/Knox identity provider. CI repeats the committed automated checks.
