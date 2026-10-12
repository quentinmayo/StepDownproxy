# Contributing

Open an issue describing the operation or threat a change addresses. Keep the gateway small and the authorization boundary explicit. New secret providers need failure, redirect, rotation, and credential-redaction tests. New request types need tests showing that OPA and the upstream see the same semantics.

Run `gofmt`, `go test -race ./...`, `go vet ./...`, the OPA policy tests, and Docker smoke tests before submitting a pull request. Never add credentials, local `.env` files, private keys, host configuration, or real secret-store data. Use generated fixtures and secret references.

For the optional control plane, keep management authorization separate, preserve atomic asset persistence, and use `textContent` for untrusted browser data. The standalone Knox tool belongs in [knox-management](https://github.com/quentinmayo/knox-management).
