# Pinterest Knox integration

Knox's v0 API uses a response envelope with `status` and `data`. Key versions have base64-encoded data and states `Primary`, `Active`, and `Inactive`. StepDownproxy requests `/v0/keys/{keyID}/?status=%22Primary%22`, checks the returned key ID, and requires exactly one nonempty Primary version.

The protocol was checked against [Pinterest Knox client.go](https://github.com/pinterest/knox/blob/61dd58235016fe07c1a63aa8afda1be3e00fbea9/client.go) and the corresponding server routes. No Knox source is embedded in the production proxy. The standard-library implementation is exposed in `pkg/knox` for the companion tool.

```json
{
  "knox": {
    "url": "https://knox.internal.example",
    "token": {"provider":"file", "ref":"/run/secrets/knox-auth"},
    "ca_file": "/run/certs/knox-ca.pem",
    "cert_file": "/run/certs/proxy.pem",
    "key_file": "/run/certs/proxy.key"
  }
}
```

Use the authorization string expected by your Knox authentication provider. For mTLS, supply the certificate and private key as well as the appropriate complete authorization string, commonly `0t` followed by the certificate's machine identity. Custom providers, including SPIFFE deployments, may use other type prefixes. No TLS-verification bypass is available. The original Knox development certificates and credentials are not used by this project.

Grant the proxy's Knox principal Read access to only its service keys. Give the separate management platform a different principal and only the Write/Admin privileges it needs. Knox still enforces its ACLs on each API call. A gateway caller's identity is not a Knox principal: OPA governs that caller's operation, while the gateway's backend identity governs secret retrieval.

Rotation sequence:

1. Add the new upstream token as an Active Knox version.
2. Ensure the upstream accepts the new token.
3. Promote the Active version to Primary; Knox makes the previous Primary Active.
4. Subsequent approved proxy requests fetch the new Primary without a proxy restart.
5. Revoke the old token at its upstream provider, then deactivate the old Knox version when appropriate.

Changing Knox state does not revoke a token at GitHub or another provider. No retries are made for key mutations, so failed network calls with an unknown outcome should be checked through inventory before being repeated.
