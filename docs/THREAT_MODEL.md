# Trust and enforcement

The caller is untrusted. The host, configuration operator, OPA service/policies, secret-store deployment, DNS/CA trust, configured upstream origins, and management administrator are trusted. The proxy process necessarily sees upstream credentials in memory.

| Boundary | Enforcement |
| --- | --- |
| Caller identity | Unique proxy tokens hashed at startup; constant-time hash comparison; caller-supplied identity headers excluded. |
| Policy | Fixed decision endpoint; authenticated principal and parsed operation; explicit boolean approval required before secret retrieval. |
| Destination | Administrator-configured origin, canonical path, normalized query; no caller-selected host; all redirects and tunnels blocked. |
| Header injection | Allowlisted application headers; credential header overwritten after approval; ambient proxy environment ignored. |
| Parsing | Reject encoded/noncanonical paths, duplicate JSON keys, non-JSON bodies, compressed requests, and oversized messages. |
| Output | Response header allowlist; no cookies; exact plaintext credential echoes blocked; no response streaming. |
| Audit | Fixed metadata fields only; no request paths, headers, queries, bodies, credential values, or backend error payloads. |
| Management | Separate optional listener and credential; authenticated same-origin APIs; secret references only; CSP; no persistent browser credential storage. |

Limitations: the policy must understand the allowed upstream operation, including its query/body semantics. A broad `GET` or path-prefix allow rule can expose more than intended. Request data is shared with OPA. Do not enable OPA decision logging of sensitive input without a masking policy. A compromised OPA can approve calls; a compromised upstream can transform and disclose an injected credential; a compromised administrator can change destinations and secret references. Response echo detection is defense in depth, not a data-loss-prevention system.

The original upstream token remains fully privileged outside this proxy. Prevent direct credential distribution and restrict network access to secret storage. Use least-privilege provider credentials in addition to OPA. Place separate management and backend networks behind appropriate access controls. Never enable development HTTP for traffic crossing an untrusted network.

This release has no multi-tenant administration, SSO, per-caller quotas, durable audit sink, policy bundle-signature management, automatic secret-store login/renewal, or arbitrary binary/streaming protocols. These are explicit follow-up areas, not implied guarantees.
