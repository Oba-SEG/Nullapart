# Certificate, HMAC and API Security

**Status:** mandatory security baseline.

## TLS and certificate validation

All HTTPS/internal TLS clients validate:

- certificate chain;
- hostname/service identity;
- validity period;
- intended key usage/policy;
- revocation/rotation behavior where supported.

Never disable certificate validation for convenience.

## Certificate pinning

Certificate/public-key pinning is **not** the default for the browser Control Plane or ordinary public HTTPS.

Reasons:

- modern PKI/browser validation is the normal trust model;
- browser applications cannot reliably implement their own transport pinning in the same way as a controlled native client;
- hard pins can cause severe outages during legitimate certificate/key rotation.

Use HSTS, trusted CA validation, ACM/managed certificate lifecycle, restrictive DNS/CAA, and mTLS/workload identity for internal service trust.

### When pinning may be considered

Pinning may be used only when:

- both client and server are controlled by Nullapart;
- the threat model specifically justifies protection beyond normal PKI;
- the client technology can enforce pinning safely;
- rotation/recovery is designed in advance.

Prefer SPKI/public-key pinning over a single leaf-certificate byte-for-byte pin where appropriate.

A pin set requires:

- at least one active pin;
- one or more backup/next-rotation pins;
- overlap during rotation;
- monitoring before old-pin removal;
- emergency recovery procedure;
- expiry/review ownership.

Do not use TOFU for security-critical production service identity without an explicit threat model.

## mTLS

For internal high-trust service paths, mTLS/workload identity is preferred to ad hoc certificate pinning.

Potential uses:

- Mail Core <-> privileged scanner services;
- internal artifact broker;
- Deep AI endpoint;
- privileged internal admin/service interfaces.

Certificates should be short-lived and issued from the regional workload PKI where practical.

## HMAC use cases

HMAC is suitable for authenticating/integrity-protecting messages where both parties share a secret and asymmetric identity is not required.

Potential uses:

- inbound webhook signature verification;
- outbound webhook signing;
- narrowly scoped integration callbacks;
- selected internal integrity tokens where a shared-secret model is explicitly justified.

HMAC is **not** the default replacement for workload identity/mTLS between internal services.

## HMAC algorithm

Use a modern HMAC such as HMAC-SHA-256 unless a protocol/provider mandates another approved algorithm.

Do not design custom hashes such as `SHA256(secret || message)`.

## Canonical signing format

Every signed integration defines an unambiguous canonical representation.

Recommended elements:

- signature version;
- key ID;
- timestamp;
- HTTP method;
- canonical path;
- canonical query where required;
- raw body hash or exact raw body bytes;
- nonce/event ID when applicable.

Example conceptual signing string:

```text
v1\n
<timestamp>\n
<method>\n
<path>\n
<body-sha256>\n
<event-id>
```

The exact format is versioned and documented.

## HMAC replay protection

Verification must include:

- timestamp freshness window;
- unique event/nonce ID where applicable;
- idempotency/event deduplication;
- constant-time signature comparison;
- key ID lookup;
- canonical-body verification before JSON parsing where required by the signing contract.

Reject signatures outside the allowed clock-skew/replay window.

## HMAC key management

Keys are:

- random high-entropy secrets;
- per integration/customer/provider where practical;
- stored in OpenBao/approved secrets store;
- never in URL/query/logs;
- rotatable;
- identified by non-secret key ID;
- redacted from UI/observability.

Rotation supports overlapping current/next key versions so integrations can move without a hard cutover outage.

## API authentication

No API credential belongs in a URL.

Do not place:

- bearer token;
- API key;
- session ID;
- HMAC secret;
- refresh token

in URL path, query or fragment.

Use appropriate authorization headers, secure cookies, mTLS or signed webhook headers.

## API versioning

See `docs/26-API-VERSIONING-FEATURE-SWITCHES.md`.

Security properties are version-independent: an old API version does not retain weaker authentication/authorization merely for compatibility.

## API request integrity

Ordinary authenticated HTTPS application APIs do not require an extra HMAC layer simply because HMAC exists.

Use HMAC when the protocol/integration threat model needs message-level shared-secret verification, especially webhooks.

Avoid redundant custom cryptography that complicates key rotation without reducing meaningful risk.

## Testing

Test:

- invalid chain/hostname;
- expired/revoked/rotated service certificates where applicable;
- pin rotation/recovery if pinning exists;
- invalid HMAC;
- body mutation;
- timestamp replay;
- duplicate event ID;
- wrong tenant/integration key;
- signature-version mismatch;
- key rotation overlap;
- timing-safe signature comparison behavior;
- credentials accidentally placed in URLs/logs.

## AI-agent rules

AI coding agents must not:

- disable TLS verification;
- add certificate pinning by default;
- pin a single expiring leaf cert without backup/rotation;
- invent custom cryptographic signing algorithms;
- use a global HMAC secret for all customers/integrations;
- compare MACs with ordinary string equality when a constant-time primitive exists;
- put credentials/signatures containing secrets in URLs.