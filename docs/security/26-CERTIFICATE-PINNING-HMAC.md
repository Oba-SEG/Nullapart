# Certificate Pinning, HMAC and Signed Request Policy

**Status:** mandatory cryptographic/application-security baseline.

## Certificate pinning stance

Nullapart does **not** use browser/public-web certificate pinning as a default security control.

Modern publicly trusted PKI, certificate transparency, HSTS and controlled certificate lifecycle are preferred for the browser Control Plane. Pinning can create severe outages during legitimate certificate/key rotation and is only justified by a specific threat model.

Use pinning only when:

- Nullapart controls both client and server;
- the client can securely receive pinset updates;
- rotation/recovery has been tested;
- backup pins/keys exist;
- the threat model demonstrates meaningful benefit.

## Browser Control Plane

For regional HTTPS administration use:

- publicly trusted certificates;
- ACM/approved certificate automation;
- HSTS;
- modern TLS;
- certificate-expiry monitoring;
- CAA where applicable.

Do not implement HPKP/browser hard pinning.

## Internal service trust

For internal workloads, prefer:

- workload identity;
- mTLS;
- OpenBao/private PKI;
- scoped trust anchors/intermediate CAs;
- short-lived certificates;
- revocation/rotation.

Do not hardcode a specific short-lived leaf certificate into every service.

## Specialized controlled clients

If a future native/controlled client requires pinning:

- prefer SPKI/public-key pinsets over brittle single leaf-certificate pins where appropriate;
- include at least one backup key/pin;
- document rotation and emergency recovery;
- monitor pin expiry/activation;
- test disaster rotation before production.

Pinning requires security-architecture approval.

## HMAC use cases

HMAC is appropriate where a shared-secret message-authentication scheme is required, especially:

- inbound third-party webhooks that support HMAC;
- internal callback payloads where mTLS/workload identity alone does not provide payload-level integrity/replay semantics;
- signed export/download intents where a shared-secret design is explicitly chosen.

HMAC is not a replacement for normal user authentication, TLS, OAuth/OIDC or workload identity.

## Algorithm

Preferred baseline:

- HMAC-SHA-256 or stronger approved equivalent.

Do not design custom hashes or signature formats without review.

## Signed request envelope

A signed request should bind at least:

- signature version;
- timestamp;
- unique request/event ID or nonce;
- HTTP method where relevant;
- canonical path;
- canonical body bytes/hash;
- relevant tenant/provider identity where the protocol supports it.

Example conceptual input:

```text
v1\ntimestamp\nrequest-id\nPOST\n/webhooks/provider\nSHA256(raw-body)
```

The exact format is versioned and documented per integration.

## Verification order

For an incoming HMAC request:

1. identify allowed provider/key version;
2. enforce maximum body size before expensive parsing;
3. obtain the exact raw bytes required by the signing scheme;
4. validate timestamp/replay window;
5. validate unique request/event ID where available;
6. compute HMAC;
7. compare using constant-time comparison;
8. only then parse/execute business logic;
9. apply idempotency and tenant/resource authorization.

Never reserialize JSON and assume it matches the provider's signed bytes unless the provider specification explicitly signs a canonical representation.

## Replay protection

HMAC without replay protection is insufficient for mutating webhooks/actions.

Use:

- timestamp tolerance;
- event/request ID deduplication;
- nonce where applicable;
- idempotent consumer/action semantics.

Reject stale/replayed requests using stable reason codes.

## Secret lifecycle

HMAC secrets are RESTRICTED.

Requirements:

- stored in OpenBao/Secrets Manager as appropriate;
- scoped per integration/customer/provider where practical;
- never logged;
- rotatable;
- support overlapping current/next key versions during controlled rotation;
- compromise triggers revocation/rotation and event review.

Do not use one global webhook HMAC secret for all providers/tenants.

## Outbound webhook signing

If Nullapart sends signed webhooks in the future:

- use versioned signature headers;
- include timestamp/event ID;
- document canonical bytes;
- support customer secret rotation;
- retry idempotently;
- never place signing secrets in URLs.

## Errors

Signature failure responses should be safe and should not reveal:

- expected signature;
- secret identity beyond what is necessary;
- detailed cryptographic comparison state.

Audit/telemetry may record sanitized provider/key-version/reason information.

## Testing

Test:

- correct signature;
- changed body;
- changed path/method where bound;
- stale timestamp;
- replayed request ID;
- wrong tenant/provider key;
- rotated current/next keys;
- malformed encoding;
- body parsing before signature verification;
- timing-safe comparison path;
- oversized payload.
