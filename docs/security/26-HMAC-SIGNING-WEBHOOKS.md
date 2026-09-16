# HMAC Signing and Webhook Security

**Status:** mandatory integrity/authenticity pattern for applicable callbacks/webhooks.

## Purpose

HMAC is used where a shared-secret message-authentication scheme is appropriate for webhook/event integrity.

HMAC is not a replacement for TLS, user authentication, password hashing, mTLS or asymmetric signing where those are the correct tools.

## Algorithm

Default new Nullapart HMAC scheme:

- HMAC-SHA-256.

Do not introduce MD5/SHA-1 HMAC for new protocols.

## Key management

HMAC keys are RESTRICTED secrets.

Requirements:

- generated from CSPRNG;
- sufficiently random;
- stored in OpenBao/approved secret store;
- scoped by integration/customer/provider where feasible;
- not reused as passwords/API bearer tokens;
- versioned/key ID;
- rotatable;
- auditable creation/rotation/revocation;
- never logged or returned to UI after initial secure provisioning where applicable.

## Outgoing Nullapart webhook signature

If Nullapart later sends signed webhooks, use explicit signature headers such as:

- `X-Nullapart-Signature`;
- `X-Nullapart-Timestamp`;
- `X-Nullapart-Event-ID`;
- `X-Nullapart-Key-ID` where key rotation requires it.

The signature version is encoded, for example conceptually:

`v1=<signature>`

## Canonical signed input

Avoid signing a parsed/re-serialized JSON object because key ordering/serialization differences create ambiguity.

Sign a deterministic envelope derived from the **raw request body** and explicit metadata.

A conceptual v1 canonical form is:

```text
v1\n
<timestamp>\n
<event_id>\n
<http_method>\n
<normalized_path>\n
<SHA256(raw_body)>
```

Compute:

```text
HMAC-SHA-256(secret, canonical_bytes)
```

Encode the result using one documented representation such as base64url or lowercase hex and keep it consistent.

The exact wire representation must be specified once before production use and then versioned rather than changed silently.

## Verification

Receiver verification order:

1. parse signature version/key ID;
2. reject unsupported version;
3. validate timestamp format/window;
4. validate event ID format;
5. reconstruct canonical input from raw body;
6. compute HMAC;
7. compare using constant-time comparison;
8. reject replayed event ID where replay prevention is required;
9. only then process the body.

Do not parse/process a destructive event before signature validation.

## Replay protection

HMAC alone does not prevent replay.

Use:

- timestamp tolerance;
- unique event ID/nonce;
- durable/idempotent event record;
- provider-specific replay strategy.

The replay window should account for clock skew and delivery retries without accepting indefinitely old signed requests.

## Idempotency

A correctly signed duplicate webhook is still a duplicate.

Consumers must be idempotent and use event/provider IDs to prevent duplicate side effects.

## Rotation

During controlled rotation:

- issue a new key/version;
- permit a bounded overlap where old/new keys are accepted;
- switch sender;
- verify traffic;
- retire old key;
- record rotation.

Do not maintain unlimited historical active keys.

## Incoming provider webhooks

For Microsoft, Google, ClickUp or other provider callbacks:

- use the provider's documented verification scheme;
- do not replace it with a Nullapart HMAC scheme;
- verify raw request/body according to provider rules;
- validate tenant/subscription/resource ownership;
- apply idempotency;
- rate limit;
- log safe verification result, not secrets.

## HMAC misuse to avoid

Do not use HMAC:

- to store passwords;
- as encryption;
- as a substitute for TLS;
- with a secret in the URL;
- with the same key for unrelated customers/integrations where isolation is feasible;
- by comparing signatures with ordinary non-constant-time string equality;
- over ambiguous canonicalization.

## HMAC-derived identifiers

If HMAC is used for privacy-preserving stable pseudonymous correlation, use a dedicated purpose-specific key separate from webhook signing keys and document rotation/consequence.

## Testing

Test:

- valid signature;
- modified body;
- modified path/method where included;
- expired/future timestamp;
- replayed event ID;
- wrong key/customer;
- unknown key ID;
- rotation overlap;
- malformed header;
- constant-time verification path;
- duplicate side-effect prevention.

## AI-agent rules

AI coding agents must not invent a bespoke signature format per endpoint.

Reuse the versioned HMAC library/contract and keep provider-specific verification isolated in adapters.
