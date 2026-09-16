# Cryptographic Standards

## Principle

Use mature libraries/protocol implementations. Do not invent cryptography.

## TLS

Production services use modern TLS.

Baseline:

- TLS 1.2 minimum unless protocol compatibility explicitly requires otherwise;
- TLS 1.3 preferred;
- disable obsolete SSL/TLS versions;
- avoid obsolete/weak cipher suites.

SMTP interoperability requirements may differ from web/internal APIs and must be documented by transport policy.

## Passwords

If Nullapart stores any passwords directly, use a modern memory-hard password KDF such as Argon2id with parameters reviewed for the environment.

Prefer external identity-provider authentication instead of custom password storage.

## Hashes

For security/integrity use SHA-256 or stronger unless a protocol mandates otherwise.

Do not use MD5/SHA-1 for new security decisions except where required to parse/verify legacy protocol data without treating it as a modern security primitive.

## Keys

Keys must have:

- owner/purpose;
- creation date;
- algorithm/size;
- rotation policy;
- expiry where applicable;
- revocation procedure;
- protected storage.

## DKIM

Use mature DKIM implementations and appropriate contemporary key sizes/algorithms.

DKIM private keys are restricted secrets and rotated according to policy.

## PKI

OpenBao PKI hierarchy should separate:

- root;
- regional/deployment intermediates;
- workload/service issuance.

Roots should not remain online unnecessarily.

## KMS

Use AWS KMS for supported regional encryption/signing/auto-unseal use cases.

Key policies must be least-privilege and deployment-scoped.

## Randomness

Use OS/CSPRNG-backed cryptographic randomness only.

## Certificates

Automate issuance/renewal where possible and alert before expiry.

Certificate validation failures must not be silently bypassed.
