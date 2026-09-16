# Cryptographic Standards

## Principle

Use mature libraries/protocol implementations. Do not invent cryptography.

## TLS

Baseline:

- TLS 1.2 minimum unless protocol compatibility explicitly requires otherwise;
- TLS 1.3 preferred;
- obsolete SSL/TLS disabled;
- weak/obsolete cipher suites disabled.

SMTP interoperability requirements may differ from web/internal APIs and must be documented by transport policy.

## Passwords

If Nullapart stores passwords directly, use a modern memory-hard KDF such as Argon2id with reviewed parameters. Prefer external identity-provider authentication.

## Hashes

Use SHA-256 or stronger for new integrity/security decisions unless a protocol mandates otherwise.

## Keys

Keys have owner/purpose, creation date, algorithm/size, rotation policy, expiry where applicable and revocation procedure.

## DKIM

Use mature DKIM implementations and contemporary key algorithms/sizes. Private keys are RESTRICTED and rotated.

## PKI

Separate root, regional/deployment intermediates and workload issuance. Roots should not remain online unnecessarily.

## KMS

Use AWS KMS where appropriate with least-privilege deployment-scoped key policies.

## Randomness

Use OS/CSPRNG-backed cryptographic randomness only.

## Certificates

Automate issuance/renewal where possible and alert before expiry. Never silently bypass certificate validation.
