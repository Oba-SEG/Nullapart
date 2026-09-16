# Certificate Trust, mTLS and Pinning

**Status:** mandatory TLS trust policy.

## Principle

Nullapart uses normal modern PKI validation by default.

Certificate/public-key pinning is **not** a blanket control and is not used in browsers via HPKP.

## Browser / Control Plane

Do not use HTTP Public Key Pinning (HPKP).

For browser-facing `nullapart.com` services use:

- publicly trusted certificates;
- HSTS;
- CAA;
- Certificate Transparency monitoring where practical;
- automated renewal;
- strong TLS configuration;
- DNS/domain monitoring.

A browser-admin deployment must not depend on a custom pin that could lock customers/operators out during legitimate certificate rotation.

## Internal service trust

For high-value internal service-to-service traffic, prefer:

- private DNS;
- workload identity;
- mTLS where justified;
- OpenBao-managed regional/deployment PKI;
- scoped CA/intermediate trust;
- short certificate lifetimes and automated rotation.

Trust the intended private CA/trust domain rather than pinning a single leaf certificate whenever normal PKI provides the required assurance.

## When pinning may be considered

Pinning may be considered only for a **controlled non-browser client** where the threat model justifies protection against a compromised/publicly trusted CA or injected trust root.

Examples could include:

- a future managed native administrative client;
- a tightly controlled server-to-server integration where both update mechanisms are under Nullapart control.

A security design review is required before adding pinning.

## Pin type

If pinning is approved, prefer a public-key/SPKI pinset over a single leaf-certificate pin so certificate renewal does not necessarily require a client update.

Do not pin a certificate serial number or one short-lived leaf without a rotation design.

## Pinset and rotation

An approved pinset must include:

- current key;
- at least one safely generated backup/next key;
- activation/retirement process;
- client distribution/update process;
- emergency recovery path;
- monitoring for near-expiry/rotation.

Never deploy a single irreversible pin with no backup path.

## Failure semantics

A pin mismatch is a security failure.

Do not silently fall back to accepting any certificate.

However, pinning availability risk must be assessed before use because an incorrect/expired pin can create a self-inflicted outage.

## Certificate validation

Whether pinned or not:

- verify hostname/service identity;
- verify validity period;
- verify chain/trust;
- verify revocation/status according to selected runtime capability/policy;
- never disable TLS verification for convenience.

## Certificate rotation

Rotation procedures must cover:

- public ACM/certificate renewal;
- private OpenBao-issued workload certificates;
- DKIM/other signing keys separately;
- pinset updates if pinning exists;
- monitoring/alerting;
- rollback/emergency replacement.

## Development/testing

Development may use a dedicated local/private development CA.

Do not add `insecureSkipVerify`, permissive TrustManagers or equivalent production bypasses because development uses self-signed certificates.

## AI-agent rules

AI coding agents must not:

- add HPKP headers;
- disable TLS certificate validation;
- hardcode one production leaf certificate fingerprint as a shortcut;
- add a pin without backup/rotation/recovery design;
- mistake certificate pinning for mTLS client authentication.
