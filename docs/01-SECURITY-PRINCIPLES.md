# Security Principles

## Trust boundaries

Nullapart recognizes boundaries between public SMTP, customer mail systems, Mail Plane, scanner nodes, Control Plane, identity, storage, Deep AI, operational integrations, administrators and tenants.

Trust does not automatically cross them.

## Authenticate every API

- browser/control access: OIDC-backed authenticated sessions;
- service-to-service: workload identity/mTLS or equivalent;
- AWS resources: scoped IAM roles;
- third-party webhooks: provider signature/HMAC plus service controls;
- Deep AI: authenticated regional OpenAI-compatible endpoint;
- SMTP: SMTP/TLS/source/connector controls.

## Least privilege

Each service receives only the rights it requires.

## Zero trust for message metadata

External `Authentication-Results` and `X-OriginatorOrg` are not trusted merely because they exist.

Trust derives from the connection/path and Nullapart-generated validation.

## Safe error disclosure

External SMTP/web responses are concise and standards-compatible.

Detailed node/engine/policy reasons remain inside permission-controlled operational views.

## Immutable audit

Audit security-relevant administration such as impersonation, policy/domain changes, tenant state changes, cache refresh, quarantine release, remediation, role changes and secret/security configuration.

## Secure failure semantics

Unknown or failed scanner state is never treated as clean. Required-pipeline failure should defer/hold rather than silently bypass security. Optional enrichment failure becomes unknown. Deep AI failure does not stop ordinary mail.
