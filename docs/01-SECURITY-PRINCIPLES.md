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

## Administrative authentication

All System, Support and Customer Admin accounts require MFA.

Prefer phishing-resistant WebAuthn/passkeys/security keys for System and Support. High-risk actions can require step-up authentication.

## Least privilege

Each service receives only the rights it requires.

Permissions apply to backend resources, artifact access, audit queries, exports and impersonation—not merely visible UI controls.

## Zero trust for message metadata

External `Authentication-Results` and `X-OriginatorOrg` are not trusted merely because they exist.

Trust derives from the connection/path and Nullapart-generated validation.

## Tenant isolation

One SMTP transaction can include recipients from multiple customers.

Nullapart separates the shared SMTP transaction/content record from customer-scoped Tenant Message Instances. Customer-specific policy/disposition and UI/API views never expose another tenant's recipients or state.

## Hostile-content isolation

Email HTML, SVG, documents, attachments and remote resources are attacker-controlled.

Never render received HTML/SVG directly into the trusted control-plane DOM. Use sanitization, sandbox/origin isolation, remote-resource blocking, permission-checked artifact access and mandatory content-access audit.

## Safe error disclosure

External SMTP/web responses are concise and standards-compatible.

Detailed node/engine/policy reasons remain inside permission-controlled operational views.

## Immutable audit

Audit security-relevant administration such as impersonation, policy/domain changes, tenant state changes, cache refresh, message-content access, quarantine release, remediation, role changes and secret/security configuration.

Administrative mutation, audit and outbox entries commit atomically where possible, and long-term audit integrity uses tamper-evident immutable checkpoints/archives.

## Durable asynchronous events

Critical events use a transactional outbox plus explicitly durable delivery, with SQS as the preferred AWS baseline.

Redis/Valkey cache is not assumed to provide durable messaging.

## Secure failure semantics

Unknown or failed scanner state is never treated as clean. Required-pipeline failure should defer/hold rather than silently bypass security. Optional enrichment failure becomes unknown. Deep AI failure does not stop ordinary mail.

After SMTP `250`, internal failures do not become retroactive SMTP rejections to the original sender.

## Resource exhaustion

Every MIME/document/archive/OCR/parser path has hard CPU, memory, time, nesting, decompression and temporary-storage limits.

## Security diagram

See [Security Trust Boundaries](diagrams/09-trust-boundaries.mmd) and the [Architecture Diagram Source Index](diagrams/README.md).
