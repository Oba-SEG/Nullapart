# NexusSEG Reference Principles

## Relationship

NexusSEG remains a separate project and reference implementation.

Nullapart is not a fork to be mechanically modernized.

Use NexusSEG to preserve product lessons and proven requirements while deliberately reconsidering runtime boundaries.

## Strong concepts to carry forward

- bidirectional SEG requirements;
- customer/domain management;
- source IP groups;
- scoped mail policies;
- greylisting;
- RBL/GeoIP concepts;
- malware/URL/QR/document scanning needs;
- inbound/outbound routing;
- DMARC/signing/domain security;
- SMTP track/trace;
- tenant settings/groups;
- auth/MFA/SSO requirements;
- connectors;
- notifications;
- cases/operations;
- ClickUp/n8n requirements;
- observability concepts.

## Do not copy blindly

Do not reproduce:

- deep synchronous HTTP chains in the mail hot path;
- Ollama/LLM dependency for every email;
- one large shared service secret;
- custom Python SMTP as production MTA;
- sequential scanner/reputation orchestration;
- base64 attachment movement between services;
- raw configuration/JSON-driven UI;
- unnecessary service/container proliferation;
- billing integration inside the SEG;
- internal business/CEO/customer-success AI agents.

## Migration rule

When considering NexusSEG code:

1. identify the product requirement;
2. identify the security requirement;
3. determine whether a mature open-source component already solves the underlying protocol/problem;
4. decide whether the code should be reused, adapted, rewritten or discarded;
5. write Nullapart tests against the desired contract rather than NexusSEG behaviour.

## Product boundary

Nullapart is a mail-security platform with carefully scoped supporting administration and intelligence.

It is not a general AI/cybersecurity agent platform.
