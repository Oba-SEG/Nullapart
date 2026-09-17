# Security and Reliability Runbooks

Before production, executable runbooks are required for:

- compromised System Admin;
- compromised Support account;
- customer-admin compromise;
- leaked OpenBao token/certificate;
- leaked AWS credential;
- leaked DKIM/TLS/HMAC key where applicable;
- TLS certificate compromise/expiry;
- compromised scanner node;
- compromised Mail Core/Postfix node;
- S3 artifact exposure;
- cross-tenant data leak;
- tenant-routing/RLS isolation failure;
- incorrect tenant feature override / System-floor bypass;
- audit integrity failure;
- malicious/compromised dependency;
- hostile-content parser zero-day;
- Internet-facing Control Plane RCE/auth-bypass zero-day;
- Postfix/Rspamd/ClamAV critical zero-day;
- OpenBao/ZITADEL critical zero-day;
- container/base-image zero-day;
- GitHub Action/build-chain compromise;
- npm/crate/native dependency supply-chain compromise;
- model-serving/runtime zero-day;
- outbound spam outbreak;
- mail reputation/blocklist incident;
- queue/storage exhaustion;
- Rspamd/ClamAV/required scanner outage;
- PostgreSQL outage/failover;
- Redis/Valkey outage;
- SQS/DLQ/outbox backlog;
- OpenBao outage;
- ZITADEL outage;
- one public MX/mail-node loss;
- AZ impairment;
- regional AWS impairment;
- Tier-3 fast/sustained burn-rate page;
- error-budget exhaustion;
- Deep AI compromise;
- prompt-injection/tool-abuse incident;
- connector/OAuth compromise;
- DMARC report ingestion attack.

## Format

Each runbook states:

- trigger;
- severity;
- owner/escalation;
- affected deployment/capability/SLO where applicable;
- containment/degraded mode;
- evidence to preserve;
- keys/credentials to rotate if applicable;
- customer impact;
- queue/data durability considerations;
- recovery;
- verification/SLI recovery;
- communication;
- post-incident actions.

Zero-day runbooks additionally follow `docs/security/27-ZERO-DAY-INTELLIGENCE-RESPONSE.md`.

Tier-3 reliability runbooks additionally follow `docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`.

Runbooks are tested through tabletop or technical exercises; their existence alone is not sufficient evidence.
