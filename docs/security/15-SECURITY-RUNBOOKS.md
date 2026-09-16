# Security Runbooks

Before production, executable runbooks are required for:

- compromised System Admin;
- compromised Support account;
- customer-admin compromise;
- leaked OpenBao token/certificate;
- leaked AWS credential;
- leaked DKIM key;
- TLS certificate compromise/expiry;
- compromised scanner node;
- compromised Mail Core/Postfix node;
- S3 artifact exposure;
- cross-tenant data leak;
- audit integrity failure;
- malicious/compromised dependency;
- outbound spam outbreak;
- mail reputation/blocklist incident;
- queue/storage exhaustion;
- Rspamd/ClamAV/scanner outage;
- PostgreSQL outage;
- Redis/Valkey outage;
- SQS/DLQ backlog;
- OpenBao outage;
- ZITADEL outage;
- regional AWS impairment;
- Deep AI compromise;
- prompt-injection/tool-abuse incident;
- connector/OAuth compromise;
- DMARC report ingestion attack.

## Format

Each runbook states trigger, severity, owner/escalation, containment, evidence, keys/credentials to rotate, customer impact, recovery, verification, communication and post-incident actions.

Runbooks are tested through tabletop or technical exercises.
