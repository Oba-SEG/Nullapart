# Nullapart Security Program

**Status:** mandatory architecture gate.

Nullapart is a security product. Product implementation does not begin until this security program is defined and accepted.

The security program governs how Nullapart is designed, built, changed, operated, monitored, compromised, recovered and audited.

## Phase -1 security gate

The following must exist before Phase 0 implementation:

1. threat-modeling process;
2. secure SDLC;
3. vulnerability management;
4. incident response;
5. privileged-access governance;
6. data classification and handling;
7. cryptographic standards;
8. network security baseline;
9. backup, restore and disaster recovery;
10. supply-chain security;
11. release/change management;
12. penetration/security testing;
13. abuse and misuse response;
14. privacy, retention and deletion;
15. third-party risk management;
16. security-exception process;
17. mail-security trust/failure model;
18. security runbooks;
19. security metrics/KPIs;
20. version-control, CI/CD, artifact-provenance and release controls;
21. application-security invariants including ownership, validation, RLS, idempotency, OAST and safe errors;
22. compliance assurance/control mapping;
23. rate limiting and abuse protection;
24. patching and dependency-version management;
25. business-logic and policy-security invariants;
26. certificate trust/mTLS/pinning policy;
27. HMAC/webhook integrity and replay protection;
28. ML/LLM skill/tool governance, context limits and prompt-injection controls;
29. coding-agent operating rules, skill boundaries and context/token discipline.

No subsystem is exempt because it is "internal", "temporary", "development-only" or "not customer-facing".

## Security ownership

Every feature/subsystem must identify:

- security owner;
- data owner;
- trust boundaries;
- required permissions;
- secrets/keys involved;
- failure mode;
- audit requirements;
- monitoring/alerts;
- recovery procedure;
- threat-model status.

## Evidence

Security controls should produce evidence that they exist and work.

Examples:

- CI security-gate results;
- access-review records;
- dependency/SBOM records;
- vulnerability remediation history;
- audit logs;
- restore-test evidence;
- penetration-test findings;
- incident/postmortem records;
- key-rotation evidence;
- security exception approvals/expiry.

## Documents

- [Threat Modeling](01-THREAT-MODELING.md)
- [Secure SDLC and Change Control](02-SECURE-SDLC.md)
- [Vulnerability Management](03-VULNERABILITY-MANAGEMENT.md)
- [Incident Response](04-INCIDENT-RESPONSE.md)
- [Access Governance](05-ACCESS-GOVERNANCE.md)
- [Data Classification and Handling](06-DATA-CLASSIFICATION.md)
- [Cryptographic Standards](07-CRYPTOGRAPHIC-STANDARDS.md)
- [Network Security Baseline](08-NETWORK-SECURITY-BASELINE.md)
- [Backup, Restore and Disaster Recovery](09-BACKUP-DR.md)
- [Supply Chain Security](10-SUPPLY-CHAIN-SECURITY.md)
- [Security Testing and Penetration Testing](11-SECURITY-TESTING.md)
- [Abuse and Misuse Response](12-ABUSE-RESPONSE.md)
- [Third-Party Risk and Security Exceptions](13-THIRD-PARTY-AND-EXCEPTIONS.md)
- [Mail Security Trust and Failure Model](14-MAIL-TRUST-FAILURE-MODEL.md)
- [Security Runbooks](15-SECURITY-RUNBOOKS.md)
- [Security Metrics](16-SECURITY-METRICS.md)
- [Privacy, Retention and Deletion](17-PRIVACY-RETENTION-DELETION.md)
- [Security Governance and Risk Ownership](18-SECURITY-GOVERNANCE.md)
- [Version Control, CI/CD and Release Security](19-VERSION-CONTROL-CICD.md)
- [Application Security Control Baseline](20-APPLICATION-SECURITY-CONTROLS.md)
- [Compliance Assurance and Control Mapping](21-COMPLIANCE-ASSURANCE.md)
- [Rate Limiting and Abuse Protection](22-RATE-LIMITING-ABUSE-PROTECTION.md)
- [Patching and Dependency Version Management](23-PATCHING-DEPENDENCY-VERSIONS.md)
- [Business Logic and Policy Security](24-BUSINESS-LOGIC-POLICY-SECURITY.md)
- [Certificate Trust, mTLS and Pinning](25-CERTIFICATE-TRUST-PINNING.md)
- [HMAC Signing and Webhook Security](26-HMAC-SIGNING-WEBHOOKS.md)
- [ML / LLM Skills and Tool Governance](../25-AI-LLM-SKILLS-TOOLS.md)
- [Coding Agent Operating Model](../ai/CODING-AGENT-OPERATING-MODEL.md)
