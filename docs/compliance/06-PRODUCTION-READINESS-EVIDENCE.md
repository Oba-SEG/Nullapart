# Production Readiness Evidence

A deployment is not production-ready because code exists.

## Required evidence categories

### Security program

- Phase -1 accepted;
- threat models reviewed;
- security ownership assigned;
- active risks/exceptions reviewed.

### Source / CI/CD

- protected/reviewed source workflow active;
- CI gates pass;
- release version/source SHA known;
- SBOM/provenance available;
- immutable artifact digests recorded;
- production approval/deployment history recorded.

### Identity/access

- MFA enabled;
- privileged roles reviewed;
- break-glass tested/controlled;
- session security verified.

### Application security

- wrong-tenant/owner tests;
- RLS tests where used;
- server validation;
- idempotency tests;
- CSRF/token-storage tests;
- OAST/SSRF tests where relevant;
- safe error tests.

### Infrastructure/network

- firewall/port registry reviewed;
- no public database/cache/secrets/AI;
- SMTP nodes commissioned;
- egress controls;
- load-balancer/WAF config;
- patch status.

### Data/privacy

- data-processing register;
- third-party register;
- retention/deletion configuration;
- regional-residency validation.

### Audit/monitoring

- Admin Audit operational;
- immutable checkpoint;
- SegLumberjack telemetry;
- CloudWatch;
- alerting/runbooks.

### Resilience

- backup success;
- restore exercise;
- queue/failover test;
- RPO/RTO evidence.

### Vulnerability/testing

- no unresolved Critical;
- High findings resolved or approved time-limited exception;
- penetration/security test evidence as required;
- dependency/container/IaC scan results.

## Approval

Production-readiness approval records:

- deployment;
- release;
- date;
- reviewers;
- unresolved risks/exceptions;
- evidence references;
- approval decision.

This document is a template, not evidence by itself.
