# Phase 0/1 Authoritative Conformance Review

**Date:** 2026-10-13 SAST  
**Reviewer:** Codex project lead  
**Branch reviewed:** `fix/security-foundation-hardening`  
**Latest commits in scope:** `8f34087 Add phase 9 durable automation categories`, `568e8df Implement phase 9 operations hardening foundation`  
**Authority:** Phase 0 and Phase 1 remain the gating source of truth. Later phase implementation is useful evidence, but does not weaken Phase 0/1 exit criteria.

## Purpose

This review links the authoritative Phase 0/1 plans to the current repository
structure, infrastructure documents, diagrams and observed implementation
evidence. It exists to prevent a later phase or local/dev smoke test from being
mistaken for production readiness.

Status vocabulary:

- `VERIFIED_LOCAL` — checked in this repository/worktree or by a local command.
- `VERIFIED_LOCAL_DEV` — documented evidence exists for the local/dev deployment
  path on `ob1@192.168.8.4`; it is not production evidence.
- `IMPLEMENTED_UNVERIFIED` — code/config exists, but this review did not verify
  the operating path end to end.
- `PARTIAL` — implementation exists for part of the required control.
- `OPEN_PRODUCTION_GATE` — production/AWS/administrator evidence is still
  required.
- `DOC_STALE` — an older document statement no longer matches the current repo
  and must defer to this dated review until corrected.

## Authoritative plan links

- [Phase 0 — Contracts and Foundations](../phases/PHASE-0-CONTRACTS-FOUNDATIONS.md)
- [Phase 1 Execution Plan — SMTP and Mail Foundation](../phases/PHASE-1-EXECUTION-PLAN.md)
- [Phase 1 Local Implementation Plan](../phases/PHASE-1-LOCAL-IMPLEMENTATION-PLAN.md)
- [Build Roadmap](../16-BUILD-ROADMAP.md)
- [Security Requirements](../../SECURITY.md)
- [Code Standards](../engineering/CODE-STANDARDS.md)

## Architecture, infrastructure and diagram links

- SMTP/AWS: [AWS deployment](../15-AWS-DEPLOYMENT.md),
  [SMTP commissioning](../21-AWS-SMTP-COMMISSIONING.md),
  [container/network architecture](../24-CONTAINER-LOADBALANCING-NETWORK.md),
  [AWS infrastructure README](../../infrastructure/aws/README.md),
  [AWS ports registry](../../infrastructure/aws/PORTS.md),
  [Terraform baseline](../../infrastructure/aws/main.tf) and
  [mail-node bootstrap](../../infrastructure/aws/templates/mail-node-bootstrap.sh).
- Local/dev runtime: [container README](../../infrastructure/containers/README.md),
  [local development runbook](../../infrastructure/containers/LOCAL-DEVELOPMENT.md)
  and [compose.local.yml](../../compose.local.yml).
- Mail-node config: [Postfix main.cf](../../infrastructure/postfix/main.cf),
  [Postfix master.cf](../../infrastructure/postfix/master.cf),
  [Postfix header checks](../../infrastructure/postfix/header_checks_nullapart),
  [Rspamd config](../../infrastructure/rspamd/rspamd.conf) and
  [Rspamd local.d](../../infrastructure/rspamd/local.d/).
- Diagrams: [diagram index](../diagrams/README.md),
  [inbound flow](../diagrams/01-inbound-mail-flow.mmd),
  [outbound flow](../diagrams/02-outbound-mail-flow.mmd),
  [regional AWS topology](../diagrams/03-regional-aws-topology.mmd),
  [trust boundaries](../diagrams/09-trust-boundaries.mmd),
  [observability architecture](../diagrams/10-observability-architecture.mmd),
  [container/network topology](../diagrams/15-container-network-topology.mmd),
  [tenant context/feature routing](../diagrams/16-tenant-context-feature-routing.mmd)
  and [Tier-3 SLO flow](../diagrams/17-tier3-slo-burn-rate.mmd).
- Evidence registers: [implementation gate status](../compliance/12-IMPLEMENTATION-GATE-STATUS.md),
  [Phase 1 security/reliability gate](../compliance/19-PHASE-1-SECURITY-RELIABILITY-GATE.md),
  [production readiness evidence](../compliance/06-PRODUCTION-READINESS-EVIDENCE.md),
  [branch protection evidence](../compliance/07-MAIN-BRANCH-PROTECTION-EVIDENCE.md),
  [Tier-3 SLO evidence](../compliance/08-TIER3-SLO-EVIDENCE.md),
  [agent instruction evidence](../compliance/10-AGENT-INSTRUCTION-EVIDENCE.md)
  and [tenant routing/feature override evidence](../compliance/11-TENANT-ROUTING-FEATURE-OVERRIDE-EVIDENCE.md).

## Verification performed for this review

Commands run on 2026-10-13 SAST:

```text
git status --short
find docs/phases -maxdepth 1 -type f | sort
find docs/diagrams -maxdepth 1 -type f | sort
find infrastructure -maxdepth 3 -type f | sort
rg -n "COMPLETE|PARTIAL|NOT STARTED|Verified|verified|Requires AWS|pending|TBD|unchecked|\\[ \\]" docs/phases docs/compliance infrastructure docs/diagrams -g '*.md'
rg -n "mail_trace|mail-trace|QuarantineReinjectionWorker|Authentication-Results|reinjection|handoff|Postfix" crates frontend migrations docs/phases/PHASE-*-LOCAL-IMPLEMENTATION-PLAN.md scripts -g '*.rs' -g '*.tsx' -g '*.ts' -g '*.sql' -g '*.md' -g '*.sh'
rg -n "spool|EIP|PTR|mynetworks|message_size_limit|content_filter|smtpd_relay_restrictions|rspamd|milter|postfix" infrastructure docs/15-AWS-DEPLOYMENT.md docs/21-AWS-SMTP-COMMISSIONING.md docs/24-CONTAINER-LOADBALANCING-NETWORK.md docs/diagrams -g '*.md' -g '*.mmd' -g '*.cf' -g '*.sh'
postconf -c infrastructure/postfix -n
```

Observed Postfix evidence from `postconf -c infrastructure/postfix -n`:

- `message_size_limit = 52428800` is active.
- `mynetworks = 127.0.0.0/8 [::1]/128` is active in the base config.
- `smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination`
  is active.
- `content_filter = mailcore:dummy` is active.
- `smtpd_milters = inet:localhost:11332`,
  `non_smtpd_milters = inet:localhost:11332` and
  `milter_default_action = tempfail` are active.

## Phase 0 gate conformance

| Phase 0 gate | Current conformance | Evidence / linked structure | Required follow-up |
|---|---|---|---|
| Protected `main` with no direct pushes | `OPEN_PRODUCTION_GATE` | Gate is still explicitly tracked in [implementation gate status](../compliance/12-IMPLEMENTATION-GATE-STATUS.md) and [branch protection evidence](../compliance/07-MAIN-BRANCH-PROTECTION-EVIDENCE.md). | Authorized repository administrator must capture live GitHub evidence. Do not claim technically enforced branch protection until then. |
| PR CI and required checks | `PARTIAL` | CI architecture and compatibility docs exist; gate register says remediation/verification pending. | Capture green CI/SBOM/provenance evidence for the current branch. |
| Agent discovery adapters | `PARTIAL` | Root `AGENTS.md` plus adapter files are documented; gate register says exercise verification pending. | Complete and date [agent instruction evidence](../compliance/10-AGENT-INSTRUCTION-EVIDENCE.md). |
| Formatter/linter/typecheck gates | `IMPLEMENTED_UNVERIFIED` in this review | Tooling exists and prior phase reports record green runs; this review did not rerun full Rust/frontend checks. | Re-run full checks after any code changes. |
| Core contracts compile/test | `IMPLEMENTED_UNVERIFIED` in this review | Rust crates and migrations exist; prior Phase 9 evidence records full local and `.4` verification. | Do not reuse prior green test evidence after future code changes. |
| DB migrations/RLS pattern | `PARTIAL` | Migrations include FORCE RLS tables and DB-backed tests, but some evidence templates still contain `TBD`. | Fill dated RLS evidence registers for Phase 0/1 critical paths. |
| TenantContext and feature overrides | `PARTIAL` to `VERIFIED_LOCAL_DEV` by referenced later evidence | `crates/policy/src/tenant_context.rs`, feature evaluator and Phase 3/9 evidence exist. | Link exact DB/UI/API evidence in [tenant routing evidence](../compliance/11-TENANT-ROUTING-FEATURE-OVERRIDE-EVIDENCE.md). |
| API/event/scanner/config version conventions | `IMPLEMENTED_UNVERIFIED` | Contract crates and phase docs exist. | Add an explicit compatibility evidence row for current `/api/v1` routes and events. |
| Audit/outbox/artifact/idempotency contracts | `VERIFIED_LOCAL_DEV` by referenced later evidence | Admin audit, outbox, artifact store, idempotency and later phase DB tests exist. | Keep production readiness evidence separate from local/dev proof. |
| UI shell/design/session baseline | `PARTIAL` | UI shell exists, but the user has identified UX/design/actionability gaps. | UI remains a product-quality follow-up; do not count dashboard existence as admin actionability. |
| Package compatibility/lockfiles/update process | `PARTIAL` | Lockfiles and compatibility docs exist; CI/SBOM evidence remains open. | Verify frozen installs and SBOM in CI. |
| HMAC/TLS/rate-limit/security primitives | `IMPLEMENTED_UNVERIFIED` | Security docs and code primitives exist; Postfix TLS config was parsed locally by `postconf`. | Live TLS/rate-limit/security evidence remains Phase 1 gate work. |
| Infrastructure firewall/port/container baseline in IaC | `PARTIAL` | AWS/container docs and Terraform baseline exist; no production apply evidence. | AWS commissioning and security-group evidence are still open. |
| Zero-day inventory from SBOM/release metadata | `PARTIAL` | Process docs exist; Phase 9 readiness marks zero-day exercise not ready. | Produce real SBOM/release mapping evidence. |
| Reliability/SLI telemetry conventions | `VERIFIED_LOCAL_DEV` by referenced Phase 9 evidence | Phase 9 migrations/API/UI/runbook implement capability and alert definitions. | Active alert firing/runbook exercise remains production readiness work. |
| Documentation matches implementation | `PARTIAL` | This review resolves known drift, but several compliance templates still intentionally say `TBD`. | Keep this review linked from Phase 0/1 and update evidence registers as gates close. |

## Phase 1 work-package conformance

| WP | Plan item | Current conformance | Evidence / linked structure | Required follow-up |
|---|---|---|---|---|
| 1 | Mail-node runtime contract | `IMPLEMENTED_UNVERIFIED` locally; `OPEN_PRODUCTION_GATE` for AWS | `crates/mail-core/src/node.rs`, [AWS deployment](../15-AWS-DEPLOYMENT.md), [container/network topology](../diagrams/15-container-network-topology.mmd). | EC2/EIP/PTR/spool lifecycle must be commissioned and evidenced. |
| 2 | Postfix baseline | `VERIFIED_LOCAL` config parse; `OPEN_PRODUCTION_GATE` for live EC2 | `postconf -c infrastructure/postfix -n` confirmed active relay/content-filter/milter/message-size settings; see Postfix files under `infrastructure/postfix/`. | Live relay-denial, queue durability and restart evidence remain required. |
| 3 | Bounded Rspamd Milter | `IMPLEMENTED_UNVERIFIED` | `infrastructure/rspamd/rspamd.conf`, `local.d/actions.conf`, Postfix milter settings parsed by `postconf`. | Run Rspamd config/service validation and timeout/failure tests in local/dev and production-like infra. |
| 4 | After-queue Mail Core handoff | `VERIFIED_LOCAL_DEV` by Phase 2/3/5 evidence | `mailcore-filter`, `phase2_handoff`, `handoff_idempotency`, HMAC handoff evidence in local implementation plans. | Keep live Postfix handoff evidence dated and repeatable; production EC2 evidence remains open. |
| 5 | SMTP Transaction and tenant partitioning | `VERIFIED_LOCAL_DEV` by code/tests; production evidence open | `crates/mail-core/src/partition.rs`, `TenantResolver`, DB/RLS tests and trace projections. | Add a dated Phase 1 gate row for multi-recipient cross-tenant live SMTP proof. |
| 6 | Trusted authentication results | `PARTIAL` | Domain-auth telemetry now parses/stores observed SPF/DKIM/DMARC/ARC details from trusted handoff context, but Phase 1 still requires maintained protocol verification implementations. | Wire maintained SPF/DKIM/DMARC/ARC verification and prove forged Internet headers cannot become trusted protocol evidence. |
| 7 | Baseline policy and reason codes | `IMPLEMENTED_UNVERIFIED` | `crates/mail-core/src/policy.rs`, policy admin later-phase wiring and tests. | Link a Phase 1 evidence row proving trusted predicates, persisted policy loading and fail-closed behavior. |
| 8 | Reinjection and downstream delivery | `VERIFIED_LOCAL_DEV` for quarantine release/reinjection; production delivery open | `migrations/005_quarantine_reinjection.sql`, `006`, `007`, `quarantine_reinjection` worker, Phase 2/3 local evidence. | Live production-like downstream 4xx/5xx retry, DSN/NDR and failover evidence remains open. |
| 9 | Outbound foundation | `IMPLEMENTED_UNVERIFIED`; later Phase 6 evidence exists | `crates/mail-core/src/outbound.rs`, Phase 6 local/remote evidence. | Reconcile Phase 1 outbound acceptance criteria with Phase 6 evidence and capture source-auth/rate/bulk proof. |
| 10 | Trace and operations UI | `DOC_STALE` in Phase 1 execution plan; current code is beyond scaffold | `crates/mail-core/src/trace.rs`, `/api/v1/mail-trace/*`, `frontend/src/pages/Messages.tsx`, `MessageDetail.tsx`, operations API/UI. | Update Phase 1 status rows only with linked tests/evidence. UI actionability/design still needs product remediation. |
| 11 | SMTP commissioning | `OPEN_PRODUCTION_GATE` | [SMTP commissioning checklist](../21-AWS-SMTP-COMMISSIONING.md), AWS docs and diagrams. | AWS account, EC2 mail nodes, EIP/PTR/DNS/port 25/TLS/MX evidence required. |
| 12 | Security/reliability gate | `PARTIAL` | [Phase 1 security/reliability gate](../compliance/19-PHASE-1-SECURITY-RELIABILITY-GATE.md) is still mostly unchecked; Phase 9 records local/dev operations hardening evidence. | Complete the end-to-end gate matrix with dated local/dev and production evidence. |

## Diagram conformance

The diagram set covers the required logical structure:

- mail flow: inbound/outbound diagrams;
- AWS regional topology and container network topology;
- trust boundaries and tenant context;
- observability and Tier-3 SLO flow.

This review did not render Mermaid diagrams. It verified source-file presence
and linked each Phase 0/1 gate to its relevant diagram source. Any architecture
change to SMTP, tenant routing, data stores, public endpoints, scanners,
artifact access, AI boundaries or Tier-3 reliability must update the matching
`.mmd` source and this conformance link set.

## Non-negotiable current truth

1. Phase 0 is not fully closed as a production gate until branch protection,
   CI/SBOM/provenance, agent-discovery evidence and production-readiness
   evidence are captured.
2. Phase 1 has substantial local/dev implementation, but production SMTP
   commissioning and the live end-to-end security/reliability matrix remain
   open.
3. Later-phase local/dev evidence can be referenced, but it cannot erase Phase
   0/1 gate requirements.
4. Compliance templates that still say `TBD` are placeholders, not evidence.
5. The Operations UI hardening from Phase 9 is local/dev readiness evidence,
   not an external compliance or production certification claim.

## Required next documentation actions

1. Fill [Phase 1 security/reliability gate](../compliance/19-PHASE-1-SECURITY-RELIABILITY-GATE.md)
   with dated evidence rows as each test is executed.
2. Fill [tenant routing/feature override evidence](../compliance/11-TENANT-ROUTING-FEATURE-OVERRIDE-EVIDENCE.md)
   from the existing DB-backed tests and live checks.
3. Attach actual branch protection screenshots/API output to
   [branch protection evidence](../compliance/07-MAIN-BRANCH-PROTECTION-EVIDENCE.md).
4. Attach current CI/SBOM/provenance output to
   [implementation gate status](../compliance/12-IMPLEMENTATION-GATE-STATUS.md)
   and [production readiness evidence](../compliance/06-PRODUCTION-READINESS-EVIDENCE.md).
5. Update the Phase 1 top status table only when the linked evidence row exists;
   do not mark local/dev evidence as production commissioning.
