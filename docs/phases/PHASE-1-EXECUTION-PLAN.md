# Phase 1 Execution Plan — SMTP and Mail Foundation

**Status:** execution plan. Implementation work is blocked until Phase 0 exit criteria are satisfied.

**Conformance review:** [2026-10-13 Phase 0/1 Authoritative Conformance Review](../reviews/2026-10-13-phase-0-1-conformance.md).
That review is the dated reconciliation between this authoritative plan, the
current codebase, infra docs and diagrams. Local/dev implementation evidence
does not close the AWS SMTP commissioning or production security/reliability
gates until those evidence rows are explicitly recorded.

## Work package status

| WP | Name | Code status | Infrastructure status | Remaining |
|----|------|-------------|----------------------|-----------|
| 1 | Mail-node runtime contract | 🟡 Contract present | 🟡 IaC incomplete | Stable EIP/PTR/spool lifecycle still required |
| 2 | Postfix baseline | 🟡 Config present | 🟡 Not live-validated | Recipient maps, install/bootstrap and EC2 validation required |
| 3 | Bounded Rspamd Milter | 🟡 Config present | 🟡 Not live-validated | Install, evidence wiring, timeout/failure tests |
| 4 | After-queue handoff | 🟡 Adapter + authenticated endpoint present | 🟡 Not deployed | Persistence/idempotency DB integration and live Postfix exercise |
| 5 | Tenant partitioning | 🟡 Logic present | — | Persistence + live cross-tenant tests |
| 6 | Trusted auth evidence | 🟠 Types only | — | Actual SPF/DKIM/DMARC/ARC verification using maintained implementations |
| 7 | Baseline policy | 🟡 Evaluator present | — | Complete trusted predicates, persisted policy loading and failure tests |
| 8 | Reinjection + loop prevention | 🟠 Validation/types only | 🟡 Listener config present | Actual SMTP reinjection client + delivery persistence |
| 9 | Outbound intake | 🟡 Validation foundation | — | Connector authz, source policy, signing, rate/bulk and live routing |
| 10 | Trace/operations UI | 🟠 API scaffold | — | Real persistence queries, RBAC/TenantContext and React trace UI |
| 11 | SMTP commissioning | ⬜ Not started | ⬜ Requires AWS | EC2, EIP, DNS, port 25, TLS |
| 12 | Security/reliability gate | 🟠 Unit-level assertions only | — | Real Postfix/Rspamd/PostgreSQL/AWS integration evidence |

## Goal

Deliver the first safe bidirectional mail path:

```text
Internet SMTP
  -> Postfix restriction stage
  -> bounded Rspamd Milter
  -> durable Postfix queue
  -> after-queue handoff
  -> Rust Mail Core
       -> SMTP Transaction
       -> tenant-recipient partitioning
       -> baseline policy
  -> trusted Postfix reinjection
  -> downstream delivery
```

Outbound uses the same responsibility model in reverse: trusted tenant/source identification -> durable queue -> Mail Core/policy -> signing/routing -> downstream SMTP.

## Gate before implementation

Do not begin production Phase 1 code until Phase 0 confirms:

- protected `main` is active;
- PR CI and required checks are active;
- Rust workspace and core contracts exist;
- SMTP Transaction / Tenant Message types are accepted;
- safe error/reason-code contracts exist;
- tenant/deployment context exists;
- config revision/last-known-good pattern exists;
- audit/outbox contracts are usable;
- test harness foundation exists.

Architecture/spec/test-design work may proceed before the gate.

## Work package 1 — Mail-node runtime contract

**Status:** ✅ COMPLETE — `crates/mail-core/src/node.rs`

Define the deployment contract for a mail node before writing Postfix configuration.

Deliverables:

- stable node identity format;
- inbound/outbound node role;
- deployment/region identity;
- private/public interfaces;
- EIP/PTR/HELO mapping;
- queue/spool volume ownership;
- runtime configuration paths;
- OpenBao/workload identity inputs;
- health/readiness semantics;
- patch/drain lifecycle;
- metrics/log sources;
- authoritative port list.

Acceptance:

- no public SSH;
- only intended SMTP ports are public;
- queue data survives service restart/replacement according to node design;
- node identity does not depend on ephemeral private IP.

## Work package 2 — Postfix baseline

**Status:** ✅ COMPLETE — `infrastructure/postfix/main.cf`, `master.cf`, `header_checks_nullapart`

Implement a minimal hardened Postfix baseline before customer policy complexity.

### Inbound listener

Required:

- SMTP/ESMTP;
- STARTTLS;
- relay denied by default;
- recipient/domain lookup interface;
- HELO/sender/recipient restriction stages;
- connection/message/recipient resource limits;
- rate controls;
- safe logging/correlation;
- queue durability;
- explicit after-queue content-filter route.

### Reinjection listener

Separate trusted listener that:

- is private only;
- cannot relay from arbitrary sources;
- accepts only Mail Core/workload-authorized traffic;
- preserves required envelope/DSN metadata;
- adds/verifies loop-prevention state;
- does not rerun the same after-queue filtering path.

### Outbound listener/path

- accepted only from trusted connector/source paths;
- no open relay;
- stable outbound SMTP public identity;
- delivery retry/DSN semantics owned by Postfix;
- signing/routing hooks explicitly separated from customer policy evaluation.

Acceptance tests:

- external open-relay attempts fail;
- reinjection endpoint is unreachable/unauthorized from public Internet;
- accepted mail remains queued if Mail Core is unavailable;
- restart preserves queued responsibility;
- loop-prevention test cannot create a re-filter cycle.

## Work package 3 — Bounded Rspamd Milter stage

**Status:** ✅ COMPLETE — `infrastructure/rspamd/rspamd.conf`

Rspamd performs only work safe for the remote SMTP session.

Initial responsibilities:

- basic spam/reputation evidence;
- DNS/RBL evidence where selected;
- authentication-related evidence;
- fuzzy/campaign signals that meet latency budget;
- message/header characteristics;
- greylisting hooks if used in this path.

Non-responsibilities:

- document parsing;
- OCR;
- archive recursion;
- Deep AI;
- slow external enrichments;
- tenant-specific final disposition.

Define hard Milter latency/failure behavior.

Acceptance tests:

- Rspamd timeout/unavailable behavior matches documented SMTP policy;
- no slow scanner is called in the Milter path;
- forged Internet `Authentication-Results` does not become trusted evidence.

## Work package 4 — After-queue Mail Core handoff

**Status:** ✅ COMPLETE — `crates/mail-core/src/handoff.rs`, Axum endpoint

Implement the internal Postfix -> Mail Core contract.

Input must carry enough trusted context to reconstruct:

- original Postfix queue ID;
- deployment/node identity;
- envelope sender;
- accepted recipients;
- DSN/envelope metadata required for correct delivery semantics;
- connection/source facts that are safe to trust;
- trusted Rspamd/auth observations;
- raw message stream/artifact reference;
- trace identity.

The handoff endpoint is private/workload authenticated and resource bounded.

Failure semantics:

- Mail Core unavailable -> Postfix retains/defer-retries queued message;
- malformed internal handoff -> explicit failure; never silently discard accepted mail;
- duplicate handoff -> idempotent transaction creation/lookup.

## Work package 5 — SMTP Transaction and tenant partitioning

**Status:** ✅ COMPLETE — `crates/mail-core/src/partition.rs`, TenantResolver

Mail Core creates one shared SMTP Transaction and one or more Tenant Message Instances.

Required invariants:

- one DATA transaction may span multiple customers;
- shared MIME/auth/basic evidence can be reused safely;
- tenant policy/disposition remains isolated;
- no tenant sees another tenant's recipients;
- tenant message IDs are distinct from Postfix queue ID, transaction ID and RFC Message-ID.

First Phase 1 processing intentionally remains minimal:

- message identity;
- safe MIME normalization sufficient for routing/basic policy;
- trusted authentication observations;
- recipient-to-tenant resolution;
- baseline policy decision;
- reinjection/quarantine placeholder disposition interface.

Acceptance tests include multi-RCPT cross-tenant transactions.

## Work package 6 — Trusted authentication results

**Status:** 🟠 PARTIAL — trusted evidence types exist; protocol verification is not yet implemented

Implement/validate trusted authentication evidence using maintained protocol implementations.

Required:

- SPF result;
- DKIM verification result;
- DMARC alignment/result;
- ARC validation state where enabled;
- explicit trust origin.

Rules:

- remove/ignore untrusted Internet authentication-result headers for security decisions;
- preserve original headers as message content/evidence where required, but distinguish them from Nullapart-generated observations;
- do not use ML/LLM for protocol correctness.

## Work package 7 — Baseline policy and reason codes

**Status:** ✅ COMPLETE — `crates/mail-core/src/policy.rs`, PolicyRuleEvaluator

Phase 1 policy is deliberately narrow.

Initial decisions may use:

- tenant/domain lifecycle;
- sender/source authorization;
- trusted authentication evidence;
- Rspamd bounded evidence;
- rate/abuse state;
- basic allow/block rules;
- operational failure state.

Every decision returns:

- disposition;
- stable Nullapart reason code;
- effective policy revision;
- safe customer explanation;
- internal detail/evidence references.

Do not introduce full scanner/ML policy here.

## Work package 8 — Reinjection and downstream delivery

**Status:** 🟠 PARTIAL — loop/envelope validation exists; actual SMTP reinjection remains open

For each allowed Tenant Message Instance:

- construct tenant-scoped delivery envelope;
- preserve allowed message content/trace metadata;
- submit through private trusted reinjection;
- prevent filter loop;
- create delivery-attempt identity;
- record downstream SMTP result;
- preserve Postfix retry ownership.

Cross-tenant instances must be independently deliverable/dispositionable after partitioning.

## Work package 9 — Outbound foundation

**Status:** 🟡 PARTIAL — authorization/intelligence foundation in
`crates/mail-core/src/outbound.rs`; private signed-submission boundary in
`crates/mail-core/src/outbound_submission.rs`; no authenticated connector,
durable outbound queue/ledger implementation, routing worker, retry/DSN
correlation, or customer delivery path is wired yet.

Implement initial trusted outbound intake.

Required:

- source/connector identity;
- customer mapping;
- INTERNAL/SEND_ONLY domain validation;
- envelope/header sender checks;
- source-IP/connector authorization;
- Microsoft/X-OriginatorOrg used only from explicitly trusted connector paths;
- basic rate/bulk protection;
- signing hooks;
- direct-MX/smart-host routing;
- downstream retry and DSN correlation.

The private signing listener and submission helper are not a generic public
relay API and must not be treated as one. Customer-facing submission needs an
explicitly reviewed connector trust model and a durable, idempotent delivery
workflow before it can be exposed.

No generic public relay API.

## Work package 10 — Trace and operations UI

**Status:** 🟠 PARTIAL — authenticated API scaffold exists; persistence/RBAC/UI are not complete

Ship backend and UI together.

Phase 1 UI must show, under RBAC:

- search by tenant message/trace/safe identifiers;
- receipt transmission;
- Postfix queue acceptance;
- tenant partitioning;
- policy reason;
- reinjection;
- delivery attempts;
- final/downstream SMTP status;
- current mail-node version/config revision/queue health.

Support still cannot access body/raw MIME/attachments.

No raw JSON.

## Work package 11 — SMTP commissioning

**Status:** ⬜ NOT STARTED — Requires AWS account and infrastructure

For the first deployment, complete the commissioning checklist in `docs/21-AWS-SMTP-COMMISSIONING.md`.

Evidence includes:

- EIP/public addresses;
- PTR + matching forward DNS;
- HELO identity;
- AWS port-25 status;
- TLS certificate;
- MX priorities;
- SPF/DKIM/DMARC platform records;
- external inbound/outbound tests;
- queue/failover tests;
- reputation/warm-up plan.

## Work package 12 — Phase 1 security and reliability test gate

**Status:** 🟠 PARTIAL — unit-level assertions exist; they are not end-to-end security evidence
**Remaining:** Live integration tests on EC2 infrastructure

Required end-to-end matrix:

### SMTP/security

- open relay;
- unauthorized outbound source;
- forged trusted headers;
- SMTP smuggling/protocol-edge tests relevant to selected Postfix version/config;
- oversized message/recipient/resource limits;
- greylisting/rate-limit behavior;
- STARTTLS behavior;
- public reinjection attempt.

### Responsibility/durability

- Mail Core unavailable after SMTP acceptance;
- Postfix restart with queued mail;
- disk/queue pressure;
- reinjection unavailable;
- downstream 4xx retry;
- downstream 5xx final failure;
- DNS failure;
- duplicate internal handoff.

### Tenant isolation

- one transaction with recipients in two tenants;
- one tenant quarantined/blocked while another allowed;
- no cross-tenant recipient/API/trace leakage;
- wrong-tenant ID lookups;
- RLS/query isolation where applicable.

### Reliability

- Tier-3 SLI instrumentation exists for mail-critical paths;
- queue-age/backlog alarms exist;
- dependency failure does not lose accepted mail;
- burn-rate input metrics exist even if final production SLO values are still pre-production provisional.

## Implementation order

Recommended order after Phase 0 gate:

1. 🟡 mail-node runtime contract and IaC hardening;
2. 🟡 Postfix baseline + recipient maps + test harness;
3. 🟡 authenticated after-queue adapter/server integration;
4. 🟡 bounded Rspamd Milter and evidence handoff;
5. 🟡 transaction + tenant partitioning persistence;
6. 🟠 maintained SPF/DKIM/DMARC/ARC verification;
7. 🟡 baseline policy/reason codes and trusted predicates;
8. 🟠 SMTP reinjection/delivery tracking;
9. 🟡 outbound authorization/signing/routing;
10. 🟠 trace persistence/RBAC/React UI;
11. ⬜ AWS SMTP commissioning;
12. ⬜ live Phase 1 security/reliability gate.

## Definition of Phase 1 done

Phase 1 is complete only when:

- ⬜ inbound and outbound mail work end-to-end;
- ⬜ no open relay is proven by live test evidence;
- ⬜ accepted mail durability is proven across downstream outages/restarts;
- 🟡 transaction/tenant partitioning logic and persistence schema exist, live isolation evidence pending;
- 🟠 trusted authentication types exist, protocol verification implementation pending;
- 🟠 reinjection loop validation exists, actual SMTP reinjection pending;
- 🟠 downstream retry classification exists, live DSN/retry behavior pending;
- 🟠 trace API scaffold exists, tenant-safe persistence/RBAC/UI pending;
- 🟡 Tier-3 metric contracts exist, runtime alarms/evidence pending;
- ⬜ SMTP commissioning is repeatable from documented evidence;
- ⬜ all mandatory security tests pass with end-to-end evidence.

### Remaining for full Phase 1 completion

1. **AWS infrastructure** — EC2 mail nodes, EIP, DNS, port 25 request, TLS certificates
2. **Live integration testing** — Postfix + Rspamd + Mail Core running on EC2
3. **Frontend trace UI** — React pages consuming trace.rs API endpoints
4. **Wire Postfix content filter** — Connect Postfix after-queue to Mail Core handoff endpoint
5. **Wire reinjection** — Connect Mail Core reinjection to Postfix private listener
6. **End-to-end mail flow** — Send real inbound mail through the full pipeline
