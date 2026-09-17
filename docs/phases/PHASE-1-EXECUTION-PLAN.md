# Phase 1 Execution Plan — SMTP and Mail Foundation

**Status:** execution plan. Implementation work is blocked until Phase 0 exit criteria are satisfied.

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

No generic public relay API.

## Work package 10 — Trace and operations UI

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

1. mail-node runtime contract;
2. Postfix baseline + test harness;
3. reinjection listener/loop prevention;
4. Rspamd bounded Milter;
5. Mail Core after-queue receiver;
6. transaction + tenant partitioning;
7. trusted auth evidence;
8. baseline policy/reason codes;
9. reinjection/delivery tracking;
10. outbound intake/routing;
11. trace/operations UI;
12. AWS SMTP commissioning;
13. full Phase 1 security/reliability gate.

## Definition of Phase 1 done

Phase 1 is complete only when:

- inbound and outbound mail work end-to-end;
- no open relay exists;
- accepted mail is durable across downstream processing outages;
- transaction/tenant partitioning is correct;
- trusted authentication observations are generated internally;
- reinjection cannot loop or be publicly abused;
- downstream retry/DSN behavior is correct;
- tenant-safe trace UI exists;
- Tier-3 operational metrics/alerts are present;
- SMTP commissioning is repeatable from documented evidence;
- all mandatory security tests pass.
