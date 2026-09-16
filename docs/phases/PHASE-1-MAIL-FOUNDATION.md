# Phase 1 — SMTP and Mail Foundation

## Objective

Produce a robust bidirectional Secure Email Gateway mail path using Postfix + Rspamd + Rust Mail Core, without relying on advanced scanner depth or Deep AI.

At the end of this phase Nullapart must safely accept, queue, partition, evaluate basic policy and deliver mail in both directions.

## Prerequisites

- Phase 0 contracts accepted.
- SMTP Transaction/Tenant Message contract stable.
- policy snapshot/cache contract stable.
- Admin Audit/event/reason-code contracts usable.
- AWS SMTP commissioning design accepted.

## Inbound deliverables

### Postfix edge

Implement/configure:

- SMTP/ESMTP;
- STARTTLS;
- size/resource controls;
- connection/rate controls by IP/network/tenant as appropriate;
- relay restrictions;
- HELO checks;
- recipient/domain lookup;
- tenant lifecycle awareness;
- RBL/DNSBL integration where chosen;
- GeoIP/ASN evidence where applicable;
- greylisting;
- safe SMTP response catalogue.

### Rspamd Milter stage

Use only bounded SMTP-session work:

- baseline spam/reputation signals;
- auth-related evidence;
- fuzzy/campaign signals where safe;
- header/message characteristics.

Do not perform slow document/OCR/Deep-AI work before queue acceptance.

### After-queue integration

Implement and test:

- Postfix content-filter handoff;
- private/internal Mail Core endpoint;
- original envelope preservation;
- DSN metadata preservation as required;
- original queue-ID/trace correlation;
- tenant-recipient partitioning;
- trusted reinjection listener;
- authenticated/restricted reinjection;
- loop prevention.

### Authentication

Nullapart generates trusted:

- SPF;
- DKIM;
- DMARC;
- ARC validation state where applicable.

Never trust Internet-supplied `Authentication-Results`.

## Outbound deliverables

Implement:

- trusted source/connector identification;
- tenant mapping;
- INTERNAL/SEND_ONLY domain validation;
- envelope/header sender validation;
- source IP authorization;
- trusted Microsoft/X-OriginatorOrg evidence only on validated connector paths;
- basic rate/abuse limits;
- queue;
- signing/transport path;
- smart-host/direct-MX routing;
- downstream retry/DSN semantics.

Use mature standards implementations for DKIM/ARC/signing.

## Mail state and trace

Persist/show:

- connection/receipt transmission;
- queue acceptance;
- shared transaction;
- Tenant Message Instance;
- policy evaluation;
- reinjection;
- delivery attempts;
- downstream SMTP response;
- final state.

Customer views remain tenant-scoped.

## Configuration runtime

Mail Plane reads:

- local last-known-good snapshot first;
- Redis/Valkey shared cache for acceleration;
- version/revision metadata;
- refresh events through outbox/SQS path.

Normal mail must not depend on Control UI availability.

## Security testing

Mandatory tests include:

- open-relay attempts;
- cross-tenant multi-RCPT transaction;
- forged auth headers;
- backscatter scenarios;
- SMTP smuggling/protocol edge cases applicable to chosen versions/config;
- queue/reinjection loops;
- unauthorized reinjection;
- stale config;
- downstream 4xx/5xx;
- DNS failure;
- Rspamd unavailable;
- Mail Core unavailable;
- queue pressure.

## UI obligations

Build at least:

- mail trace/search foundation;
- transaction/tenant-message detail;
- normalized SMTP status;
- node/queue IDs for authorized roles;
- System/Support operational mail-node state.

Support receives no body/attachment content.

## Network / port obligations

Follow `docs/24-CONTAINER-LOADBALANCING-NETWORK.md`.

For public mail nodes:

- TCP 25 exposure is deliberate and documented;
- no public SSH;
- outbound EIP/PTR identity preserved;
- Security Groups allow only required public/private flows;
- scanner/control/data ports remain private;
- direct MX to commissioned Postfix nodes is the baseline.

If an NLB is introduced, client-IP preservation/STARTTLS/timeout/rate-limit behavior must be proven before acceptance.

## Operational evidence

Expose:

- queue depth;
- oldest queue age;
- SMTP rates;
- delivery latency;
- rejects/deferrals;
- after-queue handoff failure;
- reinjection failure;
- configuration revision/staleness.

## AWS commissioning

For first target deployment:

- stable SMTP public identity;
- port-25 approval if direct MX;
- PTR/forward DNS/HELO;
- TLS;
- SPF/DKIM/DMARC for platform mail;
- external delivery tests.

## Exit criteria

- inbound/outbound mail works end-to-end;
- accepted mail is not lost on Mail Core/scanner dependency outage;
- no relay bypass;
- tenant recipient isolation tests pass;
- trusted auth results are generated internally;
- queue/reinjection loops are impossible under tested paths;
- delivery retries/DSNs behave correctly;
- trace UI accurately represents receipt and delivery;
- SMTP production commissioning can be repeated from documentation.

## Not in this phase

- full attachment scanner fabric;
- inline ML enforcement;
- Deep AI;
- full Control Plane administration;
- DMARC report analytics;
- M365/Google remediation.
