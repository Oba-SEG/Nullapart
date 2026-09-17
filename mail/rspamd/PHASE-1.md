# Phase 1 Rspamd Implementation Contract

Rspamd participates only in the bounded SMTP/Milter stage during Phase 1.

## Responsibilities

Allowed Phase 1 work:

- baseline spam/reputation evidence;
- selected DNS/RBL evidence;
- authentication-related observations;
- fuzzy/campaign evidence that fits the SMTP latency budget;
- header/message characteristics;
- greylisting integration where selected.

Rspamd does not make final customer-specific disposition decisions.

## Prohibited in SMTP hot path

Do not call or perform:

- OCR;
- recursive archive/document analysis;
- slow PDF/Office parsing;
- Deep AI;
- slow external enrichment chains;
- tenant-specific policy engines that can exceed the bounded SMTP budget.

## Trust

Internet-supplied `Authentication-Results`, `X-OriginatorOrg` or similar headers are untrusted unless validated by an explicitly trusted connector path.

Nullapart-generated authentication observations must be distinguishable from original message headers.

## Failure behavior

The Phase 1 implementation must define and test:

- Milter timeout;
- Rspamd unavailable;
- Redis/cache unavailable where used;
- DNS/RBL timeout;
- malformed message evidence.

Failure must map to documented SMTP behavior and never silently create a CLEAN security result.

## Observability

Expose at minimum:

- Milter latency p50/p95/p99;
- timeout/failure count;
- reject/defer/accept contribution;
- configuration/rules revision;
- DNS/RBL dependency failure rate.

No message body/raw MIME is sent to SegLumberjack.

See `docs/phases/PHASE-1-EXECUTION-PLAN.md`.
