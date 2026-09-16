# Mail Security Trust and Failure Model

## Purpose

Every mail-path dependency defines behaviour when unavailable, slow, stale or suspected compromised.

## Principles

- fail safely;
- never convert unknown/error into clean;
- keep remote SMTP waits bounded;
- protect queue integrity;
- preserve last-known-good configuration;
- isolate compromised components;
- distinguish optional enrichment from required controls.

## Baseline failure matrix

| Component | Failure | Baseline behaviour |
|---|---|---|
| Postfix edge | unavailable | fail over to other MX/node; sender retries |
| Rspamd before queue | unavailable | policy-defined bounded fail/defer; no silent bypass of mandatory controls |
| Mail Core | unavailable | queued mail deferred internally; accepted message retained |
| Required malware scanner | unavailable | hold/defer/quarantine by System policy; never mark clean |
| Optional reputation feed | unavailable | UNKNOWN and continue according to policy |
| Document/OCR scanner | timeout | explicit UNKNOWN/ERROR; policy decides |
| Inline ML | unavailable | deterministic scanning/policy continues if System policy permits |
| Deep AI | unavailable | ordinary mail unaffected unless explicitly held for deep analysis |
| PostgreSQL control/config | unavailable | Mail Plane uses last-known-good snapshot; changes unavailable |
| Redis/Valkey | unavailable | safe local/DB fallback where designed; no policy invention |
| SQS | unavailable | authoritative outbox accumulates; mail does not depend on async consumers |
| S3 artifact store | unavailable | artifact-dependent scanning/quarantine follows required failure policy; no masked content loss |
| OpenBao | temporary outage | valid workload credentials continue; no auth bypass |
| ZITADEL | unavailable | mail unaffected; new admin auth impaired; existing sessions follow policy |
| SegLumberjack | unavailable | telemetry degrades; authoritative audit/mail processing unaffected |
| CloudWatch | unavailable | infrastructure observability degraded; mail security unchanged |
| DNS | degraded | explicit resolver retry/cache policy |
| Threat intel | unavailable | UNKNOWN unless explicitly required |

## Compromise model

If a component is suspected compromised:

- isolate it;
- revoke workload credentials;
- stop trusting its findings;
- identify messages/actions in the exposure window;
- rescan/reprocess where possible;
- escalate under incident response.

## Stale configuration

Last-known-good snapshots include revision, creation time, max-staleness policy and integrity marker where used.

Nodes clearly report STALE status.

## Queue pressure

Define thresholds for queue depth, oldest message age, scanner backlog, disk usage and SQS/outbox backlog.

At critical thresholds, prefer SMTP deferral before exhausting storage or accepting mail that cannot be processed safely.
