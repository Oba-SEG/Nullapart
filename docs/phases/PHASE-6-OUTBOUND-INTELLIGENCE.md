# Phase 6 — Outbound Intelligence

## Objective

Detect compromised senders, unauthorized bulk behaviour and outbound campaigns while preserving approved legitimate sending.

## Prerequisites

- outbound mail path stable;
- customer/source/domain identity reliable;
- policy and durable-event systems operational;
- basic rate controls exist;
- notifications/audit exist.

## Approved bulk sender model

Bulk permission is tied to explicitly configured sending address/source context.

Configuration may include:

- approved sender address;
- allowed source system/connector;
- max messages/time;
- max recipients/message;
- max unique recipients/time;
- optional scheduling/region restrictions.

Approval does not bypass malware, malicious URL or compromise controls.

## Behaviour features

Maintain rolling metrics by:

- customer;
- source connector/IP;
- sender;
- sending domain;
- content/campaign fingerprint;
- recipient domain.

Signals:

- messages/minute/hour;
- recipient count;
- unique recipients;
- new-recipient percentage;
- domain distribution;
- subject/body/URL/attachment similarity;
- bounce/failure rate;
- unusual sending time;
- authentication/source changes.

## Campaign/fuzzy detection

Use suitable Rspamd fuzzy and/or Nullapart fingerprints for campaign clustering.

Do not store unnecessary full content merely to calculate similarity.

## Detection outcomes

Policy actions can include:

- allow;
- warn;
- throttle;
- defer;
- hold;
- block sender/source;
- suspend outbound capability pending review.

System security ceilings apply.

## Compromised-account response

Create:

- security event;
- customer notification;
- Support/System event;
- optional n8n/ClickUp incident;
- trace/audit linkage.

If connector credentials may be compromised, remediation/runbook linkage is required.

## UI

Build:

- outbound volume dashboard;
- sender/source behaviour;
- approved bulk senders;
- blocked/held events;
- campaign detail;
- failure/bounce trends;
- policy/action history;
- customer notification state.

Customer sees only own data.

## Alert quality

Avoid generating one incident/task per message.

Aggregate outbreaks/campaigns into coherent events with thresholds and cooldown/deduplication.

## Security tests

- malicious tenant;
- compromised sender burst;
- low-and-slow spam;
- rotating recipients;
- approved bulk sender sending malware;
- source spoofing;
- XOORG spoofing outside trusted connector;
- multi-tenant counter leakage;
- queue pressure from outbound abuse.

## Exit criteria

- legitimate approved bulk can operate within policy;
- unauthorized bulk is detected;
- compromised sender scenarios are contained;
- events are aggregated rather than noisy;
- actions are auditable;
- notifications/ClickUp are async and do not block mail;
- metrics/policies remain tenant isolated.

## Not in this phase

- mailbox retro-remediation;
- Deep AI as mandatory sender-abuse detector;
- billing/usage enforcement.
