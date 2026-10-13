# Nullapart Compliance Documentation

**Status:** governance/evidence structure. This directory does not assert certification.

## Purpose

Compliance documentation converts technical/security controls into reviewable evidence and accountability.

Nullapart must not claim certification or legal compliance merely because a technical control exists.

The applicable legal/regulatory/framework scope is determined by qualified business/legal/compliance owners for each region/customer context.

## Core registers

- [Compliance Scope and Applicability](00-COMPLIANCE-SCOPE.md)
- [Control Register](01-CONTROL-REGISTER.md)
- [Evidence Catalog](02-EVIDENCE-CATALOG.md)
- [Data Processing Register](03-DATA-PROCESSING-REGISTER.md)
- [Third-Party / Subprocessor Register](04-THIRD-PARTY-REGISTER.md)
- [Risk and Security Exception Register](05-RISK-EXCEPTION-REGISTER.md)
- [Production Readiness Evidence](06-PRODUCTION-READINESS-EVIDENCE.md)

## Engineering / operational evidence templates

- [Main Branch Protection Evidence](07-MAIN-BRANCH-PROTECTION-EVIDENCE.md)
- [Tier-3 Reliability / SLO Evidence](08-TIER3-SLO-EVIDENCE.md)
- [Zero-Day Response Evidence](09-ZERO-DAY-RESPONSE-EVIDENCE.md)
- [Coding-Agent Instruction Evidence](10-AGENT-INSTRUCTION-EVIDENCE.md)
- [Tenant Routing / Feature Override Evidence](11-TENANT-ROUTING-FEATURE-OVERRIDE-EVIDENCE.md)
- [Implementation Gate Status](12-IMPLEMENTATION-GATE-STATUS.md)
- [Branch Protection Activation Runbook](13-BRANCH-PROTECTION-ACTIVATION-RUNBOOK.md)
- [Agent Discovery Verification](14-AGENT-DISCOVERY-VERIFICATION.md)
- [Zero-Day Tabletop Template](15-ZERO-DAY-TABLETOP-TEMPLATE.md)
- [Open Gate Actions](16-OPEN-GATE-ACTIONS.md)
- [Repository Administrator Handoff](17-REPO-ADMIN-HANDOFF.md)

These templates distinguish documented design from controls that are actually operating.

Current Phase 0/1 conformance reconciliation:
[2026-10-13 Phase 0/1 Authoritative Conformance Review](../reviews/2026-10-13-phase-0-1-conformance.md).

## Operating model

For every control:

1. define control objective;
2. identify system/region scope;
3. identify owner;
4. implement;
5. identify evidence;
6. define test/review cadence;
7. track findings/exceptions;
8. map to applicable requirements only after applicability is reviewed.

A document marked `TBD`/template is not proof of operation.

## Potential future mappings

Depending on actual business/legal scope, the control register may later map to requirements/frameworks such as:

- South African privacy/data-protection requirements;
- EU GDPR;
- UK GDPR/Data Protection requirements;
- ISO/IEC 27001;
- SOC 2 Trust Services Criteria;
- contractual/customer security requirements.

These are not current certification claims.

## Evidence protection

Compliance/security evidence can itself be sensitive.

Access is role-controlled and evidence must not contain unnecessary:

- message body/raw MIME;
- customer secrets;
- passwords/tokens;
- private keys;
- unrestricted infrastructure credentials.

## Change management

Architecture changes involving data location, encryption, identity, audit, retention, third parties, tenant routing, reliability controls, AI data access or new regions require compliance-impact review.
