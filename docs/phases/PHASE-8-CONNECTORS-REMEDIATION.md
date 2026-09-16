# Phase 8 — Connectors and Remediation

## Objective

Add explicitly scoped customer directory/mailbox integrations for directory intelligence and post-delivery remediation.

## Prerequisites

- Control Plane/RBAC stable;
- notification/remediation state model stable;
- secrets/OAuth handling mature;
- audit operational;
- data classification/residency rules enforced.

## Initial providers

Prioritize:

- Microsoft 365;
- Google Workspace.

Optional IMAP/POP is System-controlled and disabled by default.

## Connector capability model

Capabilities are explicit and independently grantable:

- directory sync;
- mailbox search;
- retro remediation.

Do not grant broad mailbox permissions when only directory sync is required.

## OAuth/credentials

Use:

- least privilege;
- regional encrypted secret storage;
- token rotation/refresh;
- revocation;
- tenant association;
- audit;
- provider-specific security recommendations.

Never expose provider refresh/access tokens to UI/logs.

## Directory sync

Use for:

- address validation;
- groups;
- aliases;
- VIP candidate enrichment where appropriate.

Initial VIP management remains manually controlled unless explicitly changed.

## Mailbox search

Search only when:

- authorized capability exists;
- customer/tenant scope matches;
- security case/remediation purpose is valid;
- action is audited.

## Retro remediation

For post-delivery threat:

1. identify eligible delivered item;
2. search provider mailbox;
3. confirm matching identity;
4. move/delete/quarantine according to provider capability/policy;
5. persist outcome;
6. notify customer where required.

States include PENDING/SUCCEEDED/FAILED/MANUAL_ACTION_REQUIRED.

## IMAP/POP

Platform-level System flag controls availability.

If enabled:

- least privilege;
- dedicated regional storage if content must be retained;
- encryption;
- retention;
- audit;
- quotas;
- deletion;
- no default customer self-enable beyond System policy.

## UI

Build:

- connector setup/status;
- granted capabilities;
- last sync;
- auth expiry/failure;
- directory status;
- remediation history;
- remediation errors;
- capability changes.

Customer roles can manage only allowed capabilities.

## Failure semantics

Connector outage never rewrites original delivery history.

If remediation fails:

- message remains historically DELIVERED;
- remediation state records failure;
- customer/internal notification occurs;
- manual action may be required.

## Security tests

- OAuth token leakage;
- wrong-tenant connector binding;
- over-scoped permissions;
- cross-mailbox search;
- remediation wrong-message match;
- expired/revoked token;
- provider outage;
- malicious mailbox content;
- webhook spoofing if used.

## Exit criteria

- least-privilege scopes verified;
- directory sync tenant-safe;
- mailbox search/remediation audited;
- post-delivery state truthful;
- connector failure safe;
- customer UI accurately shows capabilities/status;
- secrets never leak into UI/observability.

## Not in this phase

- generic integration marketplace;
- public customer API;
- arbitrary third-party workflow execution.
