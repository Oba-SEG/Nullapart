# Nullapart UI Design System

## Design direction

Nullapart uses a **flat, dense enterprise-security** visual language in the
register of the Mimecast and Proofpoint admin consoles: hairline-bounded
panels on a light canvas, one restrained cool accent, no skeuomorphic depth.

Depth, glow, gradient and inset "pressed" styling are prohibited. Hierarchy
comes from typography, spacing, rules and a single tinted selection state.

Nullapart remains an operational security console and must support dense tables, long timelines, clear severity states and accessible controls.

## Principles

1. Security information is understandable at a glance.
2. Layout hierarchy is stronger than decoration.
3. Surfaces are flat: separation uses 1px rules and background steps, never shadows.
4. Text and state contrast meet accessibility requirements.
5. Keyboard/focus behaviour is first-class.
6. Important actions are never communicated by styling alone.
7. Every feature ships with its UI and tests.
8. No raw JSON in the UI.
9. Untrusted email content never inherits the trusted control-plane DOM/origin implicitly.

## Shell

Recommended desktop layout:

```text
+------------------------------------------------------------+
| Region / Deployment | Search | Alerts | User / Impersonate |
+--------------+---------------------------------------------+
|              |                                             |
| Navigation   | Page Header / Context                       |
|              |                                             |
|              | Main content                                |
|              |                                             |
+--------------+---------------------------------------------+
```

The navigation hierarchy changes according to System, Support and Customer context.

## Login

The login experience starts with deployment selection.

Example controls:

- Region: South Africa;
- Deployment: ZA — Primary.

If a region has only one deployment, redundant choice may be collapsed.

After selection, authentication is handled by the regional identity endpoint.

All administrative accounts require MFA.

## Surfaces

Use a small number of flat surface levels:

- canvas (`--color-bg-primary`);
- panel/card (`--color-bg-secondary` with a 1px `--color-border` rule);
- sub-tone for table headers, wells and read-only blocks (`--color-bg-tertiary`);
- selection tint (`--color-selected-*`) rather than elevation;
- modal/floating surface, which is the only place a shadow is permitted.

Avoid deep nested cards. No inset, raised or glowing control states.

## Operational tables

Tables remain tables.

Use a single hairline-bounded panel around the table/page, never clay-like cells.

Required behaviours:

- sticky headers where useful;
- column controls;
- filtering;
- pagination/virtualization;
- clear sorting;
- selectable rows;
- keyboard access;
- responsive detail drawer/page;
- export only where permission permits.

## Severity

Security severity must combine:

- text;
- icon;
- accessible contrast;
- optional color.

Do not rely only on red/amber/green.

## Message trace

Use a vertical timeline with:

- timestamp;
- normalized event label;
- state;
- duration where useful;
- expandable permitted detail;
- node detail only for authorized support/system views.

Do not show backend engine names in customer-facing trace labels.

For multi-tenant SMTP transactions, a Customer Admin sees only that customer's Tenant Message Instance. Cross-tenant recipient information is not shown.

## Full message view

### System Admin

Tabs may include:

- Overview;
- Trace;
- Headers;
- Content;
- Attachments;
- Security;
- Policy;
- Delivery;
- Remediation.

Opening full content, raw MIME, sensitive headers or attachments is audited.

### Support

Do not render body, raw MIME or attachment content. Support gets operational/derived data appropriate to role.

Direct artifact/download URLs must enforce the same backend restriction; hiding a Content tab is insufficient.

### Customer Admin

Tabs/actions are determined by customer RBAC.

## Hostile email rendering

All received message content is untrusted.

### HTML message body

The trusted Nullapart DOM must never directly execute received HTML.

Use:

- strict sanitization;
- sandboxed iframe and/or dedicated untrusted rendering origin;
- no scripts/event handlers/forms;
- remote resources blocked by default;
- restrictive CSP;
- no access to Nullapart cookies/storage/parent DOM.

Remote content is only loaded after an explicit privacy warning because loading it can disclose that the message was viewed.

### Plain text and raw data

Plain text, headers and raw MIME are escaped and displayed as text rather than interpreted markup.

### Attachments

Attachment preview/download uses an authenticated, permission-checked artifact path with short-lived authorization and safe content-disposition.

A separate artifact/download origin without control-plane session cookies is preferred.

The UI shows security state before preview/download and warns for risky file types.

See [Secure Message Rendering and Artifact Access](19-SECURE-MESSAGE-RENDERING.md).

## Client validation and authentication storage

Client-side validation provides immediate usable feedback but is never authoritative.

Every validation/security/business rule that affects acceptance or mutation is repeated/enforced by the backend and, where appropriate, database constraints.

The UI must:

- show server validation errors next to the relevant field/action;
- preserve stable product error codes/correlation IDs for supportability;
- never display raw stack traces/database errors;
- never assume hiding a control is authorization;
- never store authentication or refresh tokens in Local Storage/Session Storage;
- use the approved secure session/cookie architecture;
- avoid persisting sensitive message content in browser storage/caches beyond what is strictly necessary.

## Policy editor

Policies use guided forms, toggles, ranges, selectors and rule builders.

No JSON editor.

Every control shows:

- effective level (Customer/Support/System where permitted);
- inherited/default state;
- validation;
- consequence/help text.

## Impersonation

Impersonation displays a persistent visually distinct banner with:

- real actor;
- impersonated customer/admin;
- reason;
- exit action.

It must be impossible to confuse an impersonated session with the operator's normal session.

## Administrative Audit UI

Administrative audit is a dedicated product surface, not a raw log viewer.

### Navigation

Suggested placement:

- System Admin: `System → Audit Log`;
- Support: `Operations → Audit Log`;
- Customer Admin: `Administration → Audit Log`.

### Primary view

Use a dense operational table with:

- timestamp;
- actor;
- Acting As / impersonated subject;
- customer;
- action;
- resource;
- result;
- source IP;
- reason;
- trace ID.

Columns are permission/context aware.

### Filtering

Provide role-appropriate filters for:

- date/time;
- actor;
- customer ID;
- action category;
- resource type;
- result;
- impersonation;
- source IP;
- trace ID;
- high-risk actions.

### Detail view

Selecting an event opens a flat detail drawer/page showing:

- actor and role;
- impersonation chain;
- customer;
- source/session context;
- authorization context;
- affected resource;
- safe before/after values;
- reason;
- outcome;
- correlated trace/event IDs.

No raw JSON is shown.

### Permissions

Support audit views must never reveal message body, raw MIME or attachment content.

Customer audit views remain tenant/RBAC scoped.

Audit exports are permission-controlled and the export action is itself audited.

## System/Support operations

Operational views should include:

- deployment health;
- mail nodes;
- scanner nodes;
- stable/logical node ID;
- current hostname/IP/AWS runtime identity;
- version;
- loaded config revision;
- queue/latency;
- SQS/outbox/DLQ status;
- SMTP commissioning status for public mail nodes;
- status;
- manual refresh where authorized.

## DMARC/BIMI

Use:

- metric cards sparingly;
- trend charts;
- source tables;
- domain-security status;
- external report authorization status;
- BIMI enforcement/readiness status;
- drill-down views;
- human-readable explanations.

Never display raw report XML as the normal user experience.

Failure-report content follows the same hostile-content and RBAC controls as other message samples.

## Accessibility

Required from the beginning:

- keyboard navigation;
- visible focus;
- screen-reader labels;
- appropriate contrast;
- reduced-motion support;
- clear error messaging;
- non-color status signals;
- sensible zoom/responsive behaviour.

## Testing

Every UI-bearing feature includes:

- component tests;
- permission-state tests;
- loading/empty/error tests;
- keyboard/accessibility checks;
- role visibility tests;
- cross-tenant isolation tests;
- hostile-content rendering/XSS tests for message views;
- critical workflow E2E coverage.
