# Nullapart UI Design System

## Design direction

Nullapart uses a carefully controlled **neumorphic / soft-interface** visual language.

Neumorphism is the shell and interaction language, not an excuse to reduce readability.

Nullapart remains an operational security console and must support dense tables, long timelines, clear severity states and accessible controls.

## Principles

1. Security information is understandable at a glance.
2. Layout hierarchy is stronger than decoration.
3. Neumorphic depth is restrained and consistent.
4. Text and state contrast meet accessibility requirements.
5. Keyboard/focus behaviour is first-class.
6. Important actions are never communicated by shadow alone.
7. Every feature ships with its UI and tests.
8. No raw JSON in the UI.

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

## Surfaces

Use a small number of elevation levels:

- base canvas;
- raised panel/card;
- pressed/inset control;
- modal/floating critical surface.

Avoid deep nested cards.

## Operational tables

Tables remain tables.

Use neumorphic framing around the table/page, not individual clay-like cells.

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

Do not show backend engine names in customer/product-facing trace labels.

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

### Support

Do not render body/attachment content. Support gets operational/derived data appropriate to role.

### Customer Admin

Tabs/actions are determined by customer RBAC.

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

## System/Support operations

Operational views should include:

- deployment health;
- mail nodes;
- scanner nodes;
- unique hostname/IP;
- version;
- loaded config revision;
- queue/latency;
- status;
- manual refresh where authorized.

## DMARC/BIMI

Use:

- metric cards sparingly;
- trend charts;
- source tables;
- domain-security status;
- drill-down views;
- human-readable explanations.

Never display raw report XML as the normal user experience.

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
- critical workflow E2E coverage.
