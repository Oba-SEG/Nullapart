# Console UX Terminology

**Status:** mandatory for operator-facing console text. Applies to labels, headings,
descriptions, tooltips, placeholders, toasts, error messages and empty states.

## Purpose

The console leaks internal vocabulary: `mandatory`, `kill switch`, `wins at tenant
scope`, `inherit`, `step-up`, `idempotent`, `server-authorized`, `tenant-scoped`.
Operators read the console, not the architecture documents, so every internal term
either becomes an operator term or moves to secondary metadata where an expert
benefits from it.

This file is the single mapping. Copy that contradicts it is a defect.

## Rules

1. Never use an internal identifier as a primary label. Server-published
   `display_name` is the primary label; the raw key may appear as secondary
   metadata for operators who file support tickets or read audit events.
2. Enum values are rendered through a label function, never interpolated raw.
   `{customer.lifecycle}` is wrong; `lifecycleLabel(customer.lifecycle)` is right.
3. An action the operator cannot take is either absent or present with a reason.
   It is never present and silently failing.
4. Never name a mechanism the operator cannot act on. "Idempotent", "audited in the
   same transaction" and "resolved server-side" are implementation facts, not
   instructions. Say what happens and what to do instead.
5. Say "customer", never "tenant", in operator text. "Tenant" survives only inside a
   raw scope identifier that also appears in audit output.
6. Every control that can be refused, locked or that has a non-obvious consequence
   carries a tooltip. See [Tooltip coverage](#tooltip-coverage).

## Mapping

| Internal term | Operator text | Notes |
| --- | --- | --- |
| tenant | customer | Including "tenant scope" -> "Customer". |
| step-up | re-authentication | "Requires step-up" -> "Re-authenticate to continue". |
| idempotent | removed entirely | Never surface it. Retry safety is not the operator's task. |
| server-authorized | allowed for your role | |
| authorization / authorized (as decoration) | allowed, permitted, or the specific requirement | Prefer naming the requirement. |
| mandatory (feature badge) | Security floor | "Cannot be turned off." |
| kill switch (feature badge) | Emergency stop | "Holds an emergency off switch." |
| wins at {scope} scope | Set by {scope} / Follows {scope} | Name the winning scope in operator terms. |
| inherit (override value) | Follow the higher scope | |
| effective value | Currently active | Keep the column, rename the header. |
| deployment (as a scope label) | This installation | Retain "Deployment" only as the literal scope name in scope pickers. |
| deployment-defined role | Custom role | Matches the Roles workspace vocabulary. |
| catalog permission | Permission | |
| projection | removed; name the data | "Message trace", "delivery record". |
| payload | message, request, or the specific object | |
| upstream | the sending service, or the named connector | |
| outbox | Pending publication | Only where the operator can act on it. |
| revision | version | "Published version 12". |
| schema (input/output) | Expected input format | Explain the format, do not label it schema. |
| disposition | decision | "Release decision". |
| capability-level scanner result | scanner result | Engine detail stays out of the console. |
| normalized, content-safe evidence | safe metadata | Then say what is safe: headers, not body. |
| re-authorized | checked again | |
| mutation | change | |
| GUC, RLS, milter, HMAC, nonce | never in console text | Infrastructure vocabulary. |

## Fixed vocabulary

Pick one term per concept and keep it across every page.

| Concept | Term |
| --- | --- |
| Ending a session | Sign out |
| Beginning one | Sign in |
| Removing permanently | Delete |
| Taking away a grant | Remove |
| Making a value apply | Publish |
| Storing an edit | Save |
| Returning to a previous version | Roll back |
| A person who administers | Administrator |
| The customer an operator is acting as | Customer entry |

## Sentence rules

- Labels are sentence case. No all-caps body text; uppercase is for short badges
  and section eyebrows only.
- Buttons are verb plus object: "Save override", "Remove role", "Release message".
  Never "OK", "Submit", "Yes".
- Errors state what happened, why, and the next action. Never blame the operator:
  "Enter a SHA-256 digest" not "You entered an invalid digest".
- Help text adds something the label cannot fit. It never repeats the label.
- One idea per sentence. Operator text is read under pressure, at 2am, while mail is
  queueing.

## Tooltip coverage

A control needs a tooltip when at least one of these is true:

- it can be refused, and the reason is not visible on the screen;
- it is destructive or irreversible;
- it changes something another operator or a customer will observe;
- its label is a domain term with a precise definition the label cannot carry.

Tooltips state the rule, not the mechanism. "System-tier families can only be
published by a system-level role" is a rule. "The tier is resolved server-side from
your session roles" is a mechanism.

## Strings the server writes and the console echoes

An audit reason or a denial detail is copy authored by the backend, and a customer
reads it back in their own log. Write it for the caller who will read it: a
customer-level refusal says "This policy is changed by your provider", not
"This policy needs system-level access to change". The public response body stays
the generic `Permission is required`; only the recorded reason changes, and the
authorization outcome never does.

## Worked examples

Before:

> Set a bounded, reasoned override only where your role permits it. Mandatory
> security floors and emergency kill switches cannot be defeated from this
> workspace.

After:

> Overrides change how mail is treated for a customer, an installation or
> everywhere. Security floors and emergency stops cannot be turned off here.

Before:

> A release is an exceptional, tenant-scoped decision. Investigate the case before
> requesting the step-up and idempotent release operation.

After:

> Releasing a message returns it to delivery. Investigate the case first. You will
> re-authenticate and record why.
