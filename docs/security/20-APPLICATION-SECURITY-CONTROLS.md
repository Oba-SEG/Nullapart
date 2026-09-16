# Application Security Control Baseline

**Status:** mandatory cross-cutting engineering baseline.

These controls apply to every Nullapart HTTP/API endpoint, database access path, administrative workflow, asynchronous consumer and UI feature unless a stricter subsystem-specific rule exists.

## 1. Principal-scoped filtering

Every request/query that returns tenant/user-scoped data must derive scope from the authenticated/authorized principal.

Do not trust a client-supplied:

- customer ID;
- user ID;
- tenant ID;
- region/deployment;
- role;
- resource owner;
- permission flag

as proof of authorization.

Client filters are additional selection criteria only.

Example rule:

```text
effective query scope =
  authenticated principal
  + deployment
  + tenant/customer scope
  + resource permission
  + requested filters
```

Never:

```text
SELECT ... WHERE customer_id = request.customer_id
```

without independently proving that the authenticated principal is allowed to access that customer.

System/Support cross-customer queries require explicit platform permission and must still be scope constrained.

## 2. Object ownership / BOLA / IDOR checks

Every object read, update, delete, download or action must perform server-side ownership/authorization checks.

Examples:

- message;
- Tenant Message Instance;
- quarantine item;
- attachment;
- domain;
- policy;
- connector;
- audit record;
- notification group;
- VIP;
- DMARC source;
- remediation record.

Knowing or guessing an object ID is never authorization.

Authorization should evaluate:

- real actor;
- impersonated actor/context;
- deployment;
- customer;
- role/permission;
- resource ownership/scope;
- requested action;
- high-risk/step-up requirement.

Nested-resource endpoints must verify both parent and child ownership.

## 3. Defense-in-depth PostgreSQL Row-Level Security

PostgreSQL RLS should be used for tenant/customer-scoped control-plane tables where practical as an additional protection against application-query mistakes.

RLS is **defense in depth**, not a replacement for application authorization.

### Baseline

Tenant-scoped rows include explicit:

- deployment/region identity;
- customer ID or internal tenant key;
- resource identity.

Policies prevent the normal application database role from seeing rows outside the active authorized scope.

### Connection pooling safety

Do not place tenant identity in long-lived session variables that can leak between pooled requests.

Use transaction-scoped context such as `SET LOCAL`/equivalent patterns or narrowly designed database functions.

Every transaction resets scope automatically on completion.

### Privileged roles

Roles that can bypass RLS are limited to:

- schema migrations;
- tightly controlled maintenance;
- explicitly reviewed background/system operations.

Application request handling should not normally run with `BYPASSRLS` or table-owner privileges that defeat policies.

Consider `FORCE ROW LEVEL SECURITY` where appropriate.

### Testing

Tests must prove:

- tenant A cannot select tenant B;
- tenant A cannot update/delete tenant B;
- guessed IDs do not bypass RLS;
- Support/System allowed paths work only with explicit scope;
- connection-pool reuse cannot retain prior tenant context;
- background jobs cannot accidentally run with unrestricted tenant scope.

## 4. Client-side validation

Client validation exists for usability.

Use it for:

- required fields;
- formatting;
- ranges;
- immediate feedback;
- friendly errors.

It is never a security boundary.

An attacker can bypass or modify all browser validation.

## 5. Server-side validation

Every untrusted input is validated server-side before use.

Validate:

- type;
- length;
- allowed values;
- ranges;
- canonical form;
- relationships;
- authorization context;
- business invariants.

Prefer allowlists/enums/typed structures over denylist string checks.

Use parameterized queries/ORM bindings; never concatenate untrusted SQL.

File/URL/domain/header inputs require subsystem-specific validation.

Database constraints provide an additional invariant layer where appropriate.

## 6. Canonicalization

Validate after defining canonical representation.

Examples:

- normalized domain names;
- email addresses;
- URLs;
- IP/CIDR;
- Unicode text where security comparisons occur;
- filesystem-like names;
- MIME/content types.

Do not validate one representation and use a differently decoded/normalized value later.

## 7. Idempotency

Any operation that may be retried must define idempotency semantics.

Mandatory candidates:

- create/send notification;
- quarantine release;
- remediation;
- connector/webhook processing;
- outbox/SQS consumers;
- DMARC report ingestion;
- configuration publication;
- bulk administrative actions;
- external provider mutations.

### HTTP mutations

For retry-sensitive create/action APIs, accept/generate an idempotency key scoped to:

- authenticated principal/tenant;
- operation;
- resource;
- time/retention window.

Persist the authoritative result sufficiently to return the same outcome on legitimate retry.

An idempotency key from another tenant/principal must not collide or reveal results.

### Async/event consumers

Assume at-least-once delivery.

Consumers must record/derive an event/idempotency key before causing non-repeatable side effects.

Do not rely only on Redis for authoritative deduplication when duplicate side effects would be security/financial/operationally significant.

### External side effects

For mailbox remediation, ClickUp, notifications and other providers:

1. persist authorized intent;
2. record idempotency/correlation identity;
3. perform external action;
4. persist provider outcome;
5. safely handle unknown/timeout result without blindly repeating destructive operations.

## 8. Authentication/session storage in the browser

**Authentication credentials/tokens must not be stored in browser Local Storage.**

Also avoid storing long-lived authentication credentials in:

- `localStorage`;
- `sessionStorage`;
- IndexedDB;
- JavaScript-readable persistent storage.

Preferred browser architecture:

- server-side/BFF session where practical;
- `Secure`;
- `HttpOnly`;
- appropriate `SameSite`;
- narrowly scoped cookies;
- CSRF protection when cookie-based authentication is used.

OIDC/OAuth state/PKCE flows must follow the selected identity-provider best practice.

If a short-lived token must exist in frontend memory for a justified architecture, it remains non-persistent and the threat model must cover XSS/token theft.

Never expose refresh tokens to arbitrary JavaScript if avoidable.

## 9. CSRF

For cookie-authenticated state-changing browser requests:

- CSRF token and/or robust SameSite/origin validation;
- verify Origin/Referer as appropriate;
- state changes are never GET requests;
- high-risk operations can require step-up/reconfirmation.

CORS is not a replacement for CSRF protection.

## 10. Error handling

External/client errors must be safe and predictable.

### Client-facing response

Return:

- stable product/error code;
- suitable HTTP/SMTP status;
- safe human-readable message;
- correlation/trace ID where useful.

Do not return:

- stack trace;
- SQL/database error;
- filesystem path;
- secrets/tokens;
- internal hostnames unnecessarily;
- raw provider credentials/responses;
- security-rule internals;
- message content unless explicitly part of authorized UI content.

### Authorization errors

Avoid resource-existence leakage where it matters.

For tenant-scoped direct-object requests, `404` may be safer than distinguishing "exists but forbidden" where revealing existence is unnecessary.

Administrative audit can retain the actual deny reason internally.

### Internal diagnostics

Internal error records may include structured context such as:

- error type;
- service/node;
- trace ID;
- customer/transaction IDs where safe;
- retryability;
- upstream/provider reason sanitized.

SegLumberjack receives sanitized diagnostics.

### Panic/exception boundaries

One malformed request/message/parser result must not crash an entire service.

Rust panic boundaries/process isolation and equivalent safeguards are required where untrusted parser/native code is involved.

## 11. OAST — Out-of-Band Application Security Testing

OAST is required for components capable of causing server-side outbound interactions.

Use controlled out-of-band DNS/HTTP callbacks during authorized security testing to detect blind vulnerabilities that may not appear in normal responses.

Relevant targets include:

- URL scanners/fetchers;
- webhook/callback handling;
- XML/report parsers;
- document parsers with external references;
- image/SVG processing;
- remote-content proxies;
- connectors;
- Deep AI tools if network tools are ever introduced.

Test for:

- blind SSRF;
- XXE/external entity resolution;
- unexpected DNS resolution;
- unintended HTTP callbacks;
- unsafe redirect following;
- internal metadata/network access.

OAST infrastructure must be controlled by the authorized test process and must not contain production secrets/customer content.

Production egress controls should make unexpected OAST callbacks fail where the component has no business need for that network access.

## 12. SSRF / outbound fetch safety

Any feature that retrieves a user/message-controlled URL must define a secure fetch policy.

Controls include:

- scheme allowlist;
- DNS resolution checks;
- block loopback/link-local/private/internal ranges unless explicitly required;
- block cloud metadata endpoints;
- redirect revalidation on every hop;
- request/response size limits;
- timeout;
- no ambient credentials;
- controlled egress/proxy;
- DNS rebinding resistance;
- content-type handling.

The URL scanner should be isolated from sensitive internal networks.

## 13. Mass assignment / field allowlisting

APIs must explicitly define writable fields.

Do not deserialize arbitrary client objects directly into privileged database models.

Client input must never be able to set fields such as:

- customer owner;
- System/Support role;
- audit actor;
- tenant/deployment scope;
- verified-domain state;
- security floor;
- internal IDs;
- approval state

unless the endpoint explicitly authorizes that field/action.

## 14. Pagination / resource limits

All list/search/export endpoints require bounded:

- page size;
- result count;
- query complexity;
- time range where appropriate;
- export size.

Do not allow an ordinary customer query to become a database/resource exhaustion vector.

## 15. Concurrency / optimistic locking

Security-sensitive configuration changes should detect stale writes.

Use revision/ETag/version columns where appropriate.

A stale UI must not overwrite a newer policy/configuration silently.

## 16. Secure defaults

New configuration starts with the safer reasonable default.

Examples:

- IMAP/POP disabled;
- remote message images blocked;
- Deep AI tool use disabled unless explicitly designed;
- new external integrations no permissions until granted;
- customer security policy cannot weaken System floors;
- fail-open behaviour is never chosen silently.

## 17. Test requirements

Every resource-bearing API gets:

- unauthenticated test;
- unauthorized-role test;
- wrong-tenant/owner test;
- valid-owner test;
- malformed input test;
- boundary/range tests;
- duplicate/idempotent retry test for retryable mutations;
- safe-error test.

High-risk paths additionally get:

- RLS bypass tests;
- connection-pool tenant-context tests;
- OAST/SSRF tests where outbound interaction exists;
- mass-assignment tests;
- CSRF tests for browser mutations.

## 18. AI-agent implementation rules

AI coding agents must:

- scope every tenant/customer query from authenticated context;
- perform object ownership checks before read/write/action;
- add both client UX validation and authoritative server validation;
- use RLS as defense in depth where the table design supports it;
- add idempotency to retryable side effects;
- never store auth tokens in Local Storage;
- return safe structured errors;
- add OAST/SSRF security tests for outbound-fetch features;
- add tests proving wrong-user/wrong-tenant denial.

An AI agent must not assume middleware alone covers ownership of every nested resource.
