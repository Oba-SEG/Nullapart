# Rate Limiting and Abuse Protection

**Status:** mandatory cross-cutting security architecture.

## Principle

Rate limiting protects availability and abuse boundaries. It is not a replacement for authentication, authorization, spam policy or capacity planning.

Limits are applied at multiple layers because no single key is sufficient.

## Web/control-plane layers

### Edge

AWS WAF / edge controls provide coarse protection such as:

- abusive source IP rates;
- obvious bot/scanner floods;
- malformed/oversized requests;
- known-bad patterns where appropriate.

Edge IP rate limits must account for legitimate shared NAT/proxy populations.

### Application

The Control Backend enforces principal-aware limits using combinations of:

- authenticated actor;
- customer ID;
- source IP;
- route/action;
- resource;
- deployment.

Do not rely only on client IP after authentication.

Trust forwarded client-IP headers only from the configured AWS load-balancer/proxy chain.

### High-risk actions

Use lower dedicated limits for:

- authentication initiation/callback abuse where application-controlled;
- impersonation start;
- role/permission changes;
- quarantine release;
- remediation;
- raw MIME/attachment download;
- audit export;
- large search/export;
- connector credential validation;
- cache/config refresh;
- security-exception changes.

## SMTP/mail layers

Rate controls may apply by:

- connecting IP;
- network/source group;
- HELO identity;
- sender;
- tenant;
- connector;
- recipient count;
- message count;
- outbound campaign/bulk status.

SMTP rate limiting must use correct temporary/permanent response semantics and must not create arbitrary non-standard reply codes.

## Implementation

Use explicit algorithms such as token bucket/sliding window/fixed window where appropriate.

Redis/Valkey can provide distributed counters, but the authoritative abuse/security event remains elsewhere.

Each limiter declares:

- key(s);
- window/refill;
- burst;
- action;
- failure behaviour;
- reason code;
- observability;
- override/exception scope.

## Failure behaviour

Limiter backend failure must be explicit.

Examples:

- ordinary low-risk read: conservative local fallback may be acceptable;
- high-risk administrative mutation: fail closed or apply a conservative local limit;
- SMTP: apply defined safe degradation/defer semantics rather than unlimited bypass.

Never silently disable all rate limiting because Redis is unavailable.

## HTTP response

Use standard HTTP status such as `429 Too Many Requests` and `Retry-After` where appropriate.

Return safe product reason codes and correlation IDs.

## Exemptions

Exemptions are:

- narrowly scoped;
- time-limited where temporary;
- auditable;
- protected from customer self-escalation.

System security floors cannot be disabled by tenant configuration.

## Monitoring

Track:

- allowed/rejected rate-limited requests;
- top keys/sources;
- limiter backend failures;
- exemption use;
- repeated high-risk action limits;
- SMTP connection/message rate controls;
- false-positive/operational impact.

## Testing

Test:

- burst behaviour;
- distributed workers;
- race/concurrency;
- wrong-tenant key collision;
- spoofed forwarded-IP headers;
- Redis outage;
- exemption abuse;
- `Retry-After`;
- IPv4/IPv6 normalization;
- SMTP temporary response behaviour;
- authenticated-user versus IP-only limiting.
