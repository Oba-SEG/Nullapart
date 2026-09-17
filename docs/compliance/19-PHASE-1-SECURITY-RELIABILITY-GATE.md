# Phase 1 Security and Reliability Test Gate

**Status:** mandatory test matrix before Phase 1 production readiness.

## SMTP/security tests

### Open relay

- [ ] External attempt to relay through inbound SMTP fails
- [ ] `mynetworks` does not include public ranges
- [ ] `smtpd_relay_restrictions` rejects unauthorized destinations
- [ ] Reinjection listener rejects relay from non-localhost sources

### Unauthorized outbound source

- [ ] Outbound delivery only accepted from private trusted paths (127.0.0.1)
- [ ] No generic public relay API exists
- [ ] Connector identity authorization is enforced

### Forged trusted headers

- [ ] Internet-supplied `Authentication-Results` headers are ignored for security decisions
- [ ] Nullapart generates its own SPF/DKIM/DMARC evidence
- [ ] Untrusted headers are preserved as evidence but distinguished from trusted observations

### SMTP protocol edge cases

- [ ] Oversized message rejection (552) works correctly
- [ ] Recipient limit (503) enforced
- [ ] HELO restrictions reject invalid/non-FQDN hostnames
- [ ] STARTTLS behavior is correct (offer, not require for Phase 1)
- [ ] Connection rate limits enforced

### Greylisting/rate limiting

- [ ] Rate limit response uses correct SMTP temporary codes (452)
- [ ] Rate limit key isolation: different IPs/customers have independent limits
- [ ] Redis outage causes fail-closed behavior, not unlimited bypass

## Responsibility/durability tests

### Mail Core unavailable after SMTP acceptance

- [ ] Postfix retains queued message when Mail Core is down
- [ ] Message reprocessed after Mail Core recovers
- [ ] No accepted mail is lost

### Postfix restart with queued mail

- [ ] Queue survives Postfix restart
- [ ] Queued messages reprocessed after restart
- [ ] Queue IDs remain consistent

### Disk/queue pressure

- [ ] Message size limit enforced at SMTP level
- [ ] Queue depth monitoring exists
- [ ] Backpressure applied before spool exhaustion

### Reinjection unavailable

- [ ] Deferred when reinjection endpoint is down
- [ ] Retry follows backoff schedule
- [ ] No mail lost during reinjection outage

### Downstream delivery failures

- [ ] 4xx transient failure triggers retry with backoff
- [ ] 5xx permanent failure triggers bounce
- [ ] DSN/NDR generated correctly
- [ ] Delivery attempt tracking records all attempts

### DNS failure

- [ ] DNS resolution failure during delivery causes deferral
- [ ] Retry after DNS recovery

### Duplicate internal handoff

- [ ] Duplicate handoff creates idempotent transaction
- [ ] No duplicate delivery attempts

## Tenant isolation tests

### Multi-RCPT cross-tenant transaction

- [ ] One DATA transaction with recipients in two tenants partitions correctly
- [ ] Each tenant sees only their recipients
- [ ] Shared MIME/auth evidence is reused safely

### Per-tenant policy isolation

- [ ] One tenant quarantined/blocked while another is allowed
- [ ] Tenant A policy does not affect Tenant B delivery
- [ ] Feature overrides scoped per tenant

### Cross-tenant data isolation

- [ ] No cross-tenant recipient leakage in API responses
- [ ] No cross-tenant trace/API leakage
- [ ] Wrong-tenant ID lookups return empty/error
- [ ] RLS policies block cross-tenant queries (requires PostgreSQL)

## Reliability tests

### Tier-3 SLI instrumentation

- [ ] SMTP acceptance availability metric exists
- [ ] Accepted-message durability metric exists
- [ ] Queue age/backlog metrics exist
- [ ] Mail Core processing latency metric exists
- [ ] Reinjection/delivery failure metrics exist
- [ ] Downstream delivery latency metric exists

### Burn-rate alert inputs

- [ ] Burn-rate input metrics exist for SLO breach detection
- [ ] Multi-window alert configuration defined
- [ ] Alert runbook links exist

### Dependency failure resilience

- [ ] PostgreSQL failure: accepted mail retained in Postfix queue
- [ ] Redis failure: rate limiting fails closed, not open
- [ ] S3 failure: artifact operations fail gracefully
- [ ] Scanner failure: unknown/error result treated as HOLD, not CLEAN

## Commissioning evidence

### Pre-production tests completed

- [ ] Inbound SMTP from external networks
- [ ] STARTTLS
- [ ] Recipient validation
- [ ] SMTP reject/defer codes
- [ ] Durable queueing
- [ ] After-queue scanning/reinjection
- [ ] Outbound direct MX
- [ ] PTR/forward DNS
- [ ] SPF/DKIM/DMARC
- [ ] Downstream temporary/permanent failures
- [ ] Queue retry
- [ ] NDR/DSN handling
- [ ] Failover between SMTP nodes

## Sign-off

| Test category | Status | Evidence |
|---|---|---|
| SMTP/security | | |
| Responsibility/durability | | |
| Tenant isolation | | |
| Reliability | | |
| Commissioning | | |

Each category requires passing status and evidence before Phase 1 can be marked production-ready.
