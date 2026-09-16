# AWS SMTP Deployment Commissioning

**Status:** mandatory deployment checklist for each new Nullapart mail deployment.

## Why this exists

A regional deployment is not ready for production SMTP merely because Postfix starts successfully.

AWS EC2 restricts public outbound SMTP port 25 by default, and production mail reputation depends on stable IP identity, forward/reverse DNS and authentication.

Every deployment such as `ZA`, `ZAB`, `EU`, `UK` and `US` must complete a repeatable SMTP commissioning process.

## Outbound IP identity

Internet-facing outbound SMTP nodes require stable public addresses.

Use planned Elastic IP addresses or an equivalent stable AWS egress design that permits per-node/reputation identity and reverse DNS.

Record for every public SMTP identity:

- deployment;
- node hostname;
- public IP;
- Elastic IP allocation ID where applicable;
- PTR/rDNS hostname;
- forward DNS hostname;
- HELO/EHLO identity;
- role: inbound/outbound;
- commissioning status;
- reputation/warm-up status.

## Port 25 restriction

Before direct-to-MX production sending:

- verify AWS outbound port 25 status in the region/account;
- submit the required AWS request to remove public port 25 restrictions;
- test IPv4/IPv6 behaviour actually used by the deployment;
- document approval/commissioning evidence.

Do not route production direct-to-MX delivery through an unapproved workaround.

## Forward and reverse DNS

For every outbound SMTP public IP:

1. create the forward `A`/`AAAA` record as appropriate;
2. configure PTR/reverse DNS to the intended mail hostname;
3. verify forward-confirmed reverse DNS;
4. make the Postfix HELO/EHLO identity match the commissioned hostname policy.

Example:

```text
203.0.113.10
  PTR -> mxout-za-a-01.nullapart.com

mxout-za-a-01.nullapart.com
  A -> 203.0.113.10
```

Exact public naming may use the regional mail-DNS pattern chosen for production, but the relationship must remain deliberate and stable.

## Domain authentication

Commission the Nullapart infrastructure domains used for platform-generated mail and test traffic with:

- SPF;
- DKIM;
- DMARC;
- ARC where applicable to forwarding/authenticated-chain behaviour;
- TLS certificates;
- MTA-STS/TLS-RPT where selected.

Customer outbound signing remains customer/domain specific.

## Inbound DNS

Commission:

- MX records/priorities;
- public inbound addresses/load-balancing design;
- TLS certificate coverage;
- health/failover behaviour;
- firewall/security-group rules;
- abuse-rate controls.

SMTP is not ordinary HTTP and must not be put behind a load balancer that changes required SMTP semantics unless that design is explicitly validated.

## Reputation warm-up

New outbound IPs must not immediately send unrestricted production bulk volume.

Implement a reputation/warm-up process covering:

- gradual volume;
- bounce monitoring;
- complaint/abuse monitoring where signals exist;
- blocklist monitoring;
- destination-domain failure rates;
- rate shaping;
- emergency pause.

## Operational contacts

Maintain regional:

- postmaster contact;
- abuse contact;
- AWS account/support ownership;
- escalation route for port-25/rDNS issues.

## Pre-production tests

At minimum validate:

- inbound SMTP from external networks;
- STARTTLS;
- recipient validation;
- greylisting behaviour;
- SMTP reject/defer codes;
- durable queueing;
- after-queue scanning/reinjection;
- outbound direct MX;
- PTR/forward DNS;
- SPF/DKIM/DMARC;
- downstream temporary/permanent failures;
- queue retry;
- NDR/DSN handling;
- smart-host fallback where configured;
- failover between SMTP nodes.

## Deployment gate

A deployment cannot be marked SMTP production-ready until these checks are complete and recorded in the System Admin operations view/audit trail.
