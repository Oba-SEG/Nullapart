# mail-core

Future Rust Mail Core crate.

Responsibilities:

- consume the explicit Postfix after-queue content-filter handoff;
- create the SMTP Transaction record;
- normalize MIME and artifact references;
- coordinate shared scanner execution;
- partition recipients into customer/policy-scoped Tenant Message Instances;
- aggregate shared and tenant-specific evidence;
- invoke inline ML;
- evaluate per-tenant policy;
- produce delivery/quarantine/hold dispositions;
- emit authoritative/outbox events;
- coordinate trusted Postfix reinjection;
- preserve transaction, tenant-message, queue and trace identities.

Postfix remains the Internet-facing MTA and durable mail queue.

Mail Core may expose a narrowly scoped private SMTP/LMTP/content-filter endpoint if required by the selected Postfix after-queue integration, but it is not a public MTA and must not become an open relay.

See `docs/04-MAIL-FLOWS.md` and `docs/18-MESSAGE-TRANSACTION-CONTRACT.md`.
