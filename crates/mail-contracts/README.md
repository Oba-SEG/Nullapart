# mail-contracts

Future Rust contracts shared by Mail Core and scanner adapters.

Planned contracts include:

- SMTP Transaction;
- Tenant Message Instance;
- transaction/tenant-message/trace/Postfix queue identities;
- artifact references;
- SecurityFinding with transaction-vs-tenant scope;
- scanner result/status/resource-limit reason;
- policy disposition;
- delivery attempt/downstream SMTP result;
- stable node identity + observed runtime identity/IP;
- durable event envelope;
- idempotency metadata.

One SMTP transaction may map to multiple customer-scoped Tenant Message Instances. Contracts must not assume one accepted `DATA` transaction equals one customer.

See `docs/18-MESSAGE-TRANSACTION-CONTRACT.md`.
