# Threat Modeling

## Requirement

Threat modeling is mandatory before implementation of a new subsystem, trust boundary, external integration or high-risk feature.

Update the threat model when:

- data flow changes;
- a new public/internal endpoint is added;
- a new third-party integration is introduced;
- authorization changes;
- message content becomes newly accessible;
- new AI/tool execution is added;
- new storage/region/cross-region behaviour is introduced;
- a security incident reveals an unmodeled threat.

## Method

Use STRIDE or an equivalent structured method, supplemented by email-security abuse cases.

For every subsystem document:

- assets;
- actors;
- trust boundaries;
- entry points;
- privileged operations;
- data classes;
- dependencies;
- abuse cases;
- threats;
- mitigations;
- detection;
- residual risk;
- security owner.

## Mandatory abuse cases

At minimum consider:

- tenant breakout;
- cross-tenant recipient leakage;
- forged Authentication-Results/X-OriginatorOrg;
- relay abuse;
- mail-loop creation;
- SMTP backscatter;
- queue exhaustion;
- archive/decompression bombs;
- parser RCE;
- SSRF through URL scanners/previews;
- stored XSS through email HTML/SVG;
- privilege escalation;
- impersonation misuse;
- secret theft;
- poisoned policy/config cache;
- audit-log tampering;
- S3 artifact exposure;
- compromised scanner node;
- compromised admin account;
- compromised customer connector;
- malicious outbound customer;
- prompt injection/model-tool abuse;
- training-data poisoning;
- regional data leakage;
- observability/log leakage.

## Approval

Threat model must be reviewed before a feature leaves design.

Critical/high residual risks require an explicit mitigation or approved time-limited security exception.

Threat models are version-controlled with the relevant architecture/component.
