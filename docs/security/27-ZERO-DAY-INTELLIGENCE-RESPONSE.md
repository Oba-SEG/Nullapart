# Zero-Day Intelligence and Emergency Vulnerability Response

**Status:** mandatory security operating process.

## Purpose

Nullapart processes hostile Internet mail and depends on security-sensitive parsers, protocol implementations, identity/secrets infrastructure and third-party packages. A newly disclosed or actively exploited vulnerability may require action before a normal CVE/CVSS/patch cycle is complete.

Zero-day handling therefore uses a dedicated fast path for intelligence intake, exposure analysis, containment, patching and retrospective investigation.

## Scope

Priority components include:

- Postfix;
- Rspamd;
- ClamAV;
- MIME/archive/image/PDF/Office parsers;
- Rust dependencies used on hostile-input paths;
- OpenSSL/TLS/crypto libraries;
- ZITADEL;
- OpenBao;
- PostgreSQL/Redis clients and servers where applicable;
- container/base OS;
- browser/frontend frameworks when exploitable through the Control Plane;
- AWS services/configuration advisories;
- model-serving/runtime stacks;
- n8n/connectors;
- CI/CD/GitHub Actions/supply-chain dependencies.

## Intelligence sources

The security owner maintains monitored sources appropriate to the deployed stack, including where relevant:

- vendor/project security advisories;
- GitHub Security Advisories / dependency alerts;
- CISA Known Exploited Vulnerabilities catalog;
- national/sector CERT advisories;
- Linux/distribution/base-image advisories;
- AWS security bulletins;
- upstream release/security mailing lists;
- trusted threat-intelligence providers;
- responsible disclosure/security researchers;
- internal exploit/crash/telemetry evidence.

Do not rely on a single advisory source.

## Intake record

Create a security case for a plausible relevant zero-day/actively exploited vulnerability.

Record:

- intake time/source;
- affected product/component;
- vulnerable versions/conditions;
- exploit prerequisites;
- public exploit/active exploitation status if known;
- Internet/hostile-content exposure;
- affected Nullapart releases/images/nodes/regions;
- potential confidentiality/integrity/availability impact;
- tenant/data impact;
- current mitigations;
- owner/incident severity;
- next review time.

## Exposure status

Use explicit states:

- `UNKNOWN` — applicability not established;
- `POTENTIALLY_AFFECTED` — vulnerable component/condition may exist;
- `AFFECTED` — exposure confirmed;
- `NOT_AFFECTED` — evidence establishes non-applicability;
- `MITIGATED` — vulnerable component may remain but exploit path is contained;
- `PATCHED` — corrected release/config deployed and verified.

Do not label a component safe merely because no exploit was observed.

## Triage priority

Treat as emergency when any of the following is plausible:

- Internet-facing remote code execution;
- authentication/authorization bypass;
- cross-tenant data access;
- parser RCE on hostile email/attachment content;
- arbitrary file read/write;
- credential/private-key extraction;
- mail relay/security-policy bypass;
- supply-chain compromise;
- active exploitation affecting a deployed dependency;
- control-plane session/account compromise.

Do not wait for a CVE identifier, finalized CVSS score or ordinary SLA clock before containment when evidence warrants action.

## Immediate containment options

Select the narrowest control that materially reduces exposure.

Examples:

- System kill switch for affected feature;
- disable vulnerable parser/preview/scanner path;
- classify affected artifact type as unscannable/hold/quarantine rather than CLEAN;
- WAF rule;
- firewall/egress restriction;
- temporary SMTP/content policy floor;
- isolate/drain affected node;
- stop deployment of vulnerable artifact digest;
- revoke vulnerable connector/tool capability;
- disable affected Deep-AI tool;
- disable risky administrative action;
- rotate/revoke credentials when compromise is possible.

Containment must be auditable and have an owner/removal condition.

A mitigation that causes uncertain security analysis must surface `UNKNOWN`/`ERROR` or an explicit hold/defer state rather than treating the content as safe.

## Emergency patch workflow

1. identify fixed or mitigated upstream version/configuration;
2. verify provenance/advisory authenticity;
3. update pinned dependency/image/action/ruleset;
4. build immutable artifact in trusted CI;
5. run focused regression/security tests;
6. test exploit/indicator reproduction where safely possible;
7. deploy to controlled non-production/canary target;
8. verify health/SLO/security behavior;
9. obtain emergency production approval;
10. roll out region/deployment by region/deployment;
11. verify running digest/version and mitigation;
12. retain evidence and remove temporary workaround only when safe.

Normal review/traceability is compressed, not discarded.

## Supply-chain zero-day

If the upstream release channel/build system/package is suspected compromised:

- do not assume upgrading to the latest release is safe;
- validate known-good provenance/signatures/checksums;
- consider pinning/reverting to a known-good artifact;
- block compromised package/action/image versions;
- review CI secrets/tokens/runner exposure;
- inspect build provenance/SBOM for affected artifacts.

## Retrospective hunt

After an exposure window is established, identify:

- affected releases/image digests;
- nodes/tasks running them;
- deployment/region/time window;
- relevant messages/artifacts processed;
- admin/API requests handled;
- crashes/anomalous parser behavior;
- suspicious outbound DNS/HTTP/OAST-like callbacks;
- authentication/privilege anomalies;
- secret/credential use;
- unusual filesystem/process/network activity where telemetry exists.

The hunt should use metadata/correlation first and access Restricted message content only under authorized incident procedures.

## Reprocessing / rescanning

When a vulnerable scanner/parser may have produced unreliable results:

- identify affected message/artifact population;
- determine whether findings can still be trusted;
- rescan with corrected tooling where useful;
- create post-delivery threat/remediation cases rather than rewriting historical delivery state;
- notify customers where required.

## Credential/session/key response

If exploit impact could expose secrets:

- revoke affected workload credentials;
- rotate OpenBao credentials/certificates;
- revoke administrative sessions if relevant;
- rotate connector OAuth/client secrets as required;
- rotate TLS/DKIM/signing/HMAC keys if exposure is plausible;
- review AWS role/session activity;
- preserve old key identifiers only as needed to validate historical evidence.

Do not rotate unrelated global keys blindly if rotation itself increases outage risk; scope from the exposure analysis.

## Customer and regulatory communication

Incident/compliance owners determine required communications based on:

- confirmed/potential customer impact;
- data classes;
- region;
- contractual obligations;
- applicable notification requirements.

Technical staff/AI agents must not independently make legal compliance conclusions.

## Intelligence-to-control automation

Automation may:

- ingest advisories;
- match SBOM/component versions;
- open security cases;
- flag affected deployments;
- recommend mitigations;
- trigger additional scanning/tests.

Automation/LLMs must not autonomously disable production mail paths, rotate production keys or deploy emergency patches without the approved emergency workflow.

## Metrics

Track:

- time from intelligence receipt to triage;
- time to establish applicability;
- time to containment;
- time to patched deployment;
- deployments/components with unknown exposure;
- emergency change failures/rollbacks;
- overdue temporary mitigations;
- retrospective hunt completion.

## Runbook requirements

Maintain executable runbooks for at least:

- hostile-content parser zero-day;
- Internet-facing Control Plane RCE/auth bypass;
- Postfix/Rspamd critical issue;
- OpenBao/ZITADEL critical issue;
- container/base-image zero-day;
- GitHub Action/build-chain compromise;
- compromised npm/crate/native dependency;
- model-serving/runtime vulnerability.

## AI-agent rules

AI agents may help correlate SBOMs, versions, advisories, tests and candidate patches.

They must not:

- declare a system unaffected without evidence;
- suppress a vulnerable dependency finding to restore CI;
- wait for CVSS/CVE when active exploitation demands containment;
- invent a security advisory/source;
- automatically deploy emergency production fixes;
- automatically rotate production secrets/keys;
- treat a disabled/unavailable security control as CLEAN;
- claim regulatory notification is or is not required without qualified review.
