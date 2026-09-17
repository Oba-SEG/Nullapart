# Zero-Day Tabletop Template

Scenario example: critical remote-code-execution vulnerability announced in a parser used on hostile message attachments; patch availability initially unknown.

## Exercise objectives

- intake/triage speed;
- exposure/SBOM correlation;
- emergency kill/hold policy;
- mail-path safe degradation;
- node/workload isolation;
- emergency patch workflow;
- retrospective hunt;
- credential/key review;
- customer/compliance escalation;
- production SLO impact.

## Timeline prompts

Record decisions/evidence for:

1. intelligence received;
2. applicability UNKNOWN;
3. vulnerable version discovered in production;
4. active exploitation reported externally;
5. temporary mitigation selected;
6. backlog/queue impact grows;
7. upstream patch arrives;
8. focused security test passes/fails;
9. rollout begins;
10. retrospective indicators found/not found;
11. customer/regulatory review;
12. workaround removal.

## Findings

Capture:

- what worked;
- missing telemetry/inventory;
- unclear ownership;
- unsafe failure path;
- missing kill switch;
- missing test/runbook;
- corrective action + owner + due date.
