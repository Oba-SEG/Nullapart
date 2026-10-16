# Phase 7 Local Implementation Plan — Regional Deep AI

Status: complete for local/dev Phase 7 scope.

This plan maps the canonical Phase 7 requirements in
`docs/phases/PHASE-7-DEEP-AI.md` to the local/dev implementation. Phase 7 is
not a production GPU-capacity approval. It establishes the controlled regional
Deep-AI contract, access broker, governance records and operator surface while
keeping ordinary mail delivery independent of Deep AI availability.

## Implemented scope

- [x] Versioned skill registry:
  - migration `030_deep_ai.sql`;
  - `deep_ai_skills` keyed by deployment, skill ID and skill version;
  - seeded v1 skills for message analysis, BEC, impersonation, summaries,
    campaign correlation, false-positive review and false-negative review.
- [x] Authenticated local Control Plane API:
  - `GET /api/v1/deep-ai`;
  - `POST /api/v1/deep-ai/artifact-grants`;
  - `POST /api/v1/deep-ai/analysis-results`;
  - `POST /api/v1/deep-ai/rollback`;
  - permissions `deep-ai:view` and `deep-ai:manage`.
- [x] Local/dev OpenAI-compatible serving contract:
  - authenticated internal endpoints
    `/internal/deep-ai/v1/models` and
    `/internal/deep-ai/v1/chat/completions`;
  - workload bearer token required;
  - action/tool requests rejected by the local serving shim;
  - deterministic structured local response proves the serving API contract
    without putting Deep AI into the normal mail hot path.
- [x] Scoped artifact access broker:
  - `deep_ai_artifact_access_grants`;
  - deployment/customer RLS;
  - allowed resource/purpose/artifact classes only;
  - short-lived TTL;
  - quarantine-case eligibility check for quarantine resources;
  - audited grant creation.
- [x] Structured output validation:
  - `deep_ai_analysis_results`;
  - strict classification, attack type, severity, recommendation and validation
    states;
  - model output requires evidence references tied to the scoped grant;
  - a cited `model_release` must be an approved release of this deployment, or
    the write is rejected with `MODEL_RELEASE_NOT_APPROVED`;
  - `recorded_by` names the source of a finding (`model_runtime` or
    `administrator`). Migration `040_deep_ai_result_origin.sql` adds the checked
    column; each route sets it from the caller, never from the request body, so
    a console entry can never be replayed as model provenance. Rows written
    before the column exists stay null and are never backfilled;
  - audited result recording;
  - schema-invalid or hallucinated evidence is rejected rather than treated as
    clean.
- [x] Model release and regional capacity governance:
  - `deep_ai_model_releases` records an OpenAI-compatible serving contract;
  - `deep_ai_regional_benchmarks` records region, accelerator, context,
    throughput, failover and approval notes;
  - local/dev benchmark seed is explicitly not production ZA capacity approval.
- [x] Model/skill rollback:
  - audited rollback endpoint;
  - idempotency key required;
  - current released skill can be marked `rolled_back` to a target version;
  - approved model release can be rejected back to a named approved target.
- [x] Training governance:
  - `deep_ai_training_datasets`;
  - approved dataset version, allowed data classes, provenance, labeling,
    protected split and deletion/withdrawal process;
  - operational content access remains separate from training permission.
- [x] UI:
  - `/deep-ai`;
  - actionable skill, serving, benchmark, grant, finding and dataset surfaces;
  - short-lived artifact grant form with idempotency;
  - finding form records an administrator-issued result against one open grant,
    offering only the values and bounds the server accepts, and states in the
    operator's terms when no open grant or approved release makes a finding
    possible;
  - every finding is labelled with the server-decided origin so model output and
    administrator input are never confused;
  - no raw JSON UI.
- [x] Tests:
  - Rust unit tests for permission failure, grant validation, audited rollback,
    private serving authentication/tool denial and hallucinated evidence
    rejection;
  - ignored PostgreSQL tests for RLS fail-closed behavior, tenant isolation,
    cross-tenant write rejection, benchmark and training-governance scope;
  - Rust unit test proving a result body cannot name its own origin;
  - ignored PostgreSQL test for the `recorded_by` check constraint, including
    the null origin of pre-existing rows;
  - frontend tests for rendering, idempotent grant creation and rollback
    submission, and for recording, gating and labelling a finding.

## Non-goals preserved

- No autonomous remediation/admin action tools.
- No browser, shell, filesystem, AWS or database credentials are given to the
  model.
- No unrestricted artifact/customer history access.
- No live self-training from production mail.
- No dependency of normal mail acceptance/delivery on Deep AI availability.

## Evidence to keep current

- Local:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `pnpm --dir frontend check-all`
- Remote `.4`:
  - `SSHPASS=1234 scripts/phase7_remote_verify.sh`
  - script applies migration `030_deep_ai.sql`, rebuilds/recreates Mail Core,
    runs `postgres_deep_ai` against the tunneled remote DB, checks the
    authenticated `/api/v1/deep-ai` projection, exercises the authenticated
    CSRF/idempotency-protected rollback API, and probes the authenticated local
    OpenAI-compatible serving contract.

## Follow-up before production

- Replace the local/dev benchmark seed with a real target-region benchmark for
  every production deployment class, especially ZA.
- Move serving credentials and private-network endpoint configuration to the
  production workload identity/secrets path.
- Add production SLO/alerts in Phase 9 for Deep-AI queue health, latency,
  validation failures, tool denials and model-unavailable rates.
