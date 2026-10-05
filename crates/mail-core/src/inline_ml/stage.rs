//! Pass-2 inline ML stage: switch-gated single-scanner fabric and merge.
//!
//! The deterministic pass-1 fabric runs first and unchanged; when the
//! `inline_ml_classification` feature evaluates enabled for the message's
//! server-derived context, this stage runs ONE optional-enrichment scanner
//! over the same verified artifact snapshot and merges its outcomes into
//! the pass-1 result before policy evaluation
//! (`docs/phases/PHASE-4-LOCAL-IMPLEMENTATION-PLAN.md`, design decision 2).

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use nullapart_mail_contracts::{transaction::DeploymentId, FeatureId};
use nullapart_scanner_sdk::trait_defs::{ScanContent, Scanner, ScannerId};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::adapter::{inline_ml_params, InlineMlScanner, INLINE_ML_SCANNER_ID};
use super::runtime::{
    InlineMlRuntimeConfig, InlineModelRuntime, OrtModelRuntime, UnavailableRuntime,
};
use super::switch::FeatureSwitchResolver;
use super::thresholds::MlThresholdResolver;
use crate::scanner_fabric::{
    ScanArtifact, ScannerFabric, ScannerFabricConfig, ScannerFabricResult, ScannerProfile,
    ScannerRegistration, ScannerRequirement, ScannerResourceLimits,
};
use crate::scanner_pipeline::TenantScanContext;

/// Server-authoritative feature that gates the stage
/// (`migrations/014_policy_administration.sql` seed).
pub const INLINE_ML_FEATURE_ID: &str = "inline_ml_classification";

/// Reviewed wall-clock budget for one inline ML stage run. Covers
/// representation build, tokenization and CPU inference against the
/// measured p95 (~70 ms) with bounded headroom.
pub const INLINE_ML_STAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

/// Artifact byte bound for the stage, matching the pipeline preflight cap.
pub const INLINE_ML_STAGE_MAX_INPUT: u64 = 50 * 1024 * 1024;

const ACTIVE_REGISTRY_DIGEST_SQL: &str = "SELECT artifact_sha256 FROM inline_ml_models \
     WHERE deployment_id = $1 AND model_id = $2 AND model_version = $3 \
       AND approval_state = 'approved' \
       AND activated_at IS NOT NULL AND deactivated_at IS NULL";

/// Second-pass execution unit: one optional-enrichment registration plus
/// the server-authoritative feature switch for the same capability.
pub struct InlineMlStage {
    fabric: ScannerFabric,
    switches: FeatureSwitchResolver,
    thresholds: MlThresholdResolver,
    feature_id: FeatureId,
}

impl InlineMlStage {
    /// Build the stage around an explicit runtime (production or test).
    pub fn with_runtime(
        pool: PgPool,
        runtime: Arc<dyn InlineModelRuntime>,
    ) -> Result<Self, crate::scanner_fabric::ScannerFabricConfigError> {
        let scanner: Arc<dyn Scanner> =
            Arc::new(InlineMlScanner::new(runtime, INLINE_ML_STAGE_MAX_INPUT));
        let fabric = ScannerFabric::new(
            ScannerFabricConfig {
                max_concurrent_scans: 2,
            },
            vec![ScannerRegistration {
                scanner,
                profile: ScannerProfile {
                    scanner_id: ScannerId::new(INLINE_ML_SCANNER_ID),
                    scanner_type: nullapart_mail_contracts::ScannerType::InlineMl,
                    requirement: ScannerRequirement::Optional,
                    max_input_bytes: INLINE_ML_STAGE_MAX_INPUT,
                    timeout: INLINE_ML_STAGE_TIMEOUT,
                    max_concurrency: 2,
                    limits: ScannerResourceLimits::bounded_default(INLINE_ML_STAGE_MAX_INPUT),
                },
            }],
        )?;
        Ok(Self {
            fabric,
            switches: FeatureSwitchResolver::new(pool.clone()),
            thresholds: MlThresholdResolver::new(pool),
            feature_id: FeatureId::new(INLINE_ML_FEATURE_ID),
        })
    }

    /// Load the runtime named by `NULLAPART_INLINE_ML_*` environment
    /// configuration, but only after the active registry row for this
    /// deployment approves the same model identity and artifact digest. A
    /// missing, inactive or mismatched registry entry degrades to an
    /// explicitly unavailable runtime so switch-enabled evaluation surfaces
    /// Unknown/Error evidence instead of silently running an unapproved
    /// artifact.
    pub async fn from_environment(pool: PgPool, deployment_id: DeploymentId) -> Self {
        let config = InlineMlRuntimeConfig::from_env();
        let runtime: Arc<dyn InlineModelRuntime> = if config.is_configured() {
            match verify_active_registry_artifact(&pool, &deployment_id, &config).await {
                Ok(()) => {
                    let load_config = config.clone();
                    match tokio::task::spawn_blocking(move || OrtModelRuntime::load(&load_config))
                        .await
                    {
                        Ok(Ok(runtime)) => {
                            tracing::info!(
                                model_id = runtime.identity().model_id,
                                model_version = runtime.identity().model_version,
                                "inline ml model loaded"
                            );
                            Arc::new(runtime)
                        },
                        Ok(Err(error)) => {
                            tracing::warn!(
                                error = %error,
                                "inline ml model failed to load; runtime is unavailable"
                            );
                            Arc::new(UnavailableRuntime::from_config(
                                &config,
                                "configured inline ml model failed to load",
                            ))
                        },
                        Err(_) => {
                            tracing::warn!(
                                "inline ml model load task failed; runtime is unavailable"
                            );
                            Arc::new(UnavailableRuntime::from_config(
                                &config,
                                "inline ml model load task failed",
                            ))
                        },
                    }
                },
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        model_id = config.model_id,
                        model_version = config.model_version,
                        "inline ml registry gate failed; runtime is unavailable"
                    );
                    Arc::new(UnavailableRuntime::from_config(
                        &config,
                        "configured inline ml model is not the active approved registry artifact",
                    ))
                },
            }
        } else {
            tracing::warn!(
                "inline ml model paths are not configured; runtime is unavailable \
                 (set NULLAPART_INLINE_ML_MODEL_PATH and NULLAPART_INLINE_ML_TOKENIZER_PATH)"
            );
            Arc::new(UnavailableRuntime::from_config(
                &config,
                "inline ml model paths are not configured",
            ))
        };
        Self::with_runtime(pool, runtime)
            .expect("single inline ml registration must satisfy fabric validation")
    }

    /// Whether the stage must run for this message's context. Failures
    /// resolve to `false` inside the resolver (fail-to-off).
    pub async fn should_run(&self, context: &TenantScanContext) -> bool {
        self.switches
            .is_enabled(
                &self.feature_id,
                &context.deployment_id,
                &context.customer_id,
            )
            .await
    }

    /// Run pass 2 against the same artifact snapshot. Returns `None` when
    /// the feature switch is off (capability not evaluated, as configured).
    pub async fn run(
        &self,
        context: &TenantScanContext,
        pass1_artifact: &ScanArtifact,
        pass1: &ScannerFabricResult,
        content: Arc<dyn ScanContent>,
    ) -> Option<ScannerFabricResult> {
        if !self.should_run(context).await {
            return None;
        }
        // Thresholds are policy for this exact scope. Absent or invalid
        // configuration never invents numbers: scores stay evidence only
        // and the gap is an explicit, greppable WARN.
        let thresholds = self
            .thresholds
            .resolve(&context.deployment_id, &context.customer_id)
            .await;
        if thresholds.is_none() {
            tracing::warn!(
                family = crate::inline_ml::thresholds::ML_THREAT_CLASSIFICATION_FAMILY,
                "inline ml thresholds are not configured for this scope; scores remain evidence only and are not converted to findings"
            );
        }
        let mut artifact = pass1_artifact.clone();
        artifact.request_id =
            Uuid::new_v5(&pass1_artifact.request_id, b"nullapart-inline-ml-pass2");
        artifact.params = inline_ml_params(
            &context.envelope_sender,
            &pass1.findings,
            thresholds.as_ref(),
        );
        let started = Instant::now();
        let pass2 = self.fabric.scan(artifact, content).await;
        tracing::info!(
            duration_ms = started.elapsed().as_millis() as u64,
            pass2_results = pass2.results.len(),
            pass2_findings = pass2.findings.len(),
            pass2_failures = pass2.failures.len(),
            "inline ml pass-2 completed"
        );
        Some(pass2)
    }
}

async fn verify_active_registry_artifact(
    pool: &PgPool,
    deployment_id: &DeploymentId,
    config: &InlineMlRuntimeConfig,
) -> Result<(), String> {
    let model_path = config
        .model_path
        .clone()
        .ok_or_else(|| "NULLAPART_INLINE_ML_MODEL_PATH is not set".to_string())?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("registry check could not start: {error}"))?;
    sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
        .bind(&deployment_id.0)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("registry scope could not be set: {error}"))?;
    let expected_sha = sqlx::query_scalar::<_, String>(ACTIVE_REGISTRY_DIGEST_SQL)
        .bind(&deployment_id.0)
        .bind(&config.model_id)
        .bind(&config.model_version)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| format!("registry check failed: {error}"))?
        .ok_or_else(|| {
            format!(
                "no active approved registry row for {}/{}",
                config.model_id, config.model_version
            )
        })?;
    transaction
        .commit()
        .await
        .map_err(|error| format!("registry check could not commit: {error}"))?;
    let actual_sha = sha256_path_async(model_path).await?;
    if actual_sha != expected_sha {
        return Err(format!(
            "configured artifact digest {actual_sha} does not match active registry digest \
             {expected_sha} for {}/{}",
            config.model_id, config.model_version
        ));
    }
    Ok(())
}

async fn sha256_path_async(path: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || sha256_file(path))
        .await
        .map_err(|_| "model artifact digest task failed".to_string())?
}

fn sha256_file(path: impl AsRef<Path>) -> Result<String, String> {
    let mut file = File::open(path.as_ref())
        .map_err(|error| format!("model artifact could not be opened: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|error| format!("model artifact could not be read: {error}"))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Merge pass-2 outcomes into the pass-1 result before policy evaluation.
///
/// `requires_hold` deliberately stays the pass-1 value: the pass-2 fabric
/// registers only the OPTIONAL inline ML scanner, so its own
/// required-coverage flag would otherwise be inconclusive for every message
/// (empty required coverage) and force an unconditional hold. Pass-1
/// required coverage remains the sole hold authority; pass-2 contributes
/// findings, failures, per-scanner outcomes and profile rows only.
pub fn merge_pass2(pass1: ScannerFabricResult, pass2: ScannerFabricResult) -> ScannerFabricResult {
    let mut merged = pass1;
    merged.results.extend(pass2.results);
    merged.scanner_profiles.extend(pass2.scanner_profiles);
    merged.findings.extend(pass2.findings);
    merged.failures.extend(pass2.failures);
    merged
}

#[cfg(test)]
mod tests {
    const _: () = assert!(INLINE_ML_STAGE_MAX_INPUT >= 1024 * 1024);

    use nullapart_mail_contracts::ScannerType;
    use nullapart_scanner_sdk::fabric::ScannerOutcome;
    use nullapart_scanner_sdk::trait_defs::ScannerId as SdkScannerId;
    use nullapart_scanner_sdk::types::{ExecutionClass, ScannerProvenance, ScannerStatus};

    use super::*;

    fn empty_result() -> ScannerFabricResult {
        ScannerFabricResult {
            results: Vec::new(),
            scanner_profiles: Vec::new(),
            findings: Vec::new(),
            failures: Vec::new(),
            requires_hold: false,
        }
    }

    fn outcome(id: &str, status: ScannerStatus) -> ScannerOutcome {
        ScannerOutcome {
            scanner_id: SdkScannerId::new(id),
            scanner_type: ScannerType::InlineMl,
            execution_class: ExecutionClass::OptionalEnrichment,
            required: false,
            applicable: true,
            status,
            duration_ms: 12,
            finding_count: 0,
            failure: None,
            completed_at: chrono::Utc::now(),
            provenance: ScannerProvenance {
                scanner_node_id: None,
                scanner_profile_id: None,
                scanner_profile_version: None,
                engine_version: None,
                ruleset_version: None,
                started_at: chrono::Utc::now(),
            },
        }
    }

    #[test]
    fn merge_keeps_pass1_hold_authority_and_appends_pass2_rows() {
        let mut pass1 = empty_result();
        pass1.requires_hold = true;
        pass1
            .results
            .push(outcome("file-type", ScannerStatus::Clean));
        pass1
            .scanner_profiles
            .push(crate::scanner_fabric::ScannerResultProfile {
                scanner_id: nullapart_scanner_sdk::trait_defs::ScannerId::new("file-type"),
                scanner_type: ScannerType::Attachment,
                required: true,
            });

        let mut pass2 = empty_result();
        pass2.requires_hold = true; // must be ignored: empty required coverage
        pass2
            .results
            .push(outcome("inline-ml-classifier", ScannerStatus::Unknown));
        pass2
            .scanner_profiles
            .push(crate::scanner_fabric::ScannerResultProfile {
                scanner_id: nullapart_scanner_sdk::trait_defs::ScannerId::new(INLINE_ML_SCANNER_ID),
                scanner_type: ScannerType::InlineMl,
                required: false,
            });

        let merged = merge_pass2(pass1, pass2);
        assert!(merged.requires_hold, "pass-1 hold authority must survive");
        assert_eq!(merged.results.len(), 2);
        assert_eq!(merged.scanner_profiles.len(), 2);
        assert_eq!(merged.results[1].scanner_id.0, INLINE_ML_SCANNER_ID);
        assert!(!merged.results[1].required);
    }

    #[test]
    fn merge_appends_findings_and_failures() {
        use nullapart_mail_contracts::{
            Confidence, FindingCategory, FindingId, FindingScope, FindingSeverity, SecurityFinding,
        };
        let finding = SecurityFinding {
            id: FindingId::new(),
            scope: FindingScope::Transaction,
            scanner: ScannerType::InlineMl,
            scanner_status: ScannerStatus::Unknown,
            severity: FindingSeverity::Medium,
            confidence: Confidence::High,
            category: FindingCategory::Unknown,
            description: "scanner failed".to_string(),
            details: None,
            indicators: Vec::new(),
            created_at: chrono::Utc::now(),
            false_positive: false,
            transaction_id: None,
            tenant_message_id: None,
        };
        let mut pass2 = empty_result();
        pass2.findings.push(finding);
        let merged = merge_pass2(empty_result(), pass2);
        assert_eq!(merged.findings.len(), 1);
        assert_eq!(merged.findings[0].scanner, ScannerType::InlineMl);
    }

    #[test]
    fn stage_identity_and_feature_id_are_stable() {
        assert_eq!(INLINE_ML_FEATURE_ID, "inline_ml_classification");
        assert_eq!(INLINE_ML_SCANNER_ID, "inline-ml-classifier");
        assert!(INLINE_ML_STAGE_TIMEOUT.as_millis() >= 500);
    }

    #[test]
    fn sha256_file_reports_artifact_digest() {
        let path = std::env::temp_dir().join(format!(
            "nullapart-inline-ml-digest-{}.bin",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, b"approved-model-artifact").expect("write test artifact");
        let digest = sha256_file(&path).expect("hash test artifact");
        std::fs::remove_file(&path).expect("remove test artifact");
        assert_eq!(
            digest,
            "2e944cf2067933925530c247b0dba0bb6e399fcf9cb735ab1dff26da77fe4689"
        );
    }
}
