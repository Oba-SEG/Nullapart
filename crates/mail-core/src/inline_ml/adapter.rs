//! Inline ML scanner adapter: pass-2 representation, tokenized inference
//! and explicit outcome evidence behind the Scanner SDK contract.
//!
//! The adapter performs NO disposition policy work: a successful run always
//! reports `Clean` plus a versioned `details` payload (model identity,
//! argmax, per-class scores). Scores become classification findings only
//! when the stage supplies policy-published thresholds
//! ([`super::thresholds::MlThresholdConfig`], the `ml_threat_classification`
//! family); without them the run stays evidence-only. Model failures are
//! typed [`ScanError`]s so the fabric synthesizes Unknown/Error evidence
//! that can never be mistaken for clean.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use nullapart_scanner_sdk::trait_defs::{ScanContent, ScanError, Scanner, ScannerId};
use nullapart_scanner_sdk::types::{
    LatencyClass, ScanRequest, ScanResult, ScannerCapabilities, ScannerHealth, ScannerProvenance,
    ScannerStatus,
};
use serde::Deserialize;

use super::model_text::compose_model_text;
use super::representation::{
    build as build_representation, RepresentationSources, VipSignal,
    INLINE_ML_REPRESENTATION_VERSION,
};
use super::runtime::{InlineModelRuntime, ModelError, INLINE_ML_CLASS_COUNT, INLINE_ML_LABELS};
use super::thresholds::{band_for, band_label, category_key, label_to_category, MlThresholdConfig};
use crate::scanner_adapters::read_content_bounded;

/// Stable scanner identity for the inline ML classifier.
pub const INLINE_ML_SCANNER_ID: &str = "inline-ml-classifier";

/// Adapter implementation version, surfaced as provenance engine version.
pub const INLINE_ML_ADAPTER_VERSION: &str = "inline-ml-v1";

/// Key of the pass-2 stage parameters carried in `ScanRequest::params`.
const PARAMS_KEY: &str = "inline_ml";

/// Pass-2 stage parameters: server-derived context the representation is
/// allowed to consume. Never carries raw content; the artifact bytes are
/// read through the fabric-supplied [`ScanContent`] snapshot.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct InlineMlScanParams {
    /// Envelope sender from authenticated transport context.
    #[serde(default)]
    pub envelope_sender: Option<String>,
    /// Normalized pass-1 findings under the same transaction scope.
    #[serde(default)]
    pub findings: Vec<nullapart_mail_contracts::SecurityFinding>,
    /// Authorized VIP context, present only when the caller supplies it.
    #[serde(default)]
    pub vip: Option<VipSignal>,
    /// Policy-published thresholds for this scope. Absent means scores
    /// stay evidence only (no classification findings).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thresholds: Option<MlThresholdConfig>,
}

/// Build the `ScanRequest::params` payload for one pass-2 stage run.
pub fn inline_ml_params(
    envelope_sender: &str,
    findings: &[nullapart_mail_contracts::SecurityFinding],
    thresholds: Option<&MlThresholdConfig>,
) -> serde_json::Value {
    serde_json::json!({
        PARAMS_KEY: InlineMlScanParams {
            envelope_sender: Some(envelope_sender.to_string()),
            findings: findings.to_vec(),
            vip: None,
            thresholds: thresholds.cloned(),
        }
    })
}

#[derive(Debug, Deserialize)]
struct InlineMlScanEnvelope {
    inline_ml: InlineMlScanParams,
}

/// Inline ML scanner adapter over an [`InlineModelRuntime`].
pub struct InlineMlScanner {
    runtime: Arc<dyn InlineModelRuntime>,
    max_input_bytes: u64,
}

impl InlineMlScanner {
    pub fn new(runtime: Arc<dyn InlineModelRuntime>, max_input_bytes: u64) -> Self {
        Self {
            runtime,
            max_input_bytes,
        }
    }
}

/// Convert scores into classification findings using policy-published
/// thresholds. One finding per configured class whose score reached the
/// `low` operating point; the band (Low/Medium/High) comes from the same
/// thresholds and lands on the finding's severity. Order is the canonical
/// label order, so repeated runs over identical scores are identical.
fn threshold_findings(
    probabilities: &[f32],
    all_scores: &serde_json::Map<String, serde_json::Value>,
    thresholds: &MlThresholdConfig,
    identity: &super::runtime::ModelIdentity,
) -> Vec<nullapart_scanner_sdk::types::ScannerFinding> {
    use nullapart_scanner_sdk::types::ScannerFinding;
    let mut findings = Vec::new();
    for (index, label) in INLINE_ML_LABELS.iter().enumerate() {
        let Some(category) = label_to_category(label) else {
            continue;
        };
        let key = category_key(category);
        let Some(threshold) = thresholds.classes.get(&key) else {
            continue;
        };
        let score = probabilities[index];
        let Some(band) = band_for(score, threshold) else {
            continue;
        };
        findings.push(ScannerFinding {
            id: uuid::Uuid::new_v4(),
            severity: band,
            category: key.clone(),
            description: format!(
                "Inline ML score {score:.4} for {key} is in the {} band (thresholds low {:.4}, medium {:.4}, high {:.4})",
                band_label(band),
                threshold.low,
                threshold.medium,
                threshold.high,
            ),
            details: Some(serde_json::json!({
                "model": {
                    "id": identity.model_id,
                    "version": identity.model_version,
                },
                "category": key,
                "band": band_label(band),
                "score": score,
                "thresholds": {
                    "low": threshold.low,
                    "medium": threshold.medium,
                    "high": threshold.high,
                },
                "scores": serde_json::Value::Object(all_scores.clone()),
            })),
            indicators: Vec::new(),
            false_positive: false,
        });
    }
    findings
}

fn result_with_details(
    scanner: &InlineMlScanner,
    request: &ScanRequest,
    findings: Vec<nullapart_scanner_sdk::types::ScannerFinding>,
    details: Option<serde_json::Value>,
    started: Instant,
    started_at: DateTime<Utc>,
    model_version: &str,
) -> ScanResult {
    // A completed inline run is `Clean` at the scanner-status level:
    // band severity on the findings is escalated by the fabric, never
    // synthesized here.
    ScanResult {
        request_id: request.request_id,
        contract_version: request.contract_version,
        scanner_id: scanner.id(),
        status: ScannerStatus::Clean,
        message: None,
        findings,
        completed_at: Utc::now(),
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        details,
        provenance: ScannerProvenance {
            scanner_node_id: None,
            scanner_profile_id: None,
            scanner_profile_version: None,
            engine_version: Some(format!("{INLINE_ML_ADAPTER_VERSION}/{model_version}")),
            ruleset_version: None,
            started_at,
        },
    }
}

/// Stable, content-free error codes for operational logs.
fn model_error_code(error: &ModelError) -> &'static str {
    match error {
        ModelError::Unavailable(_) => "unavailable",
        ModelError::VersionMismatch(_) => "version_mismatch",
        ModelError::Failed(_) => "failed",
    }
}

#[async_trait]
impl Scanner for InlineMlScanner {
    fn id(&self) -> ScannerId {
        ScannerId::new(INLINE_ML_SCANNER_ID)
    }

    fn name(&self) -> &str {
        "Inline ML threat classification"
    }

    fn version(&self) -> &str {
        INLINE_ML_ADAPTER_VERSION
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            supported_content_types: vec!["message/rfc822".to_string()],
            max_content_size: self.max_input_bytes,
            latency_class: LatencyClass::Fast,
            requires_network: false,
            milter_compatible: false,
            extra: serde_json::Value::Null,
        }
    }

    async fn scan(
        &self,
        request: ScanRequest,
        content: Arc<dyn ScanContent>,
    ) -> Result<ScanResult, ScanError> {
        let started_at = Utc::now();
        let started = Instant::now();

        if !self.runtime.ready() {
            return Err(ScanError::Unavailable(
                "inline model runtime not ready".to_string(),
            ));
        }
        let identity = self.runtime.identity();
        request
            .validate_contract()
            .map_err(|_| ScanError::Failed("unsupported scanner contract version".to_string()))?;

        let envelope: InlineMlScanEnvelope = serde_json::from_value(request.params.clone())
            .map_err(|_| ScanError::Failed("invalid inline ml scan parameters".to_string()))?;
        let params = envelope.inline_ml;

        if self.runtime.representation_version() != INLINE_ML_REPRESENTATION_VERSION {
            return Err(ScanError::Failed(
                "inline model representation version mismatch".to_string(),
            ));
        }

        let bytes = read_content_bounded(content.as_ref(), self.max_input_bytes).await?;
        let representation = build_representation(&RepresentationSources {
            mime: &bytes,
            findings: &params.findings,
            envelope_sender: params.envelope_sender.as_deref(),
            vip: params.vip.as_ref(),
        });
        if representation.representation_version != INLINE_ML_REPRESENTATION_VERSION {
            return Err(ScanError::Failed(
                "inline model representation version mismatch".to_string(),
            ));
        }
        let text = compose_model_text(&representation);

        let runtime = Arc::clone(&self.runtime);
        let bound_ms = request.timeout_ms.saturating_sub(50).max(100);
        let inference = tokio::time::timeout(Duration::from_millis(bound_ms), {
            tokio::task::spawn_blocking(move || runtime.infer(&text))
        })
        .await;
        let inference = match inference {
            Err(_) => {
                return Err(ScanError::Failed(
                    "inline model inference deadline exceeded".to_string(),
                ))
            },
            Ok(Err(join_error)) => {
                let code = if join_error.is_panic() {
                    "task_panicked"
                } else {
                    "task_cancelled"
                };
                tracing::warn!(
                    stage = PARAMS_KEY,
                    code,
                    "inline model inference task ended early"
                );
                return Err(ScanError::Failed(
                    "inline model inference task failed".to_string(),
                ));
            },
            Ok(Ok(result)) => result,
        };

        let inference = match inference {
            Ok(inference) => inference,
            Err(error) => {
                tracing::warn!(
                    stage = PARAMS_KEY,
                    code = model_error_code(&error),
                    "inline model inference failed"
                );
                return Err(match error {
                    ModelError::Unavailable(_) => {
                        ScanError::Unavailable("inline model runtime unavailable".to_string())
                    },
                    ModelError::VersionMismatch(_) | ModelError::Failed(_) => {
                        ScanError::Failed("inline model inference failed".to_string())
                    },
                });
            },
        };

        if inference.probabilities.len() != INLINE_ML_CLASS_COUNT {
            return Err(ScanError::Failed(
                "inline model output shape mismatch".to_string(),
            ));
        }
        let (argmax, argmax_score) = inference.argmax();
        let argmax_label = INLINE_ML_LABELS
            .get(argmax)
            .copied()
            .unwrap_or(INLINE_ML_LABELS[INLINE_ML_LABELS.len() - 1]);
        let scores = (0..INLINE_ML_CLASS_COUNT)
            .map(|index| {
                (
                    INLINE_ML_LABELS[index].to_string(),
                    serde_json::json!(inference.probabilities[index]),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>();

        tracing::info!(
            stage = PARAMS_KEY,
            model_id = %identity.model_id,
            model_version = %identity.model_version,
            argmax = argmax_label,
            argmax_score = argmax_score,
            mime_parsed = representation.mime_parsed,
            duration_ms = started.elapsed().as_millis() as u64,
            "inline ml inference completed"
        );

        let details = serde_json::json!({
            "representation_version": representation.representation_version,
            "mime_parsed": representation.mime_parsed,
            "model": {
                "id": identity.model_id,
                "version": identity.model_version,
            },
            "inference": {
                "argmax": argmax_label,
                "argmax_score": argmax_score,
                "scores": serde_json::Value::Object(scores.clone()),
            },
        });

        let findings = match params.thresholds.as_ref() {
            Some(thresholds) => {
                threshold_findings(&inference.probabilities, &scores, thresholds, &identity)
            },
            None => Vec::new(),
        };
        if !findings.is_empty() {
            tracing::info!(
                stage = PARAMS_KEY,
                count = findings.len(),
                "inline ml scores converted to classification findings"
            );
        }

        Ok(result_with_details(
            self,
            &request,
            findings,
            Some(details),
            started,
            started_at,
            &identity.model_version,
        ))
    }

    async fn health(&self) -> ScannerHealth {
        ScannerHealth {
            healthy: self.runtime.ready(),
            message: None,
            checked_at: Utc::now(),
            uptime_seconds: None,
            queue_depth: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use nullapart_mail_contracts::{
        transaction::{ContentHash, CustomerId, DeploymentId, TransactionId},
        ArtifactId, Confidence, ContentType, FindingCategory, FindingId, FindingScope,
        FindingSeverity, ScannerType, SecurityFinding,
    };
    use nullapart_scanner_sdk::contract::SCANNER_CONTRACT_VERSION;
    use nullapart_scanner_sdk::types::ResourceLimits;
    use uuid::Uuid;

    use super::super::runtime::{ModelIdentity, ModelInference};
    use super::*;

    struct BytesContent {
        bytes: Arc<[u8]>,
        content_type: ContentType,
    }

    #[async_trait]
    impl ScanContent for BytesContent {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn content_type(&self) -> &ContentType {
            &self.content_type
        }

        async fn read_all_bounded(&self, max_bytes: u64) -> Result<Arc<[u8]>, ScanContentError> {
            if self.bytes.len() as u64 > max_bytes {
                return Err(ScanContentError::LimitExceeded);
            }
            Ok(Arc::clone(&self.bytes))
        }
    }

    use nullapart_scanner_sdk::trait_defs::ScanContentError;

    #[derive(Default)]
    struct FakeRuntime {
        ready: bool,
        representation_version: u32,
        probabilities: Option<Vec<f32>>,
        error: Option<ModelError>,
        delay_ms: u64,
        captured: Mutex<Vec<String>>,
    }

    impl FakeRuntime {
        fn healthy() -> Self {
            Self {
                ready: true,
                representation_version: INLINE_ML_REPRESENTATION_VERSION,
                probabilities: Some(vec![0.01; INLINE_ML_CLASS_COUNT]),
                error: None,
                delay_ms: 0,
                captured: Mutex::new(Vec::new()),
            }
        }
    }

    impl InlineModelRuntime for FakeRuntime {
        fn ready(&self) -> bool {
            self.ready
        }

        fn representation_version(&self) -> u32 {
            self.representation_version
        }

        fn identity(&self) -> ModelIdentity {
            ModelIdentity {
                model_id: "fake-model".to_string(),
                model_version: "test-1".to_string(),
            }
        }

        fn infer(&self, text: &str) -> Result<ModelInference, ModelError> {
            self.captured
                .lock()
                .expect("captured lock")
                .push(text.to_string());
            if self.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.delay_ms));
            }
            if let Some(error) = self.error.clone() {
                return Err(error);
            }
            let probabilities = self
                .probabilities
                .clone()
                .expect("fake probabilities configured");
            Ok(ModelInference { probabilities })
        }
    }

    fn sample_mime() -> Vec<u8> {
        [
            "From: Alice <alice@example.test>\r\n",
            "Subject: verify your account\r\n",
            "Authentication-Results: mx.example.test; spf=fail\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Visit https://login.example.test/now\r\n",
        ]
        .concat()
        .into_bytes()
    }

    fn request(timeout_ms: u64) -> ScanRequest {
        ScanRequest {
            request_id: Uuid::new_v4(),
            contract_version: SCANNER_CONTRACT_VERSION,
            transaction_id: TransactionId::new(),
            tenant_message_id: None,
            customer_id: Some(CustomerId::new("CZA-1")),
            deployment_id: DeploymentId::new("CZA-1"),
            artifact_id: ArtifactId::new(),
            content_type: ContentType::new("message/rfc822"),
            content_hash: ContentHash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            artifact_size_bytes: 0,
            timeout_ms,
            limits: ResourceLimits::bounded_defaults(),
            requested_at: Utc::now(),
            params: inline_ml_params("bounce@example.test", &[], None),
        }
    }

    fn content(bytes: Vec<u8>) -> Arc<BytesContent> {
        Arc::new(BytesContent {
            bytes: bytes.into(),
            content_type: ContentType::new("message/rfc822"),
        })
    }

    fn scanner(runtime: Arc<FakeRuntime>) -> InlineMlScanner {
        InlineMlScanner::new(runtime, 50 * 1024 * 1024)
    }

    #[tokio::test]
    async fn unavailable_runtime_is_explicit_unavailable_error() {
        let mut fake = FakeRuntime::healthy();
        fake.ready = false;
        let runtime = Arc::new(fake);
        let error = scanner(Arc::clone(&runtime))
            .scan(request(5000), content(sample_mime()))
            .await
            .expect_err("must not be clean");
        assert!(matches!(error, ScanError::Unavailable(_)));
    }

    #[tokio::test]
    async fn success_is_clean_with_versioned_score_details() {
        let runtime = Arc::new(FakeRuntime::healthy());
        let scanner = scanner(Arc::clone(&runtime));
        let req = request(5000);
        let result: ScanResult = scanner
            .scan(req.clone(), content(sample_mime()))
            .await
            .expect("clean run");
        assert_eq!(result.status, ScannerStatus::Clean);
        assert!(result.findings.is_empty());
        assert_eq!(result.request_id, req.request_id);
        assert_eq!(result.contract_version, SCANNER_CONTRACT_VERSION);
        let details = result.details.expect("details present");
        assert_eq!(
            details["representation_version"],
            INLINE_ML_REPRESENTATION_VERSION
        );
        assert_eq!(details["mime_parsed"], true);
        assert_eq!(details["model"]["id"], "fake-model");
        assert_eq!(details["model"]["version"], "test-1");
        let scores = details["inference"]["scores"].as_object().expect("scores");
        assert_eq!(scores.len(), INLINE_ML_CLASS_COUNT);
        for label in INLINE_ML_LABELS {
            assert!(scores.contains_key(label), "missing score for {label}");
        }
        assert_eq!(details["inference"]["argmax"], INLINE_ML_LABELS[0]);
        assert!(details["inference"]["argmax_score"].as_f64().is_some());
        assert!(result
            .provenance
            .engine_version
            .expect("engine version")
            .starts_with(INLINE_ML_ADAPTER_VERSION));
        assert!(runtime.captured.lock().expect("lock").len() == 1);
    }

    #[tokio::test]
    async fn missing_params_are_a_typed_failure() {
        let runtime = Arc::new(FakeRuntime::healthy());
        let mut req = request(5000);
        req.params = serde_json::Value::Null;
        let error = scanner(runtime)
            .scan(req, content(sample_mime()))
            .await
            .expect_err("must fail");
        assert!(matches!(error, ScanError::Failed(_)));
    }

    #[tokio::test]
    async fn unsupported_contract_version_is_a_typed_failure() {
        let runtime = Arc::new(FakeRuntime::healthy());
        let mut req = request(5000);
        req.contract_version = SCANNER_CONTRACT_VERSION + 100;
        let error = scanner(runtime)
            .scan(req, content(sample_mime()))
            .await
            .expect_err("must fail");
        assert!(matches!(error, ScanError::Failed(_)));
    }

    #[tokio::test]
    async fn representation_version_mismatch_is_a_typed_failure() {
        let mut fake = FakeRuntime::healthy();
        fake.representation_version = INLINE_ML_REPRESENTATION_VERSION + 1;
        let error = scanner(Arc::new(fake))
            .scan(request(5000), content(sample_mime()))
            .await
            .expect_err("must fail");
        assert!(matches!(error, ScanError::Failed(_)));
    }

    #[tokio::test]
    async fn runtime_failures_map_to_typed_errors() {
        let mut unavailable = FakeRuntime::healthy();
        unavailable.error = Some(ModelError::Unavailable("gone".to_string()));
        let error = scanner(Arc::new(unavailable))
            .scan(request(5000), content(sample_mime()))
            .await
            .expect_err("must fail");
        assert!(matches!(error, ScanError::Unavailable(_)));

        let mut failed = FakeRuntime::healthy();
        failed.error = Some(ModelError::Failed("boom".to_string()));
        let error = scanner(Arc::new(failed))
            .scan(request(5000), content(sample_mime()))
            .await
            .expect_err("must fail");
        assert!(matches!(error, ScanError::Failed(_)));

        let mut mismatch = FakeRuntime::healthy();
        mismatch.error = Some(ModelError::VersionMismatch("v2".to_string()));
        let error = scanner(Arc::new(mismatch))
            .scan(request(5000), content(sample_mime()))
            .await
            .expect_err("must fail");
        assert!(matches!(error, ScanError::Failed(_)));
    }

    #[tokio::test]
    async fn inference_overrun_is_a_typed_deadline_failure() {
        let mut slow = FakeRuntime::healthy();
        slow.delay_ms = 400;
        let error = scanner(Arc::new(slow))
            .scan(request(150), content(sample_mime()))
            .await
            .expect_err("must fail on deadline");
        assert!(matches!(error, ScanError::Failed(_)));
    }

    #[tokio::test]
    async fn malformed_mime_and_adversarial_text_stay_bounded() {
        let runtime = Arc::new(FakeRuntime::healthy());
        let scanner = scanner(Arc::clone(&runtime));
        let mut mime = b" overhanging\r\nFrom: x\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        mime.extend(std::iter::repeat_n(b'A', 300_000));
        mime.extend_from_slice("\u{1b}[2J <script>alert(1)</script> 😀".as_bytes());
        let result = scanner
            .scan(request(5000), content(mime))
            .await
            .expect("must stay bounded and clean");
        assert_eq!(result.status, ScannerStatus::Clean);
        assert_eq!(
            result.details.as_ref().expect("details")["mime_parsed"],
            false
        );
        let captured = runtime.captured.lock().expect("lock").clone();
        let text = captured.first().expect("captured text");
        assert!(text.len() < super::super::model_text::MAX_COMPOSED_TEXT_CHARS * 8);
        assert!(!text.contains("scriptalert"));
        assert!(!text.contains('\u{1b}'));
    }

    #[tokio::test]
    async fn composed_text_matches_representation_contract_without_leakage() {
        let finding = SecurityFinding {
            id: FindingId::new(),
            scope: FindingScope::Transaction,
            scanner: ScannerType::UrlAnalysis,
            scanner_status: ScannerStatus::Threat,
            severity: FindingSeverity::High,
            confidence: Confidence::High,
            category: FindingCategory::MaliciousUrl,
            description: "denied host matched".to_string(),
            details: None,
            indicators: Vec::new(),
            created_at: Utc::now(),
            false_positive: false,
            transaction_id: None,
            tenant_message_id: None,
        };
        let runtime = Arc::new(FakeRuntime::healthy());
        let scanner = scanner(Arc::clone(&runtime));
        let mut req = request(5000);
        req.params = inline_ml_params("bounce@example.test", std::slice::from_ref(&finding), None);
        scanner
            .scan(req, content(sample_mime()))
            .await
            .expect("clean run");

        let representation = build_representation(&RepresentationSources {
            mime: &sample_mime(),
            findings: std::slice::from_ref(&finding),
            envelope_sender: Some("bounce@example.test"),
            vip: None,
        });
        let expected = compose_model_text(&representation);
        let captured = runtime.captured.lock().expect("lock").clone();
        assert_eq!(captured.first().expect("captured text"), &expected);
        assert!(!expected.contains("denied host matched"));
        assert!(expected.contains("Subject: verify your account"));
    }

    fn test_thresholds() -> MlThresholdConfig {
        let mut classes = std::collections::BTreeMap::new();
        classes.insert(
            "malware".to_string(),
            super::super::thresholds::ClassThreshold {
                low: 0.4,
                medium: 0.7,
                high: 0.9,
            },
        );
        classes.insert(
            "phishing".to_string(),
            super::super::thresholds::ClassThreshold {
                low: 0.5,
                medium: 0.75,
                high: 0.95,
            },
        );
        MlThresholdConfig {
            version: super::super::thresholds::INLINE_ML_THRESHOLDS_VERSION,
            classes,
        }
    }

    fn runtime_with_scores(probabilities: Vec<f32>) -> Arc<FakeRuntime> {
        Arc::new(FakeRuntime {
            ready: true,
            representation_version: INLINE_ML_REPRESENTATION_VERSION,
            probabilities: Some(probabilities),
            error: None,
            delay_ms: 0,
            captured: Mutex::new(Vec::new()),
        })
    }

    fn request_with_thresholds(
        timeout_ms: u64,
        thresholds: Option<&MlThresholdConfig>,
    ) -> ScanRequest {
        ScanRequest {
            params: inline_ml_params("bounce@example.test", &[], thresholds),
            ..request(timeout_ms)
        }
    }

    #[tokio::test]
    async fn configured_scores_over_threshold_become_banded_findings() {
        let mut scores = vec![0.01; INLINE_ML_CLASS_COUNT];
        scores[0] = 0.96; // Malware -> high band
        scores[1] = 0.6; // Phishing -> low band (0.5 <= 0.6 < 0.75)
        let scanner = scanner(runtime_with_scores(scores));
        let thresholds = test_thresholds();
        let result = scanner
            .scan(
                request_with_thresholds(5000, Some(&thresholds)),
                content(sample_mime()),
            )
            .await
            .expect("scan must run");
        assert_eq!(result.status, ScannerStatus::Clean);
        assert_eq!(result.findings.len(), 2, "both configured classes flag");
        let malware = &result.findings[0];
        assert_eq!(malware.category, "malware");
        assert_eq!(malware.severity, FindingSeverity::High);
        assert!(!malware.false_positive);
        let details = malware.details.as_ref().expect("finding details");
        assert_eq!(details["band"], "high");
        let score = details["score"].as_f64().expect("score is a number");
        assert!(
            (score - 0.96).abs() < 1e-6,
            "score must round-trip: {score}"
        );
        assert_eq!(details["model"]["id"], "fake-model");
        let configured_low = details["thresholds"]["low"]
            .as_f64()
            .expect("low is a number");
        assert!(
            (configured_low - 0.4).abs() < 1e-6,
            "threshold must round-trip: {configured_low}"
        );
        assert_eq!(
            details["scores"].as_object().expect("scores").len(),
            INLINE_ML_CLASS_COUNT
        );
        let phishing = &result.findings[1];
        assert_eq!(phishing.category, "phishing");
        assert_eq!(phishing.severity, FindingSeverity::Low);
        assert_eq!(phishing.details.as_ref().expect("details")["band"], "low");
        let details = result.details.expect("result details stay present");
        assert_eq!(
            details["inference"]["scores"]
                .as_object()
                .expect("scores")
                .len(),
            INLINE_ML_CLASS_COUNT
        );
    }

    #[tokio::test]
    async fn scores_below_every_threshold_stay_evidence_only() {
        let scanner = scanner(FakeRuntime::healthy().into());
        let thresholds = test_thresholds();
        let result = scanner
            .scan(
                request_with_thresholds(5000, Some(&thresholds)),
                content(sample_mime()),
            )
            .await
            .expect("clean run");
        assert_eq!(result.status, ScannerStatus::Clean);
        assert!(
            result.findings.is_empty(),
            "scores under every operating point never flag"
        );
        assert!(result.details.expect("details remain evidence").is_object());
    }

    #[tokio::test]
    async fn unconfigured_classes_never_flag_even_at_high_scores() {
        let mut scores = vec![0.01; INLINE_ML_CLASS_COUNT];
        scores[0] = 0.99; // Malware is not configured in this payload
        scores[2] = 0.99; // Spam is the only configured class
        let scanner = scanner(runtime_with_scores(scores));
        let mut classes = std::collections::BTreeMap::new();
        classes.insert(
            "spam".to_string(),
            super::super::thresholds::ClassThreshold {
                low: 0.5,
                medium: 0.8,
                high: 0.95,
            },
        );
        let thresholds = MlThresholdConfig {
            version: super::super::thresholds::INLINE_ML_THRESHOLDS_VERSION,
            classes,
        };
        let result = scanner
            .scan(
                request_with_thresholds(5000, Some(&thresholds)),
                content(sample_mime()),
            )
            .await
            .expect("clean run");
        assert_eq!(result.findings.len(), 1, "only the configured class flags");
        assert_eq!(result.findings[0].category, "spam");
        assert_eq!(result.findings[0].severity, FindingSeverity::High);
    }

    #[tokio::test]
    async fn missing_thresholds_argument_still_builds_evidence_only_params() {
        let params = inline_ml_params("bounce@example.test", &[], None);
        let envelope: InlineMlScanEnvelope =
            serde_json::from_value(params).expect("params must decode");
        assert!(envelope.inline_ml.thresholds.is_none());
    }

    #[tokio::test]
    async fn health_tracks_runtime_readiness() {
        let ready = scanner(Arc::new(FakeRuntime::healthy())).health().await;
        assert!(ready.healthy);
        let mut not_ready = FakeRuntime::healthy();
        not_ready.ready = false;
        let unhealthy = scanner(Arc::new(not_ready)).health().await;
        assert!(!unhealthy.healthy);
    }

    #[tokio::test]
    async fn profile_shape_is_fast_optional_semantics() {
        let scanner = scanner(Arc::new(FakeRuntime::healthy()));
        let capabilities = scanner.capabilities();
        assert_eq!(capabilities.latency_class, LatencyClass::Fast);
        assert!(!capabilities.requires_network);
        assert!(!capabilities.milter_compatible);
        assert_eq!(
            capabilities.supported_content_types,
            vec!["message/rfc822".to_string()]
        );
        let _profile = crate::scanner_fabric::ScannerProfile {
            scanner_id: scanner.id(),
            scanner_type: ScannerType::InlineMl,
            requirement: crate::scanner_fabric::ScannerRequirement::Optional,
            max_input_bytes: capabilities.max_content_size,
            timeout: Duration::from_millis(750),
            max_concurrency: 2,
            limits: crate::scanner_fabric::ScannerResourceLimits::bounded_default(
                capabilities.max_content_size,
            ),
        };
    }
}
