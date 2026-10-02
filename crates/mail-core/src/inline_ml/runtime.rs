//! Inline ML model runtime: versioned trait plus the ONNX Runtime binding.
//!
//! The runtime owns tokenization and numeric inference behind
//! [`InlineModelRuntime`]; the scanner adapter never touches a model
//! artifact directly. Failures are typed and explicit
//! ([`ModelError::Unavailable`]/[`ModelError::Failed`]) so the fabric can
//! turn them into Unknown/Error evidence rather than a clean result
//! (`docs/phases/PHASE-4-LOCAL-IMPLEMENTATION-PLAN.md`, design decision 5).

use std::sync::Mutex;

use ort::session::Session;
use ort::value::Tensor;
use tokenizers::tokenizer::{
    PaddingDirection, PaddingParams, PaddingStrategy, TruncationDirection, TruncationParams,
    TruncationStrategy,
};

use super::representation::INLINE_ML_REPRESENTATION_VERSION;

/// Ordered label taxonomy the checkpoint was trained against
/// (`ml/inline/prepare_dataset.py::LABELS`).
pub const INLINE_ML_LABELS: [&str; 13] = [
    "Malware",
    "Phishing",
    "Spam",
    "Spoofing",
    "BusinessEmailCompromise",
    "CredentialHarvest",
    "MaliciousUrl",
    "MaliciousAttachment",
    "SuspiciousContent",
    "PolicyViolation",
    "AuthFailure",
    "Reputation",
    "Unknown",
];

/// Number of output probabilities the model produces.
pub const INLINE_ML_CLASS_COUNT: usize = INLINE_ML_LABELS.len();

/// Fixed sequence length of the exported ONNX graph (batch 1 x 128).
pub const INLINE_ML_MAX_SEQUENCE: usize = 128;

/// Stable identity of the loaded model artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity {
    pub model_id: String,
    pub model_version: String,
}

/// Probabilities for one classified text: exactly
/// [`INLINE_ML_CLASS_COUNT`] values in `(0, 1)`, ordered as
/// [`INLINE_ML_LABELS`].
#[derive(Debug, Clone, PartialEq)]
pub struct ModelInference {
    pub probabilities: Vec<f32>,
}

impl ModelInference {
    /// Index and probability of the highest-scoring class.
    pub fn argmax(&self) -> (usize, f32) {
        let mut best = (0usize, f32::NEG_INFINITY);
        for (index, probability) in self.probabilities.iter().enumerate() {
            if *probability > best.1 {
                best = (index, *probability);
            }
        }
        best
    }
}

/// Typed runtime failure. Never carries message bytes or artifact paths in
/// display output once converted to scanner evidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// The runtime cannot serve inference (not configured, artifact
    /// missing or unreadable, tokenizer unusable).
    #[error("model runtime unavailable: {0}")]
    Unavailable(String),

    /// The loaded model does not match the requested input contract.
    #[error("model contract mismatch: {0}")]
    VersionMismatch(String),

    /// Inference ran and failed (session error, malformed output).
    #[error("model inference failed: {0}")]
    Failed(String),
}

/// Server-side runtime configuration, read from environment variables:
/// `NULLAPART_INLINE_ML_MODEL_PATH`, `NULLAPART_INLINE_ML_TOKENIZER_PATH`,
/// `NULLAPART_INLINE_ML_MODEL_ID`, `NULLAPART_INLINE_ML_MODEL_VERSION`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InlineMlRuntimeConfig {
    pub model_path: Option<String>,
    pub tokenizer_path: Option<String>,
    pub model_id: String,
    pub model_version: String,
}

impl InlineMlRuntimeConfig {
    pub fn from_env() -> Self {
        let read = |key: &str| {
            std::env::var(key)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        Self {
            model_path: read("NULLAPART_INLINE_ML_MODEL_PATH"),
            tokenizer_path: read("NULLAPART_INLINE_ML_TOKENIZER_PATH"),
            model_id: read("NULLAPART_INLINE_ML_MODEL_ID")
                .unwrap_or_else(|| "multilabel-v1".to_string()),
            model_version: read("NULLAPART_INLINE_ML_MODEL_VERSION")
                .unwrap_or_else(|| "1".to_string()),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.model_path.is_some() && self.tokenizer_path.is_some()
    }
}

/// Versioned inference contract. Implementations are pure with respect to
/// message data: input is the already-composed bounded text, output is the
/// probability vector.
pub trait InlineModelRuntime: Send + Sync {
    /// Whether the runtime can serve inference right now.
    fn ready(&self) -> bool;

    /// Representation version this runtime accepts.
    fn representation_version(&self) -> u32;

    /// Identity of the model artifact this runtime serves.
    fn identity(&self) -> ModelIdentity;

    /// Run inference for one composed text.
    fn infer(&self, text: &str) -> Result<ModelInference, ModelError>;
}

/// Explicitly unavailable runtime: used when no model is configured or the
/// configured artifacts failed to load. Every scan surfaces typed
/// `Unavailable` evidence instead of silently skipping evaluation.
#[derive(Debug, Clone)]
pub struct UnavailableRuntime {
    reason: String,
    identity: ModelIdentity,
}

impl UnavailableRuntime {
    pub fn new(reason: impl Into<String>, identity: ModelIdentity) -> Self {
        Self {
            reason: reason.into(),
            identity,
        }
    }

    pub fn from_config(config: &InlineMlRuntimeConfig, reason: impl Into<String>) -> Self {
        Self::new(
            reason,
            ModelIdentity {
                model_id: config.model_id.clone(),
                model_version: config.model_version.clone(),
            },
        )
    }
}

impl InlineModelRuntime for UnavailableRuntime {
    fn ready(&self) -> bool {
        false
    }

    fn representation_version(&self) -> u32 {
        INLINE_ML_REPRESENTATION_VERSION
    }

    fn identity(&self) -> ModelIdentity {
        self.identity.clone()
    }

    fn infer(&self, _text: &str) -> Result<ModelInference, ModelError> {
        Err(ModelError::Unavailable(self.reason.clone()))
    }
}

/// ONNX Runtime implementation: DistilBERT tokenizer feeding a fixed
/// batch-1 x 128 session, sigmoid applied over raw logits to mirror the
/// evaluation-side probability space (`ml/inline/evaluate.py`).
pub struct OrtModelRuntime {
    session: Mutex<Session>,
    tokenizer: tokenizers::Tokenizer,
    identity: ModelIdentity,
}

impl OrtModelRuntime {
    /// Load tokenizer and session from explicit paths. Blocking (model
    /// artifact I/O): callers run this at startup inside `spawn_blocking`.
    pub fn load(config: &InlineMlRuntimeConfig) -> Result<Self, ModelError> {
        let model_path = config.model_path.as_ref().ok_or_else(|| {
            ModelError::Unavailable("NULLAPART_INLINE_ML_MODEL_PATH is not set".to_string())
        })?;
        let tokenizer_path = config.tokenizer_path.as_ref().ok_or_else(|| {
            ModelError::Unavailable("NULLAPART_INLINE_ML_TOKENIZER_PATH is not set".to_string())
        })?;

        let mut tokenizer = tokenizers::Tokenizer::from_file(tokenizer_path).map_err(|error| {
            ModelError::Unavailable(format!("tokenizer failed to load: {error}"))
        })?;
        let pad_id = tokenizer.token_to_id("[PAD]").ok_or_else(|| {
            ModelError::VersionMismatch("tokenizer has no [PAD] token".to_string())
        })?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: INLINE_ML_MAX_SEQUENCE,
                strategy: TruncationStrategy::LongestFirst,
                stride: 0,
                direction: TruncationDirection::Right,
            }))
            .map_err(|error| ModelError::VersionMismatch(format!("truncation setup: {error}")))?;
        tokenizer.with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::Fixed(INLINE_ML_MAX_SEQUENCE),
            direction: PaddingDirection::Right,
            pad_to_multiple_of: None,
            pad_id,
            pad_token: "[PAD]".to_string(),
            pad_type_id: 0,
        }));

        let session = Session::builder()
            .map_err(|error| ModelError::Unavailable(format!("session builder: {error}")))?
            .commit_from_file(model_path)
            .map_err(|error| ModelError::Unavailable(format!("model failed to load: {error}")))?;

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            identity: ModelIdentity {
                model_id: config.model_id.clone(),
                model_version: config.model_version.clone(),
            },
        })
    }
}

fn sigmoid(logit: f32) -> f32 {
    1.0 / (1.0 + (-logit.clamp(-50.0, 50.0)).exp())
}

impl InlineModelRuntime for OrtModelRuntime {
    fn ready(&self) -> bool {
        true
    }

    fn representation_version(&self) -> u32 {
        INLINE_ML_REPRESENTATION_VERSION
    }

    fn identity(&self) -> ModelIdentity {
        self.identity.clone()
    }

    fn infer(&self, text: &str) -> Result<ModelInference, ModelError> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|error| ModelError::Failed(format!("tokenization failed: {error}")))?;
        let ids = encoding.get_ids();
        let mask = encoding.get_attention_mask();
        if ids.len() != INLINE_ML_MAX_SEQUENCE || mask.len() != INLINE_ML_MAX_SEQUENCE {
            return Err(ModelError::Failed(format!(
                "tokenizer produced {} ids, expected {INLINE_ML_MAX_SEQUENCE}",
                ids.len()
            )));
        }
        let ids: Vec<i64> = ids.iter().map(|value| i64::from(*value)).collect();
        let mask: Vec<i64> = mask.iter().map(|value| i64::from(*value)).collect();

        let ids_tensor = Tensor::from_array(([1_i64, INLINE_ML_MAX_SEQUENCE as i64], ids))
            .map_err(|error| ModelError::Failed(format!("input tensor: {error}")))?;
        let mask_tensor = Tensor::from_array(([1_i64, INLINE_ML_MAX_SEQUENCE as i64], mask))
            .map_err(|error| ModelError::Failed(format!("mask tensor: {error}")))?;

        let logits: Vec<f32> = {
            let mut session = self
                .session
                .lock()
                .map_err(|_| ModelError::Failed("model session lock poisoned".to_string()))?;
            let outputs = session
                .run(ort::inputs! {
                    "input_ids" => ids_tensor,
                    "attention_mask" => mask_tensor,
                })
                .map_err(|error| ModelError::Failed(format!("session run failed: {error}")))?;
            let (_shape, logits) = outputs["logits"]
                .try_extract_tensor::<f32>()
                .map_err(|error| ModelError::Failed(format!("model output unreadable: {error}")))?;
            logits.to_vec()
        };
        if logits.len() != INLINE_ML_CLASS_COUNT {
            return Err(ModelError::Failed(format!(
                "model produced {} logits, expected {INLINE_ML_CLASS_COUNT}",
                logits.len()
            )));
        }
        let probabilities: Vec<f32> = logits.iter().map(|logit| sigmoid(*logit)).collect();
        if probabilities.iter().any(|probability| {
            !probability.is_finite() || *probability <= 0.0 || *probability >= 1.0
        }) {
            return Err(ModelError::Failed(
                "model probabilities out of range".to_string(),
            ));
        }
        Ok(ModelInference { probabilities })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> InlineMlRuntimeConfig {
        InlineMlRuntimeConfig {
            model_path: None,
            tokenizer_path: None,
            model_id: "test-model".to_string(),
            model_version: "7".to_string(),
        }
    }

    #[test]
    fn labels_are_unique_and_class_count_matches() {
        let mut seen = std::collections::HashSet::new();
        for label in INLINE_ML_LABELS {
            assert!(seen.insert(label), "duplicate label {label}");
        }
        assert_eq!(INLINE_ML_CLASS_COUNT, 13);
    }

    #[test]
    fn sigmoid_is_symmetric_and_bounded() {
        assert!((sigmoid(0.0) - 0.5).abs() < f32::EPSILON);
        assert!(sigmoid(500.0) > 0.999);
        assert!(sigmoid(-500.0) < 0.001);
    }

    #[test]
    fn argmax_returns_first_maximum() {
        let inference = ModelInference {
            probabilities: vec![0.1, 0.9, 0.9, 0.2],
        };
        assert_eq!(inference.argmax(), (1, 0.9));
    }

    #[test]
    fn unavailable_runtime_is_not_ready_and_fails_typed() {
        let runtime = UnavailableRuntime::from_config(&config(), "model missing");
        assert!(!runtime.ready());
        assert_eq!(
            runtime.representation_version(),
            INLINE_ML_REPRESENTATION_VERSION
        );
        assert_eq!(
            runtime.infer("text"),
            Err(ModelError::Unavailable("model missing".to_string()))
        );
        let identity = runtime.identity();
        assert_eq!(identity.model_id, "test-model");
        assert_eq!(identity.model_version, "7");
    }

    #[test]
    fn load_without_paths_reports_unconfigured_paths() {
        let error = OrtModelRuntime::load(&config())
            .err()
            .expect("must not load");
        assert!(matches!(error, ModelError::Unavailable(_)));
    }

    #[test]
    fn load_with_missing_files_reports_unavailable() {
        let error = OrtModelRuntime::load(&InlineMlRuntimeConfig {
            model_path: Some("/nonexistent/model.onnx".to_string()),
            tokenizer_path: Some("/nonexistent/tokenizer.json".to_string()),
            model_id: "m".to_string(),
            model_version: "1".to_string(),
        })
        .err()
        .expect("must not load");
        assert!(matches!(error, ModelError::Unavailable(_)));
    }

    #[test]
    fn load_with_corrupt_tokenizer_reports_unavailable() {
        let dir = std::env::temp_dir().join("nullapart-inline-ml-corrupt");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let tokenizer = dir.join("tokenizer.json");
        std::fs::write(&tokenizer, "not-json").expect("write corrupt tokenizer");
        let error = OrtModelRuntime::load(&InlineMlRuntimeConfig {
            model_path: Some(dir.join("model.onnx").to_string_lossy().to_string()),
            tokenizer_path: Some(tokenizer.to_string_lossy().to_string()),
            model_id: "m".to_string(),
            model_version: "1".to_string(),
        })
        .err()
        .expect("must not load");
        assert!(matches!(error, ModelError::Unavailable(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
