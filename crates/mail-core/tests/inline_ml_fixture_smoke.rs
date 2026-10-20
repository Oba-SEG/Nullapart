//! CI smoke: load the generated inline-ML fixture (tiny ONNX + WordLevel
//! tokenizer) through the real `OrtModelRuntime::load` path and assert one
//! inference produces the expected logits shape and probability contract.
//!
//! Ignored by default; the CI compose-smoke job generates the fixture with
//! `tests/fixtures/make_inline_ml_fixture.py` and runs:
//!
//! ```sh
//! cargo test -p nullapart-mail-core --test inline_ml_fixture_smoke -- --ignored
//! ```

use nullapart_mail_core::inline_ml::runtime::{
    InlineMlRuntimeConfig, InlineModelRuntime, OrtModelRuntime, INLINE_ML_CLASS_COUNT,
};

#[test]
#[ignore = "requires generated fixture; run via ci compose-smoke"]
fn fixture_model_loads_and_infers_contract_shape() {
    let root = std::env::var("NULLAPART_INLINE_ML_FIXTURE_DIR")
        .unwrap_or_else(|_| "/tmp/inline-ml-fixture".to_string());
    let config = InlineMlRuntimeConfig {
        model_path: Some(format!("{root}/model.onnx")),
        tokenizer_path: Some(format!("{root}/tokenizer.json")),
        model_id: "ci-fixture".to_string(),
        model_version: "0".to_string(),
    };
    let runtime = OrtModelRuntime::load(&config).expect("fixture model and tokenizer must load");
    let inference = runtime
        .infer("CONGRATULATIONS you won a prize, click here now")
        .expect("fixture inference must succeed");
    assert_eq!(
        inference.probabilities.len(),
        INLINE_ML_CLASS_COUNT,
        "fixture must produce one probability per class"
    );
    for probability in &inference.probabilities {
        assert!(
            probability.is_finite() && *probability > 0.0 && *probability < 1.0,
            "fixture probability {probability} outside (0,1)"
        );
    }
    // Constant-zero logits => sigmoid(0) = 0.5 for every class.
    for probability in &inference.probabilities {
        assert!(
            (*probability - 0.5).abs() < 1e-6,
            "fixture logits must be zero, got {probability}"
        );
    }
}
