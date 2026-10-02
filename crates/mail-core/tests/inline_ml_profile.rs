//! Ignored latency/parity harness for the live ONNX runtime (Phase 4
//! increment 3). Run on the deployment host where the exported checkpoint
//! artifacts exist: `cargo test --test inline_ml_profile -- --ignored
//! --nocapture`. The printed probability vector is the fixture's model
//! output; it can be diffed against the Python tokenizer/ONNX path for
//! live-vs-training parity evidence.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use nullapart_mail_core::inline_ml::{
    model_text::compose_model_text,
    representation::{build, RepresentationSources},
    runtime::{InlineMlRuntimeConfig, InlineModelRuntime, OrtModelRuntime, INLINE_ML_LABELS},
};

fn configured_runtime() -> Option<OrtModelRuntime> {
    let mut config = InlineMlRuntimeConfig::from_env();
    if !config.is_configured() {
        let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../ml/inline/checkpoints/multilabel-v1");
        let model = fallback.join("onnx/model_int8.onnx");
        let tokenizer = fallback.join("model/tokenizer.json");
        if model.is_file() && tokenizer.is_file() {
            config.model_path = Some(model.display().to_string());
            config.tokenizer_path = Some(tokenizer.display().to_string());
        }
    }
    if !config.is_configured() {
        return None;
    }
    match OrtModelRuntime::load(&config) {
        Ok(runtime) => Some(runtime),
        Err(error) => {
            eprintln!("inline ml profile skipped: model failed to load: {error}");
            None
        },
    }
}

#[test]
#[ignore = "requires exported ONNX checkpoint + tokenizer (ml/inline/checkpoints/multilabel-v1)"]
fn inline_onnx_runtime_latency_and_probability_profile() {
    let Some(runtime) = configured_runtime() else {
        eprintln!("inline ml profile skipped: model artifacts not configured");
        return;
    };

    let mime = [
        "From: alice@example.test\r\n",
        "Subject: verify your account today\r\n",
        "Authentication-Results: mx.example.test; spf=fail\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Please review https://login.example.test/now before the deadline.\r\n",
    ]
    .concat();
    let representation = build(&RepresentationSources {
        mime: mime.as_bytes(),
        findings: &[],
        envelope_sender: None,
        vip: None,
    });
    let text = compose_model_text(&representation);

    for _ in 0..20 {
        runtime.infer(&text).expect("warmup inference must run");
    }

    let mut samples = Vec::with_capacity(200);
    let mut last = None;
    for _ in 0..200 {
        let started = Instant::now();
        last = Some(runtime.infer(&text).expect("inference must run"));
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() * 50 / 100];
    let p95 = samples[samples.len() * 95 / 100];
    let max = *samples.last().expect("samples must not be empty");
    let inference = last.expect("at least one inference");
    let (argmax, score) = inference.argmax();
    let label = INLINE_ML_LABELS
        .get(argmax)
        .copied()
        .unwrap_or("<out-of-range>");
    eprintln!(
        "inline ml profile: n=200 p50={p50:?} p95={p95:?} max={max:?} \
         argmax={argmax} label={label} score={score:.6}"
    );
    eprintln!(
        "inline ml fixture probabilities: {:?}",
        inference.probabilities
    );
    eprintln!("inline ml fixture composed text: {text:?}");
    assert!(
        p95 < Duration::from_millis(500),
        "p95 inference latency {p95:?} must stay inside the stage budget"
    );
}
