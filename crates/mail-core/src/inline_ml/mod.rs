//! Inline ML (Phase 4): low-latency, evidence-only threat classification.
//!
//! The model is evidence for policy, never policy itself. This module owns
//! the versioned canonical input representation, the model-text contract,
//! the ONNX runtime, the scanner adapter, the feature-switch resolver and
//! the pass-2 stage (`docs/phases/PHASE-4-LOCAL-IMPLEMENTATION-PLAN.md`,
//! increments 1-3); registry, threshold policy, feedback and shadow
//! evaluation attach here in later increments.

pub mod adapter;
pub mod model_text;
pub mod representation;
pub mod runtime;
pub mod stage;
pub mod switch;
pub mod thresholds;
