//! Inline ML (Phase 4): low-latency, evidence-only threat classification.
//!
//! The model is evidence for policy, never policy itself. This module owns
//! the versioned canonical input representation the model receives; the
//! inference stage, registry and feedback surfaces attach here in later
//! increments (`docs/phases/PHASE-4-LOCAL-IMPLEMENTATION-PLAN.md`).

pub mod representation;
