//! Nullapart Policy Engine
//!
//! Policy evaluation and decision making.
//! The core policy evaluation engine (rule matching, condition evaluation, reason codes)
//! is implemented in `nullapart_mail_core::policy`. This crate provides the feature
//! evaluator and tenant context foundations.

pub mod feature_evaluator;
pub mod tenant_context;

pub use feature_evaluator::*;
pub use tenant_context::*;
