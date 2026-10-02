//! Nullapart Mail Core
//!
//! Core mail processing logic for the SEG.

pub mod admin_audit;
pub mod admin_customers;
pub mod admin_rbac;
pub mod artifact_recovery;
pub mod artifact_store;
pub mod auth;
pub mod delivery;
pub mod dns_txt;
pub mod handoff;
pub mod idempotency;
pub mod inline_ml;
pub mod node;
pub mod oidc;
pub mod operations_api;
pub mod outbound;
pub mod partition;
pub mod phase2_handoff;
pub mod phase2_persistence;
pub mod pipeline;
pub mod policy;
pub mod policy_admin;
pub mod quarantine;
pub mod quarantine_api;
pub mod quarantine_reinjection;
pub mod reinjection;
pub mod runtime;
pub mod scanner_adapters;
pub mod scanner_evidence;
pub mod scanner_fabric;
pub mod scanner_operations;
pub mod scanner_pipeline;
pub mod trace;
