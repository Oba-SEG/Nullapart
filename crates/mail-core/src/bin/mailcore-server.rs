//! Loopback Mail Core HTTP runtime for mail-node internal APIs.
//!
//! The server binds to loopback by default. Handoff authentication is mandatory;
//! the process refuses to start without the per-deployment HMAC secret.

use std::{env, path::PathBuf, sync::Arc, time::Duration};

use nullapart_mail_contracts::{transaction::DeploymentId, ScannerType};
use nullapart_mail_core::admin_audit::{admin_audit_router, AdminAuditState};
use nullapart_mail_core::admin_customers::{admin_customers_router, AdminCustomersState};
use nullapart_mail_core::admin_rbac::{
    admin_rbac_router, authenticated_local_router, AdminRbacState, ControlPlaneTemplate,
    SessionConfig,
};
use nullapart_mail_core::artifact_recovery::recover_persisted_artifacts;
use nullapart_mail_core::artifact_store::{FilesystemArtifactRuntime, FilesystemArtifactStore};
use nullapart_mail_core::deep_ai::{deep_ai_router, DeepAiState};
use nullapart_mail_core::dmarc_ingress::{DmarcReportIngressConfig, DmarcReportIngressWorker};
use nullapart_mail_core::dns_txt::DnsTxtResolver;
use nullapart_mail_core::domain_observer::{DomainObserverConfig, DomainObserverWorker};
use nullapart_mail_core::domain_security::{domain_security_router, DomainSecurityState};
use nullapart_mail_core::handoff::HandoffConfig;
use nullapart_mail_core::inline_ml::stage::InlineMlStage;
use nullapart_mail_core::model_registry::{model_registry_router, ModelRegistryState};
use nullapart_mail_core::operations_api::{operations_router, OperationsState};
use nullapart_mail_core::outbound_intelligence_api::{
    outbound_intelligence_router, OutboundIntelligenceApiState,
};
use nullapart_mail_core::phase2_handoff::{durable_handoff_router, DurableHandoffState};
use nullapart_mail_core::policy_admin::{policy_admin_router, AdminPolicyState};
use nullapart_mail_core::quarantine::{PostgresQuarantineRepository, QuarantineService};
use nullapart_mail_core::quarantine_api::{quarantine_router, QuarantineApiState};
use nullapart_mail_core::quarantine_reinjection::{
    QuarantineReinjectionConfig, QuarantineReinjectionWorker,
};
use nullapart_mail_core::scanner_adapters::{
    AttachmentAnalysisScanner, ClamAvScanner, StaticRuleScanner, UrlReputationScanner,
};
use nullapart_mail_core::scanner_fabric::{
    ScannerFabric, ScannerFabricConfig, ScannerProfile, ScannerRegistration, ScannerRequirement,
    ScannerResourceLimits,
};
use nullapart_mail_core::scanner_operations::{scanner_operations_router, ScannerOperationsState};
use nullapart_mail_core::scanner_pipeline::DurableScannerPipeline;
use nullapart_mail_core::trace::{mail_trace_router, trace_router, MailTraceState, TraceConfig};
use nullapart_policy::{CustomerLifecycle, RegionId};
use nullapart_scanner_sdk::trait_defs::{Scanner, ScannerId};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .try_init()
        .map_err(|_| "structured tracing subscriber initialization failed")?;

    let deployment_id = DeploymentId::new(
        &env::var("NULLAPART_DEPLOYMENT_ID").map_err(|_| "NULLAPART_DEPLOYMENT_ID is required")?,
    );
    let node_id = env::var("NULLAPART_NODE_ID").map_err(|_| "NULLAPART_NODE_ID is required")?;
    let node_version = env!("CARGO_PKG_VERSION").to_string();

    let handoff_secret = env::var("NULLAPART_HANDOFF_HMAC_SECRET")
        .map_err(|_| "NULLAPART_HANDOFF_HMAC_SECRET is required")?;
    let handoff_key_id =
        env::var("NULLAPART_HANDOFF_HMAC_KEY_ID").unwrap_or_else(|_| "mail-handoff-v1".into());

    let handoff_config = HandoffConfig {
        deployment_id: deployment_id.clone(),
        node_id: node_id.clone(),
        max_message_size: 52_428_800,
        hmac_secret: Some(handoff_secret),
        hmac_key_id: handoff_key_id,
        signature_max_age_secs: 300,
        signature_future_skew_secs: 30,
    };

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;
    validate_database_role(&pool).await?;
    let artifact_root = PathBuf::from(
        env::var("NULLAPART_ARTIFACT_ROOT")
            .unwrap_or_else(|_| "/var/lib/nullapart/artifacts".to_string()),
    );
    let artifact_store = FilesystemArtifactStore::try_new(
        artifact_root,
        FilesystemArtifactRuntime::LocalDevelopment,
    )
    .await?;
    let artifact_recovery =
        recover_persisted_artifacts(&pool, &artifact_store, &deployment_id.0).await?;
    tracing::info!(
        candidates = artifact_recovery.candidates,
        recovered = artifact_recovery.recovered,
        skipped = artifact_recovery.skipped,
        "artifact index recovered from database"
    );
    let scanner_fabric = Arc::new(local_scanner_fabric()?);
    let quarantine_api = local_quarantine_api(
        &pool,
        &deployment_id,
        &node_id,
        Arc::clone(&scanner_fabric),
        &artifact_store,
    )
    .await?;
    let inline_ml_stage =
        Arc::new(InlineMlStage::from_environment(pool.clone(), deployment_id.clone()).await);
    let pipeline =
        DurableScannerPipeline::new_shared(artifact_store.clone(), scanner_fabric, pool.clone())
            .with_inline_ml(Some(inline_ml_stage));
    let handoff = durable_handoff_router(DurableHandoffState::new(
        handoff_config,
        pool.clone(),
        pipeline,
        artifact_store.clone(),
    ));
    let reinjection_worker = QuarantineReinjectionWorker::new(
        pool.clone(),
        artifact_store.clone(),
        QuarantineReinjectionConfig {
            endpoint: env::var("NULLAPART_POSTFIX_REINJECTION_ENDPOINT")
                .unwrap_or_else(|_| "127.0.0.1:10026".to_string()),
            timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(5),
            max_attempts: 3,
        },
    );
    tokio::spawn(reinjection_worker.run());
    if env::var("NULLAPART_DMARC_INGRESS_WORKER_ENABLED")
        .map(|value| value != "false")
        .unwrap_or(true)
    {
        let dmarc_ingress_worker = DmarcReportIngressWorker::new(
            pool.clone(),
            artifact_store.clone(),
            deployment_id.clone(),
            DmarcReportIngressConfig::default(),
        );
        tokio::spawn(dmarc_ingress_worker.run());
    }
    if env::var("NULLAPART_DOMAIN_OBSERVER_WORKER_ENABLED")
        .map(|value| value != "false")
        .unwrap_or(true)
    {
        let domain_observer_worker = DomainObserverWorker::new(
            pool.clone(),
            DnsTxtResolver::from_env(),
            deployment_id.clone(),
            DomainObserverConfig::default(),
        );
        tokio::spawn(domain_observer_worker.run());
    }

    let mut trace_config = TraceConfig {
        deployment_id,
        node_id,
        node_version,
        config_revision: env::var("NULLAPART_CONFIG_REVISION").ok(),
        workload_token_sha256: None,
        pool: pool.clone(),
    };
    if let Ok(token) = env::var("NULLAPART_TRACE_WORKLOAD_TOKEN") {
        if !token.is_empty() {
            trace_config.set_workload_token(&token);
        }
    }

    let app = handoff
        .merge(quarantine_api)
        .merge(trace_router(trace_config))
        .layer(axum::extract::DefaultBodyLimit::max(52_428_800));
    let bind = env::var("NULLAPART_MAILCORE_BIND").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let private_container_bind = bind.starts_with("0.0.0.0:")
        && matches!(
            env::var("NULLAPART_ENVIRONMENT").as_deref(),
            Ok("local") | Ok("dev")
        )
        && env::var("NULLAPART_ALLOW_PRIVATE_NETWORK_BIND").as_deref() == Ok("true");
    if !bind.starts_with("127.0.0.1:") && !bind.starts_with("[::1]:") && !private_container_bind {
        return Err("Mail Core must bind to loopback or an explicitly approved local private container network".into());
    }

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(bind = %bind, "Mail Core internal server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseRolePosture {
    role_name: String,
    superuser: bool,
    bypass_rls: bool,
    owns_protected_table: bool,
}

fn require_restricted_database_role(posture: &DatabaseRolePosture) -> Result<(), &'static str> {
    if posture.superuser || posture.bypass_rls || posture.owns_protected_table {
        return Err(
            "Mail Core database role must be non-superuser, NOBYPASSRLS, and not own protected tables",
        );
    }
    Ok(())
}

async fn validate_database_role(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user::text AS role_name, role.rolsuper AS superuser, \
                role.rolbypassrls AS bypass_rls, \
                EXISTS ( \
                    SELECT 1 FROM pg_catalog.pg_class AS class \
                    JOIN pg_catalog.pg_namespace AS namespace \
                      ON namespace.oid = class.relnamespace \
                    WHERE namespace.nspname = 'public' \
                      AND class.relname IN ( \
                          'tenant_message_instances', 'tenant_message_recipients', \
                          'artifacts', 'scanner_results', 'security_findings', \
                          'quarantine_cases', 'quarantine_reinjection_envelopes', \
                          'reinjection_deliveries', 'reinjection_dead_letters', \
                          'audit_events', 'outbox_events', 'inline_ml_models' \
                          , 'deep_ai_skills', 'deep_ai_model_releases', \
                          'deep_ai_regional_benchmarks', 'deep_ai_training_datasets', \
                          'deep_ai_artifact_access_grants', 'deep_ai_analysis_results' \
                      ) \
                      AND class.relowner = role.oid \
                ) AS owns_protected_table \
         FROM pg_catalog.pg_roles AS role WHERE role.rolname = current_user",
    )
    .fetch_one(pool)
    .await?;
    let posture = DatabaseRolePosture {
        role_name: row.get("role_name"),
        superuser: row.get("superuser"),
        bypass_rls: row.get("bypass_rls"),
        owns_protected_table: row.get("owns_protected_table"),
    };
    require_restricted_database_role(&posture)?;
    tracing::info!(database_role = %posture.role_name, "Mail Core database role posture verified");
    Ok(())
}

async fn local_quarantine_api(
    pool: &sqlx::PgPool,
    deployment_id: &DeploymentId,
    node_id: &str,
    scanner_fabric: Arc<ScannerFabric>,
    artifact_store: &FilesystemArtifactStore,
) -> Result<axum::Router, Box<dyn std::error::Error>> {
    if !matches!(
        env::var("NULLAPART_ENVIRONMENT").as_deref(),
        Ok("local") | Ok("dev")
    ) {
        return Err("the embedded quarantine API is restricted to local/dev".into());
    }
    let token = env::var("NULLAPART_LOCAL_CONTROL_TOKEN")
        .map_err(|_| "NULLAPART_LOCAL_CONTROL_TOKEN is required")?;
    let customer_id = env::var("NULLAPART_LOCAL_CONTROL_CUSTOMER_ID")
        .map_err(|_| "NULLAPART_LOCAL_CONTROL_CUSTOMER_ID is required")?;
    let customer = sqlx::query(
        "SELECT internal_key, display_name FROM customers \
         WHERE id = $1 AND deployment_id = $2 AND lifecycle = 'active'",
    )
    .bind(&customer_id)
    .bind(&deployment_id.0)
    .fetch_optional(pool)
    .await?
    .ok_or("configured local control customer is not active")?;
    let template = ControlPlaneTemplate {
        region: RegionId::new("local"),
        customer_id: nullapart_mail_contracts::CustomerId::new(&customer_id),
        customer_internal_key: customer.get("internal_key"),
        customer_display_name: customer.get("display_name"),
        customer_lifecycle: CustomerLifecycle::Active,
        config_revision: 1,
    };
    // Server-authoritative identity mode: boundary proxy header (default)
    // or OIDC. Invalid configuration fails startup rather than silently
    // falling back to a weaker mode.
    let identity = nullapart_mail_core::oidc::IdentityConfig::from_env()?;
    let rbac_state = AdminRbacState::postgres(
        pool.clone(),
        token,
        deployment_id.clone(),
        template,
        SessionConfig::default(),
        identity,
    )?;
    let repository = std::sync::Arc::new(PostgresQuarantineRepository::new(pool.clone()));
    let service = QuarantineService::new(repository);
    let routes = quarantine_router(QuarantineApiState::new(service))
        .merge(scanner_operations_router(ScannerOperationsState::new(
            pool.clone(),
            scanner_fabric,
            deployment_id.clone(),
            node_id.to_string(),
        )))
        .merge(admin_audit_router(AdminAuditState::postgres(
            pool.clone(),
            deployment_id.clone(),
        )))
        .merge(admin_customers_router(AdminCustomersState::new(
            pool.clone(),
            deployment_id.clone(),
        )))
        .merge(policy_admin_router(AdminPolicyState::new(
            pool.clone(),
            deployment_id.clone(),
        )))
        .merge(model_registry_router(ModelRegistryState::new(
            pool.clone(),
            deployment_id.clone(),
        )))
        .merge(operations_router(OperationsState::new(
            pool.clone(),
            deployment_id.clone(),
        )))
        .merge(domain_security_router(DomainSecurityState::new(
            pool.clone(),
            deployment_id.clone(),
        )))
        .merge(deep_ai_router(DeepAiState::new(
            pool.clone(),
            deployment_id.clone(),
        )))
        .merge(outbound_intelligence_router(
            OutboundIntelligenceApiState::new(pool.clone(), deployment_id.clone()),
        ))
        .merge(admin_rbac_router(rbac_state.clone()))
        .merge(mail_trace_router(MailTraceState::new(
            pool.clone(),
            deployment_id.clone(),
            artifact_store.clone(),
        )));
    Ok(authenticated_local_router(routes, rbac_state))
}

fn local_scanner_fabric() -> Result<ScannerFabric, Box<dyn std::error::Error>> {
    const MAX_INPUT: u64 = 50 * 1024 * 1024;
    let scanners: Vec<(Arc<dyn Scanner>, ScannerType, ScannerRequirement)> = vec![
        (
            Arc::new(ClamAvScanner::new(
                env::var("NULLAPART_CLAMAV_ENDPOINT").unwrap_or_else(|_| "clamav:3310".to_string()),
                MAX_INPUT,
            )),
            ScannerType::Clamav,
            ScannerRequirement::Required,
        ),
        (
            Arc::new(AttachmentAnalysisScanner::new(MAX_INPUT, 100_000_000)),
            ScannerType::Attachment,
            ScannerRequirement::Required,
        ),
        (
            Arc::new(StaticRuleScanner::new(MAX_INPUT)),
            ScannerType::Custom,
            ScannerRequirement::Required,
        ),
        (
            Arc::new(UrlReputationScanner::new(MAX_INPUT, Vec::new())),
            ScannerType::UrlAnalysis,
            ScannerRequirement::Optional,
        ),
    ];
    let registrations = scanners
        .into_iter()
        .map(|(scanner, scanner_type, requirement)| ScannerRegistration {
            profile: ScannerProfile {
                scanner_id: ScannerId::new(&scanner.id().0),
                scanner_type,
                requirement,
                max_input_bytes: MAX_INPUT,
                timeout: Duration::from_secs(10),
                max_concurrency: 2,
                limits: ScannerResourceLimits::bounded_default(MAX_INPUT),
            },
            scanner,
        })
        .collect();
    Ok(ScannerFabric::new(
        ScannerFabricConfig {
            max_concurrent_scans: 4,
        },
        registrations,
    )?)
}

#[cfg(test)]
mod database_role_tests {
    use super::{require_restricted_database_role, DatabaseRolePosture};

    fn posture(
        superuser: bool,
        bypass_rls: bool,
        owns_protected_table: bool,
    ) -> DatabaseRolePosture {
        DatabaseRolePosture {
            role_name: "mailcore-test".to_string(),
            superuser,
            bypass_rls,
            owns_protected_table,
        }
    }

    #[test]
    fn accepts_a_restricted_non_owner_role() {
        assert!(require_restricted_database_role(&posture(false, false, false)).is_ok());
    }

    #[test]
    fn rejects_superuser_bypass_and_table_ownership() {
        assert!(require_restricted_database_role(&posture(true, false, false)).is_err());
        assert!(require_restricted_database_role(&posture(false, true, false)).is_err());
        assert!(require_restricted_database_role(&posture(false, false, true)).is_err());
    }
}
