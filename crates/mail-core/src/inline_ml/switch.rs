//! Server-authoritative feature-switch resolution for the inline ML stage.
//!
//! The stage consults the reviewed `feature_definitions`/`feature_overrides`
//! pair through the same [`FeatureEvaluator`] precedence model as the admin
//! API (`docs/29-TENANT-FEATURE-ROUTING.md`): system kill switch, mandatory
//! floor, deployment override, tenant override, then default. A resolution
//! error is fail-to-off: an unreadable switch never invents capability and
//! never produces failure evidence noise — pass-1 deterministic coverage is
//! unaffected either way.

use chrono::Utc;
use nullapart_mail_contracts::{CustomerId, DeploymentId, FeatureId};
use nullapart_policy::FeatureEvaluator;
use sqlx::PgPool;
use tracing::warn;

#[derive(Clone)]
pub struct FeatureSwitchResolver {
    pool: PgPool,
}

impl FeatureSwitchResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Resolve one feature to its effective enabled state for this
    /// deployment/customer context. Any database, scope or evaluation
    /// error resolves to `false` (switch not evaluated) and is logged.
    pub async fn is_enabled(
        &self,
        feature_id: &FeatureId,
        deployment_id: &DeploymentId,
        customer_id: &CustomerId,
    ) -> bool {
        let mut transaction = match self.pool.begin().await {
            Ok(transaction) => transaction,
            Err(_) => {
                warn!(feature = %feature_id.0, "feature switch transaction failed");
                return false;
            },
        };
        if crate::policy_admin::set_scope(&mut transaction, &deployment_id.0, &customer_id.0)
            .await
            .is_err()
        {
            warn!(feature = %feature_id.0, "feature switch scope failed");
            return false;
        }
        let definitions = match crate::policy_admin::load_definitions(
            &mut transaction,
            crate::policy_admin::FEATURE_DEFINITIONS_SQL,
            None,
        )
        .await
        {
            Ok(definitions) => definitions,
            Err(_) => {
                warn!(feature = %feature_id.0, "feature definitions load failed");
                return false;
            },
        };
        let overrides = match crate::policy_admin::load_overrides(&mut transaction).await {
            Ok(overrides) => overrides,
            Err(_) => {
                warn!(feature = %feature_id.0, "feature overrides load failed");
                return false;
            },
        };
        if transaction.commit().await.is_err() {
            warn!(feature = %feature_id.0, "feature switch commit failed");
            return false;
        }

        let applicable = overrides
            .into_iter()
            .filter(|loaded| loaded.item.feature_id == *feature_id)
            .map(|loaded| loaded.item)
            .collect::<Vec<_>>();
        let now = Utc::now();
        match FeatureEvaluator::new(definitions).evaluate(
            feature_id,
            deployment_id,
            customer_id,
            &applicable,
            now,
        ) {
            Ok(evaluation) => evaluation.value.is_enabled(),
            Err(_) => {
                warn!(feature = %feature_id.0, "feature switch evaluation failed");
                false
            },
        }
    }
}
