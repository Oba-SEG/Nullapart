//! Phase 5 domain-security DNS observer and validators.
//!
//! This worker consumes the existing verified-domain and Phase 5 read-model
//! tables. It persists normalized DNS posture and notifications only; resolver
//! payloads, message content, SVG bytes and report XML are never stored.

use std::time::Duration;

use nullapart_mail_contracts::transaction::DeploymentId;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::dns_txt::DnsTxtResolver;

const DEFAULT_BIMI_SELECTOR: &str = "default";
const DKIM_SELECTORS: [&str; 3] = ["default", "selector1", "selector2"];

#[derive(Debug, Clone)]
pub struct DomainObserverConfig {
    pub poll_interval: Duration,
}

impl Default for DomainObserverConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(900),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainObserverRunOutcome {
    pub domains_checked: usize,
    pub authorizations_checked: usize,
    pub notifications_created: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DomainObserverError {
    #[error("domain observer persistence is unavailable")]
    Persistence,
}

#[derive(Debug, Clone)]
struct ObservedDomain {
    domain_id: Uuid,
    customer_id: String,
    domain: String,
}

#[derive(Debug, Clone)]
struct ReportAuthorizationRow {
    domain_id: Uuid,
    customer_id: String,
    report_host: String,
    owner_name: String,
    expected_value: String,
}

#[derive(Debug, Clone)]
struct ActiveCustomer {
    customer_id: String,
}

#[derive(Clone)]
pub struct DomainObserverWorker {
    pool: PgPool,
    resolver: DnsTxtResolver,
    deployment_id: DeploymentId,
    config: DomainObserverConfig,
}

impl DomainObserverWorker {
    pub fn new(
        pool: PgPool,
        resolver: DnsTxtResolver,
        deployment_id: DeploymentId,
        config: DomainObserverConfig,
    ) -> Self {
        Self {
            pool,
            resolver,
            deployment_id,
            config,
        }
    }

    pub async fn run(self) {
        loop {
            match self.run_once().await {
                Ok(outcome) => {
                    tracing::info!(
                        domains_checked = outcome.domains_checked,
                        authorizations_checked = outcome.authorizations_checked,
                        notifications_created = outcome.notifications_created,
                        "domain-security observer completed"
                    );
                },
                Err(error) => tracing::error!(error = %error, "domain-security observer failed"),
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    pub async fn run_once(&self) -> Result<DomainObserverRunOutcome, DomainObserverError> {
        let domains = self.load_domains().await?;
        let authorizations = self.load_authorizations().await?;
        let mut outcome = DomainObserverRunOutcome::default();

        for domain in domains {
            outcome.notifications_created += self.observe_domain(domain).await?;
            outcome.domains_checked += 1;
        }
        for authorization in authorizations {
            outcome.notifications_created += self.validate_authorization(authorization).await?;
            outcome.authorizations_checked += 1;
        }
        Ok(outcome)
    }

    async fn load_domains(&self) -> Result<Vec<ObservedDomain>, DomainObserverError> {
        let customers = self.load_active_customers().await?;
        let mut domains = Vec::new();
        for customer in customers {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| DomainObserverError::Persistence)?;
            set_scope(
                &mut transaction,
                &self.deployment_id.0,
                &customer.customer_id,
            )
            .await?;
            let rows = sqlx::query(
                "SELECT id AS domain_id, customer_id, domain \
                 FROM domains \
                 WHERE customer_id = $1 AND verification_status = 'verified' \
                 ORDER BY domain",
            )
            .bind(&customer.customer_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| DomainObserverError::Persistence)?;
            for row in rows {
                domains.push(ObservedDomain {
                    domain_id: row
                        .try_get("domain_id")
                        .map_err(|_| DomainObserverError::Persistence)?,
                    customer_id: row
                        .try_get("customer_id")
                        .map_err(|_| DomainObserverError::Persistence)?,
                    domain: row
                        .try_get("domain")
                        .map_err(|_| DomainObserverError::Persistence)?,
                });
            }
            transaction
                .commit()
                .await
                .map_err(|_| DomainObserverError::Persistence)?;
        }
        Ok(domains)
    }

    async fn load_active_customers(&self) -> Result<Vec<ActiveCustomer>, DomainObserverError> {
        sqlx::query(
            "SELECT id AS customer_id \
             FROM customers \
             WHERE deployment_id = $1 AND lifecycle = 'active' \
             ORDER BY id",
        )
        .bind(&self.deployment_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| DomainObserverError::Persistence)?
        .into_iter()
        .map(|row| {
            Ok(ActiveCustomer {
                customer_id: row
                    .try_get("customer_id")
                    .map_err(|_| DomainObserverError::Persistence)?,
            })
        })
        .collect()
    }

    async fn load_authorizations(
        &self,
    ) -> Result<Vec<ReportAuthorizationRow>, DomainObserverError> {
        let customers = self.load_active_customers().await?;
        let mut authorizations = Vec::new();
        for customer in customers {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| DomainObserverError::Persistence)?;
            set_scope(
                &mut transaction,
                &self.deployment_id.0,
                &customer.customer_id,
            )
            .await?;
            let rows = sqlx::query(
                "SELECT domain_id, customer_id, report_host, owner_name, expected_value \
                 FROM dmarc_report_authorizations \
                 WHERE deployment_id = $1 AND customer_id = $2 \
                 ORDER BY owner_name",
            )
            .bind(&self.deployment_id.0)
            .bind(&customer.customer_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| DomainObserverError::Persistence)?;
            for row in rows {
                authorizations.push(ReportAuthorizationRow {
                    domain_id: row
                        .try_get("domain_id")
                        .map_err(|_| DomainObserverError::Persistence)?,
                    customer_id: row
                        .try_get("customer_id")
                        .map_err(|_| DomainObserverError::Persistence)?,
                    report_host: row
                        .try_get("report_host")
                        .map_err(|_| DomainObserverError::Persistence)?,
                    owner_name: row
                        .try_get("owner_name")
                        .map_err(|_| DomainObserverError::Persistence)?,
                    expected_value: row
                        .try_get("expected_value")
                        .map_err(|_| DomainObserverError::Persistence)?,
                });
            }
            transaction
                .commit()
                .await
                .map_err(|_| DomainObserverError::Persistence)?;
        }
        Ok(authorizations)
    }

    async fn observe_domain(&self, domain: ObservedDomain) -> Result<usize, DomainObserverError> {
        let mx = self.mx_check(&domain.domain).await;
        let spf = self
            .txt_prefix_check(&domain.domain, "v=spf1", "SPF record published")
            .await;
        let dmarc = self.dmarc_check(&domain.domain).await;
        let dkim = self.dkim_check(&domain.domain).await;
        let mta_sts = self
            .txt_prefix_check(
                &format!("_mta-sts.{}", domain.domain),
                "v=stsv1",
                "MTA-STS TXT policy id published",
            )
            .await;
        let tls_rpt = self
            .txt_prefix_check(
                &format!("_smtp._tls.{}", domain.domain),
                "v=tlsrptv1",
                "TLS-RPT TXT policy published",
            )
            .await;
        let bimi = self.bimi_check(&domain.domain, dmarc.policy_enforced).await;
        let dmarc_problem = matches!(dmarc.observation.status.as_str(), "fail" | "warning");
        let dmarc_detail = dmarc.observation.detail.clone();
        let dkim_problem = dkim.status == "fail";
        let mta_sts_degraded = mta_sts.status == "fail";
        let tls_rpt_degraded = tls_rpt.status == "fail";
        let bimi_problem = bimi.status != "ready" && bimi.observation.status != "unknown";

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DomainObserverError::Persistence)?;
        set_scope(&mut transaction, &self.deployment_id.0, &domain.customer_id).await?;
        let mut notifications = 0usize;
        for (check_type, check) in [
            ("mx", mx),
            ("spf", spf),
            ("dmarc", dmarc.observation),
            ("dkim", dkim),
            ("mta_sts", mta_sts),
            ("tls_rpt", tls_rpt),
            ("bimi", bimi.observation.clone()),
        ] {
            insert_observation(
                &mut transaction,
                &self.deployment_id.0,
                &domain.customer_id,
                domain.domain_id,
                check_type,
                &check,
            )
            .await?;
        }
        upsert_bimi_status(
            &mut transaction,
            &self.deployment_id.0,
            &domain.customer_id,
            domain.domain_id,
            &bimi,
        )
        .await?;

        notifications += notify_if_problem(
            &mut transaction,
            &self.deployment_id.0,
            &domain.customer_id,
            Some(domain.domain_id),
            "dmarc_record_invalid",
            "warning",
            "DMARC record needs attention",
            &dmarc_detail,
            dmarc_problem,
        )
        .await?;
        notifications += notify_if_problem(
            &mut transaction,
            &self.deployment_id.0,
            &domain.customer_id,
            Some(domain.domain_id),
            "dkim_selector_failure",
            "warning",
            "No known DKIM selector resolved",
            "Known DKIM selectors default, selector1 and selector2 did not publish DKIM TXT records.",
            dkim_problem,
        )
        .await?;
        notifications += notify_if_problem(
            &mut transaction,
            &self.deployment_id.0,
            &domain.customer_id,
            Some(domain.domain_id),
            "bimi_invalid",
            "warning",
            "BIMI is not ready",
            &bimi.observation.detail,
            bimi_problem,
        )
        .await?;
        notifications += notify_if_problem(
            &mut transaction,
            &self.deployment_id.0,
            &domain.customer_id,
            Some(domain.domain_id),
            "mta_sts_degraded",
            "warning",
            "MTA-STS is not fully configured",
            "Publish _mta-sts TXT with v=STSv1 and a current policy id.",
            mta_sts_degraded,
        )
        .await?;
        notifications += notify_if_problem(
            &mut transaction,
            &self.deployment_id.0,
            &domain.customer_id,
            Some(domain.domain_id),
            "tls_rpt_degraded",
            "info",
            "TLS-RPT is not configured",
            "Publish _smtp._tls TXT with v=TLSRPTv1 to receive TLS reporting.",
            tls_rpt_degraded,
        )
        .await?;

        transaction
            .commit()
            .await
            .map_err(|_| DomainObserverError::Persistence)?;
        Ok(notifications)
    }

    async fn validate_authorization(
        &self,
        authorization: ReportAuthorizationRow,
    ) -> Result<usize, DomainObserverError> {
        let txt = self.resolver.lookup(&authorization.owner_name).await;
        let (status, actual_value, detail) = match txt {
            Ok(records)
                if records.iter().any(|value| {
                    value
                        .trim()
                        .eq_ignore_ascii_case(authorization.expected_value.trim())
                }) =>
            {
                (
                    "valid",
                    records.join("; ").chars().take(512).collect::<String>(),
                    "External DMARC report authorization is valid.".to_string(),
                )
            },
            Ok(records) if records.is_empty() => (
                "missing",
                String::new(),
                format!(
                    "Publish TXT {} = {} for report host {}.",
                    authorization.owner_name,
                    authorization.expected_value,
                    authorization.report_host
                ),
            ),
            Ok(records) => (
                "invalid",
                records.join("; ").chars().take(512).collect::<String>(),
                format!(
                    "TXT exists but does not match expected value {}.",
                    authorization.expected_value
                ),
            ),
            Err(_) => (
                "unknown",
                String::new(),
                "DNS lookup failed; retry before changing policy.".to_string(),
            ),
        };

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DomainObserverError::Persistence)?;
        set_scope(
            &mut transaction,
            &self.deployment_id.0,
            &authorization.customer_id,
        )
        .await?;
        sqlx::query(
            "UPDATE dmarc_report_authorizations \
             SET actual_value = NULLIF($1, ''), status = $2, checked_at = now(), detail = $3, updated_at = now() \
             WHERE deployment_id = $4 AND customer_id = $5 AND domain_id = $6 AND report_host = $7",
        )
        .bind(actual_value)
        .bind(status)
        .bind(&detail)
        .bind(&self.deployment_id.0)
        .bind(&authorization.customer_id)
        .bind(authorization.domain_id)
        .bind(&authorization.report_host)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DomainObserverError::Persistence)?;
        insert_observation(
            &mut transaction,
            &self.deployment_id.0,
            &authorization.customer_id,
            authorization.domain_id,
            "report_authorization",
            &Observation {
                status: if status == "valid" { "pass" } else { "fail" }.to_string(),
                observed_value: Some(authorization.owner_name.clone()),
                detail: detail.clone(),
            },
        )
        .await?;
        let notifications = notify_if_problem(
            &mut transaction,
            &self.deployment_id.0,
            &authorization.customer_id,
            Some(authorization.domain_id),
            "report_authorization_broken",
            "warning",
            "External DMARC report authorization is broken",
            &detail,
            matches!(status, "missing" | "invalid"),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| DomainObserverError::Persistence)?;
        Ok(notifications)
    }

    async fn mx_check(&self, domain: &str) -> Observation {
        match self.resolver.lookup_mx(domain).await {
            Ok(records) if !records.is_empty() => Observation::pass(
                Some(records.join(", ").chars().take(512).collect()),
                "MX records are present.",
            ),
            Ok(_) => Observation::fail(None, "No MX records were found."),
            Err(_) => Observation::unknown(None, "MX lookup failed."),
        }
    }

    async fn txt_prefix_check(&self, name: &str, prefix: &str, pass_detail: &str) -> Observation {
        match self.resolver.lookup(name).await {
            Ok(records) if records.iter().any(|value| value_has_prefix(value, prefix)) => {
                Observation::pass(
                    records
                        .iter()
                        .find(|value| value_has_prefix(value, prefix))
                        .map(|value| value.chars().take(512).collect()),
                    pass_detail,
                )
            },
            Ok(_) => Observation::fail(None, "Expected TXT record was not found."),
            Err(_) => Observation::unknown(None, "DNS TXT lookup failed."),
        }
    }

    async fn dkim_check(&self, domain: &str) -> Observation {
        let mut resolved = Vec::new();
        let mut completed_lookup = false;
        for selector in DKIM_SELECTORS {
            let name = format!("{selector}._domainkey.{domain}");
            if let Ok(records) = self.resolver.lookup(&name).await {
                completed_lookup = true;
                if records
                    .iter()
                    .any(|value| value_has_prefix(value, "v=dkim1"))
                {
                    resolved.push(selector);
                }
            }
        }
        if !resolved.is_empty() {
            Observation::pass(
                Some(resolved.join(",")),
                "At least one known DKIM selector publishes a DKIM record.",
            )
        } else if completed_lookup {
            Observation::fail(None, "No known DKIM selectors resolved.")
        } else {
            Observation::unknown(None, "DKIM selector lookups failed.")
        }
    }

    async fn dmarc_check(&self, domain: &str) -> DmarcCheck {
        let name = format!("_dmarc.{domain}");
        match self.resolver.lookup(&name).await {
            Ok(records) => {
                let record = records
                    .iter()
                    .find(|value| value_has_prefix(value, "v=dmarc1"));
                match record {
                    Some(value) => {
                        let policy = tag_value(value, "p").unwrap_or_else(|| "none".to_string());
                        let enforced = matches!(policy.as_str(), "quarantine" | "reject");
                        DmarcCheck {
                            policy_enforced: enforced,
                            observation: if enforced {
                                Observation::pass(
                                    Some(value.chars().take(512).collect()),
                                    "DMARC policy is enforced.",
                                )
                            } else {
                                Observation::warning(
                                    Some(value.chars().take(512).collect()),
                                    "DMARC exists but is not yet enforced.",
                                )
                            },
                        }
                    },
                    None => DmarcCheck {
                        policy_enforced: false,
                        observation: Observation::fail(None, "DMARC TXT record was not found."),
                    },
                }
            },
            Err(_) => DmarcCheck {
                policy_enforced: false,
                observation: Observation::unknown(None, "DMARC lookup failed."),
            },
        }
    }

    async fn bimi_check(&self, domain: &str, dmarc_enforced: bool) -> BimiCheck {
        let name = format!("{DEFAULT_BIMI_SELECTOR}._bimi.{domain}");
        match self.resolver.lookup(&name).await {
            Ok(records) => {
                let record = records
                    .iter()
                    .find(|value| value_has_prefix(value, "v=bimi1"));
                let Some(record) = record else {
                    return BimiCheck::not_ready(
                        None,
                        None,
                        "unknown",
                        if dmarc_enforced {
                            "enforced"
                        } else {
                            "not_enforced"
                        },
                        "BIMI TXT record was not found.",
                    );
                };
                let logo_url = tag_value(record, "l");
                let cert_url = tag_value(record, "a");
                let svg_status = match logo_url.as_deref() {
                    Some(value) if safe_bimi_svg_url(value) => "not_checked",
                    Some(_) => "invalid",
                    None => "invalid",
                };
                let certificate_status = match cert_url.as_deref() {
                    Some(value) if safe_https_url(value) => "unknown",
                    Some(_) => "invalid",
                    None => "missing",
                };
                let ready =
                    dmarc_enforced && svg_status != "invalid" && certificate_status == "unknown";
                BimiCheck {
                    selector: DEFAULT_BIMI_SELECTOR.to_string(),
                    record_value: Some(record.chars().take(512).collect()),
                    logo_url,
                    status: if ready { "ready" } else { "not_ready" }.to_string(),
                    svg_status: svg_status.to_string(),
                    dmarc_enforcement_status: if dmarc_enforced {
                        "enforced".to_string()
                    } else {
                        "not_enforced".to_string()
                    },
                    certificate_status: certificate_status.to_string(),
                    errors: bimi_errors(dmarc_enforced, svg_status, certificate_status),
                    observation: if ready {
                        Observation::pass(
                            Some(name),
                            "BIMI record is present and prerequisites are ready for safe validation.",
                        )
                    } else {
                        Observation::warning(
                            Some(name),
                            "BIMI exists but readiness prerequisites are incomplete.",
                        )
                    },
                }
            },
            Err(_) => BimiCheck::not_ready(
                None,
                None,
                "unknown",
                if dmarc_enforced {
                    "enforced"
                } else {
                    "not_enforced"
                },
                "BIMI lookup failed.",
            ),
        }
    }
}

#[derive(Debug, Clone)]
struct DmarcCheck {
    policy_enforced: bool,
    observation: Observation,
}

#[derive(Debug, Clone)]
struct BimiCheck {
    selector: String,
    record_value: Option<String>,
    logo_url: Option<String>,
    status: String,
    svg_status: String,
    dmarc_enforcement_status: String,
    certificate_status: String,
    errors: Vec<String>,
    observation: Observation,
}

impl BimiCheck {
    fn not_ready(
        record_value: Option<String>,
        logo_url: Option<String>,
        svg_status: &str,
        dmarc_enforcement_status: &str,
        detail: &str,
    ) -> Self {
        Self {
            selector: DEFAULT_BIMI_SELECTOR.to_string(),
            record_value,
            logo_url,
            status: "not_ready".to_string(),
            svg_status: svg_status.to_string(),
            dmarc_enforcement_status: dmarc_enforcement_status.to_string(),
            certificate_status: "unknown".to_string(),
            errors: vec![detail.to_string()],
            observation: Observation::warning(None, detail),
        }
    }
}

#[derive(Debug, Clone)]
struct Observation {
    status: String,
    observed_value: Option<String>,
    detail: String,
}

impl Observation {
    fn pass(observed_value: Option<String>, detail: &str) -> Self {
        Self {
            status: "pass".to_string(),
            observed_value,
            detail: detail.to_string(),
        }
    }

    fn warning(observed_value: Option<String>, detail: &str) -> Self {
        Self {
            status: "warning".to_string(),
            observed_value,
            detail: detail.to_string(),
        }
    }

    fn fail(observed_value: Option<String>, detail: &str) -> Self {
        Self {
            status: "fail".to_string(),
            observed_value,
            detail: detail.to_string(),
        }
    }

    fn unknown(observed_value: Option<String>, detail: &str) -> Self {
        Self {
            status: "unknown".to_string(),
            observed_value,
            detail: detail.to_string(),
        }
    }
}

async fn set_scope(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &str,
    customer_id: &str,
) -> Result<(), DomainObserverError> {
    sqlx::query(
        "SELECT set_config('app.current_deployment_id', $1, true), \
                set_config('app.current_customer_id', $2, true)",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(|_| DomainObserverError::Persistence)
}

async fn insert_observation(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &str,
    customer_id: &str,
    domain_id: Uuid,
    check_type: &str,
    observation: &Observation,
) -> Result<(), DomainObserverError> {
    sqlx::query(
        "INSERT INTO domain_security_observations (\
             deployment_id, customer_id, domain_id, check_type, status, observed_value, detail, observed_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, now())",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(domain_id)
    .bind(check_type)
    .bind(&observation.status)
    .bind(&observation.observed_value)
    .bind(observation.detail.chars().take(512).collect::<String>())
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(|_| DomainObserverError::Persistence)
}

async fn upsert_bimi_status(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &str,
    customer_id: &str,
    domain_id: Uuid,
    bimi: &BimiCheck,
) -> Result<(), DomainObserverError> {
    sqlx::query(
        "INSERT INTO bimi_domain_status (\
             deployment_id, customer_id, domain_id, selector, record_value, logo_url, status, \
             svg_status, dmarc_enforcement_status, certificate_status, errors, checked_at\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,now()) \
         ON CONFLICT (deployment_id, domain_id, selector) DO UPDATE SET \
             record_value = EXCLUDED.record_value, \
             logo_url = EXCLUDED.logo_url, \
             status = EXCLUDED.status, \
             svg_status = EXCLUDED.svg_status, \
             dmarc_enforcement_status = EXCLUDED.dmarc_enforcement_status, \
             certificate_status = EXCLUDED.certificate_status, \
             errors = EXCLUDED.errors, \
             checked_at = EXCLUDED.checked_at, \
             updated_at = now()",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(domain_id)
    .bind(&bimi.selector)
    .bind(&bimi.record_value)
    .bind(&bimi.logo_url)
    .bind(&bimi.status)
    .bind(&bimi.svg_status)
    .bind(&bimi.dmarc_enforcement_status)
    .bind(&bimi.certificate_status)
    .bind(serde_json::to_value(&bimi.errors).unwrap_or_else(|_| serde_json::json!([])))
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(|_| DomainObserverError::Persistence)
}

#[allow(clippy::too_many_arguments)]
async fn notify_if_problem(
    transaction: &mut Transaction<'_, Postgres>,
    deployment_id: &str,
    customer_id: &str,
    domain_id: Option<Uuid>,
    notification_type: &str,
    severity: &str,
    title: &str,
    detail: &str,
    condition: bool,
) -> Result<usize, DomainObserverError> {
    if !condition {
        return Ok(0);
    }
    let result = sqlx::query(
        "INSERT INTO domain_security_notifications (\
             deployment_id, customer_id, domain_id, notification_type, severity, title, detail\
         ) \
         SELECT $1,$2,$3,$4,$5,$6,$7 \
         WHERE NOT EXISTS (\
             SELECT 1 FROM domain_security_notifications \
             WHERE deployment_id = $1 AND customer_id = $2 \
               AND notification_type = $4 \
               AND status = 'open' \
               AND (domain_id IS NOT DISTINCT FROM $3)\
         )",
    )
    .bind(deployment_id)
    .bind(customer_id)
    .bind(domain_id)
    .bind(notification_type)
    .bind(severity)
    .bind(title)
    .bind(detail.chars().take(512).collect::<String>())
    .execute(&mut **transaction)
    .await
    .map_err(|_| DomainObserverError::Persistence)?;
    Ok(result.rows_affected() as usize)
}

fn value_has_prefix(value: &str, prefix: &str) -> bool {
    value.trim_start().to_ascii_lowercase().starts_with(prefix)
}

fn tag_value(record: &str, tag: &str) -> Option<String> {
    for part in record.split(';') {
        let (key, value) = part.trim().split_once('=')?;
        if key.trim().eq_ignore_ascii_case(tag) {
            let value = value.trim();
            if !value.is_empty() && value.len() <= 512 {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn safe_https_url(value: &str) -> bool {
    value.starts_with("https://")
        && !value.contains(['\r', '\n', '<', '>', '"', '\''])
        && value.len() <= 512
}

fn safe_bimi_svg_url(value: &str) -> bool {
    safe_https_url(value)
        && value
            .split('?')
            .next()
            .is_some_and(|path| path.to_ascii_lowercase().ends_with(".svg"))
}

fn bimi_errors(dmarc_enforced: bool, svg_status: &str, certificate_status: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if !dmarc_enforced {
        errors.push("DMARC policy must be quarantine or reject".to_string());
    }
    if svg_status == "invalid" {
        errors.push("BIMI logo URL must be a safe HTTPS SVG URL".to_string());
    }
    if certificate_status == "missing" {
        errors.push("BIMI certificate URL is missing".to_string());
    }
    if certificate_status == "invalid" {
        errors.push("BIMI certificate URL is invalid".to_string());
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tag_values_without_exposing_raw_dns_shape() {
        let record = "v=BIMI1; l=https://brand.example/logo.svg; a=https://brand.example/vmc.pem";
        assert_eq!(
            tag_value(record, "l"),
            Some("https://brand.example/logo.svg".to_string())
        );
        assert_eq!(tag_value(record, "x"), None);
    }

    #[test]
    fn bimi_svg_url_validation_is_shape_only_and_rejects_active_payloads() {
        assert!(safe_bimi_svg_url("https://brand.example/logo.svg"));
        assert!(safe_bimi_svg_url("https://brand.example/logo.svg?cache=1"));
        assert!(!safe_bimi_svg_url("http://brand.example/logo.svg"));
        assert!(!safe_bimi_svg_url("data:image/svg+xml,<svg></svg>"));
        assert!(!safe_bimi_svg_url("https://brand.example/logo.png"));
    }
}
