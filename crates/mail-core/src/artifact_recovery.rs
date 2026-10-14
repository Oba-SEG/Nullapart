//! Boot-time recovery of the local filesystem artifact index from PostgreSQL.
//!
//! The local filesystem artifact store keeps its metadata index in process
//! memory while the bytes live on disk, and PostgreSQL is the authoritative
//! record of every persisted artifact. After a restart the index is empty, so
//! without this recovery a content read for an artifact whose bytes are
//! still on disk would fail closed as missing. This module rebuilds the
//! index from the `artifacts` table for one deployment: each customer's rows
//! are read inside a short transaction that sets `app.current_customer_id`
//! for that transaction only, so the existing row-level security policy is
//! satisfied exactly as it is for every other artifact query, and
//! [`FilesystemArtifactStore`] then re-verifies the on-disk file
//! (server-derived name, size and SHA-256) before the record enters process
//! state. Rows whose bytes cannot be verified — deleted, truncated, corrupt
//! or fixture rows written by tests — are skipped with a warning and stay
//! unreadable; recovery never weakens a fail-closed read.

use chrono::{DateTime, Utc};
use nullapart_mail_contracts::artifact::{
    Artifact, ArtifactHash, ArtifactId, ContentType, HashAlgorithm, RetentionClass, StorageBackend,
    StorageLocation,
};
use nullapart_mail_contracts::transaction::{CustomerId, DeploymentId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::artifact_store::FilesystemArtifactStore;

/// Outcome of one recovery pass over a deployment's persisted artifacts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArtifactRecoveryReport {
    /// Artifact rows found for the deployment across its customers.
    pub candidates: u64,
    /// Rows whose on-disk bytes were re-verified and re-indexed.
    pub recovered: u64,
    /// Rows skipped because the record or the stored bytes could not be
    /// verified.
    pub skipped: u64,
}

/// Rebuilds `store`'s in-memory artifact index from the `artifacts` table
/// for `deployment_id`.
///
/// The customer list is read first (deployment-scoped; `customers` carries
/// no tenant row-level security policy), then each customer's artifact rows
/// are selected in a transaction that sets `app.current_customer_id`
/// transaction-locally, mirroring the `set_config(..., true)` discipline
/// used by request handlers, and filtered by `customer_id` explicitly so
/// each row is visited exactly once under any database role. Reconstruction
/// follows the same strict rules
/// as the quarantine reinjection worker's row mapping: a `filesystem`
/// backend, a server-derived `<uuid>.artifact` path, a `sha256:`-prefixed
/// 64-character digest and `standard` retention; anything else is skipped,
/// not guessed. Database failures abort recovery (the caller decides
/// whether that is fatal for startup); unverifiable individual rows never
/// do.
pub async fn recover_persisted_artifacts(
    pool: &PgPool,
    store: &FilesystemArtifactStore,
    deployment_id: &str,
) -> Result<ArtifactRecoveryReport, sqlx::Error> {
    let customers = {
        // customers carries FORCE RLS (migration 034); an unscoped pool read
        // matches zero rows and recovery would silently recover nothing.
        let mut transaction = pool.begin().await?;
        sqlx::query("SELECT set_config('app.current_deployment_id', $1, true)")
            .bind(deployment_id)
            .execute(&mut *transaction)
            .await?;
        let ids = sqlx::query_scalar::<_, String>(
            "SELECT id FROM customers WHERE deployment_id = $1 ORDER BY id",
        )
        .bind(deployment_id)
        .fetch_all(&mut *transaction)
        .await?;
        transaction.commit().await?;
        ids
    };

    let mut report = ArtifactRecoveryReport::default();
    for customer in customers {
        let mut transaction = pool.begin().await?;
        sqlx::query("SELECT set_config('app.current_customer_id', $1, true)")
            .bind(&customer)
            .execute(&mut *transaction)
            .await?;
        let rows = sqlx::query(
            "SELECT id, content_type, size_bytes, content_hash, storage_backend, \
                    storage_path, retention_class, encryption_enabled, created_at \
             FROM artifacts \
             WHERE deployment_id = $1 AND customer_id = $2 AND storage_backend = 'filesystem' \
             ORDER BY id",
        )
        .bind(deployment_id)
        .bind(&customer)
        .fetch_all(&mut *transaction)
        .await?;
        transaction.commit().await?;

        for row in rows {
            report.candidates += 1;
            let artifact_id: Uuid = row.get("id");
            match artifact_from_row(&row, artifact_id, deployment_id, &customer) {
                Ok(artifact) => match store.recover_existing(artifact).await {
                    Ok(()) => report.recovered += 1,
                    Err(error) => {
                        report.skipped += 1;
                        tracing::warn!(
                            artifact_id = %artifact_id,
                            error = ?error,
                            "persisted artifact bytes could not be re-verified; staying unreadable"
                        );
                    },
                },
                Err(reason) => {
                    report.skipped += 1;
                    tracing::warn!(
                        artifact_id = %artifact_id,
                        reason,
                        "persisted artifact row does not describe a local artifact; skipped"
                    );
                },
            }
        }
    }
    Ok(report)
}

/// Reconstructs a store-compatible [`Artifact`] from one `artifacts` row by
/// decoding its columns and delegating to [`artifact_from_parts`].
fn artifact_from_row(
    row: &sqlx::postgres::PgRow,
    artifact_id: Uuid,
    deployment_id: &str,
    customer_id: &str,
) -> Result<Artifact, &'static str> {
    artifact_from_parts(ArtifactRowParts {
        artifact_id,
        deployment_id,
        customer_id,
        content_type: row.get("content_type"),
        size_bytes: row.get("size_bytes"),
        content_hash: row.get("content_hash"),
        storage_path: row.get("storage_path"),
        retention_class: row.get("retention_class"),
        encryption_enabled: row.get("encryption_enabled"),
        created_at: row.get("created_at"),
    })
}

/// The decoded columns of one `artifacts` row, passed as plain values so the
/// mapping rules are testable without a live PostgreSQL row decoder.
struct ArtifactRowParts<'a> {
    artifact_id: Uuid,
    deployment_id: &'a str,
    customer_id: &'a str,
    content_type: String,
    size_bytes: i64,
    content_hash: String,
    storage_path: String,
    retention_class: String,
    encryption_enabled: bool,
    created_at: DateTime<Utc>,
}

/// Mirrors the quarantine reinjection worker's row mapping: strict shapes
/// are rejected instead of coerced, unknown retention or hash encodings
/// never become plausible defaults, and only the columns the schema stores
/// are read — the schema carries no expiry, so the recovered record carries
/// none. `scanner_eligible` follows the same canonical reconstruction the
/// reinjection worker uses (`true`), which matches every row the production
/// pipeline writes for MIME artifacts.
fn artifact_from_parts(parts: ArtifactRowParts<'_>) -> Result<Artifact, &'static str> {
    let hash = parts
        .content_hash
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64)
        .ok_or("content hash is not a sha256 digest")?;
    if parts.storage_path != format!("{}.artifact", parts.artifact_id) {
        return Err("storage path is not server-derived");
    }
    if parts.retention_class != "standard" {
        return Err("retention class is not standard");
    }
    let size = u64::try_from(parts.size_bytes).map_err(|_| "size is negative")?;
    Ok(Artifact {
        id: ArtifactId(parts.artifact_id),
        deployment_id: DeploymentId::new(parts.deployment_id),
        customer_id: Some(CustomerId::new(parts.customer_id)),
        content_type: ContentType::new(&parts.content_type),
        size,
        storage_location: StorageLocation {
            backend: StorageBackend::Filesystem,
            bucket: None,
            key: format!("{}.artifact", parts.artifact_id),
            region: None,
        },
        hash: ArtifactHash {
            algorithm: HashAlgorithm::Sha256,
            value: hash.to_string(),
        },
        retention_class: RetentionClass::Standard,
        created_at: parts.created_at,
        expires_at: None,
        encrypted: parts.encryption_enabled,
        scanner_eligible: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_parts(id: Uuid) -> ArtifactRowParts<'static> {
        ArtifactRowParts {
            artifact_id: id,
            deployment_id: "LOCAL-TEST",
            customer_id: "local-customer",
            content_type: "message/rfc822".to_string(),
            size_bytes: 12,
            content_hash: format!("sha256:{}", "a".repeat(64)),
            storage_path: format!("{id}.artifact"),
            retention_class: "standard".to_string(),
            encryption_enabled: false,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn canonical_local_row_maps_to_a_store_ready_artifact() {
        let id = Uuid::new_v4();
        let artifact = artifact_from_parts(row_parts(id)).expect("a canonical local row must map");
        assert_eq!(artifact.id, ArtifactId(id));
        assert_eq!(artifact.deployment_id, DeploymentId::new("LOCAL-TEST"));
        assert_eq!(
            artifact.customer_id,
            Some(CustomerId::new("local-customer"))
        );
        assert_eq!(artifact.size, 12);
        assert_eq!(artifact.content_type, ContentType::new("message/rfc822"));
        assert_eq!(
            artifact.storage_location.backend,
            StorageBackend::Filesystem
        );
        assert_eq!(artifact.storage_location.key, format!("{id}.artifact"));
        assert!(artifact.storage_location.bucket.is_none());
        assert!(artifact.storage_location.region.is_none());
        assert_eq!(artifact.hash.algorithm, HashAlgorithm::Sha256);
        assert_eq!(artifact.hash.value, "a".repeat(64));
        assert_eq!(artifact.retention_class, RetentionClass::Standard);
        assert!(artifact.expires_at.is_none());
        assert!(artifact.scanner_eligible);
    }

    #[test]
    fn non_sha256_hash_encodings_are_rejected() {
        let id = Uuid::new_v4();

        let mut parts = row_parts(id);
        parts.content_hash = "deadbeef".to_string();
        assert!(artifact_from_parts(parts).is_err());

        let mut parts = row_parts(id);
        parts.content_hash = format!("sha512:{}", "a".repeat(64));
        assert!(artifact_from_parts(parts).is_err());

        let mut parts = row_parts(id);
        parts.content_hash = format!("sha256:{}", "a".repeat(63));
        assert!(artifact_from_parts(parts).is_err());
    }

    #[test]
    fn non_server_derived_storage_shapes_are_rejected() {
        let id = Uuid::new_v4();

        let mut parts = row_parts(id);
        parts.storage_path = "elsewhere.artifact".to_string();
        assert!(artifact_from_parts(parts).is_err());

        let mut parts = row_parts(id);
        parts.retention_class = "litigation".to_string();
        assert_eq!(
            artifact_from_parts(parts).unwrap_err(),
            "retention class is not standard"
        );
    }

    #[test]
    fn negative_size_is_rejected() {
        let mut parts = row_parts(Uuid::new_v4());
        parts.size_bytes = -1;
        assert_eq!(artifact_from_parts(parts).unwrap_err(), "size is negative");
    }

    #[test]
    fn report_defaults_to_empty() {
        assert_eq!(
            ArtifactRecoveryReport::default(),
            ArtifactRecoveryReport {
                candidates: 0,
                recovered: 0,
                skipped: 0,
            }
        );
    }

    #[tokio::test]
    #[ignore = "requires migrated local PostgreSQL through 015_and_NULLAPART_TEST_DATABASE_URL"]
    async fn persisted_artifacts_are_reindexed_after_a_store_restart() {
        use crate::artifact_store::{
            ArtifactAccessGrant, ArtifactAccessPurpose, ArtifactPermissions, ArtifactScope,
            ArtifactStoreError, FilesystemArtifactRuntime,
        };
        use nullapart_mail_contracts::artifact::{
            ArtifactHash, HashAlgorithm, RetentionClass, StorageBackend, StorageLocation,
        };
        use sha2::{Digest, Sha256};

        let database_url = std::env::var("NULLAPART_TEST_DATABASE_URL")
            .expect("NULLAPART_TEST_DATABASE_URL must target local test PostgreSQL");
        let pool = PgPool::connect(&database_url)
            .await
            .expect("local PostgreSQL must connect");

        let suffix = Uuid::new_v4().to_string();
        let deployment = DeploymentId::new(&format!("phase3-recovery-{suffix}"));
        let customer_a = CustomerId::new(&format!("customer-a-{suffix}"));
        let customer_b = CustomerId::new(&format!("customer-b-{suffix}"));

        sqlx::query(
            "INSERT INTO deployments (id, region, display_name) \
             VALUES ($1, 'local', 'Phase 3 artifact recovery test')",
        )
        .bind(&deployment.0)
        .execute(&pool)
        .await
        .expect("deployment fixture must insert");
        for (id, name) in [
            (&customer_a, "recovery customer A"),
            (&customer_b, "recovery customer B"),
        ] {
            sqlx::query(
                "INSERT INTO customers (id, deployment_id, display_name) VALUES ($1, $2, $3)",
            )
            .bind(&id.0)
            .bind(&deployment.0)
            .bind(name)
            .execute(&pool)
            .await
            .expect("customer fixture must insert");
        }

        let root = std::env::temp_dir().join(format!("nullapart-artifact-recovery-{suffix}"));
        std::fs::create_dir_all(&root).expect("artifact root must be created");
        let bytes = b"restart recovery evidence".to_vec();
        let hash_hex = hex::encode(Sha256::digest(&bytes));
        let artifact_a_id = ArtifactId(Uuid::new_v4());
        let artifact_b_id = ArtifactId(Uuid::new_v4());

        {
            let store = FilesystemArtifactStore::try_new(
                root.clone(),
                FilesystemArtifactRuntime::LocalDevelopment,
            )
            .await
            .expect("store must open");
            store
                .put(
                    Artifact {
                        id: artifact_a_id.clone(),
                        deployment_id: deployment.clone(),
                        customer_id: Some(customer_a.clone()),
                        content_type: ContentType::new("message/rfc822"),
                        size: bytes.len() as u64,
                        storage_location: StorageLocation {
                            backend: StorageBackend::Filesystem,
                            bucket: None,
                            key: format!("{}.artifact", artifact_a_id.0),
                            region: None,
                        },
                        hash: ArtifactHash {
                            algorithm: HashAlgorithm::Sha256,
                            value: hash_hex.clone(),
                        },
                        retention_class: RetentionClass::Standard,
                        created_at: Utc::now(),
                        expires_at: None,
                        encrypted: false,
                        scanner_eligible: true,
                    },
                    bytes.clone(),
                )
                .await
                .expect("artifact bytes must publish");
        }

        for (artifact_id, customer) in
            [(&artifact_a_id, &customer_a), (&artifact_b_id, &customer_b)]
        {
            sqlx::query(
                "INSERT INTO artifacts (id, deployment_id, customer_id, content_type, size_bytes, \
                        content_hash, storage_backend, storage_path, retention_class) \
                 VALUES ($1, $2, $3, 'message/rfc822', $4, $5, 'filesystem', $6, 'standard')",
            )
            .bind(artifact_id.0)
            .bind(&deployment.0)
            .bind(&customer.0)
            .bind(bytes.len() as i64)
            .bind(format!("sha256:{hash_hex}"))
            .bind(format!("{}.artifact", artifact_id.0))
            .execute(&pool)
            .await
            .expect("artifact fixture must insert");
        }

        let store = FilesystemArtifactStore::try_new(
            root.clone(),
            FilesystemArtifactRuntime::LocalDevelopment,
        )
        .await
        .expect("store must reopen after restart");
        let grant = ArtifactAccessGrant::issue_server_authorized(
            deployment.clone(),
            ArtifactScope::Customer(customer_a.clone()),
            "phase3-artifact-recovery-test".to_string(),
            ArtifactPermissions::content_read_only(),
            ArtifactAccessPurpose::ContentReview,
            [artifact_a_id.clone()],
            Utc::now() + chrono::Duration::seconds(60),
        )
        .expect("grant must issue");

        let before = store.get(&grant, &artifact_a_id).await;
        assert!(
            matches!(before, Err(ArtifactStoreError::NotFound)),
            "the index must be empty after a store restart before recovery"
        );

        let report = recover_persisted_artifacts(&pool, &store, &deployment.0)
            .await
            .expect("recovery must succeed");
        assert_eq!(
            report,
            ArtifactRecoveryReport {
                candidates: 2,
                recovered: 1,
                skipped: 1,
            }
        );

        let recovered = store
            .get(&grant, &artifact_a_id)
            .await
            .expect("recovered artifact bytes must be readable");
        assert_eq!(recovered.bytes, bytes);
        assert_eq!(recovered.content_type, ContentType::new("message/rfc822"));
        assert_eq!(recovered.hash.value, hash_hex);

        let missing = store.get(&grant, &artifact_b_id).await;
        assert!(
            matches!(missing, Err(ArtifactStoreError::NotFound)),
            "a row whose bytes are absent must stay unreadable"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
