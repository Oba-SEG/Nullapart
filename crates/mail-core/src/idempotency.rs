//! Transactional idempotency claims for retry-sensitive administration APIs.
//!
//! The claim and the caller's mutation share one PostgreSQL transaction, so a
//! committed row always carries the stored response: a duplicate key can only
//! replay a completed request, observe another in-flight one, or reveal that
//! the key already belongs to a different operation inside the same tenant
//! scope. Every claim runs with the deployment and customer scope settings
//! set, and the claim records them so keys are isolated per tenant
//! (migration 034).

use std::time::Duration;

use serde_json::Value;
use sqlx::{Postgres, Transaction};

/// How a claim attempt resolved for this key.
pub enum ClaimOutcome {
    /// This request owns the key and may mutate.
    Fresh,
    /// The operation already completed; return the stored response.
    Replay(Value),
    /// The key is claimed but has no stored response yet.
    InProgress,
    /// The key already belongs to a different operation.
    OperationMismatch,
}

const IN_FLIGHT_RECHECK: Duration = Duration::from_millis(50);

/// Claims `key` for `operation` inside the caller's transaction.
pub async fn claim(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    operation: &str,
) -> Result<ClaimOutcome, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO idempotency_keys \
             (key, operation, result, created_at, expires_at, deployment_id, customer_id) \
         VALUES ($1, $2, NULL, now(), now() + interval '7 days', \
                 current_setting('app.current_deployment_id', true), \
                 current_setting('app.current_customer_id', true)) \
         ON CONFLICT (deployment_id, customer_id, key) DO NOTHING",
    )
    .bind(key)
    .bind(operation)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(ClaimOutcome::Fresh);
    }
    let Some((stored_operation, result)) = stored(transaction, key).await? else {
        // The conflicting row disappeared between insert and read; refusing
        // is safer than mutating without a recorded response.
        return Err(sqlx::Error::RowNotFound);
    };
    if stored_operation != operation {
        return Ok(ClaimOutcome::OperationMismatch);
    }
    if let Some(result) = result {
        return Ok(ClaimOutcome::Replay(result));
    }
    // Claim and response commit together, so a null result can only be a
    // write that is about to land: re-read once before calling it in flight.
    tokio::time::sleep(IN_FLIGHT_RECHECK).await;
    match stored(transaction, key).await? {
        Some((_, Some(result))) => Ok(ClaimOutcome::Replay(result)),
        Some(_) => Ok(ClaimOutcome::InProgress),
        None => Err(sqlx::Error::RowNotFound),
    }
}

/// Stores the response that every later replay of `key` returns.
pub async fn complete(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    operation: &str,
    result: Value,
) -> Result<(), sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE idempotency_keys SET result = $3 \
         WHERE key = $1 AND operation = $2 \
           AND deployment_id = current_setting('app.current_deployment_id', true) \
           AND customer_id = current_setting('app.current_customer_id', true)",
    )
    .bind(key)
    .bind(operation)
    .bind(sqlx::types::Json(result))
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(sqlx::Error::RowNotFound)
    }
}

async fn stored(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<Option<(String, Option<Value>)>, sqlx::Error> {
    sqlx::query_as::<_, (String, Option<Value>)>(
        "SELECT operation, result FROM idempotency_keys \
         WHERE key = $1 \
           AND deployment_id = current_setting('app.current_deployment_id', true) \
           AND customer_id = current_setting('app.current_customer_id', true)",
    )
    .bind(key)
    .fetch_optional(&mut **transaction)
    .await
}
