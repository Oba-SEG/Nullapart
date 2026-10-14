//! Rate limiting primitives for Nullapart.
//!
//! Token-bucket algorithm backed by Redis/Valkey for distributed rate limiting.
//! Follows `docs/security/22-RATE-LIMITING-ABUSE-PROTECTION.md`.

use serde::{Deserialize, Serialize};

/// Rate limiter key components.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RateLimitKey {
    /// Rate limiter namespace (e.g., "api", "smtp", "admin").
    pub namespace: String,
    /// Principal identifier (authenticated actor, customer, IP).
    pub principal: String,
    /// Optional sub-key for route/action specificity.
    pub action: Option<String>,
}

impl RateLimitKey {
    pub fn new(namespace: &str, principal: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
            principal: principal.to_string(),
            action: None,
        }
    }

    pub fn with_action(mut self, action: &str) -> Self {
        self.action = Some(action.to_string());
        self
    }

    /// Composite key for Redis storage.
    ///
    /// Segments are percent-escaped so that `:` (the separator) and `%`
    /// (the escape character) inside a segment can never collide with a
    /// different segment layout — e.g. `("a", "b:c")` must not produce the
    /// same key as `("a:b", "c")`.
    pub fn redis_key(&self) -> String {
        fn escape(segment: &str) -> String {
            segment.replace('%', "%25").replace(':', "%3A")
        }
        match &self.action {
            Some(action) => format!(
                "rl:{}:{}:{}",
                escape(&self.namespace),
                escape(&self.principal),
                escape(action)
            ),
            None => format!("rl:{}:{}", escape(&self.namespace), escape(&self.principal)),
        }
    }
}

/// Rate limit configuration for a specific limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum tokens in the bucket (burst capacity).
    pub max_tokens: u64,
    /// Tokens added per second (sustained rate).
    pub refill_rate_per_sec: f64,
    /// Time window for sliding window limiters in seconds.
    pub window_secs: u64,
    /// Burst tolerance: how far above the steady-state rate a burst can go.
    pub burst_tolerance: u64,
    /// Action on limit exceeded.
    pub exceeded_action: ExceededAction,
    /// Reason code for observability.
    pub reason_code: String,
    /// Whether to trust forwarded IP headers from the configured LB chain.
    pub trust_forwarded_ip: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_tokens: 100,
            refill_rate_per_sec: 10.0,
            window_secs: 60,
            burst_tolerance: 20,
            exceeded_action: ExceededAction::Reject,
            reason_code: "RATE_LIMIT_EXCEEDED".to_string(),
            trust_forwarded_ip: false,
        }
    }
}

/// Action to take when rate limit is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceededAction {
    /// Reject with 429 / SMTP 452.
    Reject,
    /// Defer with SMTP 452 temporarily.
    Defer,
    /// Fail closed for high-risk actions.
    FailClosed,
    /// Allow but log for monitoring.
    AllowAndLog,
}

/// Result of a rate limit check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitResult {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Current token count.
    pub current_tokens: u64,
    /// Maximum tokens.
    pub max_tokens: u64,
    /// Time until next token is available (seconds).
    pub retry_after_secs: Option<f64>,
    /// Reason code if denied.
    pub reason_code: Option<String>,
    /// Action taken.
    pub action: ExceededAction,
}

/// High-risk action configurations with lower dedicated limits.
pub struct HighRiskLimits;

impl HighRiskLimits {
    pub fn impersonation_start() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 10,
            refill_rate_per_sec: 0.1,
            window_secs: 60,
            burst_tolerance: 2,
            exceeded_action: ExceededAction::FailClosed,
            reason_code: "HIGH_RISK_IMPERSONATION".to_string(),
            trust_forwarded_ip: false,
        }
    }

    pub fn quarantine_release() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 20,
            refill_rate_per_sec: 0.5,
            window_secs: 60,
            burst_tolerance: 5,
            exceeded_action: ExceededAction::FailClosed,
            reason_code: "HIGH_RISK_QUARANTINE_RELEASE".to_string(),
            trust_forwarded_ip: false,
        }
    }

    pub fn permission_change() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 5,
            refill_rate_per_sec: 0.05,
            window_secs: 60,
            burst_tolerance: 1,
            exceeded_action: ExceededAction::FailClosed,
            reason_code: "HIGH_RISK_PERMISSION_CHANGE".to_string(),
            trust_forwarded_ip: false,
        }
    }

    pub fn audit_export() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 10,
            refill_rate_per_sec: 0.1,
            window_secs: 60,
            burst_tolerance: 2,
            exceeded_action: ExceededAction::Reject,
            reason_code: "HIGH_RISK_AUDIT_EXPORT".to_string(),
            trust_forwarded_ip: false,
        }
    }

    pub fn attachment_download() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 30,
            refill_rate_per_sec: 1.0,
            window_secs: 60,
            burst_tolerance: 10,
            exceeded_action: ExceededAction::Reject,
            reason_code: "HIGH_RISK_ATTACHMENT_DOWNLOAD".to_string(),
            trust_forwarded_ip: false,
        }
    }

    pub fn cache_refresh() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 20,
            refill_rate_per_sec: 0.5,
            window_secs: 60,
            burst_tolerance: 5,
            exceeded_action: ExceededAction::Reject,
            reason_code: "HIGH_RISK_CACHE_REFRESH".to_string(),
            trust_forwarded_ip: false,
        }
    }
}

/// SMTP-specific rate limit configurations.
pub struct SmtpRateLimits;

impl SmtpRateLimits {
    pub fn connection_per_ip() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 50,
            refill_rate_per_sec: 5.0,
            window_secs: 60,
            burst_tolerance: 20,
            exceeded_action: ExceededAction::Defer,
            reason_code: "SMTP_CONNECTION_RATE".to_string(),
            trust_forwarded_ip: false,
        }
    }

    pub fn message_per_sender() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 200,
            refill_rate_per_sec: 10.0,
            window_secs: 60,
            burst_tolerance: 50,
            exceeded_action: ExceededAction::Defer,
            reason_code: "SMTP_MESSAGE_RATE".to_string(),
            trust_forwarded_ip: false,
        }
    }

    pub fn recipient_per_message() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 500,
            refill_rate_per_sec: 0.0,
            window_secs: 1,
            burst_tolerance: 0,
            exceeded_action: ExceededAction::Reject,
            reason_code: "SMTP_RECIPIENT_LIMIT".to_string(),
            trust_forwarded_ip: false,
        }
    }
}

/// Application-level rate limit configurations.
pub struct AppRateLimits;

impl AppRateLimits {
    pub fn api_read() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 100,
            refill_rate_per_sec: 20.0,
            window_secs: 60,
            burst_tolerance: 50,
            exceeded_action: ExceededAction::Reject,
            reason_code: "API_READ_RATE".to_string(),
            trust_forwarded_ip: true,
        }
    }

    pub fn api_mutation() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 30,
            refill_rate_per_sec: 5.0,
            window_secs: 60,
            burst_tolerance: 10,
            exceeded_action: ExceededAction::Reject,
            reason_code: "API_MUTATION_RATE".to_string(),
            trust_forwarded_ip: true,
        }
    }

    pub fn auth_initiation() -> RateLimitConfig {
        RateLimitConfig {
            max_tokens: 10,
            refill_rate_per_sec: 0.5,
            window_secs: 60,
            burst_tolerance: 3,
            exceeded_action: ExceededAction::Reject,
            reason_code: "AUTH_INITIATION_RATE".to_string(),
            trust_forwarded_ip: true,
        }
    }
}

/// Token bucket state for local (non-Redis) fallback.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub tokens: f64,
    pub max_tokens: f64,
    pub refill_rate: f64,
    pub last_refill: std::time::Instant,
}

impl TokenBucket {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            tokens: config.max_tokens as f64,
            max_tokens: config.max_tokens as f64,
            refill_rate: config.refill_rate_per_sec,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Attempt to consume one token. Returns whether allowed.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Current token count.
    pub fn available(&self) -> u64 {
        self.tokens as u64
    }

    /// Time until next token is available.
    ///
    /// Returns `None` when a token is already available. A bucket with a
    /// non-positive refill rate never recovers a token on its own; the wait
    /// is clamped to a finite cap rather than returning `inf` (which is not
    /// representable in JSON and would poison any downstream arithmetic).
    pub fn retry_after_secs(&self) -> Option<f64> {
        if self.tokens >= 1.0 {
            None
        } else if self.refill_rate <= 0.0 {
            Some(MAX_RETRY_AFTER_SECS)
        } else {
            Some((1.0 - self.tokens) / self.refill_rate)
        }
    }
}

/// Clamp for `retry_after_secs` on a bucket that never refills.
const MAX_RETRY_AFTER_SECS: f64 = 86_400.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_key_redis_format() {
        let key = RateLimitKey::new("smtp", "192.168.1.1");
        assert_eq!(key.redis_key(), "rl:smtp:192.168.1.1");

        // `:` inside the action segment is escaped so it cannot be confused
        // with a segment boundary.
        let key = key.with_action("sender:test@example.com");
        assert_eq!(
            key.redis_key(),
            "rl:smtp:192.168.1.1:sender%3Atest@example.com"
        );
    }

    #[test]
    fn rate_limit_key_segments_never_collide() {
        let a = RateLimitKey::new("a", "b").with_action("c");
        let b = RateLimitKey::new("a", "b:c");
        assert_ne!(
            a.redis_key(),
            b.redis_key(),
            "different segment layouts must map to different Redis keys"
        );

        let c = RateLimitKey::new("a:b", "c");
        assert_ne!(a.redis_key(), c.redis_key());
        assert_ne!(b.redis_key(), c.redis_key());

        // `%` must be escaped too, otherwise "%3A" inside a segment could
        // forge an escaped `:` from a literal segment boundary.
        let forged = RateLimitKey::new("a", "b%3Ac");
        assert_ne!(b.redis_key(), forged.redis_key());
        assert_eq!(forged.redis_key(), "rl:a:b%253Ac");
    }

    #[test]
    fn retry_after_on_never_refilling_bucket_is_finite() {
        let config = RateLimitConfig {
            max_tokens: 1,
            refill_rate_per_sec: 0.0,
            ..Default::default()
        };
        let mut bucket = TokenBucket::new(&config);
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume());
        let retry_after = bucket.retry_after_secs();
        assert!(retry_after.is_some());
        let retry_after = retry_after.expect("drained bucket must report a wait");
        assert!(
            retry_after.is_finite(),
            "retry_after_secs must never be inf/NaN"
        );
        assert_eq!(retry_after, MAX_RETRY_AFTER_SECS);
    }

    #[test]
    fn retry_after_on_positive_refill_rate_is_proportional() {
        let config = RateLimitConfig {
            max_tokens: 1,
            refill_rate_per_sec: 2.0,
            ..Default::default()
        };
        let mut bucket = TokenBucket::new(&config);
        assert!(bucket.try_consume());
        let retry_after = bucket.retry_after_secs().expect("drained bucket waits");
        assert!(retry_after.is_finite());
        assert!((retry_after - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn token_bucket_consume() {
        let config = RateLimitConfig {
            max_tokens: 5,
            refill_rate_per_sec: 0.0,
            ..Default::default()
        };
        let mut bucket = TokenBucket::new(&config);
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume());
    }

    #[test]
    fn token_bucket_refill() {
        let config = RateLimitConfig {
            max_tokens: 10,
            refill_rate_per_sec: 1000.0,
            ..Default::default()
        };
        let mut bucket = TokenBucket::new(&config);
        // Drain all tokens
        for _ in 0..10 {
            bucket.try_consume();
        }
        assert!(!bucket.try_consume());
        // Simulate elapsed time by manually setting last_refill to past
        bucket.last_refill = std::time::Instant::now() - std::time::Duration::from_secs(1);
        assert!(bucket.try_consume());
    }

    #[test]
    fn high_risk_limits_are_restrictive() {
        let config = HighRiskLimits::impersonation_start();
        assert_eq!(config.exceeded_action, ExceededAction::FailClosed);
        assert!(config.max_tokens <= 10);
    }

    #[test]
    fn smtp_defer_on_rate_limit() {
        let config = SmtpRateLimits::connection_per_ip();
        assert_eq!(config.exceeded_action, ExceededAction::Defer);
    }

    #[test]
    fn app_mutation_limits_tighter_than_read() {
        let read = AppRateLimits::api_read();
        let mutation = AppRateLimits::api_mutation();
        assert!(mutation.max_tokens < read.max_tokens);
    }

    #[test]
    fn default_config_has_reason_code() {
        let config = RateLimitConfig::default();
        assert!(!config.reason_code.is_empty());
    }
}
