//! Multi-window, multi-burn-rate SLO evaluator (`docs/30-RELIABILITY-SLO-ERROR-BUDGETS.md`).
//!
//! Pure evaluation only: no metrics collection, no alert delivery. Callers
//! supply window SLI observations (event and error counts over a window) and
//! the deployment's thresholds; this module reports which threshold pairs
//! currently breach. Alert *routing*, ownership and runbook links are
//! caller concerns (the doc's alert-requirements list).
//!
//! Burn rate for an availability SLO is the error-budget consumption rate:
//!
//! ```text
//! burn = (errors / events) / (1 - slo_availability)
//! ```
//!
//! A 99.9% SLO with 1% observed errors burns at 10x. Every threshold
//! requires BOTH its long and short window to breach (the SRE-workbook
//! pattern), so momentary spikes alone never page.

use std::time::Duration;

/// Availability SLO target, e.g. 0.999 for 99.9%.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AvailabilitySlo(pub f64);

impl AvailabilitySlo {
    /// Validate the SLO is a probability in (0, 1).
    pub fn validate(self) -> Result<Self, BurnRateError> {
        if self.0.is_finite() && self.0 > 0.0 && self.0 < 1.0 {
            Ok(self)
        } else {
            Err(BurnRateError::InvalidSlo)
        }
    }

    fn budget(self) -> f64 {
        1.0 - self.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BurnRateError {
    #[error("availability SLO must be a finite probability in (0,1)")]
    InvalidSlo,
    #[error("window event counts must be finite and errors cannot exceed events")]
    InvalidWindow,
    #[error("threshold burn rate must be finite and positive")]
    InvalidThreshold,
}

/// Observed SLI counts for one evaluation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSli {
    pub events: u64,
    pub errors: u64,
}

impl WindowSli {
    /// Burn rate of this window against the SLO budget.
    pub fn burn_rate(self, slo: AvailabilitySlo) -> Result<f64, BurnRateError> {
        if self.errors > self.events {
            return Err(BurnRateError::InvalidWindow);
        }
        if self.events == 0 {
            // No traffic: no evidence of budget consumption; never page.
            return Ok(0.0);
        }
        Ok((self.errors as f64 / self.events as f64) / slo.budget())
    }
}

/// One multi-window burn-rate threshold (SRE-workbook style).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BurnRateThreshold {
    /// Burn-rate multiple that must be reached in BOTH windows.
    pub burn_rate: f64,
    pub long_window: Duration,
    pub short_window: Duration,
}

impl BurnRateThreshold {
    pub fn validate(self) -> Result<Self, BurnRateError> {
        if self.burn_rate.is_finite() && self.burn_rate > 0.0 {
            Ok(self)
        } else {
            Err(BurnRateError::InvalidThreshold)
        }
    }
}

/// The baseline production alert set from `docs/30` §"Burn-rate alerting".
pub const BASELINE_THRESHOLDS: [BurnRateThreshold; 3] = [
    // Fast page: severe rapid consumption; both windows must breach.
    BurnRateThreshold {
        burn_rate: 14.4,
        long_window: Duration::from_secs(60 * 60),
        short_window: Duration::from_secs(5 * 60),
    },
    // Sustained page: slower but urgent.
    BurnRateThreshold {
        burn_rate: 6.0,
        long_window: Duration::from_secs(6 * 60 * 60),
        short_window: Duration::from_secs(30 * 60),
    },
    // Slow burn: ticket-grade response, not a page. The long window is
    // intentionally multi-day and is calibrated after production behavior
    // is understood (doc: "Exact low-burn windows may be tuned").
    BurnRateThreshold {
        burn_rate: 1.0,
        long_window: Duration::from_secs(7 * 24 * 60 * 60),
        short_window: Duration::from_secs(60 * 60),
    },
];

/// A breached threshold with the per-window burn rates that caused it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BurnRateAlert {
    pub threshold: BurnRateThreshold,
    pub long_window_burn: f64,
    pub short_window_burn: f64,
}

/// SLI observations keyed by window length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowObservation {
    pub window: Duration,
    pub sli: WindowSli,
}

/// Evaluate every threshold: an alert fires only when the SAME threshold's
/// long AND short window SLIs both reach its burn rate. Missing windows are
/// treated as non-breaching (absent evidence never pages).
pub fn evaluate(
    slo: AvailabilitySlo,
    thresholds: &[BurnRateThreshold],
    observations: &[WindowObservation],
) -> Result<Vec<BurnRateAlert>, BurnRateError> {
    let slo = slo.validate()?;
    let mut alerts = Vec::new();
    for threshold in thresholds {
        threshold.validate()?;
        let long = observations
            .iter()
            .find(|observation| observation.window == threshold.long_window)
            .and_then(|observation| observation.sli.burn_rate(slo).ok());
        let short = observations
            .iter()
            .find(|observation| observation.window == threshold.short_window)
            .and_then(|observation| observation.sli.burn_rate(slo).ok());
        if let (Some(long), Some(short)) = (long, short) {
            if long >= threshold.burn_rate && short >= threshold.burn_rate {
                alerts.push(BurnRateAlert {
                    threshold: *threshold,
                    long_window_burn: long,
                    short_window_burn: short,
                });
            }
        }
    }
    Ok(alerts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLO: AvailabilitySlo = AvailabilitySlo(0.999);

    fn observation(window_secs: u64, error_rate: f64) -> WindowObservation {
        let events = 100_000u64;
        WindowObservation {
            window: Duration::from_secs(window_secs),
            sli: WindowSli {
                events,
                errors: (events as f64 * error_rate) as u64,
            },
        }
    }

    #[test]
    fn healthy_traffic_produces_no_alerts() {
        let observations = [
            observation(3600, 0.0001),
            observation(300, 0.0001),
            observation(6 * 3600, 0.0001),
            observation(1800, 0.0001),
        ];
        let alerts = evaluate(SLO, &BASELINE_THRESHOLDS, &observations).expect("valid input");
        assert!(
            alerts.is_empty(),
            "healthy traffic must not alert: {alerts:?}"
        );
    }

    #[test]
    fn fast_page_requires_both_windows() {
        // 1.5% errors on a 99.9% SLO = 15x burn (above the 14.4x page).
        let observations = [observation(3600, 0.015), observation(300, 0.015)];
        let alerts = evaluate(SLO, &BASELINE_THRESHOLDS, &observations).expect("valid input");
        assert!(alerts.iter().any(|alert| alert.threshold.burn_rate == 14.4));
        // Short window alone must not page.
        let short_only = [observation(300, 0.015)];
        let alerts = evaluate(SLO, &BASELINE_THRESHOLDS, &short_only).expect("valid input");
        assert!(alerts.is_empty(), "short window alone must not page");
        // Long window alone must not page.
        let long_only = [observation(3600, 0.015)];
        let alerts = evaluate(SLO, &BASELINE_THRESHOLDS, &long_only).expect("valid input");
        assert!(alerts.is_empty(), "long window alone must not page");
    }

    #[test]
    fn sustained_page_burns_at_six_x() {
        // 0.65% errors = 6.5x burn over the sustained windows.
        let observations = [observation(6 * 3600, 0.0065), observation(1800, 0.0065)];
        let alerts = evaluate(SLO, &BASELINE_THRESHOLDS, &observations).expect("valid input");
        assert!(alerts.iter().any(|alert| alert.threshold.burn_rate == 6.0));
        assert!(!alerts.iter().any(|alert| alert.threshold.burn_rate == 14.4));
    }

    #[test]
    fn zero_events_never_alert() {
        let observations = [
            WindowObservation {
                window: Duration::from_secs(3600),
                sli: WindowSli {
                    events: 0,
                    errors: 0,
                },
            },
            WindowObservation {
                window: Duration::from_secs(300),
                sli: WindowSli {
                    events: 0,
                    errors: 0,
                },
            },
        ];
        let alerts = evaluate(SLO, &BASELINE_THRESHOLDS, &observations).expect("valid input");
        assert!(alerts.is_empty());
    }

    #[test]
    fn errors_exceeding_events_is_an_error_not_an_alert() {
        let slo = SLO.validate().expect("valid slo");
        let sli = WindowSli {
            events: 10,
            errors: 11,
        };
        assert_eq!(sli.burn_rate(slo), Err(BurnRateError::InvalidWindow));
    }

    #[test]
    fn invalid_slo_and_thresholds_are_rejected() {
        assert_eq!(
            AvailabilitySlo(1.0).validate(),
            Err(BurnRateError::InvalidSlo)
        );
        assert_eq!(
            AvailabilitySlo(f64::NAN).validate(),
            Err(BurnRateError::InvalidSlo)
        );
        assert_eq!(
            BurnRateThreshold {
                burn_rate: 0.0,
                long_window: Duration::from_secs(60),
                short_window: Duration::from_secs(5),
            }
            .validate(),
            Err(BurnRateError::InvalidThreshold)
        );
    }
}
