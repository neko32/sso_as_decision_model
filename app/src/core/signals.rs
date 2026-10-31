//! Contextual signals (Device / Location / Time anomaly / Risk) and the provider abstraction.

use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Timelike};
use serde_json::Value;
use thiserror::Error;

use super::domain::{DeviceTrust, Probability, RiskScore};

#[derive(Debug, Clone, PartialEq)]
pub struct Signals {
    pub device: DeviceTrust,
    pub device_confidence: Probability,
    pub location_anomaly: Probability,
    pub time_anomaly: Probability,
    pub risk: RiskScore,
    pub risk_confidence: Probability,
    /// Which model (or provider) produced the signals.
    pub model: String,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SignalError {
    #[error("signal provider rejected the API key")]
    Unauthorized,
    #[error("signal provider rate limit exceeded")]
    RateLimited,
    #[error("signal provider overloaded")]
    Overloaded,
    #[error("signal provider returned HTTP {0}")]
    Upstream(u16),
    #[error("signal provider unreachable: {0}")]
    Transport(String),
    #[error("signal provider returned an unusable response: {0}")]
    InvalidResponse(String),
}

pub type SignalFuture<'a> = Pin<Box<dyn Future<Output = Result<Signals, SignalError>> + Send + 'a>>;

/// Produces contextual signals for a minimised request `state` (see `Engine::jev_state`).
pub trait SignalProvider: Send + Sync {
    fn evaluate<'a>(&'a self, state: &'a Value) -> SignalFuture<'a>;
}

/// Returns a fixed result. Used by unit tests.
pub struct StaticSignalProvider(pub Result<Signals, SignalError>);

impl SignalProvider for StaticSignalProvider {
    fn evaluate<'a>(&'a self, _state: &'a Value) -> SignalFuture<'a> {
        let result = self.0.clone();
        Box::pin(async move { result })
    }
}

/// Offline stand-in for Jev (`SIGNAL_MODE=mock`): simple heuristics over the same `state`.
/// Lets CI and Playwright run without network access or an API key.
pub struct RuleBasedSignalProvider;

impl RuleBasedSignalProvider {
    #[must_use]
    pub fn derive(state: &Value) -> Signals {
        let ctx = &state["context"];
        let device = match (&ctx["device"]["compromised"], &ctx["device"]["managed"]) {
            (Value::Bool(true), _) => DeviceTrust::Compromised,
            (_, Value::Bool(true)) => DeviceTrust::Managed,
            (_, Value::Bool(false)) => DeviceTrust::Byod,
            _ => DeviceTrust::Unknown,
        };

        let current = ctx["location"]["country"].as_str();
        let last = ctx["history"]["recent_logins"]
            .as_array()
            .and_then(|logins| logins.last())
            .and_then(|l| l["country"].as_str());
        let location = match (current, last) {
            (Some(c), Some(l)) if c.eq_ignore_ascii_case(l) => 0.1,
            (Some(_), Some(_)) => 0.9,
            _ => 0.5,
        };

        let hour = state["request_time"]
            .as_str()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.hour());
        let time = if hour.is_some_and(|h| h < 6) {
            0.8
        } else {
            0.1
        };

        let failed = ctx["signals"]["failed_attempts_24h"]
            .as_f64()
            .unwrap_or(0.0);
        let device_risk = match device {
            DeviceTrust::Compromised => 3.0,
            DeviceTrust::Unknown => 0.5,
            DeviceTrust::Managed | DeviceTrust::Byod => 0.0,
        };
        let risk = (device_risk + location * 1.2 + time * 0.5 + failed / 3.0).clamp(0.0, 3.0);

        // Every value above is constructed within range, so these cannot fail.
        let p = |v: f64| Probability::new(v).unwrap_or_else(|_| unreachable!());
        Signals {
            device,
            device_confidence: p(0.9),
            location_anomaly: p(location),
            time_anomaly: p(time),
            risk: RiskScore::new(risk).unwrap_or_else(|_| unreachable!()),
            risk_confidence: p(0.6),
            model: "rule-based-mock".to_owned(),
        }
    }
}

impl SignalProvider for RuleBasedSignalProvider {
    fn evaluate<'a>(&'a self, state: &'a Value) -> SignalFuture<'a> {
        let signals = Self::derive(state);
        Box::pin(async move { Ok(signals) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rule_based_trusts_a_familiar_managed_login() {
        let s = RuleBasedSignalProvider::derive(&json!({
            "request_time": "2026-10-30T10:00:00+09:00",
            "context": {
                "device": {"managed": true},
                "location": {"country": "JP"},
                "history": {"recent_logins": [{"country": "JP"}]}
            }
        }));
        assert_eq!(s.device, DeviceTrust::Managed);
        assert!(s.location_anomaly.value() < 0.5);
        assert!(s.time_anomaly.value() < 0.5);
        assert!(s.risk.value() < 1.0);
    }

    #[test]
    fn rule_based_flags_anomalies() {
        let s = RuleBasedSignalProvider::derive(&json!({
            "request_time": "2026-10-30T03:00:00+09:00",
            "context": {
                "device": {"managed": false},
                "location": {"country": "BR"},
                "history": {"recent_logins": [{"country": "JP"}]},
                "signals": {"failed_attempts_24h": 6}
            }
        }));
        assert_eq!(s.device, DeviceTrust::Byod);
        assert!(s.location_anomaly.value() > 0.5);
        assert!(s.time_anomaly.value() > 0.5);
        assert!(s.risk.value() >= 2.0);

        let c =
            RuleBasedSignalProvider::derive(&json!({"context": {"device": {"compromised": true}}}));
        assert_eq!(c.device, DeviceTrust::Compromised);
        assert!((c.risk.value() - 3.0).abs() < f64::EPSILON);
        assert_eq!(
            RuleBasedSignalProvider::derive(&json!({})).device,
            DeviceTrust::Unknown
        );
    }

    #[tokio::test]
    async fn providers_resolve_through_the_trait() {
        let state = json!({});
        assert!(RuleBasedSignalProvider.evaluate(&state).await.is_ok());
        let failing = StaticSignalProvider(Err(SignalError::Overloaded));
        assert_eq!(failing.evaluate(&state).await, Err(SignalError::Overloaded));
    }
}
