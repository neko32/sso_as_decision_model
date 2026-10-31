//! Turns contextual signals into per-factor effects using policy thresholds.

use serde::Serialize;

use super::domain::{DeviceTrust, Outcome};
use super::policy::{PolicyRule, Thresholds};
use super::signals::Signals;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Factor {
    Identity,
    Policy,
    Role,
    Time,
    Device,
    Location,
    Risk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Deterministic rule evaluated in Rust.
    Rule,
    /// Contextual signal from the decision model (Jev or the offline mock).
    Model,
    /// Fail-closed handling of an infrastructure error.
    System,
}

/// One line of the decision trace: which factor, who judged it, what it did and why.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TraceEntry {
    pub factor: Factor,
    pub source: Source,
    pub effect: Outcome,
    pub detail: String,
}

impl TraceEntry {
    #[must_use]
    pub fn new(factor: Factor, source: Source, effect: Outcome, detail: impl Into<String>) -> Self {
        Self {
            factor,
            source,
            effect,
            detail: detail.into(),
        }
    }
}

#[must_use]
pub fn combine(s: &Signals, rule: &PolicyRule, t: &Thresholds) -> Vec<TraceEntry> {
    let model =
        |factor, effect, detail: String| TraceEntry::new(factor, Source::Model, effect, detail);

    let device_effect = match s.device {
        DeviceTrust::Compromised => Outcome::Deny,
        DeviceTrust::Unknown => Outcome::StepUp,
        DeviceTrust::Byod if rule.require_managed_device => Outcome::StepUp,
        DeviceTrust::Managed | DeviceTrust::Byod => Outcome::Allow,
    };
    let threshold = |value: f64, limit: f64| {
        if value >= limit {
            Outcome::StepUp
        } else {
            Outcome::Allow
        }
    };
    let risk = s.risk.value();
    let risk_effect = if risk >= t.deny_risk {
        Outcome::Deny
    } else {
        threshold(risk, t.step_up_risk)
    };

    vec![
        model(
            Factor::Device,
            device_effect,
            format!(
                "device judged '{}' (confidence {:.2}){}",
                s.device.as_str(),
                s.device_confidence.value(),
                if rule.require_managed_device {
                    "; resource requires a managed device"
                } else {
                    ""
                }
            ),
        ),
        model(
            Factor::Location,
            threshold(s.location_anomaly.value(), t.step_up_location),
            format!(
                "P(implausible location) = {:.2} (step-up at {:.2})",
                s.location_anomaly.value(),
                t.step_up_location
            ),
        ),
        model(
            Factor::Time,
            threshold(s.time_anomaly.value(), t.step_up_time),
            format!(
                "P(unusual login time) = {:.2} (step-up at {:.2})",
                s.time_anomaly.value(),
                t.step_up_time
            ),
        ),
        model(
            Factor::Risk,
            risk_effect,
            format!(
                "expected risk {:.2} of 3 (confidence {:.2}; step-up at {:.2}, deny at {:.2})",
                risk,
                s.risk_confidence.value(),
                t.step_up_risk,
                t.deny_risk
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::domain::{Probability, ResourceId, RiskScore};

    fn signals(device: DeviceTrust, location: f64, time: f64, risk: f64) -> Signals {
        Signals {
            device,
            device_confidence: Probability::new(0.9).unwrap(),
            location_anomaly: Probability::new(location).unwrap(),
            time_anomaly: Probability::new(time).unwrap(),
            risk: RiskScore::new(risk).unwrap(),
            risk_confidence: Probability::new(0.8).unwrap(),
            model: "test".into(),
        }
    }

    fn rule(require_managed_device: bool) -> PolicyRule {
        PolicyRule {
            resource: ResourceId::parse("payroll").unwrap(),
            actions: vec![],
            roles: vec![],
            hours: None,
            require_managed_device,
        }
    }

    fn effects(s: &Signals, r: &PolicyRule) -> Vec<Outcome> {
        combine(s, r, &Thresholds::default())
            .iter()
            .map(|e| e.effect)
            .collect()
    }

    #[test]
    fn clean_signals_allow_everything() {
        let e = effects(&signals(DeviceTrust::Managed, 0.1, 0.1, 0.2), &rule(true));
        assert_eq!(e, vec![Outcome::Allow; 4]);
    }

    #[test]
    fn device_trust_maps_to_effects() {
        let first = |d, managed| effects(&signals(d, 0.0, 0.0, 0.0), &rule(managed))[0];
        assert_eq!(first(DeviceTrust::Compromised, false), Outcome::Deny);
        assert_eq!(first(DeviceTrust::Unknown, false), Outcome::StepUp);
        assert_eq!(first(DeviceTrust::Byod, true), Outcome::StepUp);
        assert_eq!(first(DeviceTrust::Byod, false), Outcome::Allow);
    }

    #[test]
    fn thresholds_are_inclusive_boundaries() {
        let t = Thresholds::default();
        let e = effects(
            &signals(
                DeviceTrust::Managed,
                t.step_up_location,
                t.step_up_time,
                t.step_up_risk,
            ),
            &rule(false),
        );
        assert_eq!(
            e,
            vec![
                Outcome::Allow,
                Outcome::StepUp,
                Outcome::StepUp,
                Outcome::StepUp
            ]
        );
        let deny = effects(
            &signals(DeviceTrust::Managed, 0.0, 0.0, t.deny_risk),
            &rule(false),
        );
        assert_eq!(deny[3], Outcome::Deny);
        let below = effects(
            &signals(DeviceTrust::Managed, 0.59, 0.69, 0.99),
            &rule(false),
        );
        assert_eq!(below, vec![Outcome::Allow; 4]);
    }

    #[test]
    fn trace_details_explain_the_numbers() {
        let trace = combine(
            &signals(DeviceTrust::Byod, 0.75, 0.1, 1.5),
            &rule(true),
            &Thresholds::default(),
        );
        assert!(trace[0].detail.contains("requires a managed device"));
        assert!(trace[1].detail.contains("0.75"));
        assert!(trace.iter().all(|e| e.source == Source::Model));
    }
}
