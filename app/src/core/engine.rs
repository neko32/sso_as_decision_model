//! The decision pipeline: deterministic gate -> contextual signals -> combine -> trace.

use std::sync::Arc;

use chrono::{DateTime, FixedOffset, Timelike};
use serde_json::{Value, json};

use super::combiner::{Factor, Source, TraceEntry, combine};
use super::domain::{AccountStatus, ActionName, Outcome, ResourceId, RoleName, SubjectId};
use super::policy::{PolicyRule, PolicySet};
use super::signals::SignalProvider;

#[derive(Debug, Clone)]
pub struct EvaluationInput {
    pub subject: SubjectId,
    pub roles: Vec<RoleName>,
    pub account_status: AccountStatus,
    pub resource: ResourceId,
    pub action: ActionName,
    /// Request time in the user's local offset (used for business hours).
    pub time: DateTime<FixedOffset>,
    /// Free-form device / location / history context, interpreted by the decision model.
    pub context: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub outcome: Outcome,
    pub trace: Vec<TraceEntry>,
    /// Model that produced the contextual signals, if it was consulted.
    pub model: Option<String>,
}

pub struct Engine {
    policies: PolicySet,
    signals: Arc<dyn SignalProvider>,
}

impl Engine {
    #[must_use]
    pub fn new(policies: PolicySet, signals: Arc<dyn SignalProvider>) -> Self {
        Self { policies, signals }
    }

    pub async fn evaluate(&self, input: &EvaluationInput) -> Decision {
        let (mut trace, rule) = gate(&self.policies, input);
        let Some(rule) = rule else {
            // Deterministic deny: no need to spend a model call.
            return Decision {
                outcome: Outcome::Deny,
                trace,
                model: None,
            };
        };

        let state = jev_state(input);
        match self.signals.evaluate(&state).await {
            Ok(signals) => {
                trace.extend(combine(&signals, rule, &self.policies.thresholds));
                Decision {
                    outcome: worst(&trace),
                    trace,
                    model: Some(signals.model),
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "signal provider failed; failing closed");
                trace.push(TraceEntry::new(
                    Factor::Risk,
                    Source::System,
                    Outcome::Deny,
                    format!("fail-closed: {e}"),
                ));
                Decision {
                    outcome: Outcome::Deny,
                    trace,
                    model: None,
                }
            }
        }
    }
}

fn worst(trace: &[TraceEntry]) -> Outcome {
    trace
        .iter()
        .map(|e| e.effect)
        .max()
        .unwrap_or(Outcome::Deny)
}

/// Deterministic checks (Identity, Policy, Role, Time). Returns the matching rule only if all pass.
#[must_use]
pub fn gate<'p>(
    policies: &'p PolicySet,
    input: &EvaluationInput,
) -> (Vec<TraceEntry>, Option<&'p PolicyRule>) {
    let rule_entry =
        |factor, effect, detail: String| TraceEntry::new(factor, Source::Rule, effect, detail);
    let mut trace = Vec::new();

    if input.account_status != AccountStatus::Active {
        trace.push(rule_entry(
            Factor::Identity,
            Outcome::Deny,
            format!("account is {:?}", input.account_status).to_lowercase(),
        ));
        return (trace, None);
    }
    trace.push(rule_entry(
        Factor::Identity,
        Outcome::Allow,
        "account is active".into(),
    ));

    let Some(rule) = policies.find(&input.resource) else {
        trace.push(rule_entry(
            Factor::Policy,
            Outcome::Deny,
            format!("no policy for resource '{}' (default deny)", input.resource),
        ));
        return (trace, None);
    };
    if !rule.actions.contains(&input.action) {
        trace.push(rule_entry(
            Factor::Policy,
            Outcome::Deny,
            format!(
                "action '{}' is not permitted on '{}'",
                input.action, input.resource
            ),
        ));
        return (trace, None);
    }
    trace.push(rule_entry(
        Factor::Policy,
        Outcome::Allow,
        format!("policy permits '{}' on '{}'", input.action, input.resource),
    ));

    if let Some(role) = input.roles.iter().find(|r| rule.roles.contains(r)) {
        trace.push(rule_entry(
            Factor::Role,
            Outcome::Allow,
            format!("role '{role}' is authorised"),
        ))
    } else {
        trace.push(rule_entry(
            Factor::Role,
            Outcome::Deny,
            "none of the subject's roles are authorised".into(),
        ));
        return (trace, None);
    }

    if let Some(hours) = rule.hours {
        let hour = input.time.hour();
        if !hours.contains(hour) {
            trace.push(rule_entry(
                Factor::Time,
                Outcome::Deny,
                format!(
                    "{hour:02}:00 is outside allowed hours {:02}-{:02}",
                    hours.start, hours.end
                ),
            ));
            return (trace, None);
        }
        trace.push(rule_entry(
            Factor::Time,
            Outcome::Allow,
            format!(
                "{hour:02}:00 is within allowed hours {:02}-{:02}",
                hours.start, hours.end
            ),
        ));
    }

    (trace, Some(rule))
}

/// The state sent to the decision model. Data minimisation: the subject id is never sent.
#[must_use]
pub fn jev_state(input: &EvaluationInput) -> Value {
    json!({
        "subject": { "roles": input.roles },
        "resource": input.resource,
        "action": input.action,
        "request_time": input.time.to_rfc3339(),
        "context": input.context,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::domain::{DeviceTrust, Probability, RiskScore};
    use crate::core::signals::{SignalError, Signals, StaticSignalProvider};

    const POLICY: &str = "policies:\n  - {resource: payroll, actions: [read], roles: [hr], hours: {start: 7, end: 22}, require_managed_device: true}\n  - {resource: wiki, actions: [read], roles: [hr]}";

    fn input(time: &str) -> EvaluationInput {
        EvaluationInput {
            subject: SubjectId::parse("alice@example.com").unwrap(),
            roles: vec![RoleName::parse("hr").unwrap()],
            account_status: AccountStatus::Active,
            resource: ResourceId::parse("payroll").unwrap(),
            action: ActionName::parse("read").unwrap(),
            time: DateTime::parse_from_rfc3339(time).unwrap(),
            context: json!({"device": {"managed": true}}),
        }
    }

    fn signals(device: DeviceTrust, risk: f64) -> Signals {
        Signals {
            device,
            device_confidence: Probability::new(0.9).unwrap(),
            location_anomaly: Probability::new(0.1).unwrap(),
            time_anomaly: Probability::new(0.1).unwrap(),
            risk: RiskScore::new(risk).unwrap(),
            risk_confidence: Probability::new(0.8).unwrap(),
            model: "jev-test".into(),
        }
    }

    fn engine(result: Result<Signals, SignalError>) -> Engine {
        Engine::new(
            PolicySet::from_yaml(POLICY).unwrap(),
            Arc::new(StaticSignalProvider(result)),
        )
    }

    const OFFICE_HOURS: &str = "2026-10-30T10:00:00+09:00";

    #[tokio::test]
    async fn allows_when_gate_and_signals_are_clean() {
        let d = engine(Ok(signals(DeviceTrust::Managed, 0.2)))
            .evaluate(&input(OFFICE_HOURS))
            .await;
        assert_eq!(d.outcome, Outcome::Allow);
        assert_eq!(d.model.as_deref(), Some("jev-test"));
        assert_eq!(d.trace.len(), 4 + 4);
    }

    #[tokio::test]
    async fn steps_up_and_denies_from_signals() {
        let e = engine(Ok(signals(DeviceTrust::Byod, 0.2)));
        assert_eq!(
            e.evaluate(&input(OFFICE_HOURS)).await.outcome,
            Outcome::StepUp
        );
        let e = engine(Ok(signals(DeviceTrust::Managed, 2.4)));
        assert_eq!(
            e.evaluate(&input(OFFICE_HOURS)).await.outcome,
            Outcome::Deny
        );
    }

    #[tokio::test]
    async fn fails_closed_when_the_model_is_unavailable() {
        let d = engine(Err(SignalError::Overloaded))
            .evaluate(&input(OFFICE_HOURS))
            .await;
        assert_eq!(d.outcome, Outcome::Deny);
        let last = d.trace.last().unwrap();
        assert_eq!(last.source, Source::System);
        assert!(last.detail.starts_with("fail-closed"));
        assert!(d.model.is_none());
    }

    #[tokio::test]
    async fn gate_denies_without_consulting_the_model() {
        // The provider would allow, so any Deny must come from the gate.
        let e = engine(Ok(signals(DeviceTrust::Managed, 0.0)));
        let deny = |i: EvaluationInput| {
            let e = &e;
            async move { e.evaluate(&i).await }
        };

        let mut suspended = input(OFFICE_HOURS);
        suspended.account_status = AccountStatus::Suspended;
        let d = deny(suspended).await;
        assert_eq!(
            (d.outcome, d.trace[0].factor),
            (Outcome::Deny, Factor::Identity)
        );
        assert!(d.model.is_none());

        let mut unknown = input(OFFICE_HOURS);
        unknown.resource = ResourceId::parse("vault").unwrap();
        assert_eq!(deny(unknown).await.trace[1].factor, Factor::Policy);

        let mut write = input(OFFICE_HOURS);
        write.action = ActionName::parse("write").unwrap();
        assert!(deny(write).await.trace[1].detail.contains("not permitted"));

        let mut sales = input(OFFICE_HOURS);
        sales.roles = vec![RoleName::parse("sales").unwrap()];
        assert_eq!(deny(sales).await.trace[2].factor, Factor::Role);

        let late = deny(input("2026-10-30T23:30:00+09:00")).await;
        assert_eq!(
            (late.outcome, late.trace[3].factor),
            (Outcome::Deny, Factor::Time)
        );
    }

    #[tokio::test]
    async fn rules_without_hours_skip_the_time_gate() {
        let mut wiki = input("2026-10-30T23:30:00+09:00");
        wiki.resource = ResourceId::parse("wiki").unwrap();
        let d = engine(Ok(signals(DeviceTrust::Managed, 0.0)))
            .evaluate(&wiki)
            .await;
        assert_eq!(d.outcome, Outcome::Allow);
        assert_eq!(d.trace.len(), 3 + 4);
    }

    #[test]
    fn state_never_contains_the_subject_id() {
        let state = jev_state(&input(OFFICE_HOURS));
        assert!(!state.to_string().contains("alice"));
        assert_eq!(state["resource"], "payroll");
        assert_eq!(state["subject"]["roles"][0], "hr");
    }

    #[test]
    fn empty_trace_is_treated_as_deny() {
        assert_eq!(worst(&[]), Outcome::Deny);
    }
}
