//! `OpenID` `AuthZEN` Access Evaluation API request/response shapes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::combiner::TraceEntry;
use crate::core::domain::{
    AccountStatus, ActionName, Outcome, ResourceId, RoleName, SubjectId, ValidationError,
};
use crate::core::engine::{Decision, EvaluationInput};

#[derive(Debug, Deserialize)]
pub struct EvaluationRequest {
    pub subject: Subject,
    pub resource: Resource,
    pub action: Action,
    #[serde(default)]
    pub context: Value,
}

#[derive(Debug, Deserialize)]
pub struct Subject {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub properties: SubjectProperties,
}

#[derive(Debug, Deserialize)]
pub struct SubjectProperties {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default = "default_status")]
    pub account_status: String,
}

fn default_status() -> String {
    "active".to_owned()
}

impl Default for SubjectProperties {
    fn default() -> Self {
        Self {
            roles: Vec::new(),
            account_status: default_status(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Resource {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct Action {
    pub name: String,
}

impl EvaluationRequest {
    /// Validates the request into domain types. `context.time` defaults to now (UTC).
    ///
    /// # Errors
    /// Returns [`ValidationError`] for any invalid field.
    pub fn into_input(self) -> Result<EvaluationInput, ValidationError> {
        let time = match self.context.get("time") {
            None | Some(Value::Null) => Utc::now().fixed_offset(),
            Some(Value::String(t)) => DateTime::parse_from_rfc3339(t)
                .map_err(|e| ValidationError::InvalidTime(e.to_string()))?,
            Some(other) => {
                return Err(ValidationError::InvalidTime(format!(
                    "expected string, got {other}"
                )));
            }
        };
        Ok(EvaluationInput {
            subject: SubjectId::parse(&self.subject.id)?,
            roles: self
                .subject
                .properties
                .roles
                .iter()
                .map(|r| RoleName::parse(r))
                .collect::<Result<_, _>>()?,
            account_status: AccountStatus::parse(&self.subject.properties.account_status)?,
            resource: ResourceId::parse(&self.resource.id)?,
            action: ActionName::parse(&self.action.name)?,
            time,
            context: self.context,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EvaluationResponse {
    /// `AuthZEN` boolean decision. `step_up` is `false` until the user completes MFA.
    pub decision: bool,
    pub context: ResponseContext,
}

#[derive(Debug, Serialize)]
pub struct ResponseContext {
    pub outcome: Outcome,
    pub reason_admin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub trace: Vec<TraceEntry>,
}

impl From<Decision> for EvaluationResponse {
    fn from(d: Decision) -> Self {
        let reason_admin = d
            .trace
            .iter()
            .filter(|e| e.effect == d.outcome && e.effect != Outcome::Allow)
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        let reason_admin = if reason_admin.is_empty() {
            "all checks passed".to_owned()
        } else {
            reason_admin
        };
        Self {
            decision: d.outcome == Outcome::Allow,
            context: ResponseContext {
                outcome: d.outcome,
                reason_admin,
                model: d.model,
                trace: d.trace,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::combiner::{Factor, Source};
    use serde_json::json;

    fn request(context: Value) -> EvaluationRequest {
        serde_json::from_value(json!({
            "subject": {"type": "user", "id": "bob@example.com", "properties": {"roles": ["engineer"]}},
            "resource": {"type": "app", "id": "wiki"},
            "action": {"name": "read"},
            "context": context
        }))
        .unwrap()
    }

    #[test]
    fn converts_a_valid_request() {
        let input = request(json!({"time": "2026-10-30T10:00:00+09:00"}))
            .into_input()
            .unwrap();
        assert_eq!(input.account_status, AccountStatus::Active);
        assert_eq!(input.roles[0].as_str(), "engineer");
        assert_eq!(input.time.to_rfc3339(), "2026-10-30T10:00:00+09:00");
        assert!(request(Value::Null).into_input().is_ok());
    }

    #[test]
    fn rejects_bad_time_values() {
        assert!(matches!(
            request(json!({"time": "yesterday"})).into_input(),
            Err(ValidationError::InvalidTime(_))
        ));
        assert!(matches!(
            request(json!({"time": 5})).into_input(),
            Err(ValidationError::InvalidTime(_))
        ));
    }

    #[test]
    fn response_explains_non_allow_outcomes() {
        let entry =
            |effect, detail: &str| TraceEntry::new(Factor::Device, Source::Model, effect, detail);
        let step_up: EvaluationResponse = Decision {
            outcome: Outcome::StepUp,
            trace: vec![
                entry(Outcome::Allow, "fine"),
                entry(Outcome::StepUp, "byod"),
            ],
            model: Some("jev-1.14.0".into()),
        }
        .into();
        assert!(!step_up.decision);
        assert_eq!(step_up.context.reason_admin, "byod");

        let allow: EvaluationResponse = Decision {
            outcome: Outcome::Allow,
            trace: vec![entry(Outcome::Allow, "fine")],
            model: None,
        }
        .into();
        assert!(allow.decision);
        assert_eq!(allow.context.reason_admin, "all checks passed");
        let json = serde_json::to_value(&allow).unwrap();
        assert_eq!(json["context"]["outcome"], "allow");
        assert!(json["context"].get("model").is_none());
    }
}
