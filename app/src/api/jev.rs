//! HTTP client for Jev (`TypeSafe` System One). One batched call answers all signal questions.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::core::domain::{ApiKey, DeviceTrust, Probability, RiskScore};
use crate::core::signals::{SignalError, SignalFuture, SignalProvider, Signals};

pub const DEFAULT_BASE_URL: &str = "https://api.typesafe.ai";
/// Pinned on purpose: aliases such as `jev-latest` can change decisions when a new release ships.
pub const DEFAULT_MODEL: &str = "jev-1.14.0";

const RISK_LEVELS: [&str; 4] = [
    "Low: consistent with the user's normal behaviour",
    "Medium: some unusual signals, worth verifying",
    "High: several strong indicators of account takeover or misuse",
    "Critical: almost certainly malicious",
];

#[derive(Debug, Clone)]
pub struct JevConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: ApiKey,
    pub timeout: Duration,
}

pub struct JevClient {
    http: reqwest::Client,
    endpoint: String,
    model: String,
    api_key: ApiKey,
}

impl JevClient {
    /// # Errors
    /// Returns an error when the HTTP client cannot be constructed (e.g. TLS backend failure).
    pub fn new(cfg: JevConfig) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder().timeout(cfg.timeout).build()?;
        Ok(Self {
            http,
            endpoint: format!("{}/v1/systemone", cfg.base_url.trim_end_matches('/')),
            model: cfg.model,
            api_key: cfg.api_key,
        })
    }

    #[must_use]
    pub fn build_request(&self, state: &Value) -> Value {
        json!({ "model": self.model, "state": state, "questions": questions() })
    }

    async fn call(&self, state: &Value) -> Result<Signals, SignalError> {
        let response = self
            .http
            .post(&self.endpoint)
            .bearer_auth(self.api_key.expose())
            .json(&self.build_request(state))
            .send()
            .await
            .map_err(|e| SignalError::Transport(e.without_url().to_string()))?;

        match response.status() {
            s if s.is_success() => {}
            StatusCode::UNAUTHORIZED => return Err(SignalError::Unauthorized),
            StatusCode::TOO_MANY_REQUESTS => return Err(SignalError::RateLimited),
            s if s.as_u16() == 529 => return Err(SignalError::Overloaded),
            s => return Err(SignalError::Upstream(s.as_u16())),
        }

        let body: JevResponse = response
            .json()
            .await
            .map_err(|e| SignalError::InvalidResponse(e.without_url().to_string()))?;
        parse_answers(body)
    }
}

impl SignalProvider for JevClient {
    fn evaluate<'a>(&'a self, state: &'a Value) -> SignalFuture<'a> {
        Box::pin(self.call(state))
    }
}

/// The typed questions asked about every request state.
#[must_use]
pub fn questions() -> Value {
    json!({
        "device_trust": {
            "type": "choice",
            "instructions": "Classify how trustworthy the device in context.device is for corporate SSO.",
            "criteria": {
                "managed": "Corporate-managed device in good health (MDM enrolled, encrypted, recently patched)",
                "byod": "Personal device that looks healthy but is not corporate-managed",
                "unknown": "Not enough device information to judge, or the device has never been seen",
                "compromised": "Signs of compromise: jailbroken/rooted, malware, disabled protections, or tampered posture"
            }
        },
        "location_anomaly": {
            "type": "noul",
            "instructions": "Compare context.location with context.history.recent_logins and request_time. Is the current location implausible for this user (e.g. impossible travel, anonymising network, or a country never seen before)?"
        },
        "time_anomaly": {
            "type": "noul",
            "instructions": "Is request_time unusual for this user compared with the times in context.history.recent_logins?"
        },
        "risk": {
            "type": "score",
            "instructions": "Considering every signal in this state (roles, resource sensitivity, device, location, time, failed attempts), how risky is granting this SSO request?",
            "criteria": RISK_LEVELS
        }
    })
}

#[derive(Debug, Deserialize)]
pub struct JevResponse {
    pub model: String,
    pub answers: HashMap<String, Answer>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Answer {
    Noul {
        noul: f64,
    },
    Choice {
        choice: String,
        confidence: f64,
    },
    Score {
        score: f64,
        confidence: f64,
    },
    #[serde(other)]
    Other,
}

/// Maps Jev answers to validated signals. Anything missing or out of range is an error (-> fail-closed).
///
/// # Errors
/// Returns [`SignalError::InvalidResponse`] when an answer is missing, has the wrong type or is out of range.
pub fn parse_answers(body: JevResponse) -> Result<Signals, SignalError> {
    let invalid = |m: String| SignalError::InvalidResponse(m);
    let prob =
        |name: &str, v: f64| Probability::new(v).map_err(|e| invalid(format!("{name}: {e}")));
    let get = |name: &str| {
        body.answers
            .get(name)
            .ok_or_else(|| invalid(format!("missing answer '{name}'")))
    };
    let noul = |name: &str| match get(name)? {
        Answer::Noul { noul } => prob(name, *noul),
        _ => Err(invalid(format!("'{name}' is not a noul answer"))),
    };

    let (device, device_confidence) = match get("device_trust")? {
        Answer::Choice { choice, confidence } => (
            DeviceTrust::from_name(choice)
                .ok_or_else(|| invalid(format!("unknown device choice '{choice}'")))?,
            prob("device_trust", *confidence)?,
        ),
        _ => return Err(invalid("'device_trust' is not a choice answer".into())),
    };
    let (risk, risk_confidence) = match get("risk")? {
        Answer::Score { score, confidence } => (
            RiskScore::new(*score).map_err(|e| invalid(format!("risk: {e}")))?,
            prob("risk", *confidence)?,
        ),
        _ => return Err(invalid("'risk' is not a score answer".into())),
    };

    Ok(Signals {
        device,
        device_confidence,
        location_anomaly: noul("location_anomaly")?,
        time_anomaly: noul("time_anomaly")?,
        risk,
        risk_confidence,
        model: body.model,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(answers: Value) -> JevResponse {
        serde_json::from_value(json!({"model": "jev-1.14.0", "answers": answers, "usage": {"input_tokens": 1, "output_tokens": 1}})).unwrap()
    }

    fn good() -> Value {
        json!({
            "device_trust": {"type": "choice", "choice": "byod", "confidence": 0.7, "probabilities": {}},
            "location_anomaly": {"type": "noul", "noul": 0.2},
            "time_anomaly": {"type": "noul", "noul": 0.05},
            "risk": {"type": "score", "score": 1.3, "confidence": 0.5, "legend": {}, "probabilities": {}}
        })
    }

    #[test]
    fn parses_a_complete_answer_set() {
        let s = parse_answers(response(good())).unwrap();
        assert_eq!(s.device, DeviceTrust::Byod);
        assert!((s.risk.value() - 1.3).abs() < f64::EPSILON);
        assert_eq!(s.model, "jev-1.14.0");
    }

    #[test]
    fn rejects_missing_mistyped_or_out_of_range_answers() {
        let mutate = |key: &str, v: Value| {
            let mut a = good();
            a[key] = v;
            parse_answers(response(a))
        };
        let mut missing = good();
        missing.as_object_mut().unwrap().remove("risk");
        assert!(parse_answers(response(missing)).is_err());
        assert!(mutate("risk", json!({"type": "noul", "noul": 0.1})).is_err());
        assert!(
            mutate(
                "risk",
                json!({"type": "score", "score": 7.0, "confidence": 0.5})
            )
            .is_err()
        );
        assert!(
            mutate(
                "device_trust",
                json!({"type": "choice", "choice": "toaster", "confidence": 0.5})
            )
            .is_err()
        );
        assert!(
            mutate(
                "device_trust",
                json!({"type": "box", "box": {}, "confidence": null})
            )
            .is_err()
        );
        assert!(mutate("location_anomaly", json!({"type": "noul", "noul": 1.5})).is_err());
        assert!(
            mutate(
                "time_anomaly",
                json!({"type": "score", "score": 1.0, "confidence": 0.5})
            )
            .is_err()
        );
    }

    #[test]
    fn request_pins_model_and_asks_all_questions() {
        let client = JevClient::new(JevConfig {
            base_url: "http://localhost/".into(),
            model: DEFAULT_MODEL.into(),
            api_key: ApiKey::new("k").unwrap(),
            timeout: Duration::from_secs(1),
        })
        .unwrap();
        assert_eq!(client.endpoint, "http://localhost/v1/systemone");
        let req = client.build_request(&json!({"x": 1}));
        assert_eq!(req["model"], DEFAULT_MODEL);
        let q = req["questions"].as_object().unwrap();
        assert_eq!(q.len(), 4);
        assert_eq!(q["risk"]["criteria"].as_array().unwrap().len(), 4);
    }
}
