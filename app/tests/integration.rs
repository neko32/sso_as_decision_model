//! End-to-end through the Axum router with Jev stubbed by wiremock.
//! `live_jev_*` calls the real API and runs only with `cargo test -- --ignored` and `API_KEY_JEV` set.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sso_decision::api::jev::{DEFAULT_MODEL, JevClient, JevConfig};
use sso_decision::api::server::{AppState, router};
use sso_decision::core::domain::ApiKey;
use sso_decision::core::engine::Engine;
use sso_decision::core::policy::PolicySet;
use tower::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn app(base_url: &str, key: &str) -> axum::Router {
    let policies =
        PolicySet::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.yaml")).unwrap();
    let client = JevClient::new(JevConfig {
        base_url: base_url.to_owned(),
        model: DEFAULT_MODEL.to_owned(),
        api_key: ApiKey::new(key).unwrap(),
        timeout: Duration::from_secs(20),
    })
    .unwrap();
    router(AppState {
        engine: Arc::new(Engine::new(policies, Arc::new(client))),
        public_base_url: "http://pdp.test".into(),
    })
}

fn jev_answers(device: &str, location: f64, risk: f64) -> Value {
    json!({
        "model": DEFAULT_MODEL,
        "answers": {
            "device_trust": {"type": "choice", "choice": device, "confidence": 0.8, "probabilities": {}},
            "location_anomaly": {"type": "noul", "noul": location},
            "time_anomaly": {"type": "noul", "noul": 0.1},
            "risk": {"type": "score", "score": risk, "confidence": 0.7, "legend": {}, "probabilities": {}}
        },
        "usage": {"input_tokens": 300, "output_tokens": 20}
    })
}

fn evaluation(roles: &[&str], resource: &str, time: &str, context: &Value) -> Value {
    let mut ctx = context.clone();
    ctx["time"] = json!(time);
    json!({
        "subject": {"type": "user", "id": "alice@example.com", "properties": {"roles": roles}},
        "resource": {"type": "app", "id": resource},
        "action": {"name": "read"},
        "context": ctx
    })
}

async fn post(app: axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::post("/access/v1/evaluation")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn jev_stub(response: ResponseTemplate, expected_calls: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(response)
        .expect(expected_calls)
        .mount(&server)
        .await;
    server
}

const OFFICE: &str = "2026-10-30T10:00:00+09:00";

#[tokio::test]
async fn allow_step_up_and_deny_from_jev_signals() {
    let cases = [
        (jev_answers("managed", 0.1, 0.3), "allow", true),
        (jev_answers("managed", 0.85, 0.6), "step_up", false),
        (jev_answers("compromised", 0.1, 2.8), "deny", false),
    ];
    for (answers, outcome, decision) in cases {
        let jev = jev_stub(ResponseTemplate::new(200).set_body_json(answers), 1).await;
        let (status, body) = post(
            app(&jev.uri(), "test-key"),
            &evaluation(&["hr"], "payroll", OFFICE, &json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["context"]["outcome"], outcome, "{body}");
        assert_eq!(body["decision"], decision);
        assert_eq!(body["context"]["model"], DEFAULT_MODEL);
    }
}

#[tokio::test]
async fn jev_failures_fail_closed() {
    for status in [401_u16, 429, 500, 529] {
        let jev = jev_stub(ResponseTemplate::new(status), 1).await;
        let (_, body) = post(
            app(&jev.uri(), "test-key"),
            &evaluation(&["hr"], "payroll", OFFICE, &json!({})),
        )
        .await;
        assert_eq!(body["context"]["outcome"], "deny");
        let last = body["context"]["trace"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert_eq!(last["source"], "system", "{body}");
    }
    let garbage = jev_stub(ResponseTemplate::new(200).set_body_string("not json"), 1).await;
    let (_, body) = post(
        app(&garbage.uri(), "test-key"),
        &evaluation(&["hr"], "payroll", OFFICE, &json!({})),
    )
    .await;
    assert_eq!(body["context"]["outcome"], "deny");

    // Nothing listening: transport error.
    let (_, body) = post(
        app("http://127.0.0.1:9", "test-key"),
        &evaluation(&["hr"], "payroll", OFFICE, &json!({})),
    )
    .await;
    assert_eq!(body["context"]["outcome"], "deny");
}

#[tokio::test]
async fn deterministic_denies_never_call_jev() {
    let jev = jev_stub(
        ResponseTemplate::new(200).set_body_json(jev_answers("managed", 0.0, 0.0)),
        0,
    )
    .await;
    let (_, body) = post(
        app(&jev.uri(), "test-key"),
        &evaluation(&["sales"], "payroll", OFFICE, &json!({})),
    )
    .await;
    assert_eq!(body["context"]["outcome"], "deny");
    assert!(body["context"].get("model").is_none());
    // MockServer verifies `expect(0)` on drop.
}

#[tokio::test]
async fn jev_receives_minimised_state() {
    let jev = jev_stub(
        ResponseTemplate::new(200).set_body_json(jev_answers("managed", 0.0, 0.0)),
        1,
    )
    .await;
    let ctx = json!({"device": {"managed": true}, "location": {"country": "JP"}});
    post(
        app(&jev.uri(), "test-key"),
        &evaluation(&["hr"], "payroll", OFFICE, &ctx),
    )
    .await;
    let sent: Value =
        serde_json::from_slice(&jev.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(sent["model"], DEFAULT_MODEL);
    assert_eq!(sent["state"]["context"]["location"]["country"], "JP");
    assert!(!sent.to_string().contains("alice@example.com"));
}

#[tokio::test]
async fn validation_errors_and_metadata_endpoints() {
    let a = app("http://127.0.0.1:9", "test-key");
    let (status, body) = post(
        a.clone(),
        &evaluation(&["Not A Role"], "payroll", OFFICE, &json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("roles"));

    let (status, _) = post(a.clone(), &json!({"subject": {}})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let res = a
        .clone()
        .oneshot(
            Request::get("/.well-known/authzen-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        meta["access_evaluation_endpoint"],
        "http://pdp.test/access/v1/evaluation"
    );

    let res = a
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "calls the real Jev API; needs API_KEY_JEV"]
async fn live_jev_distinguishes_safe_and_risky_logins() {
    let key = std::env::var("API_KEY_JEV").expect("API_KEY_JEV");
    let a = app(sso_decision::api::jev::DEFAULT_BASE_URL, &key);

    let safe = json!({
        "device": {"managed": true, "mdm": "Intune", "disk_encrypted": true, "os": "macOS 15.4", "last_patch_days": 3},
        "location": {"country": "JP", "city": "Tokyo", "network": "corporate"},
        "history": {"recent_logins": [{"time": "2026-10-29T09:12:00+09:00", "country": "JP", "city": "Tokyo"}]},
        "signals": {"failed_attempts_24h": 0}
    });
    let risky = json!({
        "device": {"managed": false, "jailbroken": true, "os": "Android 9", "last_patch_days": 900},
        "location": {"country": "BR", "city": "Sao Paulo", "network": "tor_exit_node"},
        "history": {"recent_logins": [{"time": "2026-10-30T09:40:00+09:00", "country": "JP", "city": "Tokyo"}]},
        "signals": {"failed_attempts_24h": 14}
    });

    let (_, s) = post(
        a.clone(),
        &evaluation(&["hr"], "payroll", "2026-10-30T10:00:00+09:00", &safe),
    )
    .await;
    let (_, r) = post(
        a,
        &evaluation(&["hr"], "payroll", "2026-10-30T11:00:00+09:00", &risky),
    )
    .await;
    println!("SAFE  => {}", serde_json::to_string_pretty(&s).unwrap());
    println!("RISKY => {}", serde_json::to_string_pretty(&r).unwrap());
    assert_eq!(s["context"]["outcome"], "allow");
    assert_eq!(r["context"]["outcome"], "deny");
}
