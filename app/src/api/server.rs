//! Axum router: `AuthZEN` evaluation, discovery metadata and health.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use super::authzen::{EvaluationRequest, EvaluationResponse};
use crate::core::engine::Engine;

pub const EVALUATION_PATH: &str = "/access/v1/evaluation";

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    /// Absolute base URL advertised in the `AuthZEN` discovery document.
    pub public_base_url: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(EVALUATION_PATH, post(evaluate))
        .route("/.well-known/authzen-configuration", get(discovery))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

async fn evaluate(State(state): State<AppState>, Json(req): Json<EvaluationRequest>) -> Response {
    let input = match req.into_input() {
        Ok(input) => input,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let decision = state.engine.evaluate(&input).await;
    tracing::info!(
        subject = %input.subject,
        resource = %input.resource,
        action = %input.action,
        outcome = ?decision.outcome,
        "evaluated"
    );
    Json(EvaluationResponse::from(decision)).into_response()
}

async fn discovery(State(state): State<AppState>) -> Json<serde_json::Value> {
    let base = state.public_base_url.trim_end_matches('/');
    Json(json!({
        "policy_decision_point": base,
        "access_evaluation_endpoint": format!("{base}{EVALUATION_PATH}"),
    }))
}
