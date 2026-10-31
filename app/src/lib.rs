//! SSO as a Decision Model.
//!
//! Identity, Role, Policy and Time are decided by deterministic rules; Device, Location,
//! unusual time and overall Risk are judged by Jev (`TypeSafe` System One). The result is
//! Allow / `StepUp` / Deny with a trace explaining every factor, served over `OpenID` `AuthZEN`.

pub mod api;
pub mod config;
pub mod core;

use std::sync::Arc;

use crate::config::{Config, SignalMode};
use crate::core::engine::Engine;
use crate::core::policy::{PolicyError, PolicySet};
use crate::core::signals::{RuleBasedSignalProvider, SignalProvider};

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("failed to build Jev client: {0}")]
    Http(#[from] reqwest::Error),
}

/// Wires configuration into a ready-to-serve router.
///
/// # Errors
/// Returns [`StartupError`] when the policy file or the HTTP client cannot be loaded.
pub fn build_app(cfg: &Config) -> Result<axum::Router, StartupError> {
    let policies = PolicySet::load(&cfg.policy_path)?;
    let signals: Arc<dyn SignalProvider> = match &cfg.signal_mode {
        SignalMode::Jev(jev) => Arc::new(api::jev::JevClient::new(jev.clone())?),
        SignalMode::Mock => Arc::new(RuleBasedSignalProvider),
    };
    Ok(api::server::router(api::server::AppState {
        engine: Arc::new(Engine::new(policies, signals)),
        public_base_url: cfg.public_base_url.clone(),
    }))
}
