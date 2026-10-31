//! Runtime configuration from environment variables (optionally via `.env`).

use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

use crate::api::jev::{DEFAULT_BASE_URL, DEFAULT_MODEL, JevConfig};
use crate::core::domain::ApiKey;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("API_KEY_JEV is required when SIGNAL_MODE=jev")]
    MissingApiKey,
    #[error("invalid value for {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Clone)]
pub enum SignalMode {
    Jev(JevConfig),
    /// Offline heuristic provider for CI and E2E tests.
    Mock,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub public_base_url: String,
    pub policy_path: PathBuf,
    pub signal_mode: SignalMode,
}

impl Config {
    /// # Errors
    /// Returns [`ConfigError`] when a variable is invalid or the API key is missing in Jev mode.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let bind_addr = get("BIND_ADDR").unwrap_or_else(|| "127.0.0.1:8080".to_owned());
        let public_base_url =
            get("PUBLIC_BASE_URL").unwrap_or_else(|| format!("http://{bind_addr}"));
        let policy_path =
            PathBuf::from(get("POLICY_PATH").unwrap_or_else(|| "policy.yaml".to_owned()));

        let signal_mode = match get("SIGNAL_MODE").as_deref().unwrap_or("jev") {
            "mock" => SignalMode::Mock,
            "jev" => {
                let raw = get("API_KEY_JEV").ok_or(ConfigError::MissingApiKey)?;
                let api_key = ApiKey::new(&raw).map_err(|_| ConfigError::MissingApiKey)?;
                let timeout_ms = match get("JEV_TIMEOUT_MS") {
                    None => 5_000,
                    Some(v) => v
                        .parse::<u64>()
                        .map_err(|_| ConfigError::Invalid("JEV_TIMEOUT_MS"))?,
                };
                SignalMode::Jev(JevConfig {
                    base_url: get("JEV_BASE_URL").unwrap_or_else(|| DEFAULT_BASE_URL.to_owned()),
                    model: get("JEV_MODEL").unwrap_or_else(|| DEFAULT_MODEL.to_owned()),
                    api_key,
                    timeout: Duration::from_millis(timeout_ms),
                })
            }
            _ => return Err(ConfigError::Invalid("SIGNAL_MODE")),
        };

        Ok(Self {
            bind_addr,
            public_base_url,
            policy_path,
            signal_mode,
        })
    }

    /// # Errors
    /// See [`Config::from_lookup`].
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults_to_jev_and_requires_a_key() {
        assert_eq!(cfg(&[]).unwrap_err(), ConfigError::MissingApiKey);
        assert_eq!(
            cfg(&[("API_KEY_JEV", "  ")]).unwrap_err(),
            ConfigError::MissingApiKey
        );
        let c = cfg(&[("API_KEY_JEV", "k")]).unwrap();
        assert_eq!(c.public_base_url, "http://127.0.0.1:8080");
        let SignalMode::Jev(j) = c.signal_mode else {
            panic!("expected jev mode")
        };
        assert_eq!(
            (j.model.as_str(), j.timeout),
            (DEFAULT_MODEL, Duration::from_secs(5))
        );
        assert!(format!("{j:?}").contains("ApiKey(****)"));
    }

    #[test]
    fn mock_mode_and_invalid_values() {
        let c = cfg(&[("SIGNAL_MODE", "mock"), ("BIND_ADDR", "0.0.0.0:9000")]).unwrap();
        assert!(matches!(c.signal_mode, SignalMode::Mock));
        assert_eq!(c.public_base_url, "http://0.0.0.0:9000");
        assert_eq!(
            cfg(&[("SIGNAL_MODE", "llm")]).unwrap_err(),
            ConfigError::Invalid("SIGNAL_MODE")
        );
        assert_eq!(
            cfg(&[("API_KEY_JEV", "k"), ("JEV_TIMEOUT_MS", "soon")]).unwrap_err(),
            ConfigError::Invalid("JEV_TIMEOUT_MS")
        );
    }
}
