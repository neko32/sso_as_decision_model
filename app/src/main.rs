use sso_decision::config::{Config, SignalMode};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A missing .env is fine; real environment variables take precedence.
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;
    let mode = match &cfg.signal_mode {
        SignalMode::Jev(j) => j.model.clone(),
        SignalMode::Mock => "mock".to_owned(),
    };
    let app = sso_decision::build_app(&cfg)?;
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, signals = %mode, "SSO decision PDP listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
