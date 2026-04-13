mod auth;
mod config;
mod contribute;
mod db;
mod knowledge;
mod models;
mod stats;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

pub async fn run() -> anyhow::Result<()> {
    let cfg = config::Config::from_env()?;
    let pool = db::pool_from_database_url(&cfg.database_url)?;
    db::init_schema(&pool).await?;

    let mailer = if cfg.smtp_enabled() {
        Some(auth::Mailer::new(&cfg)?)
    } else {
        None
    };

    let state = auth::AppState::new(pool, cfg.clone(), mailer);

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            "https://leanctx.com".parse().unwrap(),
            "https://www.leanctx.com".parse().unwrap(),
        ]))
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(true);

    let app = Router::new()
        .route("/health", get(auth::health))
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/request-link", post(auth::request_magic_link))
        .route("/api/auth/exchange", get(auth::exchange_magic_link))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/stats", get(stats::get_stats).post(stats::post_stats))
        .route("/api/contribute", post(contribute::post_contribute))
        .route(
            "/api/sync/knowledge",
            get(knowledge::get_knowledge).post(knowledge::post_knowledge),
        )
        .route("/api/cloud/models", get(models::get_models))
        .route("/api/pro/models", get(models::get_models))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr()).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

