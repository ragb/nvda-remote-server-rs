use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::config::MetricsConfig;
use crate::server::ServerState;

#[derive(Clone)]
struct AppState {
    prometheus: PrometheusHandle,
    server: Arc<ServerState>,
}

/// Start the observability HTTP server on a separate port.
pub async fn serve(
    config: &MetricsConfig,
    prometheus_handle: PrometheusHandle,
    state: Arc<ServerState>,
) {
    let app_state = AppState {
        prometheus: prometheus_handle,
        server: state,
    };

    let mut app = Router::new();

    #[cfg(feature = "prometheus")]
    {
        app = app.route("/metrics", get(metrics_handler));
    }

    #[cfg(feature = "admin")]
    {
        app = app
            .route("/", get(dashboard_handler))
            .route("/stats", get(stats_handler));
    }

    let app = app.with_state(app_state);

    let bind = format!("{}:{}", config.bind, config.port);
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            error!(address = %bind, "Failed to bind metrics server: {e}");
            return;
        }
    };
    info!(address = %bind, "Metrics/admin server listening");

    if let Err(e) = axum::serve(listener, app).await {
        error!("Metrics server error: {e}");
    }
}

#[cfg(feature = "prometheus")]
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.prometheus.render();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

#[cfg(feature = "admin")]
async fn dashboard_handler(State(state): State<AppState>) -> Html<String> {
    Html(super::dashboard::render(&state.server, &state.prometheus))
}

#[cfg(feature = "admin")]
async fn stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    let details = state.server.channel_details();
    let stats = serde_json::json!({
        "connections": state.server.connection_count(),
        "channels": state.server.channel_count(),
        "channel_details": details.iter().map(|(name, count)| {
            serde_json::json!({"channel": name, "members": count})
        }).collect::<Vec<_>>(),
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&stats).unwrap_or_default(),
    )
}
