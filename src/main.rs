mod auth;
mod error;
mod startup;

use crate::auth::*;
use crate::startup::AppState;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, get_service, post};
use axum::{Extension, Router};
use axum_sessions::extractors::ReadableSession;
use axum_sessions::{async_session::MemoryStore, SameSite, SessionLayer};
use rand::prelude::*;
use std::net::SocketAddr;
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing::*;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(debug_assertions)]
const TRACE_LEVEL: &str = "axum_webauthn=trace,webauthn_rs=trace,tower_http=debug";
#[cfg(not(debug_assertions))]
const TRACE_LEVEL: &str = "axum_webauthn=info,tower_http=info";

#[tokio::main]
async fn main() {
    // Enable tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| TRACE_LEVEL.into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting application");

    let app_state = AppState::new();

    //Configure cookie based sessions
    let store = MemoryStore::new();
    let secret = thread_rng().gen::<[u8; 128]>(); // MUST be at least 64 bytes!
    let session_layer = SessionLayer::new(store, &secret)
        .with_cookie_name("webauthnrs")
        .with_same_site_policy(SameSite::Lax)
        .with_secure(true);

    // Build the application
    let app = Router::new()
        // Routes
        .route("/", get(index))
        .route("/register_start/:username", post(start_register))
        .route("/register_finish", post(finish_register))
        .route("/login_start/:username", post(start_authentication))
        .route("/login_finish", post(finish_authentication))
        // Serve the login HTML file
        .nest_service(
            "/login",
            get_service(ServeFile::new("assets/index.html")).handle_error(handle_404),
        )
        // Serve the assets directory
        .nest_service(
            "/assets",
            get_service(ServeDir::new("assets").precompressed_gzip()).handle_error(handle_404),
        )
        // Automatically compress responses
        .layer(CompressionLayer::new())
        // The pool of database connections
        //.layer(Extension(pool))
        // Tracing
        .layer(TraceLayer::new_for_http())
        .layer(Extension(app_state))
        .layer(session_layer);

    info!("Registered routes");

    // Run it
    let address = SocketAddr::from(([127, 0, 0, 1], 8080));
    match axum::Server::try_bind(&address) {
        Ok(server) => {
            info!("Application ready. Listening on {}", address);
            server.serve(app.into_make_service()).await.unwrap();
        }
        Err(e) => error!("Unable to start application: {}", e),
    }
}

async fn index(session: ReadableSession) -> impl IntoResponse {
    let Some(user) =  session.get::<String>("user") else {
        return Redirect::to("/login").into_response();
    };

    let output = format!("<h1>Hello {0}</h1>", user);
    Html(output).into_response()
}

async fn handle_404(_: std::io::Error) -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}
