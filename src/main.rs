mod auth;
mod config;
mod error;
mod startup;

use crate::auth::*;
use crate::startup::AppState;
use async_sqlx_session::PostgresSessionStore;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, get_service, post};
use axum::{Extension, Router};
use axum_sessions::extractors::ReadableSession;
use axum_sessions::{SameSite, SessionLayer};
use rand::prelude::*;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::time::Duration;
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

    // Setup the Postgres pool
    let pool: PgPool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect("postgres://postgres:test@localhost:5432")
        .await
        .expect("Can't connect to database");

    //Configure cookie based sessions
    let pg_store = PostgresSessionStore::new("postgres://postgres:test@localhost:5432")
        .await
        .unwrap();
    //pg_store.spawn_cleanup_task(Duration::from_secs(1));
    pg_store.migrate().await.unwrap();

    let secret = thread_rng().gen::<[u8; 128]>(); // MUST be at least 64 bytes!
    let session_layer = SessionLayer::new(pg_store, &secret)
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
        .with_state(pool)
        // Tracing
        .layer(TraceLayer::new_for_http())
        // App State
        .layer(Extension(app_state))
        // Session
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
