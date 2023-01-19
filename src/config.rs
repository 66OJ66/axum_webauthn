use tracing::*;

const DEFAULT_POSTGRES_USER: &str = "postgres";
const DEFAULT_POSTGRES_PASSWORD: &str = "test";
const DEFAULT_POSTGRES_IP: &str = "localhost";
const DEFAULT_POSTGRES_PORT: &str = "5432";

/// Prepares a Postgres connection string using environmental variables (where provided) or default values.
/// If successful, will output something like "postgres://postgres:postgres@localhost:5432"
pub fn prepare_postgres_connection_string() -> Result<String, ()> {
    let postgres_user: String =
        std::env::var("POSTGRES_USER").unwrap_or_else(|_| DEFAULT_POSTGRES_USER.to_string());

    let postgres_password: String = std::env::var("POSTGRES_PASSWORD")
        .unwrap_or_else(|_| DEFAULT_POSTGRES_PASSWORD.to_string());

    let ip_address: String =
        std::env::var("POSTGRES_IP").unwrap_or_else(|_| DEFAULT_POSTGRES_IP.to_string());

    let port: String = match std::env::var("POSTGRES_PORT") {
        Ok(port) => match port.parse::<u16>() {
            Ok(_) => port,
            Err(_) => {
                error!("Value of environmental variable POSTGRES_PORT is not an integer");
                return Err(());
            }
        },

        Err(_) => DEFAULT_POSTGRES_PORT.to_string(),
    };

    Ok(format!(
        "postgres://{0}:{1}@{2}:{3}",
        postgres_user, postgres_password, ip_address, port
    ))
}
