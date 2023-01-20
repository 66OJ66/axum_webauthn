use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tracing::*;
use webauthn_rs::prelude::*;

// Postgres defaults
const DEFAULT_POSTGRES_USER: &str = "postgres";
const DEFAULT_POSTGRES_PASSWORD: &str = "postgres";
const DEFAULT_POSTGRES_IP: &str = "localhost";
const DEFAULT_POSTGRES_PORT: &str = "5432";

// Webauthn defaults
const DEFAULT_RP_ID: &str = "localhost";
const DEFAULT_RP_ORIGIN: &str = "http://localhost";

// Server defaults
const DEFAULT_SERVER_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const DEFAULT_SERVER_PORT: u16 = 8080;

/// Prepares a Postgres connection string using environmental variables (where provided) or default values.
/// If successful, will output something like "postgres://postgres:postgres@localhost:5432"
pub fn prepare_postgres_connection_string() -> Result<String, ()> {
    let postgres_user: String = std::env::var("POSTGRES_USER").unwrap_or_else(|_| {
        #[cfg(not(debug_assertions))]
        warn!(
            "Environmental variable POSTGRES_USER is not set. Using default value: {}",
            DEFAULT_POSTGRES_USER
        );

        DEFAULT_POSTGRES_USER.to_string()
    });

    let postgres_password: String = std::env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| {
        #[cfg(not(debug_assertions))]
        warn!(
            "Environmental variable POSTGRES_PASSWORD is not set. Using default value: {}",
            DEFAULT_POSTGRES_PASSWORD
        );

        DEFAULT_POSTGRES_PASSWORD.to_string()
    });

    let ip_address: String = std::env::var("POSTGRES_IP").unwrap_or_else(|_| {
        #[cfg(not(debug_assertions))]
        warn!(
            "Environmental variable POSTGRES_IP is not set. Using default value: {}",
            DEFAULT_POSTGRES_IP
        );

        DEFAULT_POSTGRES_IP.to_string()
    });

    let port: String = match std::env::var("POSTGRES_PORT") {
        Ok(port) => match port.parse::<u16>() {
            Ok(_) => port,
            Err(_) => {
                error!("Value of environmental variable POSTGRES_PORT is not an integer");
                return Err(());
            }
        },

        Err(_) => {
            #[cfg(not(debug_assertions))]
            warn!(
                "Environmental variable POSTGRES_PORT is not set. Using default value: {}",
                DEFAULT_POSTGRES_PORT
            );

            DEFAULT_POSTGRES_PORT.to_string()
        }
    };

    Ok(format!(
        "postgres://{0}:{1}@{2}:{3}",
        postgres_user, postgres_password, ip_address, port
    ))
}

pub fn prepare_server_address() -> Result<SocketAddr, ()> {
    let ip_address: IpAddr = match std::env::var("SERVER_IP") {
        Ok(ip_address) => match IpAddr::from_str(&ip_address) {
            Ok(ip_address) => ip_address,
            Err(e) => {
                error!("Unable to parse SERVER_IP: {}", e);
                return Err(());
            }
        },

        Err(_) => {
            #[cfg(not(debug_assertions))]
            warn!(
                "Environmental variable SERVER_IP is not set. Using default value: {}",
                DEFAULT_SERVER_IP
            );

            IpAddr::from(DEFAULT_SERVER_IP)
        }
    };

    let port: u16 = match std::env::var("SERVER_PORT") {
        Ok(port) => match port.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                error!("Value of environmental variable SERVER_PORT is not an integer");
                return Err(());
            }
        },

        Err(_) => {
            #[cfg(not(debug_assertions))]
            warn!(
                "Environmental variable SERVER_PORT is not set. Using default value: {}",
                DEFAULT_SERVER_PORT
            );

            DEFAULT_SERVER_PORT
        }
    };

    Ok(SocketAddr::new(ip_address, port))
}

#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
}

impl AppState {
    pub fn new() -> Result<Self, ()> {
        let rp_id: String = std::env::var("RP_ID").unwrap_or_else(|_| {
            #[cfg(not(debug_assertions))]
            warn!(
                "Environmental variable RP_ID is not set. Using default value: {}",
                DEFAULT_RP_ID
            );

            DEFAULT_RP_ID.to_string()
        });

        let rp_origin: Url = match std::env::var("RP_ORIGIN") {
            Ok(rp_origin) => match Url::parse(&rp_origin) {
                Ok(rp_origin) => rp_origin,
                Err(e) => {
                    error!("Unable to parse RP_ORIGIN into a valid Url: {}", e);
                    return Err(());
                }
            },

            Err(_) => {
                #[cfg(not(debug_assertions))]
                warn!(
                    "Environmental variable RP_ORIGIN is not set. Using default value: {}",
                    DEFAULT_RP_ORIGIN
                );

                Url::parse(DEFAULT_RP_ORIGIN).unwrap()
            }
        };

        let builder = match WebauthnBuilder::new(&rp_id, &rp_origin) {
            Ok(builder) => builder,
            Err(e) => {
                error!("Unable to build the WebAuthn instance: {}", e);
                return Err(());
            }
        };

        // Now, with the builder you can define other options.
        // Set a "nice" relying party name. Has no security properties and
        // may be changed in the future.
        let builder = builder.allow_any_port(true).rp_name("Axum Webauthn-rs");

        // Consume the builder and create our webauthn instance.
        let webauthn = Arc::new(builder.build().expect("Invalid configuration"));

        Ok(AppState { webauthn })
    }
}
