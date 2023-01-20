use crate::config::AppState;
use crate::error::WebauthnError;
use axum::extract::State;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use axum_sessions::async_session::serde_json;
use axum_sessions::extractors::WritableSession;
use sqlx::PgPool;
use tracing::*;

/*
 * Webauthn RS auth handlers.
 * These files use webauthn to process the data received from each route, and are closely tied to axum
 */

// 1. Import the prelude - this contains everything needed for the server to function.
use webauthn_rs::prelude::*;

// 2. The first step a client (user) will carry out is requesting a credential to be
// registered. We need to provide a challenge for this. The work flow will be:
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Reg     │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │  4. Yield PubKey    │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │                      │
//                  │                     │  5. Send Reg Opts    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │         PubKey
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │─ ─ ─
//                  │                     │                      │     │ 6. Persist
//                  │                     │                      │       Credential
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// In this step, we are responding to the start reg(istration) request, and providing
// the challenge to the browser.

// TODO - Improve error handling and messages

pub async fn start_register(
    State(pool): State<PgPool>,
    Extension(app_state): Extension<AppState>,
    mut session: WritableSession,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start register");

    // Remove any previous registrations that may have occurred from the session.
    session.remove("reg_state");

    let (user_id, exclude_credentials): (Uuid, Option<Vec<CredentialID>>) = match sqlx::query!(
        "SELECT user_id FROM users WHERE user_name = $1;",
        &username
    )
    .fetch_optional(&pool)
    .await
    {
        Ok(record) => match record {
            Some(record) => {
                let Ok(records) = sqlx::query!("SELECT credential FROM auth WHERE user_id = $1;", &record.user_id).fetch_all(&pool).await else {
                    // Internal server error
                    return Err(WebauthnError::Unknown);
                };

                (
                    record.user_id,
                    Some(
                        records
                            .iter()
                            .map(|record| {
                                serde_json::from_str::<Passkey>(&record.credential)
                                    .unwrap()
                                    .cred_id()
                                    .clone()
                            })
                            .collect(),
                    ),
                )
            }
            None => (Uuid::new_v4(), None),
        },
        Err(e) => {
            error!("Error in start register process: {}", e);
            return Err(WebauthnError::Unknown);
        }
    };

    let res = match app_state.webauthn.start_passkey_registration(
        user_id,
        &username,
        &username,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            // Note that due to the session store in use being a server side memory store, this is
            // safe to store the reg_state into the session since it is not client controlled and
            // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
            session
                .insert("reg_state", (username, user_id, reg_state))
                .expect("Failed to insert");
            Json(ccr)
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

// 3. The browser has completed it's steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.

pub async fn finish_register(
    State(pool): State<PgPool>,
    Extension(app_state): Extension<AppState>,
    mut session: WritableSession,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Confirming registration....");
    let (user_name, user_id, reg_state): (String, Uuid, PasskeyRegistration) = session
        .get("reg_state")
        .ok_or(WebauthnError::CorruptSession)?; //Corrupt Session

    session.remove("reg_state");

    let res = match app_state
        .webauthn
        .finish_passkey_registration(&reg, &reg_state)
    {
        Ok(key) => {
            info!("Passkey is okay");

            // Check if the user_id already exists
            match sqlx::query!(
                "SELECT COUNT(user_id) AS count FROM users WHERE user_id = $1;",
                &user_id
            )
            .fetch_one(&pool)
            .await
            {
                Ok(record) => {
                    // If the user doesn't exist, insert them into the users table
                    if record.count == Some(0) {
                        if let Err(e) = sqlx::query!(
                            "INSERT INTO users(user_id, user_name) VALUES($1, $2);",
                            &user_id,
                            &user_name
                        )
                        .execute(&pool)
                        .await
                        {
                            error!("Error whilst inserting user: {}", e);
                            // Internal server error
                            return Err(WebauthnError::Unknown);
                        };
                    }
                }
                Err(e) => {
                    error!("Error in finish register process: {}", e);
                    return Err(WebauthnError::Unknown);
                }
            }

            // Serialise the key
            let Ok(serialised_key) = serde_json::ser::to_string(&key) else {
                // Serialisation error
                return Err(WebauthnError::Unknown);
            };

            // Insert the key into the auth table
            let Ok(_) = sqlx::query!("INSERT INTO auth(user_id, credential) VALUES($1, $2);", &user_id, &serialised_key).execute(&pool).await else {
                // Internal server error
                return Err(WebauthnError::Unknown);
            };

            StatusCode::OK
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };

    Ok(res)
}

// 4. Now that our public key has been registered, we can authenticate a user and verify
// that they are the holder of that security token. The work flow is similar to registration.
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Auth    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │    4. Yield Sig     │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │    5. Send Auth      │
//                  │                     │        Opts          │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │          Sig
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// The user indicates the wish to start authentication and we need to provide a challenge.

pub async fn start_authentication(
    State(pool): State<PgPool>,
    Extension(app_state): Extension<AppState>,
    mut session: WritableSession,
    Path(user_name): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start Authentication");

    // Remove any previous authentication that may have occurred from the session.
    session.remove("auth_state");

    let user_id = match sqlx::query!(
        "SELECT user_id FROM users WHERE user_name = $1;",
        &user_name
    )
    .fetch_one(&pool)
    .await
    {
        Ok(record) => record.user_id,
        Err(e) => {
            error!("Error in start authentication process: {}", e);
            return Err(WebauthnError::Unknown);
        }
    };

    let Ok(records) = sqlx::query!("SELECT credential FROM auth WHERE user_id = $1;", &user_id).fetch_all(&pool).await else {
        // Internal server error
        return Err(WebauthnError::Unknown);
    };

    if records.is_empty() {
        return Err(WebauthnError::UserHasNoCredentials);
    }

    let mut allow_credentials: Vec<Passkey> = Vec::new();

    for record in records {
        match serde_json::de::from_str::<Passkey>(&record.credential) {
            Ok(credential) => allow_credentials.push(credential),
            Err(e) => {
                error!("{}", e);
                // Internal server error
                return Err(WebauthnError::Unknown);
            }
        }
    }

    let res = match app_state
        .webauthn
        .start_passkey_authentication(&allow_credentials)
    {
        Ok((rcr, auth_state)) => {
            // Note that due to the session store in use being a server side memory store, this is
            // safe to store the auth_state into the session since it is not client controlled and
            // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
            session
                .insert("auth_state", (&user_id, auth_state))
                .expect("Failed to insert");
            Json(rcr)
        }
        Err(e) => {
            debug!("challenge_authenticate -> {:?}", e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

// 5. The browser and user have completed their part of the processing. Only in the
// case that the webauthn authenticate call returns Ok, is authentication considered
// a success. If the browser does not complete this call, or *any* error occurs,
// this is an authentication failure.

pub async fn finish_authentication(
    State(pool): State<PgPool>,
    Extension(app_state): Extension<AppState>,
    mut session: WritableSession,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (user_id, auth_state): (Uuid, PasskeyAuthentication) = session
        .get("auth_state")
        .ok_or(WebauthnError::CorruptSession)?;

    session.remove("auth_state");

    let res = match app_state
        .webauthn
        .finish_passkey_authentication(&auth, &auth_state)
    {
        Ok(auth_result) => {
            let Ok(records) = sqlx::query!("SELECT credential FROM auth WHERE user_id = $1;", &user_id).fetch_all(&pool).await else {
                // Internal server error
                return Err(WebauthnError::Unknown);
            };

            for record in records {
                let Ok(mut credential) = serde_json::from_str::<Passkey>(&record.credential) else {
                    // Internal server error
                    return Err(WebauthnError::Unknown);
                };

                if credential.cred_id() == auth_result.cred_id() {
                    info!("Incrementing counter");
                    credential.update_credential(&auth_result);

                    let Ok(credential) = serde_json::to_string(&credential) else {
                        return Err(WebauthnError::Unknown);
                    };

                    let Ok(_) = sqlx::query!("UPDATE auth SET credential = $1 WHERE user_id = $2 AND credential = $3;", &credential, &user_id, record.credential).execute(&pool).await else {
                        // Internal server error
                        return Err(WebauthnError::Unknown);
                    };

                    break;
                }
            }

            let Ok(record) = sqlx::query!("SELECT user_name FROM users WHERE user_id = $1;", &user_id).fetch_one(&pool).await else {
                // Internal server error
                return Err(WebauthnError::Unknown);
            };

            // Add our own values to the session
            session.insert("user_id", user_id).unwrap();
            session.insert("user_name", record.user_name).unwrap();

            StatusCode::OK
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };

    info!("Authentication Successful!");
    Ok(res)
}
