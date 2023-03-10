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

    let (user_id, exclude_credentials): (Uuid, Option<Vec<CredentialID>>) =
        match sqlx::query!("SELECT user_id FROM users WHERE user_name = $1;", &username)
            .fetch_optional(&pool)
            .await?
        {
            Some(record) => {
                let records = sqlx::query!(
                    "SELECT credential FROM auth WHERE user_id = $1;",
                    &record.user_id
                )
                .fetch_all(&pool)
                .await?;

                (
                    record.user_id,
                    Some(
                        records
                            .iter()
                            .map(|record| serde_json::from_str::<Passkey>(&record.credential))
                            .collect::<Result<Vec<Passkey>, _>>()
                            .map_err(WebauthnError::SerialisationError)?
                            .iter()
                            .map(|passkey| passkey.cred_id().clone())
                            .collect(),
                    ),
                )
            }
            None => (Uuid::new_v4(), None),
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
                .map_err(WebauthnError::SessionError)?;
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
            let record = sqlx::query!(
                "SELECT COUNT(user_id) AS count FROM users WHERE user_id = $1;",
                &user_id
            )
            .fetch_one(&pool)
            .await?;

            // If the user doesn't exist, insert them into the users table
            if record.count == Some(0)
                && sqlx::query!(
                    "INSERT INTO users(user_id, user_name) VALUES($1, $2);",
                    &user_id,
                    &user_name
                )
                .execute(&pool)
                .await?
                .rows_affected()
                    != 1
            {
                return Err(WebauthnError::Unknown);
            }

            // Serialise the key
            let serialised_key =
                serde_json::ser::to_string(&key).map_err(WebauthnError::SerialisationError)?;

            // Insert the key into the auth table
            if sqlx::query!(
                "INSERT INTO auth(user_id, credential) VALUES($1, $2);",
                &user_id,
                &serialised_key
            )
            .execute(&pool)
            .await?
            .rows_affected()
                != 1
            {
                return Err(WebauthnError::Unknown);
            }

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

    let user_id = sqlx::query!(
        "SELECT user_id FROM users WHERE user_name = $1;",
        &user_name
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| WebauthnError::UserNotFound)?
    .user_id;

    let records = sqlx::query!("SELECT credential FROM auth WHERE user_id = $1;", &user_id)
        .fetch_all(&pool)
        .await?;

    if records.is_empty() {
        return Err(WebauthnError::UserHasNoCredentials);
    }

    let allow_credentials: Vec<Passkey> = records
        .iter()
        .map(|record| serde_json::de::from_str::<Passkey>(&record.credential))
        .collect::<Result<Vec<Passkey>, _>>()
        .map_err(WebauthnError::SerialisationError)?;

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
                .map_err(WebauthnError::SessionError)?;
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
            let records = sqlx::query!("SELECT credential FROM auth WHERE user_id = $1;", &user_id)
                .fetch_all(&pool)
                .await?;

            if records.is_empty() {
                return Err(WebauthnError::UserHasNoCredentials);
            }

            for record in records {
                let mut credential = serde_json::from_str::<Passkey>(&record.credential)
                    .map_err(WebauthnError::SerialisationError)?;

                if credential.cred_id() == auth_result.cred_id() {
                    credential.update_credential(&auth_result);

                    let credential = serde_json::to_string(&credential)
                        .map_err(WebauthnError::SerialisationError)?;

                    if sqlx::query!(
                        "UPDATE auth SET credential = $1 WHERE user_id = $2 AND credential = $3;",
                        &credential,
                        &user_id,
                        record.credential
                    )
                    .execute(&pool)
                    .await?
                    .rows_affected()
                        != 1
                    {
                        return Err(WebauthnError::Unknown);
                    }

                    break;
                }
            }

            let user_name =
                sqlx::query!("SELECT user_name FROM users WHERE user_id = $1;", &user_id)
                    .fetch_one(&pool)
                    .await?
                    .user_name;

            // Add our own values to the session
            session
                .insert("user_id", user_id)
                .map_err(WebauthnError::SessionError)?;
            session
                .insert("user_name", user_name)
                .map_err(WebauthnError::SessionError)?;

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
