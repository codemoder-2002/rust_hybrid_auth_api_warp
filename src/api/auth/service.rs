use std::sync::Arc;

use deadpool_redis::Connection;

use serde_json::json;
pub use sqlx::PgPool;
use uuid::Uuid;
use warp::{
    Rejection, Reply,
    http::StatusCode,
    http::{HeaderValue, header},
};

use super::{
    dto::{OAuthCallbackBody, TwofaRequest},
    repository::{self, store_2fa_code},
};
use crate::{
    api::auth::dto::{LoginRequest, RegisterRequest},
    schema::models::User,
    shared::{
        error::*,
        kafka_message::{payload, producer::KafkaProducer, topics::KafkaTopic},
        utils::{
            hash::{hash_password, verify_password},
            jwt::*,
        },
    },
};

pub async fn login(
    pool: PgPool,
    mut redis_conn: Connection,
    kafka: Arc<KafkaProducer>,
    body: LoginRequest,
) -> Result<Box<dyn Reply>, warp::Rejection> {
    // 1. Find user by email
    let user = repository::find_user_by_email(&pool, &body.email)
        .await
        .map_err(|_| warp::reject::custom(AppError::EmailNotFound))?;

    // 2. Get password hash (fail early if not found)
    let password_hash = user
        .password_hash
        .clone()
        .ok_or_else(|| warp::reject::custom(AuthError::InvalidCredentials))?;

    // 3. If email not verified, store password and respond
    if !user.email_verified {
        if let Err(err) = repository::update_user_password(&pool, user.id, &password_hash).await {
            tracing::error!("Failed to update password: {:?}", err);
            return Err(warp::reject::custom(AuthError::EmailNotVerified));
        }

        // TODO: Trigger email verification here via Kafka if needed

        let token = generate_email_verification_token();

        if let Err(err) = kafka
            .send_event(
                KafkaTopic::EmailVerificationToken,
                &user.email,
                payload::KafkaPayload::EmailVerificationToken {
                    email: user.email.clone(),
                    token,
                },
            )
            .await
        {
            tracing::error!("Failed to send Kafka event: {:?}", err);
        }

        let response = json!({
            "message": "User registered but not verified. A new verification link has been sent.",
            "success": true,
            "email_verification": false,
        });

        return Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::OK,
        )));
    }

    // 4. Verify password
    if !verify_password(&body.password, &password_hash)? {
        return Err(warp::reject::custom(AppError::WrongCredentialsError));
    }

    // 5. Handle 2FA
    if user.is_two_factor_enabled {
        match &body.code {
            Some(code) => {
                let stored_code = repository::get_2fa_code(&mut redis_conn, &user.email).await?;

                if let Some(ref stored) = stored_code {
                    if stored == code {
                        repository::delete_2fa_code(&mut redis_conn, &user.email).await?;

                        return generate_success_response(&mut redis_conn, &user).await;
                    }
                }

                return Err(warp::reject::custom(AuthError::InvalidCredentials));
            }
            None => {
                //send 2fa code

                let code: String = generate_2fa_code();

                if let Err(err) = kafka
                    .send_event(
                        KafkaTopic::TwoFactorCode,
                        &user.email,
                        payload::KafkaPayload::TwoFactorCode {
                            email: user.email.clone(),
                            code,
                        },
                    )
                    .await
                {
                    tracing::error!("Failed to send Kafka event: {:?}", err);
                }

                let body = json!({ "two_factor": true });
                return Ok(Box::new(warp::reply::json(&body)));
            }
        }
    }

    // 6. No 2FA, successful login
    generate_success_response(&mut redis_conn, &user).await
}

fn generate_cookie(value: &str) -> String {
    format!(
        "refresh_token={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800;",
        value
    )
}

async fn generate_success_response(
    redis_conn: &mut Connection,
    user: &User,
) -> Result<Box<dyn Reply>, warp::Rejection> {
    let access_token = generate_access_token(user.id.to_string(), user.email.clone())?;
    let refresh_token = generate_refresh_token()?;
    let session_id = Uuid::new_v4().to_string();

    repository::store_refresh_token(redis_conn, &session_id, &refresh_token, user.id.to_string())
        .await?;

    let body = json!({
        "access_token": access_token,
        "session_id": session_id,
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role
        },
        "two_factor": false
    });

    let reply = warp::reply::json(&body);
    let reply_with_cookie = warp::reply::with_header(
        reply,
        header::SET_COOKIE,
        HeaderValue::from_str(&generate_cookie(&refresh_token)).unwrap(),
    );

    Ok(Box::new(reply_with_cookie))
}

pub async fn register(
    pool: PgPool,
    redis_pool: Connection,
    kafka: Arc<KafkaProducer>,
    body: RegisterRequest,
) -> Result<impl Reply, Rejection> {
    match repository::find_user_by_email(&pool, &body.email).await {
        Ok(existing_user) => {
            if existing_user.email_verified {
                return Err(warp::reject::custom(AppError::UserAlreadyExists));
            }
            // User exists but not verified — update password and resend verification
            let password_hash = hash_password(&body.password)?;

            // User exists but not verified — update password and resend verification
            repository::update_user_password(&pool, existing_user.id, &password_hash).await?;
            return handle_email_verification(
                redis_pool,
                kafka,
                existing_user.email.clone(),
                "User already registered but not verified. A new verification link has been sent.",
            )
            .await;
        }

        Err(AppError::EmailNotFound) => {
            let mut body = body; // Make it mutable if not already
            body.password = hash_password(&body.password)?;
            let new_user = repository::create_user(&pool, body).await?;
            return handle_email_verification(
                redis_pool,
                kafka,
                new_user.email,
                "User registered successfully. Verification email sent.",
            )
            .await;
        }

        Err(e) => return Err(warp::reject::custom(e)),
    }
}

async fn handle_email_verification(
    mut redis_pool: Connection,
    kafka: Arc<KafkaProducer>,
    email: String,
    message: &str,
) -> Result<impl Reply, Rejection> {
    let token = generate_email_verification_token();

    repository::save_email_verification_token(&mut redis_pool, email.clone(), &token).await?;

    if let Err(err) = kafka
        .send_event(
            KafkaTopic::TwoFactorCode,
            &email,
            payload::KafkaPayload::EmailVerificationToken {
                email: email.clone(),
                token,
            },
        )
        .await
    {
        tracing::error!("Failed to send Kafka event: {:?}", err);
    }

    Ok(warp::reply::json(
        &serde_json::json!({ "message": message }),
    ))
}

pub async fn refresh_token(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    Ok(warp::reply::json(&"Token refreshed"))
}

pub async fn verify_email(
    token: String,
    pool: PgPool,
    mut redis_conn: Connection,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Retrieve the email linked to the verification token
    let email = repository::get_email_verification_token(&mut redis_conn, &token)
        .await
        .map_err(warp::reject::custom)?;

    if email.trim().is_empty() {
        return Err(warp::reject::custom(AppError::InvalidToken));
    }

    // Find user by email
    let user = repository::find_user_by_email(&pool, &email)
        .await
        .map_err(warp::reject::custom)?;

    if user.id.is_nil() {
        return Err(warp::reject::custom(AppError::EmailNotFound));
    }

    if user.email_verified {
        return Err(warp::reject::custom(AppError::EmailAlreadyVerified));
    }

    // Mark the email as verified
    repository::update_user_email_verified(&pool, user.id)
        .await
        .map_err(warp::reject::custom)?;

    // Clean up the used token
    repository::delete_email_verification_token(&mut redis_conn, &token)
        .await
        .map_err(warp::reject::custom)?;

    // Send a success response
    let response = warp::reply::json(&json!({
        "message": "Email verified successfully",
        "success": true,
    }));

    Ok(response)
}

pub async fn request_2fa(
    mut redis_pool: Connection,
    kafka: Arc<KafkaProducer>,
    body: TwofaRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    let code = generate_2fa_code();

    store_2fa_code(&mut redis_pool, &body.email, &code).await?;

    if let Err(err) = kafka
        .send_event(
            KafkaTopic::TwoFactorCode,
            &body.email,
            payload::KafkaPayload::TwoFactorCode {
                email: body.email.clone(),
                code,
            },
        )
        .await
    {
        tracing::error!("Failed to send Kafka event: {:?}", err);
    }
    let res = json!({
        "message": "Code sent successfully",
        "success": true,
    });
    let reply = warp::reply::json(&res);

    Ok(reply)
}

// pub async fn oauth_callback(
//     pool: PgPool,
//     body: OAuthCallbackBody,
// ) -> Result<impl warp::Reply, warp::Rejection> {
//     // Step 1: Exchange authorization code for access token
//     let token_response = exchange_google_code(&body.code)
//         .await
//         .map_err(warp::reject::custom)?;

//     // Step 2: Use access token to fetch user info from Google
//     let user_info = fetch_google_user_info(&token_response.access_token)
//         .await
//         .map_err(warp::reject::custom)?;

//     // Step 3: Check if user exists, else register
//     let user = match repository::find_user_by_email(&pool, &user_info.email).await {
//         Ok(existing_user) => existing_user,
//         Err(AppError::EmailNotFound) => repository::create_user_from_oauth(&pool, &user_info)
//             .await
//             .map_err(warp::reject::custom)?,
//         Err(e) => return Err(warp::reject::custom(e)),
//     };

//     // Step 4: Generate your own session token (JWT)
//     let jwt = generate_access_token(&user.id, &user.email).map_err(warp::reject::custom)?;

//     // Step 5: Respond with token + user info
//     let response = warp::reply::json(&serde_json::json!({
//         "token": jwt,
//         "user": user,
//     }));

//     Ok(response)
// }

pub async fn logout(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}

pub async fn me(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}

pub async fn isUserExist(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}
