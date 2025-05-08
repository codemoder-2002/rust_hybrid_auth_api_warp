use std::sync::Arc;

use deadpool_redis::Connection;

use redis::aio::MultiplexedConnection;
use serde_json::json;
pub use sqlx::PgPool;
use uuid::Uuid;
use warp::{
    Rejection, Reply,
    http::StatusCode,
    http::{HeaderValue, header},
};

use super::repository;
use crate::{
    api::auth::dto::{LoginRequest, RegisterRequest},
    schema::models::User,
    shared::{
        error::*,
        kafka_message::{payload, producer::KafkaProducer, topics::KafkaTopic},
        utils::{hash::verify_password, jwt::*},
    },
};
use tracing::*;

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
            let body = json!({ "success": false, "message": "Failed to save password" });
            return Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&body),
                StatusCode::INTERNAL_SERVER_ERROR,
            )));
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
        return Err(warp::reject::custom(AuthError::InvalidCredentials));
    }

    // 5. Handle 2FA
    if user.is_two_factor_enabled {
        match &body.code {
            Some(code) => {
                let stored_code =
                    repository::get2fa_code_redis(&mut redis_conn, &user.email).await?;

                if let Some(ref stored) = stored_code {
                    if stored == code {
                        repository::delete_2fa_code_redis(&mut redis_conn, &user.email).await?;

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
    _pool: PgPool,
    mut redis_pool: Connection,
    kafka: Arc<KafkaProducer>,
    body: RegisterRequest,
) -> Result<impl Reply, Rejection> {
    match repository::find_user_by_email(&_pool, &body.email).await {
        Ok(existing_user) => {
            if existing_user.email_verified {
                // User already exists and verified
                return Err(warp::reject::custom(AppError::UserAlreadyExists));
            } else {
                // User exists but not verified — resend verification link
                repository::update_user_password(&_pool, existing_user.id, &body.password).await?;
                //also save the email verification code and expiration to the redis for the 15 minutes
                let token = generate_email_verification_token();
                repository::save_email_verification_token(
                    &mut redis_pool,
                    existing_user.email.clone(),
                    token,
                )
                .await?;
                // repository::send_email_verification_kafka(
                //     &redis_pool,
                //     &existing_user.email,
                //     &token,
                // )
                // .await?;
                return Ok(warp::reply::json(&{
                    serde_json::json!({
                        "message": "User already registered but not verified. A new verification link has been sent."
                    })
                }));
            }
        }

        Err(AppError::EmailNotFound) => {
            info!("User not found, creating new user");
            // User does not exist, safe to create
            let new_user = repository::create_user(&_pool, body).await?;
            info!("New user created: {:?}", new_user);

            // repository::send_email_verification_kafka( new_user.id).await?;

            let token = generate_email_verification_token();

            if let Err(err) = kafka
                .send_event(
                    KafkaTopic::EmailVerificationToken,
                    &new_user.email,
                    payload::KafkaPayload::EmailVerificationToken {
                        email: new_user.email.clone(),
                        token,
                    },
                )
                .await
            {
                tracing::error!("Failed to send Kafka event: {:?}", err);
            }

            Ok(warp::reply::json(&serde_json::json!({
                "message": "User registered successfully. Verification email sent."
            })))
        }

        Err(e) => {
            // Some other DB or unexpected error
            return Err(warp::reject::custom(e));
        }
    }
}
pub async fn refresh_token(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    Ok(warp::reply::json(&"Token refreshed"))
}

pub async fn get_all_users(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}

pub async fn verify_email(
    _pool: PgPool,
    body: LoginRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&format!("Registered {}", body.email)))
}

pub async fn request_2fa(_pool: PgPool, body: LoginRequest) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&format!("Registered {}", body.email)))
}

pub async fn verify_2fa(_pool: PgPool, body: LoginRequest) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&format!("Registered {}", body.email)))
}

pub async fn oauth_callback(
    _pool: PgPool,
    body: LoginRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&format!("Registered {}", body.email)))
}

pub async fn logout(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}

pub async fn getsession(redis_pool: MultiplexedConnection) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}

// pub async fn send_email_verification_kafka(
//     _pool: PgPool,
//     redis_pool: MultiplexedConnection,
//     email: String,
// ) -> Result<impl Reply, Rejection> {
//     // 1. Check if user exists
//     let user = repository::find_user_by_email(&_pool, &email)
//         .await
//         .map_err(|_| warp::reject::custom(AppError::EmailNotFound))?;

//     // 2. If already verified, return early
//     if user.email_verified {
//         return Err(warp::reject::custom(AuthError::EmailNotVerified));
//     }

//     // 3. Generate verification token (store in Redis)
//     let token =
//         generate_email_verification_token(user.id.to_string(), &user.email, "secreat is here")?; // UUID or secure random
//     println!("Generated token: {}", token);
//     // store_email_token(&redis_pool, &token, user.id).await?;

//     // 4. Send email with link (yourdomain.com/verify-email?token=xyz)
//     // send_verification_email(&user.email, &token).await?;

//     Ok(warp::reply::json(&"Verification email sent"))
// }
