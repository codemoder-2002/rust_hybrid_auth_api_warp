pub use sqlx::PgPool;
use tracing::info;

use super::repository;
use crate::{
    api::auth::dto::{LoginRequest, RegisterRequest},
    schema::models::User,
    shared::{error::*, utils::hash::verify_password},
};
use warp::Rejection;
use warp::Reply;

pub async fn login(pool: PgPool, body: LoginRequest) -> Result<impl Reply, Rejection> {
    // 1. Check if user exists by email
    info!("Checking if user exists by email: {}", body.email);

    let user: User = repository::find_user_by_email(pool, body.email.clone())
        .await
        .map_err(|_| warp::reject::custom(AppError::EmailNotFound))?;

    if !user.email_verified {
        return Err(warp::reject::custom(AuthError::EmailNotVerified));
    }

    // 2. Extract password from DB and form
    let password_hash: String = user
        .password_hash
        .clone()
        .ok_or_else(|| warp::reject::custom(AuthError::InvalidCredentials))?;

    // 3. Verify password using argon2
    if !verify_password(&body.password, &password_hash)? {
        return Err(warp::reject::custom(AuthError::InvalidCredentials));
    }

    // 4. [Optional] Generate JWT or session (placeholder)
    // let token = generate_jwt(user.id)?;

    // 5. Success: return response (here, email)
    Ok(warp::reply::json(&format!("Logged in as {}", user.email)))
}

pub async fn register(_pool: PgPool, body: RegisterRequest) -> Result<impl Reply, warp::Rejection> {
    // Logic to create a user

    Ok(warp::reply::json(&format!("Registered {}", body.email)))
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
