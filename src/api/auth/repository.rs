use sqlx::PgPool;

use warp::Reply;

use crate::{api::auth::dto::*, schema::models::User};

pub async fn find_user_by_email(pool: PgPool, email: String) -> Result<User, warp::Rejection> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&pool)
        .await
        .map_err(|_| warp::reject::not_found()) // you can replace with your own error handler
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
