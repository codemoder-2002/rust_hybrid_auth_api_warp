use rdkafka::{
    ClientConfig,
    producer::{FutureProducer, FutureRecord},
};
use redis::AsyncCommands;
use serde_json::json;
use sqlx::PgPool;

use redis::aio::MultiplexedConnection;
use uuid::Uuid;

// Import the required trait for map_err

use crate::{
    api::auth::dto::*,
    schema::models::{EmailVerification, User},
    shared::{error::AppError, utils::hash::hash_password},
};

pub async fn find_user_by_email(pool: &PgPool, email: String) -> Result<User, AppError> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .map_err(|_| AppError::EmailNotFound) // you can replace with your own error handler
}

pub async fn create_user(pool: &PgPool, req: RegisterRequest) -> Result<User, AppError> {
    let hashed_password =
        hash_password(&req.password).map_err(|_| AppError::InternalServerError)?;

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (email, password_hash, is_verified) VALUES ($1, $2, FALSE)
         RETURNING *",
    )
    .bind(req.email)
    .bind(hashed_password)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::InternalServerError)?;
    Ok(user)
}
pub async fn update_user_password(
    pool: &PgPool,
    user_id: Uuid,
    new_password: String,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(new_password)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalServerError)?; // 💡 Proper error propagation

    Ok(())
}

pub async fn send_email_verification_kafka(
    producer: &FutureProducer,
    topic: &str,
    email: EmailMessage,
) {
    let payload = serde_json::to_string(&email).expect("Failed to serialize email message");

    let record = FutureRecord::to(topic).payload(&payload).key(&email);

    match producer.send(record, 0).await {
        Ok(_) => println!("Message sent to Kafka"),
        Err(e) => eprintln!("Failed to send message to Kafka: {}", e),
    }
}

pub async fn store_refresh_token(
    redis_conn: &mut MultiplexedConnection,
    session_id: &str,
    refresh_token: &str,
    user_id: String,
) -> Result<(), warp::Rejection> {
    let key: String = format!("session:{}", session_id);

    let value: String = json!({
        "refresh_token": refresh_token,
        "user_id": user_id
    })
    .to_string();

    // Store session with a 7-day expiration
    let expiry_seconds = 7 * 24 * 60 * 60;

    let _: () = redis_conn
        .set_ex(key, value, expiry_seconds)
        .await
        .map_err(|_| warp::reject::not_found())?;

    Ok(())
}
