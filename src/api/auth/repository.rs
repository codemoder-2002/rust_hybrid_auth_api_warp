use deadpool_redis::{Connection, redis::AsyncCommands};

use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

// Import the required trait for map_err

use crate::{
    api::auth::dto::*,
    schema::models::User,
    shared::{error::AppError, utils::hash::hash_password},
};

pub async fn find_user_by_email(_pool: &PgPool, email: &String) -> Result<User, AppError> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(_pool)
        .await
        .map_err(|_| AppError::EmailNotFound) // you can replace with your own error handler
}

pub async fn create_user(pool: &PgPool, req: RegisterRequest) -> Result<User, AppError> {
    let hashed_password =
        hash_password(&req.password).map_err(|_| AppError::InternalServerError)?;
    println!("hashed_password: {:?}", hashed_password);

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (
            id,email, first_name, last_name, email_verified, is_two_factor_enabled, role
         )
    VALUES ($1, $2, $3, $4, $5, $6, $7::user_role)
         RETURNING *",
    )
    .bind(Uuid::new_v4())
    .bind(req.email)
    .bind(req.first_name)
    .bind(req.last_name)
    .bind(false) // default value for email_verified
    .bind(false) // default value for 2FA
    .bind("user") // role string or UserRole enum as needed
    .fetch_one(pool)
    .await
    .map_err(|e| {
        warn!("DB error: {:?}", e);
        AppError::InternalServerError
    })?;
    Ok(user)
}

pub async fn update_user_password(
    pool: &PgPool,
    user_id: Uuid,
    new_password: &str,
) -> Result<(), AppError> {
    let result = sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(new_password)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|err| {
            tracing::error!("Failed to update user password: {:?}", err);
            AppError::InternalServerError
        })?;

    if result.rows_affected() == 0 {
        return Err(AppError::EmailNotFound); // Custom error for "user not found"
    }

    Ok(())
}

pub async fn send_email_verification_kafka(email: EmailMessage) {
    let payload = serde_json::to_string(&email).expect("Failed to serialize email message");

    // let record = FutureRecord::to(topic).payload(&payload).key(&email);

    // match producer.send(record, 0).await {
    //     Ok(_) => println!("Message sent to Kafka"),
    //     Err(e) => eprintln!("Failed to send message to Kafka: {}", e),
    // }
}

pub async fn save_email_verification_token(
    redis_conn: &mut Connection,
    email: String,
    token: String,
) -> Result<(), AppError> {
    // Key in Redis: email_verification_token:{email}
    let key = format!("email_verification_token:{}", email);

    // Store value as JSON (can be plain string if you want)
    let value = serde_json::json!({ "token": token }).to_string();

    // Token expiration: 15 minutes
    let expiry_seconds = 15 * 60;

    redis_conn
        .set_ex::<_, _, ()>(&key, value, expiry_seconds)
        .await
        .map_err(|_| AppError::InternalServerError)?;

    Ok(())
}

pub async fn store_refresh_token(
    redis_conn: &mut Connection,
    session_id: &str,
    refresh_token: &str,
    user_id: String,
) -> Result<(), AppError> {
    // Get a connection from the pool

    // Create the key and value for Redis
    let key = format!("session:{}", session_id);
    let value = serde_json::json!({
        "refresh_token": refresh_token,
        "user_id": user_id
    })
    .to_string();

    // Set the expiration (7 days in seconds)
    let expiry_seconds: u64 = 7 * 24 * 60 * 60;

    // Use the connection to set the key-value pair with expiration
    redis_conn
        .set_ex::<_, _, ()>(&key, value, expiry_seconds)
        .await
        .map_err(|_| AppError::InternalServerError)?;

    Ok(())
}

pub async fn get2fa_code_redis(
    redis_conn: &mut Connection,
    email: &str,
) -> Result<Option<String>, AppError> {
    let key = format!("2fa:{}", email);
    let stored_code: Option<String> = redis_conn
        .get(&key)
        .await
        .map_err(|_| AppError::InternalServerError)?;

    Ok(stored_code)
}

pub async fn delete_2fa_code_redis(
    redis_conn: &mut Connection,
    email: &str,
) -> Result<Option<String>, AppError> {
    let key = format!("2fa:{}", email);
    let stored_code: Option<String> = redis_conn
        .del(&key)
        .await
        .map_err(|_| AppError::InternalServerError)?;

    Ok(stored_code)
}
