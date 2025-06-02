use deadpool_redis::{Connection, redis::AsyncCommands};

use serde_json::{Value, json};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

// Import the required trait for map_err

use crate::{
    api::auth::dto::*,
    schema::models::{Account, User},
    shared::error::AppError,
};

pub async fn find_user_by_email(_pool: &PgPool, email: &String) -> Result<User, AppError> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(_pool)
        .await
        .map_err(|_| AppError::EmailNotFound) // you can replace with your own error handler
}

pub async fn find_user_by_id(_pool: &PgPool, user_id: &String) -> Result<User, AppError> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(_pool)
        .await
        .map_err(|_| AppError::EmailNotFound) // you can replace with your own error handler
}

pub async fn find_account_by_provider_id(
    pool: &PgPool,
    provider: &str,
    provider_account_id: &str,
) -> Result<Option<Account>, AppError> {
    let account = sqlx::query_as::<_, Account>(
        "SELECT * FROM accounts WHERE provider = $1 AND provider_account_id = $2",
    )
    .bind(provider)
    .bind(provider_account_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::InternalServerError)?;
    Ok(account)
}

pub async fn create_user(pool: &PgPool, req: RegisterRequest) -> Result<User, AppError> {
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (
            id,email, first_name, last_name, email_verified, is_two_factor_enabled, role , password_hash
         )
    VALUES ($1, $2, $3, $4, $5, $6, $7::user_role , $8)
         RETURNING *",
    )
    .bind(Uuid::new_v4())
    .bind(req.email)
    .bind(req.first_name)
    .bind(req.last_name)
    .bind(false) // default value for email_verified
    .bind(false) // default value for 2FA
    .bind("user")
    .bind(req.password) // role string or UserRole enum as needed
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

pub async fn update_user_email_verified(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|err| {
            tracing::error!("Failed to verify the user's email: {:?}", err);
            AppError::InternalServerError
        })?;

    if result.rows_affected() == 0 {
        return Err(AppError::EmailNotFound); // Custom error for "user not found"
    }

    Ok(())
}

pub async fn save_email_verification_token(
    redis_conn: &mut Connection,
    email: String,
    token: &str,
) -> Result<(), AppError> {
    // Key format: email_verification_token:{token}
    let redis_key = format!("email_verification_token:{}", token);

    // Store value as JSON string
    let redis_value = json!({ "email": email }).to_string();

    // Expire in 15 minutes
    let expiry_seconds = 15 * 60;

    redis_conn
        .set_ex::<_, _, ()>(&redis_key, redis_value, expiry_seconds)
        .await
        .map_err(|err| {
            tracing::error!("Failed to save email verification token to Redis: {}", err);
            AppError::InternalServerError
        })?;

    Ok(())
}

pub async fn get_email_verification_token(
    redis_conn: &mut Connection,
    token: &str,
) -> Result<String, AppError> {
    // 1. Build Redis key using the token
    let key = format!("email_verification_token:{}", token);

    // 2. Fetch the stored JSON string from Redis
    let json: String = redis_conn.get::<_, String>(&key).await.map_err(|err| {
        tracing::error!("Redis GET failed: {}", err);
        AppError::InternalServerError
    })?;

    // 3. Parse the JSON to extract the "email" field
    let email = serde_json::from_str::<Value>(&json)
        .ok()
        .and_then(|v| v.get("email")?.as_str().map(str::to_owned))
        .ok_or(AppError::InternalServerError)?;

    // 4. Return the extracted email
    Ok(email)
}

pub async fn delete_email_verification_token(
    redis_conn: &mut Connection,
    token: &String,
) -> Result<(), AppError> {
    // Key in Redis: email_verification_token:{email}
    let key = format!("email_verification_token:{}", token);

    redis_conn
        .del::<_, usize>(&key)
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

pub async fn get_refresh_token(
    redis_conn: &mut Connection,
    session_id: &str,
) -> Result<(), AppError> {
    // Get a connection from the pool

    // Create the key and value for Redis
    let key = format!("session:{}", session_id);

    // Use the connection to set the key-value pair with expiration
    redis_conn
        .get::<_, usize>(&key)
        .await
        .map_err(|_| AppError::InternalServerError)?;

    Ok(())
}

pub async fn delete_refresh_token(
    redis_conn: &mut Connection,
    session_id: &str,
) -> Result<(), AppError> {
    // Get a connection from the pool

    // Create the key and value for Redis
    let key = format!("session:{}", session_id);

    // Set the expiration (7 days in seconds)

    // Use the connection to set the key-value pair with expiration
    redis_conn
        .del::<_, usize>(&key)
        .await
        .map_err(|_| AppError::InternalServerError)?;

    Ok(())
}

pub async fn get_2fa_code(
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

pub async fn store_2fa_code(
    redis_conn: &mut Connection,
    email: &str,
    code: &str,
) -> Result<(), AppError> {
    let key = format!("2fa:{}", email);
    let expiry_seconds: u64 = 7 * 24 * 60 * 60;
    redis_conn
        .set_ex::<_, _, ()>(&key, code, expiry_seconds)
        .await
        .map_err(|_| AppError::InternalServerError)?;
    Ok(())
}

pub async fn delete_2fa_code(
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

pub async fn find_account_by_user_id(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<Account>, AppError> {
    let accounts = sqlx::query_as::<_, Account>("SELECT * FROM accounts WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(|_| AppError::InternalServerError)?;

    Ok(accounts)
}

pub async fn refresh_access_token() -> Result<String, AppError> {
    // This function is a placeholder. Implement your logic to refresh the access token.
    // For example, you might want to generate a new JWT token or fetch a new one from an OAuth provider.
    Err(AppError::InternalServerError)
}

pub async fn link_oauth_account(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
    provider_account_id: &str,
    access_token: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "
        INSERT INTO accounts (
            user_id, provider, provider_account_id, access_token
        )
        VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(user_id)
    .bind(provider)
    .bind(provider_account_id)
    .bind(access_token)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalServerError)?;

    Ok(())
}

pub async fn get_session_by_refresh_token(
    redis: &mut Connection,
    refresh_token: &str,
) -> Result<(String, String), AppError> {
    // Assuming you store session_id and user_id in Redis with refresh token as key
    let session_info: Option<String> = redis.get(refresh_token).await.map_err(|e| {
        tracing::error!("Redis error: {:?}", e);
        return AppError::InternalServerError;
    })?;

    let session_info = session_info.ok_or_else(|| AppError::InvalidToken)?;

    // Example stored format: "session_id:user_id"
    let parts: Vec<&str> = session_info.split(':').collect();
    if parts.len() != 2 {
        return Err(AppError::InvalidToken);
    }

    let session_id = parts[0].to_string();
    let user_id = parts[1].to_string();

    Ok((user_id, session_id))
}
