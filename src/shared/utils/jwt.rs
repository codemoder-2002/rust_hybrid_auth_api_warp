//generate_jwt
use crate::shared::error::AppError;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ACCESS_TOKEN_EXPIRY_MINUTES: i64 = 15;
const REFRESH_TOKEN_LENGTH: usize = 64;

/// Your secret should come from an env/config file.
const SECRET_KEY: &[u8] = b"your_super_secret_key_change_me";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user ID
    pub email: String,
    pub exp: usize,
    pub iat: usize,
}

/// Generate a JWT access token (15 min expiry)
pub fn generate_access_token(user_id: String, email: String) -> Result<String, AppError> {
    let now = Utc::now();
    let claims: Claims = Claims {
        sub: user_id,
        email,
        iat: now.timestamp() as usize,
        exp: (now + Duration::minutes(ACCESS_TOKEN_EXPIRY_MINUTES)).timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET_KEY),
    )
    .map_err(|_| AppError::JWTTokenCreationError)
}

/// Generate a secure random refresh token (e.g., 64-char UUID string)
pub fn generate_refresh_token() -> Result<String, AppError> {
    Ok(Uuid::new_v4().to_string().replace("-", "") + &Uuid::new_v4().to_string().replace("-", ""))
}

/// Decode and validate a JWT token
pub fn decode_jwt_token(token: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET_KEY),
        &Validation::new(Algorithm::HS256),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::JWTTokenError)
}

// Define the EmailVerificationClaims struct
#[derive(Serialize, Deserialize)]
pub struct EmailVerificationClaims {
    sub: String,
    email: String,
    exp: usize,
}

pub fn generate_email_verification_token() -> String {
    Uuid::new_v4().to_string()
}

pub fn generate_2fa_code() -> String {
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(100000..999999);
    code.to_string()
}
