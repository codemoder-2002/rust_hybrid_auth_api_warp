use serde::{Deserialize, Serialize};
use thiserror::Error;
// use warp::{Rejection, Reply, http::StatusCode, reject::MethodNotAllowed};
// src/shared/error/mod.rs
pub mod handlers; // This makes sure handlers.rs is part of the module tree.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("could not hash password")]
    ArgonError,
    #[error("could not verify password")]
    ArgonVerifyError,
    #[error("could not create token")]
    JWTTokenCreationError,
    #[error("could not verify token")]
    JWTTokenVerifyError,
    #[error("email not verified")]
    EmailNotVerified,
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("token not found")]
    TokenNotFound,
    #[error("token already used")]
    TokenAlreadyUsed,
}
impl warp::reject::Reject for AuthError {}

#[derive(Error, Debug, Serialize)]
pub enum AppError {
    #[error("email not found")]
    EmailNotFound,
    #[error("wrong credentials")]
    WrongCredentialsError,
    #[error("jwt token not valid")]
    JWTTokenError,
    #[error("jwt token creation failed")]
    JWTTokenCreationError,
    #[error("no auth header")]
    NoAuthHeaderError,
    #[error("invalid auth header")]
    InvalidAuthHeaderError,
    #[error("no permission")]
    NoPermissionError,
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("internal server error")]
    InternalServerError,
    #[error("user already exists")]
    UserAlreadyExists,

    #[error("Invalid Token")]
    InvalidToken,

    #[error("Email already verified")]
    EmailAlreadyVerified,

    #[error("Missing Token")]
    MissingToken,
}
impl warp::reject::Reject for AppError {}

#[derive(Serialize, Debug)]
pub struct ErrorResponse {
    pub message: String,
    pub code: Option<String>,               // Optional error code
    pub details: Option<serde_json::Value>, // Optional extra data
    pub status: u16,                        // Status as number, not string
}

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum UserError {
    #[error("could not create user")]
    CreateError,
    #[error("could not update user")]
    UpdateError,
}
impl warp::reject::Reject for UserError {}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DatabaseError {
    pub message: String,
}
impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Database error")
    }
}
