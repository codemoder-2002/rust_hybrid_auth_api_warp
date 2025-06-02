use crate::shared::error::{AppError, AuthError, ErrorResponse, UserError};
use std::convert::Infallible;
use warp::{Rejection, Reply, http::StatusCode, reject::MethodNotAllowed};

pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (code, message, code_str) = if err.is_not_found() {
        (
            StatusCode::NOT_FOUND,
            "Resource not found".to_string(),
            Some("NOT_FOUND".to_string()),
        )
    } else if let Some(e) = err.find::<UserError>() {
        (
            StatusCode::BAD_REQUEST,
            e.to_string(),
            Some("USER_ERROR".to_string()),
        )
    } else if let Some(e) = err.find::<AppError>() {
        match e {
            AppError::WrongCredentialsError => (
                StatusCode::FORBIDDEN,
                e.to_string(),
                Some("WRONG_CREDENTIALS".to_string()),
            ),
            AppError::NoPermissionError | AppError::JWTTokenError => (
                StatusCode::UNAUTHORIZED,
                e.to_string(),
                Some("UNAUTHORIZED".to_string()),
            ),
            AppError::JWTTokenCreationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token generation failed".to_string(),
                Some("TOKEN_CREATION_FAILED".to_string()),
            ),
            AppError::ValidationError(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                msg.clone(),
                Some("VALIDATION_ERROR".to_string()),
            ),
            AppError::InternalServerError => {
                println!("Internal Server Error encountered: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    Some("INTERNAL_SERVER_ERROR".to_string()),
                )
            }
            AppError::UserAlreadyExists => (
                StatusCode::CONFLICT,
                "User already exists".to_string(),
                Some("USER_EXISTS".to_string()),
            ),
            AppError::EmailNotFound => (
                StatusCode::BAD_REQUEST,
                "Email not found".to_string(),
                Some("EMAIL_NOT_FOUND".to_string()),
            ),
            AppError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Missing token".to_string(),
                Some("MISSING_TOKEN".to_string()),
            ),
            _ => (
                StatusCode::BAD_REQUEST,
                e.to_string(),
                Some("APP_ERROR".to_string()),
            ),
        }
    } else if let Some(e) = err.find::<AuthError>() {
        let (status, msg, code) = match e {
            AuthError::InvalidCredentials => (
                StatusCode::BAD_REQUEST,
                "Invalid credentials",
                "INVALID_CREDENTIALS",
            ),
            AuthError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                "Email not verified",
                "EMAIL_NOT_VERIFIED",
            ),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token", "INVALID_TOKEN"),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired", "TOKEN_EXPIRED"),
            AuthError::TokenNotFound => (
                StatusCode::UNAUTHORIZED,
                "Token not found",
                "TOKEN_NOT_FOUND",
            ),
            AuthError::TokenAlreadyUsed => (
                StatusCode::UNAUTHORIZED,
                "Token already used",
                "TOKEN_ALREADY_USED",
            ),
            AuthError::JWTTokenCreationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token creation failed",
                "TOKEN_CREATION_ERROR",
            ),
            AuthError::JWTTokenVerifyError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token verification failed",
                "TOKEN_VERIFY_ERROR",
            ),
            AuthError::ArgonError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password hashing failed",
                "HASH_FAILED",
            ),
            AuthError::ArgonVerifyError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password verification failed",
                "VERIFY_FAILED",
            ),
        };
        (status, msg.to_string(), Some(code.to_string()))
    } else if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid request body: {}", e),
            Some("BODY_DESERIALIZATION_ERROR".to_string()),
        )
    } else if let Some(_) = err.find::<MethodNotAllowed>() {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed".to_string(),
            Some("METHOD_NOT_ALLOWED".to_string()),
        )
    } else {
        eprintln!("[handle_rejection] Unhandled rejection: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error".to_string(),
            Some("INTERNAL".to_string()),
        )
    };
    eprintln!("[handle_rejection] Unhandled rejection: {:?}", err);
    let json = warp::reply::json(&ErrorResponse {
        message,
        code: code_str,
        details: None,
        status: code.as_u16(),
    });

    Ok(warp::reply::with_status(json, code))
}
