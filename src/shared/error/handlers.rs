use crate::shared::error::{AppError, AuthError, ErrorResponse, UserError};
use std::convert::Infallible;
use warp::{Rejection, Reply, http::StatusCode, reject::MethodNotAllowed};

pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Resource not found".to_string())
    } else if let Some(e) = err.find::<UserError>() {
        (StatusCode::BAD_REQUEST, e.to_string())
    } else if let Some(e) = err.find::<AppError>() {
        match e {
            AppError::WrongCredentialsError => (StatusCode::FORBIDDEN, e.to_string()),
            AppError::NoPermissionError | AppError::JWTTokenError => {
                (StatusCode::UNAUTHORIZED, e.to_string())
            }
            AppError::JWTTokenCreationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token generation failed".to_string(),
            ),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::EmailNotFound => (StatusCode::BAD_REQUEST, "Email not found".to_string()),
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        }
    } else if let Some(e) = err.find::<AuthError>() {
        match e {
            AuthError::InvalidCredentials => {
                (StatusCode::BAD_REQUEST, "Invalid credentials".to_string())
            }
            AuthError::EmailNotVerified => {
                (StatusCode::FORBIDDEN, "Email not verified".to_string())
            }
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired".to_string()),
            AuthError::TokenNotFound => (StatusCode::UNAUTHORIZED, "Token not found".to_string()),
            AuthError::TokenAlreadyUsed => {
                (StatusCode::UNAUTHORIZED, "Token already used".to_string())
            }
            AuthError::JWTTokenCreationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token generation failed".to_string(),
            ),
            AuthError::JWTTokenVerifyError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token verification failed".to_string(),
            ),
            AuthError::ArgonError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password hashing failed".to_string(),
            ),
            AuthError::ArgonVerifyError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password verification failed".to_string(),
            ),
            _ => (StatusCode::UNAUTHORIZED, e.to_string()),
        }
    } else if let Some(_) = err.find::<MethodNotAllowed>() {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed".to_string(),
        )
    } else {
        eprintln!("[handle_rejection] Unhandled error: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error".to_string(),
        )
    };

    let json = warp::reply::json(&ErrorResponse {
        status: code.as_u16().to_string(),
        message,
    });

    Ok(warp::reply::with_status(json, code))
}
