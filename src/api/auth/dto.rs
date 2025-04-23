use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 6))]
    pub password: String,

    #[validate(length(min = 6, max = 6))]
    pub code: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub id: i32,
    pub user_id: i32,
}

#[derive(Deserialize, Debug, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 6))]
    pub password: String,

    #[validate(length(min = 3))]
    pub username: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub email: String,
    pub password: String,
    pub username: String,
    pub token: String,
    pub id: i32,
}

#[derive(Serialize)]
pub struct EmailMessage {
    to: String,
    subject: String,
    code: String,
}
