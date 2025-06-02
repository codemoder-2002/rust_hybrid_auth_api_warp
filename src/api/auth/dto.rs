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

#[derive(Serialize, Deserialize, Debug, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 2, max = 30))]
    pub first_name: String,

    #[validate(length(min = 2, max = 50))]
    pub last_name: String,

    #[validate(email)]
    pub email: String,

    #[validate(length(min = 6))]
    pub password: String,
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
#[derive(Deserialize, Validate)]
pub struct EmailVerification {
    #[validate(length(min = 6))]
    pub token: String,
}

#[derive(Deserialize, Validate)]
pub struct TwofaRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Deserialize, Validate)]
pub struct OAuthCallbackBody {
    pub code: String,
}
