use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "type", content = "data")]
pub enum KafkaPayload {
    EmailVerificationToken { email: String, token: String },
    TwoFactorCode { email: String, code: String },
    ChangePasswordCode { email: String, code: String },
    LogEvent { level: String, message: String },
}

// EmailVerificationToken,
// TwoFactorCode,
// ChangePasswordCode,
// LogEvent,
// Custom(String),
