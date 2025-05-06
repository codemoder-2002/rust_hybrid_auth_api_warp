use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "type", content = "data")]
pub enum KafkaPayload {
    UserSignup { user_id: String, email: String },
    VerificationCode { user_id: String, code: String },
    LogEvent { level: String, message: String },
}
