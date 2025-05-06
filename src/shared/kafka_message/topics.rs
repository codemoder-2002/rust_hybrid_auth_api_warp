#[derive(Debug)]
pub enum KafkaTopic {
    UserSignup,
    VerificationCode,
    LogEvent,
    Custom(String),
}

impl KafkaTopic {
    pub fn as_str(&self) -> &str {
        match self {
            KafkaTopic::UserSignup => "user-signup",
            KafkaTopic::VerificationCode => "verification-code",
            KafkaTopic::LogEvent => "log-event",
            KafkaTopic::Custom(val) => val,
        }
    }
}
