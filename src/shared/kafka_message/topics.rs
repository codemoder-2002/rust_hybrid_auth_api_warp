#[derive(Debug)]
pub enum KafkaTopic {
    EmailVerificationToken,
    TwoFactorCode,
    ChangePasswordCode,
    LogEvent,
    Custom(String),
}

impl KafkaTopic {
    pub fn as_str(&self) -> &str {
        match self {
            KafkaTopic::EmailVerificationToken => "email_verification_token",
            KafkaTopic::TwoFactorCode => "two_factor_code",
            KafkaTopic::ChangePasswordCode => "change_password_code",
            KafkaTopic::LogEvent => "log-event",
            KafkaTopic::Custom(val) => val,
        }
    }
}
