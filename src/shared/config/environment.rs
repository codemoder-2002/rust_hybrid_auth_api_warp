use std::env;

#[derive(Debug, Clone)]
pub struct Environment {
    pub database_url: String,
    #[allow(dead_code)]
    pub jwt_secret: String,
    #[allow(dead_code)]
    pub redis_url: String,
}

impl Environment {
    pub fn new() -> Result<Self, String> {
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| "Missing required env: DATABASE_URL".to_string())?;

        let jwt_secret =
            env::var("JWT_SECRET").map_err(|_| "Missing required env: JWT_SECRET".to_string())?;

        let redis_url =
            env::var("REDIS_URL").map_err(|_| "Missing required env: REDIS_URL".to_string())?;

        Ok(Self {
            database_url,
            jwt_secret,
            redis_url,
        })
    }
}
