use std::env;

#[derive(Debug, Clone)]
pub struct Environment {
    pub database_url: String,

    pub jwt_secret: String,

    pub redis_url: String,

    pub kafka_url: String,
    // pub frontend_url: String,
}

impl Environment {
    pub fn new() -> Result<Self, String> {
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| "Missing required env: DATABASE_URL".to_string())?;

        let jwt_secret =
            env::var("JWT_SECRET").map_err(|_| "Missing required env: JWT_SECRET".to_string())?;

        let redis_url =
            env::var("REDIS_URL").map_err(|_| "Missing required env: REDIS_URL".to_string())?;

        let kafka_url =
            env::var("KAFKA_URL").map_err(|_| "Missing required env: KAFKA_URL".to_string())?;

        // let frontend_url = env::var("FRONTEND_URL")
        //     .map_err(|_| "Missing required env: FRONTEND_URL".to_string())?;

        Ok(Self {
            database_url,
            jwt_secret,
            redis_url,
            kafka_url,
            // frontend_url,
        })
    }
}
