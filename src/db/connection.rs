use crate::shared::config::environment::Environment;
use deadpool_redis::{Config, Connection, Pool, Runtime, redis::cmd};

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::error::Error;

pub async fn establish_connection(env: &Environment) -> PgPool {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(&env.database_url)
        .await
        .expect("Failed to create SQLx pool")
}

pub async fn create_redis_connection(env: &Environment) -> Result<Pool, Box<dyn Error>> {
    let cfg = Config::from_url(&env.redis_url);
    let pool = cfg.create_pool(Some(Runtime::Tokio1))?;

    // Redis command using redis-rs style inside deadpool connection
    // let value: String = cmd("GET")
    //     .arg(&["deadpool/test_key"])
    //     .query_async(&mut conn)
    //     .await
    //     .unwrap();

    Ok(pool)
}
