use crate::shared::config::environment::Environment;
use redis::Client;
use redis::aio::MultiplexedConnection;
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

pub async fn create_redis_connection(
    env: &Environment,
) -> Result<MultiplexedConnection, Box<dyn Error>> {
    let client = Client::open(env.redis_url.clone())?;
    let connection = client.get_multiplexed_async_connection().await?;
    Ok(connection)
}
