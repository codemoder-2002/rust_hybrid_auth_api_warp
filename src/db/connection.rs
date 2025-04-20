use crate::shared::config::environment::Environment;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub async fn establish_connection(env: &Environment) -> PgPool {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(&env.database_url)
        .await
        .expect("Failed to create SQLx pool")
}
