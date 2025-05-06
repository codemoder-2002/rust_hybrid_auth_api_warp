mod api;
mod db;
mod schema;
mod shared;

use crate::shared::config::environment::Environment;
use crate::shared::utils::logger::init_logger;

use shared::kafka_message::producer::KafkaProducer;
use tracing::*;

#[tokio::main]
async fn main() {
    if dotenvy::dotenv().is_err() {
        eprintln!("⚠️  .env file not found. Continuing with system environment variables.");
    }
    // schema::models::User;

    init_logger();

    let env: Environment = Environment::new().unwrap_or_else(|err| {
        error!("❌ Failed to load configuration: {}", err);
        std::process::exit(1);
    });

    let pool: sqlx::Pool<sqlx::Postgres> = db::connection::establish_connection(&env).await;
    info!("🚀 Postgres is connected");
    let redis_pool = db::connection::create_redis_connection(&env)
        .await
        .unwrap_or_else(|err| {
            error!("❌ Failed to create Redis connection: {}", err);
            std::process::exit(1);
        });
    info!("🚀 Redis is connected");

    let kafka_producer = KafkaProducer::new(&env.kafka_url).unwrap_or_else(|err| {
        error!("❌ Failed to create Kafka producer: {}", err);
        std::process::exit(1);
    });

    let routes = api::auth::controller::auth_routes(pool, redis_pool);

    let (addr, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], 3030), async {
            tokio::signal::ctrl_c()
                .await
                .expect("❌ Failed to listen for shutdown signal");
        });

    info!("🚀 Server running on http://{}", addr);
    server.await;
}
