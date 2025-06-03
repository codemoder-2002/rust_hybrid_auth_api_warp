mod api;
mod db;
mod schema;
mod shared;

use std::sync::Arc;

use crate::shared::config::environment::Environment;
use crate::shared::utils::logger::init_logger;

use shared::kafka_message::producer::KafkaProducer;
use tracing::*;
use warp::Filter;

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
    info!("✅ Postgres is connected");
    let redis_pool = db::connection::create_redis_connection(&env)
        .await
        .unwrap_or_else(|err| {
            error!("❌ Failed to create Redis connection: {}", err);
            std::process::exit(1);
        });
    info!("✅ Redis is connected");

    let kafka_producer: Arc<KafkaProducer> =
        Arc::new(KafkaProducer::new(&env.kafka_url).unwrap_or_else(|err| {
            error!("❌ Failed to create Kafka producer: {}", err);
            std::process::exit(1);
        }));

    info!("✅ Kafka is connected");

    let health_route = warp::path!("health")
        .and(warp::get())
        .map(|| warp::reply::json(&serde_json::json!({ "status": "ok" })));

    let cors = warp::cors()
        .allow_origin("http://localhost:3000") // allow your frontend dev server
        .allow_credentials(true)
        .allow_headers(vec!["content-type", "authorization"]);

    let routes = api::auth::controller::auth_routes(pool, redis_pool, kafka_producer.clone())
        .recover(shared::error::handlers::handle_rejection)
        .with(cors) // 👈 Apply the CORS filter here
        .with(warp::log("api"));

    let routes = health_route.or(routes);

    let (addr, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], 3030), async {
            tokio::signal::ctrl_c()
                .await
                .expect("❌ Failed to listen for shutdown signal");
            info!("⚠️ Shutdown signal received, terminating server...");
        });

    info!("🚀 Server running on http://{}", addr);
    server.await;
}
