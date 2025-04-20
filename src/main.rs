mod api;
mod db;
mod schema;
mod shared;

use crate::shared::config::environment::Environment;
use crate::shared::utils::logger::init_logger;

use tracing::*;

#[tokio::main]
async fn main() {
    println!("🚀 Starting the application...");
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
    info!("connected");

    let routes = api::auth::controller::auth_routes(pool);

    let (addr, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], 3030), async {
            tokio::signal::ctrl_c()
                .await
                .expect("❌ Failed to listen for shutdown signal");
        });

    info!("🚀 Server running on http://{}", addr);
    server.await;
}
