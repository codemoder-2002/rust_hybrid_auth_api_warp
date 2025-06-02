use std::sync::Arc;

use super::dto::TwofaRequest;
use super::service;
use crate::api::auth::dto::{LoginRequest, RegisterRequest};
use crate::shared::error::AppError;
use crate::shared::error::handlers::handle_rejection;
use crate::shared::kafka_message::producer::KafkaProducer;
use crate::shared::utils::jwt::Claims;
use crate::shared::utils::validator::with_validated_body;
use deadpool_redis::{Connection, Pool};

// use redis::aio::MultiplexedConnection;

use sqlx::PgPool;

use warp::Filter;

fn with_db(
    pool: PgPool,
) -> impl Filter<Extract = (PgPool,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || pool.clone())
}

fn with_kafka(
    kafka: Arc<KafkaProducer>,
) -> impl Filter<Extract = (Arc<KafkaProducer>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || kafka.clone())
}

pub fn with_redis(
    pool: Pool,
) -> impl Filter<Extract = (Connection,), Error = warp::Rejection> + Clone {
    warp::any().and_then(move || {
        println!("with_redis called");
        let pool = pool.clone();
        async move {
            match pool.get().await {
                Ok(conn) => Ok(conn),
                Err(e) => {
                    eprintln!("[with_redis] Failed to get Redis connection: {}", e);
                    Err(warp::reject::custom(AppError::InternalServerError))
                }
            }
        }
    })
}

// let kafka_filter = warp::any().map(move || kafka.clone());

pub fn auth_routes(
    pool: PgPool,
    redis_pool: Pool,
    kafka: Arc<KafkaProducer>,
) -> warp::filters::BoxedFilter<(impl warp::Reply,)> {
    let credentials_login = warp::path!("login")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and(with_redis(redis_pool.clone()))
        .and(with_kafka(kafka.clone()))
        .and(with_validated_body::<LoginRequest>()) // ✅ this already extracts and validates
        .and_then(service::login);

    let register = warp::path!("register")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and(with_redis(redis_pool.clone()))
        .and(with_kafka(kafka.clone()))
        .and(with_validated_body::<RegisterRequest>())
        .and_then(service::register);

    let refresh = warp::path!("refresh")
        .and(warp::get())
        .and(with_db(pool.clone()))
        .and(with_redis(redis_pool.clone()))
        .and(warp::header::headers_cloned()) // 👈 correct way to get cookies
        .and_then(service::refresh_token);

    let verify_email = warp::path!("verify-email" / String) // token as path param
        .and(warp::get())
        .and(with_db(pool.clone()))
        .and(with_redis(redis_pool.clone()))
        .and_then(service::verify_email);

    let request_2fa = warp::path!("2fa" / "request")
        .and(warp::post())
        .and(with_redis(redis_pool.clone()))
        .and(with_kafka(kafka.clone()))
        .and(with_validated_body::<TwofaRequest>())
        .and_then(service::request_2fa);

    // warp::path("me")
    //     .and(warp::post())
    //     .and(with_redis(redis_pool.clone()))
    //     .and(with_authenticated_user(redis_pool.clone()))
    //     .and_then(
    //         |_redis, claims: Claims, maybe_new_token: Option<String>| async move {
    //             let user_id = claims.sub;

    //             let mut json = serde_json::json!({ "user_id": user_id });

    //             if let Some(new_token) = maybe_new_token {
    //                 json["new_access_token"] = serde_json::Value::String(new_token);
    //             }

    //             Ok::<_, warp::Rejection>(warp::reply::json(&json))
    //         },
    //     );

    // let oauth_callback = warp::path!("oauth" / "callback")
    //     .and(warp::post())
    //     .and(with_db(pool.clone())) // Assumes a helper function to inject DB pool
    //     .and(warp::body::json()) // Expecting JSON body
    //     .and_then(service::oauth_callback); // Call the service layer to handle logic

    let logout = warp::path!("logout")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and_then(service::logout);

    credentials_login
        .or(register)
        .or(refresh)
        .or(verify_email)
        .or(request_2fa)
        // .or(oauth_callback)
        // .or(oauth_callback)
        .or(logout)
        .recover(handle_rejection)
        .boxed()
}
