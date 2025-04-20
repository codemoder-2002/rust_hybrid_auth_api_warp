use super::service;
use crate::api::auth::dto::*;
use crate::shared::error::handlers::handle_rejection;
use crate::shared::utils::validator::with_validated_body;
use sqlx::PgPool;
use warp::Filter;

fn with_db(
    pool: PgPool,
) -> impl Filter<Extract = (PgPool,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || pool.clone())
}

pub fn auth_routes(pool: PgPool) -> warp::filters::BoxedFilter<(impl warp::Reply,)> {
    let credentials_login = warp::path!("login")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and(with_validated_body::<LoginRequest>()) // ✅ this already extracts and validates
        .and_then(service::login);

    let register = warp::path!("register")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and(with_validated_body::<RegisterRequest>())
        .and_then(service::register);

    let refresh = warp::path!("refresh")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and_then(service::refresh_token);

    let verify_email = warp::path!("verify-email")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and(warp::body::json())
        .and_then(service::verify_email);

    let request_2fa = warp::path!("2fa" / "request")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and(warp::body::json())
        .and_then(service::request_2fa);

    let verify_2fa = warp::path!("2fa" / "verify")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and(warp::body::json())
        .and_then(service::verify_2fa);

    let oauth_callback = warp::path!("oauth" / "callback")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and(warp::body::json())
        .and_then(service::oauth_callback);

    let logout = warp::path!("logout")
        .and(warp::post())
        .and(with_db(pool.clone()))
        .and_then(service::logout);

    credentials_login
        .or(register)
        .or(refresh)
        .or(verify_email)
        .or(request_2fa)
        .or(verify_2fa)
        .or(oauth_callback)
        .or(logout)
        .recover(handle_rejection)
        .boxed()
}
