use std::sync::Arc;

use deadpool_redis::Connection;

use serde_json::json;
pub use sqlx::PgPool;
use uuid::Uuid;
use warp::{
    Rejection, Reply,
    http::StatusCode,
    http::{HeaderValue, header},
    reject,
    reply::json,
};

use super::{
    dto::{OAuthCallbackBody, TwofaRequest},
    repository::{self, store_2fa_code},
};
use crate::{
    api::auth::dto::{LoginRequest, RegisterRequest},
    schema::models::User,
    shared::{
        error::*,
        kafka_message::{payload, producer::KafkaProducer, topics::KafkaTopic},
        utils::{
            hash::{hash_password, verify_password},
            jwt::*,
        },
    },
};

pub async fn login(
    pool: PgPool,
    mut redis_conn: Connection,
    kafka: Arc<KafkaProducer>,
    body: LoginRequest,
) -> Result<Box<dyn Reply>, warp::Rejection> {
    // 1. Find user by email
    let user = repository::find_user_by_email(&pool, &body.email)
        .await
        .map_err(|_| warp::reject::custom(AppError::EmailNotFound))?;

    // 2. Get password hash (fail early if not found)
    let password_hash = user
        .password_hash
        .clone()
        .ok_or_else(|| warp::reject::custom(AuthError::InvalidCredentials))?;

    // 3. If email not verified, store password and respond
    if !user.email_verified {
        // Update password in DB if needed (you had this part)
        if let Err(err) = repository::update_user_password(&pool, user.id, &password_hash).await {
            tracing::error!("Failed to update password: {:?}", err);
            return Err(warp::reject::custom(AuthError::EmailNotVerified));
        }

        // Call shared email verification handler
        return handle_email_verification(
            redis_conn,
            kafka,
            user.email.clone(),
            "Email not verified. Verification email sent.",
        )
        .await;
    }

    // 4. Verify password
    if !verify_password(&body.password, &password_hash)? {
        return Err(warp::reject::custom(AppError::WrongCredentialsError));
    }

    // 5. Handle 2FA
    if user.is_two_factor_enabled {
        match &body.code {
            Some(code) => {
                let stored_code = repository::get_2fa_code(&mut redis_conn, &user.email).await?;

                if let Some(ref stored) = stored_code {
                    if stored == code {
                        repository::delete_2fa_code(&mut redis_conn, &user.email).await?;

                        return generate_success_response(&mut redis_conn, &user).await;
                    }
                }

                return Err(warp::reject::custom(AuthError::InvalidCredentials));
            }
            None => {
                //send 2fa code

                let code: String = generate_2fa_code();

                if let Err(err) = kafka
                    .send_event(
                        KafkaTopic::TwoFactorCode,
                        &user.email,
                        payload::KafkaPayload::TwoFactorCode {
                            email: user.email.clone(),
                            code,
                        },
                    )
                    .await
                {
                    tracing::error!("Failed to send Kafka event: {:?}", err);
                }

                let body = json!({ "two_factor": true });
                return Ok(Box::new(warp::reply::json(&body)));
            }
        }
    }

    // 6. No 2FA, successful login
    generate_success_response(&mut redis_conn, &user).await
}

fn generate_cookie(value: &str) -> String {
    format!(
        "refresh_token={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800;",
        value
    )
}

async fn generate_success_response(
    redis_conn: &mut Connection,
    user: &User,
) -> Result<Box<dyn Reply>, warp::Rejection> {
    let access_token = generate_access_token(user.id.to_string(), user.email.clone())?;
    let refresh_token = generate_refresh_token()?;
    let session_id = Uuid::new_v4().to_string();

    repository::store_refresh_token(redis_conn, &session_id, &refresh_token, user.id.to_string())
        .await?;

    let body = json!({
        "access_token": access_token,
        "session_id": session_id,
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "name":user.last_name.clone() + " " + &user.first_name,
            "profile_picture": user.profile_picture.clone(),
        },
        "two_factor": false,
        "success": true,
    });

    let reply = warp::reply::json(&body);
    let reply_with_cookie = warp::reply::with_header(
        reply,
        header::SET_COOKIE,
        HeaderValue::from_str(&generate_cookie(&refresh_token)).unwrap(),
    );

    Ok(Box::new(reply_with_cookie))
}

pub async fn register(
    pool: PgPool,
    redis_pool: Connection,
    kafka: Arc<KafkaProducer>,
    mut body: RegisterRequest,
) -> Result<impl Reply, Rejection> {
    println!("[REGISTER] Handler called");

    // 1. Check if the user exists
    match repository::find_user_by_email(&pool, &body.email).await {
        Ok(existing_user) => {
            if existing_user.email_verified {
                println!("[REGISTER] User already exists and is verified");
                return Err(reject::custom(AppError::UserAlreadyExists));
            }

            // User exists but not verified – update password
            println!("[REGISTER] User exists but not verified – updating password");

            let password_hash = match hash_password(&body.password) {
                Ok(hash) => hash,
                Err(err) => {
                    eprintln!("[REGISTER] Password hashing failed: {:?}", err);
                    return Err(reject::custom(err));
                }
            };

            // User exists but not verified – update password and trigger email verification
            if let Err(err) =
                repository::update_user_password(&pool, existing_user.id, &password_hash).await
            {
                eprintln!("[REGISTER] Failed to update password: {:?}", err);
                return Err(reject::custom(err));
            }

            return handle_email_verification(
                redis_pool,
                kafka,
                existing_user.email.clone(),
                "User already registered but not verified. A new verification link has been sent.",
            )
            .await;
        }

        Err(AppError::EmailNotFound) => {
            println!("[REGISTER] No existing user. Proceeding to register");

            let password_hash = match hash_password(&body.password) {
                Ok(hash) => hash,
                Err(err) => {
                    eprintln!("[REGISTER] Password hashing failed: {:?}", err);
                    return Err(reject::custom(err));
                }
            };
            body.password = password_hash;

            let new_user = match repository::create_user(&pool, body).await {
                Ok(user) => user,
                Err(err) => {
                    eprintln!("[REGISTER] Failed to create user: {:?}", err);
                    return Err(reject::custom(err));
                }
            };

            return handle_email_verification(
                redis_pool,
                kafka,
                new_user.email,
                "User registered successfully. Verification email sent.",
            )
            .await;
        }

        Err(err) => {
            eprintln!("[REGISTER] Unexpected error when finding user: {:?}", err);
            return Err(reject::custom(err));
        }
    }
}

// This helper wraps the email verification logic, used in login and register
async fn handle_email_verification(
    mut redis_conn: Connection,
    kafka: Arc<KafkaProducer>,
    email: String,
    message: &str,
) -> Result<Box<dyn Reply>, Rejection> {
    let token = generate_email_verification_token();

    repository::save_email_verification_token(&mut redis_conn, email.clone(), &token).await?;

    if let Err(err) = kafka
        .send_event(
            KafkaTopic::EmailVerificationToken, // <-- fix topic here, see below
            &email,
            payload::KafkaPayload::EmailVerificationToken {
                email: email.clone(),
                token,
            },
        )
        .await
    {
        tracing::error!("Failed to send Kafka event: {:?}", err);
    }

    let reply = warp::reply::json(&serde_json::json!({ "message": message }));

    Ok(Box::new(reply))
}

pub async fn refresh_token(
    pool: PgPool,
    mut redis_conn: Connection,
    cookies: warp::http::HeaderMap,
) -> Result<impl Reply, Rejection> {
    // 1. Extract refresh_token from cookie
    let cookie_header = cookies.get("cookie").and_then(|h| h.to_str().ok());

    let refresh_token = cookie_header
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let parts: Vec<&str> = c.trim().splitn(2, '=').collect();
                if parts.get(0)? == &"refresh_token" {
                    parts.get(1).map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| warp::reject::custom(AppError::MissingToken))?;

    // 2. Look up session by refresh token in Redis
    let (user_id, session_id) =
        repository::get_session_by_refresh_token(&mut redis_conn, &refresh_token)
            .await
            .map_err(warp::reject::custom)?;

    // 3. Generate new access token
    let user = repository::find_user_by_id(&pool, &user_id)
        .await
        .map_err(warp::reject::custom)?;

    let access_token = generate_access_token(user.id.to_string(), user.email.clone())
        .map_err(warp::reject::custom)?;

    // 4. Build response
    let response = json!({
        "access_token": access_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role
        }
    });

    Ok(warp::reply::with_status(
        warp::reply::json(&response),
        StatusCode::OK,
    ))
}
pub async fn verify_email(
    token: String,
    pool: PgPool,
    mut redis_conn: Connection,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Retrieve the email linked to the verification token
    let email = repository::get_email_verification_token(&mut redis_conn, &token)
        .await
        .map_err(warp::reject::custom)?;

    if email.trim().is_empty() {
        return Err(warp::reject::custom(AppError::InvalidToken));
    }

    // Find user by email
    let user = repository::find_user_by_email(&pool, &email)
        .await
        .map_err(warp::reject::custom)?;

    if user.id.is_nil() {
        return Err(warp::reject::custom(AppError::EmailNotFound));
    }

    if user.email_verified {
        return Err(warp::reject::custom(AppError::EmailAlreadyVerified));
    }

    // Mark the email as verified
    repository::update_user_email_verified(&pool, user.id)
        .await
        .map_err(warp::reject::custom)?;

    // Clean up the used token
    repository::delete_email_verification_token(&mut redis_conn, &token)
        .await
        .map_err(warp::reject::custom)?;

    // Send a success response
    let response = warp::reply::json(&json!({
        "message": "Email verified successfully",
        "success": true,
    }));

    Ok(response)
}

pub async fn request_2fa(
    mut redis_pool: Connection,
    kafka: Arc<KafkaProducer>,
    body: TwofaRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    let code = generate_2fa_code();

    store_2fa_code(&mut redis_pool, &body.email, &code).await?;

    if let Err(err) = kafka
        .send_event(
            KafkaTopic::TwoFactorCode,
            &body.email,
            payload::KafkaPayload::TwoFactorCode {
                email: body.email.clone(),
                code,
            },
        )
        .await
    {
        tracing::error!("Failed to send Kafka event: {:?}", err);
    }
    let res = json!({
        "message": "Code sent successfully",
        "success": true,
    });
    let reply = warp::reply::json(&res);

    Ok(reply)
}

// pub async fn oauth_callback(
//     pool: PgPool,
//     body: OAuthCallbackBody,
// ) -> Result<impl warp::Reply, warp::Rejection> {
//     // Step 1: Exchange authorization code for access token
//     let token_response = exchange_google_code(&body.code)
//         .await
//         .map_err(warp::reject::custom)?;

//     // Step 2: Use access token to fetch user info from Google
//     let user_info = fetch_google_user_info(&token_response.access_token)
//         .await
//         .map_err(warp::reject::custom)?;

//     // Step 3: Check if user exists, else register
//     let user = match repository::find_user_by_email(&pool, &user_info.email).await {
//         Ok(existing_user) => existing_user,
//         Err(AppError::EmailNotFound) => repository::create_user_from_oauth(&pool, &user_info)
//             .await
//             .map_err(warp::reject::custom)?,
//         Err(e) => return Err(warp::reject::custom(e)),
//     };

//     // Step 4: Generate your own session token (JWT)
//     let jwt = generate_access_token(&user.id, &user.email).map_err(warp::reject::custom)?;

//     // Step 5: Respond with token + user info
//     let response = warp::reply::json(&serde_json::json!({
//         "token": jwt,
//         "user": user,
//     }));

//     Ok(response)
// }

pub async fn logout(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}

pub async fn me(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}

pub async fn isUserExist(_pool: PgPool) -> Result<impl Reply, warp::Rejection> {
    // Pretend to return a list of users
    Ok(warp::reply::json(&vec!["user1", "user2"]))
}

// pub fn with_authenticated_user(
//     pool: PgPool,
//     mut redis_conn: Connection,
// ) -> impl Filter<Extract = (Claims, Option<String>), Error = Rejection> + Clone {
//     warp::header::headers_cloned().and_then(move |headers: warp::http::HeaderMap| {
//         let redis = redis.clone();
//         async move {
//             let access_token = headers
//                 .get("authorization")
//                 .and_then(|h| h.to_str().ok())
//                 .and_then(|s| s.strip_prefix("Bearer "))
//                 .ok_or_else(|| warp::reject::custom(AuthError::MissingToken))?;

//             let refresh_token = headers.get("x-refresh-token").and_then(|h| h.to_str().ok());

//             let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

//             // Validate access token
//             let validation = Validation::new(Algorithm::HS256);
//             let result = decode::<Claims>(
//                 &access_token,
//                 &DecodingKey::from_secret(jwt_secret.as_ref()),
//                 &validation,
//             );

//             match result {
//                 Ok(token_data) => {
//                     let claims = token_data.claims;
//                     let now = Utc::now().timestamp();
//                     let expires_in = claims.exp as i64 - now;

//                     if expires_in < 300 {
//                         // Token is expiring in <5 mins, refresh if possible
//                         if let Some(refresh_token) = refresh_token {
//                             let new_claims =
//                                 refresh_access_token(&redis, &claims.sub, refresh_token).await?;
//                             let new_token = create_jwt(&new_claims)?;
//                             return Ok((new_claims, Some(new_token)));
//                         }
//                     }

//                     Ok((claims, None))
//                 }
//                 Err(_) => Err(warp::reject::custom(AuthError::InvalidToken)),
//             }
//         }
//     })
// }
