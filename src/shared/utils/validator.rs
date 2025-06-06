use serde::de::DeserializeOwned;
use validator::Validate;
use warp::http::HeaderMap;
use warp::{Filter, Rejection};

pub fn with_validated_body<T>() -> impl Filter<Extract = (T,), Error = Rejection> + Clone
where
    T: Send + DeserializeOwned + Validate + 'static,
{
    warp::body::json().and_then(|body: T| async move {
        match body.validate() {
            Ok(_) => Ok(body),
            Err(errors) => {
                let message = format!("Validation failed: {}", errors);
                eprintln!("[validator] Validation error: {}", message);
                Err(warp::reject::custom(
                    crate::shared::error::AppError::ValidationError(message),
                ))
            }
        }
    })
}

#[derive(Debug, Validate)]
pub struct AuthHeader {
    #[validate(length(min = 1))]
    pub authorization: String,
}

pub fn with_validated_header() -> impl Filter<Extract = (AuthHeader,), Error = Rejection> + Clone {
    warp::header::headers_cloned().and_then(|headers: HeaderMap| async move {
        // Extract and build the AuthHeader struct manually

        println!("with_validated_header called:{headers:?}");
        let auth = headers
            .get("authorization")
            .and_then(|val| val.to_str().ok())
            .map(|s| s.to_string());

        match auth {
            Some(auth_value) => {
                let header = AuthHeader {
                    authorization: auth_value,
                };

                match header.validate() {
                    Ok(_) => Ok(header),
                    Err(errors) => {
                        let message = format!("Validation failed: {}", errors);
                        eprintln!("[validator] Header validation error: {}", message);
                        Err(warp::reject::custom(
                            crate::shared::error::AppError::ValidationError(message),
                        ))
                    }
                }
            }
            None => Err(warp::reject::custom(
                crate::shared::error::AppError::ValidationError(
                    "Missing authorization header".to_string(),
                ),
            )),
        }
    })
}

use cookie::Cookie;

pub fn with_parsed_cookie() -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    println!("with_parsed_cookie called");
    warp::header::header::<String>("Cookie").and_then(|cookie_header: String| async move {
        // Print all cookies in the header
        let parsed = Cookie::split_parse(&cookie_header);
        println!("[cookie raw] {}", cookie_header);
        for cookie in parsed.flatten() {
            println!("[cookie] {} = {}", cookie.name(), cookie.value());
        }
        println!("[cookie raw] {}", cookie_header);

        let parsed = Cookie::split_parse(cookie_header);
        for cookie in parsed.flatten() {
            if cookie.name() == "refresh_token" {
                return Ok(cookie.value().to_string());
            }
        }

        Err(warp::reject::custom(
            crate::shared::error::AppError::ValidationError("Missing refresh_token cookie".into()),
        ))
    })
}
