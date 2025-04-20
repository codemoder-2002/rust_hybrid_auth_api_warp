use serde::de::DeserializeOwned;
use validator::Validate;
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
                Err(warp::reject::custom(
                    crate::shared::error::AppError::ValidationError(message),
                ))
            }
        }
    })
}
