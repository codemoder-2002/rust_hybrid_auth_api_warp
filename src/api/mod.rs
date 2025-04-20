// use crate::db::PgPool;
// use warp::Filter;
// pub fn register(pool: PgPool) -> impl Filter<Extract = impl warp::Reply> + Clone {
//     let health_route = warp::path!("health").map(|| warp::reply::json(&"OK"));

//     let with_db = warp::any().map(move || pool.clone());

//     let hello_route = warp::path!("hello" / String)
//         .and(with_db.clone())
//         .map(|name: String, _db_pool| warp::reply::json(&format!("Hello, {}!", name)));

//     // Combine routes and add `.recover()` for error handling
//     health_route.or(hello_route)
// }

pub mod auth;
