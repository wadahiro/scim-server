use axum::{
    extract::Request,
    http::{Method, Uri},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use std::time::Instant;
use tracing::info;

pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let remote_addr = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|h| h.to_str().ok())
        })
        .unwrap_or("-")
        .to_string();

    let response = next.run(request).await;
    
    let duration = start.elapsed();
    let status = response.status();
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

    info!(
        target: "access_log",
        "{} {} \"{}\" {} {} {}ms \"{}\" \"{}\"",
        timestamp,
        remote_addr,
        format_request(&method, &uri),
        status.as_u16(),
        response.headers()
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("-"),
        duration.as_millis(),
        user_agent,
        method
    );

    response
}

fn format_request(method: &Method, uri: &Uri) -> String {
    format!("{} {} HTTP/1.1", method, uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::Html, routing::get, Router};
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_logging_middleware() {
        let app = Router::new()
            .route("/test", get(|| async { Html("Hello, World!") }))
            .layer(axum::middleware::from_fn(logging_middleware));

        let server = TestServer::new(app).unwrap();
        let response = server.get("/test").await;

        assert_eq!(response.status_code(), StatusCode::OK);
    }
}