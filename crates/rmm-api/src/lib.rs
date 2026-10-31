//! HTTP API routes and OpenAPI document.

use axum::{Json, Router, routing::get};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};

/// Body returned by the health endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    /// Always `ok` when the process is serving.
    pub status: String,
}

/// Liveness probe.
#[utoipa::path(
    get,
    path = "/healthz",
    responses((status = 200, description = "Service is healthy", body = Health))
)]
async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok".to_string(),
    })
}

/// OpenAPI document for the RMM API.
#[derive(Debug, OpenApi)]
#[openapi(info(title = "RMM API"), paths(healthz), components(schemas(Health)))]
pub struct ApiDoc;

async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Build the API router.
pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/openapi.json", get(openapi))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let res = router()
            .oneshot(Request::get("/healthz").body(Body::empty()).expect("req"))
            .await
            .expect("response");
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn doc_title() {
        let doc = ApiDoc::openapi();
        assert_eq!(doc.info.title, "RMM API");
        assert_eq!(doc.info.version, env!("CARGO_PKG_VERSION"));
    }
}
