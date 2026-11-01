//! HTTP API routes and OpenAPI document.

pub mod actions;
pub mod admin;
pub mod attestation;
pub mod auth;
pub mod enroll;
pub mod state;
pub mod technicians;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Serialize;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

pub use state::{AppState, TrustRoots, load_command_key};

/// Body returned by the health endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    /// Always `ok` when the process is serving.
    pub status: String,
}

/// JSON error body.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Human-readable reason.
    pub error: String,
}

/// Errors returned by handlers; rendered as `{"error": "..."}`.
#[derive(Debug)]
pub enum ApiError {
    /// 400.
    BadRequest(String),
    /// 401 (deliberately uninformative).
    Unauthorized,
    /// 403.
    Forbidden,
    /// 404.
    NotFound(String),
    /// 409.
    Conflict(String),
    /// 422.
    Unprocessable(String),
    /// 429.
    TooManyRequests,
    /// 503.
    Unavailable(String),
    /// 500; the cause is logged, not returned.
    Internal,
}

impl ApiError {
    pub(crate) fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!(%err, "internal error");
        Self::Internal
    }
}

impl From<rmm_db::DbError> for ApiError {
    fn from(err: rmm_db::DbError) -> Self {
        Self::internal(err)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        Self::internal(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, m),
            Self::Conflict(m) => (StatusCode::CONFLICT, m),
            Self::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            Self::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "rate limited".to_string()),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ),
        };
        (status, Json(ErrorBody { error: msg })).into_response()
    }
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

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

/// OpenAPI document for the RMM API.
#[derive(Debug, OpenApi)]
#[openapi(
    info(title = "RMM API"),
    paths(
        healthz,
        enroll::enroll,
        admin::create_enrollment_token,
        admin::revoke_agent,
        admin::approve_device,
        admin::reject_device,
        admin::put_trust,
        actions::put_catalog,
        actions::issue_action,
        actions::get_action_run,
        technicians::register_begin,
        technicians::register_finish,
        technicians::techlist_draft
    ),
    components(schemas(
        Health,
        ErrorBody,
        admin::CreateTokenRequest,
        admin::CreateTokenResponse,
        actions::CatalogEntry,
        actions::IssueRequest,
        actions::IssueResponse,
        actions::ActionRunResponse,
        technicians::AuthenticatorSelection,
        technicians::RegisterBeginResponse,
        technicians::RegisterFinishRequest,
        technicians::RegisterFinishResponse
    )),
    modifiers(&BearerAuth)
)]
pub struct ApiDoc;

async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Build the API router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/openapi.json", get(openapi))
        .route("/v1/enroll", post(enroll::enroll))
        .route(
            "/api/v1/enrollment-tokens",
            post(admin::create_enrollment_token),
        )
        .route(
            "/api/v1/agents/{agent_id}/revoke",
            post(admin::revoke_agent),
        )
        .route(
            "/api/v1/devices/{device_id}/approve",
            post(admin::approve_device),
        )
        .route(
            "/api/v1/devices/{device_id}/reject",
            post(admin::reject_device),
        )
        .route("/api/v1/trust/{kind}", put(admin::put_trust))
        .route("/api/v1/catalog", put(actions::put_catalog))
        .route(
            "/api/v1/agents/{agent_id}/actions",
            post(actions::issue_action),
        )
        .route("/api/v1/action-runs/{cmd_id}", get(actions::get_action_run))
        .route(
            "/api/v1/technicians/me/credentials/register/begin",
            post(technicians::register_begin),
        )
        .route(
            "/api/v1/technicians/me/credentials/register/finish",
            post(technicians::register_finish),
        )
        .route(
            "/api/v1/admin/techlist-draft",
            get(technicians::techlist_draft),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_title() {
        let doc = ApiDoc::openapi();
        assert_eq!(doc.info.title, "RMM API");
        assert_eq!(doc.info.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn doc_lists_routes() {
        let doc = ApiDoc::openapi();
        for p in [
            "/healthz",
            "/v1/enroll",
            "/api/v1/enrollment-tokens",
            "/api/v1/agents/{agent_id}/revoke",
            "/api/v1/devices/{device_id}/approve",
            "/api/v1/devices/{device_id}/reject",
            "/api/v1/trust/{kind}",
            "/api/v1/catalog",
            "/api/v1/agents/{agent_id}/actions",
            "/api/v1/action-runs/{cmd_id}",
            "/api/v1/technicians/me/credentials/register/begin",
            "/api/v1/technicians/me/credentials/register/finish",
            "/api/v1/admin/techlist-draft",
        ] {
            assert!(doc.paths.paths.contains_key(p), "missing {p}");
        }
    }
}
