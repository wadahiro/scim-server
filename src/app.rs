//! Shared HTTP router construction.
//!
//! This is the single place that wires up every SCIM route (and the
//! operator-configured custom endpoints) for a given [`AppConfig`]. Both the
//! production binary (`main.rs`) and the integration tests build their
//! router from here, so the route table -- including the RFC 7644 §3.12
//! fallback error handler -- can never drift between the two.

use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};
use std::sync::Arc;

use crate::backend::ScimBackend;
use crate::config::AppConfig;
use crate::{error, extractors, resource};

/// Shared application state: the storage backend and the (immutable, shared)
/// configuration.
pub type AppState = (Arc<dyn ScimBackend>, Arc<AppConfig>);

/// RFC 7644 §3.12: an unmatched route is still a SCIM error resource, not a
/// bare, bodyless 404.
async fn scim_not_found() -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    error::scim_error_response(
        axum::http::StatusCode::NOT_FOUND,
        None,
        "The requested resource does not exist",
    )
}

/// Build the router for the operator-configured custom endpoints.
///
/// This is kept separate from [`build_scim_router`] because custom endpoints
/// serve whatever `content_type` the operator configured (`text/plain`,
/// `application/xml`, ...) and must never be rewritten to
/// `application/scim+json`.
pub fn build_custom_router(app_config: &AppConfig) -> Router<AppState> {
    let mut custom_app = Router::new();

    for tenant in &app_config.tenants {
        for endpoint in &tenant.custom_endpoints {
            custom_app = custom_app.route(
                &endpoint.path,
                get(resource::custom::handle_custom_endpoint),
            );
        }
    }

    custom_app
}

/// Build the router for every SCIM 2.0 endpoint, for every configured
/// tenant, plus the RFC 7644 §3.12 fallback for unmatched paths.
pub fn build_scim_router(app_config: &AppConfig) -> Router<AppState> {
    let mut app = Router::new();

    for tenant in &app_config.tenants {
        let base_path = if tenant.path.starts_with("http://") || tenant.path.starts_with("https://")
        {
            if let Ok(url) = url::Url::parse(&tenant.path) {
                url.path().trim_end_matches('/').to_string()
            } else {
                "/scim".to_string() // fallback
            }
        } else {
            tenant.path.trim_end_matches('/').to_string()
        };

        // ServiceProviderConfig routes
        app = app.route(
            &format!("{}/ServiceProviderConfig", base_path),
            get(resource::service_provider::service_provider_config),
        );

        // Schema and ResourceType routes (collection and single-resource
        // forms, RFC 7644 §4)
        app = app.route(
            &format!("{}/Schemas", base_path),
            get(resource::schema::schemas),
        );
        app = app.route(
            &format!("{}/Schemas/{{id}}", base_path),
            get(resource::schema::schema_by_id),
        );
        app = app.route(
            &format!("{}/ResourceTypes", base_path),
            get(resource::resource_type::resource_types),
        );
        app = app.route(
            &format!("{}/ResourceTypes/{{id}}", base_path),
            get(resource::resource_type::resource_type_by_id),
        );

        // User routes
        app = app.route(
            &format!("{}/Users", base_path),
            post(resource::user::create_user),
        );
        app = app.route(
            &format!("{}/Users", base_path),
            get(resource::user::search_users),
        );
        app = app.route(
            &format!("{}/Users/.search", base_path),
            post(resource::user::search_users_post),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            get(resource::user::get_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            put(resource::user::update_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            patch(resource::user::patch_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            delete(resource::user::delete_user),
        );

        // Group routes
        app = app.route(
            &format!("{}/Groups", base_path),
            post(resource::group::create_group),
        );
        app = app.route(
            &format!("{}/Groups", base_path),
            get(resource::group::search_groups),
        );
        app = app.route(
            &format!("{}/Groups/.search", base_path),
            post(resource::group::search_groups_post),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            get(resource::group::get_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            put(resource::group::update_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            patch(resource::group::patch_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            delete(resource::group::delete_group),
        );
    }

    // RFC 7644 §3.12: any path under a tenant's base that doesn't match one
    // of the routes above (or an unresolvable tenant path entirely, which
    // the auth middleware already turns into a SCIM error before routing)
    // must still be a SCIM Error resource, not a bare, bodyless 404.
    app = app.fallback(scim_not_found);

    // RFC 7644 §3.1: SCIM responses use application/scim+json. Applied here
    // so it covers every SCIM route (fallback included) without touching
    // each handler, and so the custom-endpoint router (merged in by the
    // caller) keeps its own configured content types.
    app.layer(middleware::from_fn(
        extractors::scim_content_type_middleware,
    ))
}

/// Build the complete router: custom endpoints merged with the SCIM router.
///
/// Callers still need to add the auth middleware (`with_state`d to the
/// backend + config) and any transport-level middleware (logging, etc.)
/// themselves, since those differ slightly between the production binary and
/// tests.
pub fn build_router(app_config: &AppConfig) -> Router<AppState> {
    build_custom_router(app_config).merge(build_scim_router(app_config))
}
