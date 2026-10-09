//! Route-claiming session endpoints for local agent hosts.
//!
//! This module deliberately exposes no room or message content. An agent can
//! obtain a short-lived token only for routes whose agent name and configured
//! workspace contain the validated local client cwd.

use super::{auth, ApiState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Component, Path as FsPath},
    time::Duration,
};

const LEASE_TTL: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateSessionRequest {
    host: String,
    session_id: String,
    cwd: String,
    agent_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteClaim {
    id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    token: String,
    lease_ttl: u64,
    routes: Vec<RouteClaim>,
}

fn json_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({ "code": code, "message": message })),
    )
        .into_response()
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|ch| ch.is_ascii_graphic() && !ch.is_ascii_control())
}

/// A route workspace owns its directory tree. Reject relative and parent-dir
/// client paths so a lexical prefix cannot escape the configured workspace.
fn workspace_matches(route_workspace: &str, cwd: &str) -> bool {
    let valid_absolute = |path: &FsPath| {
        path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    };
    let workspace = FsPath::new(route_workspace);
    let cwd = FsPath::new(cwd);
    valid_absolute(workspace) && valid_absolute(cwd) && cwd.starts_with(workspace)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

fn session_error(error: auth::SessionError) -> Response {
    match error {
        auth::SessionError::Scope => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "Session is not authorized for agent endpoints",
        ),
        auth::SessionError::Peer => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_peer",
            "Session belongs to a different local process",
        ),
        auth::SessionError::Missing | auth::SessionError::Expired => json_error(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "A valid agent session is required",
        ),
        auth::SessionError::SessionId => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_session",
            "Session ID does not match the bearer token",
        ),
    }
}

async fn create_session(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Json(request): Json<CreateSessionRequest>,
) -> Response {
    if !valid_identifier(&request.host, 128)
        || !valid_identifier(&request.session_id, 128)
        || !valid_identifier(&request.agent_name, 128)
        || request.cwd.is_empty()
        || request.cwd.len() > 4096
        || request.cwd.chars().any(char::is_control)
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Agent session fields are invalid",
        );
    }

    let route_ids = state
        .config()
        .routes
        .iter()
        .filter(|route| {
            route.agent_name == request.agent_name
                && workspace_matches(&route.workspace, &request.cwd)
        })
        .map(|route| route.id.clone())
        .collect::<Vec<_>>();
    if route_ids.is_empty() {
        return json_error(
            StatusCode::FORBIDDEN,
            "not_routed",
            "No configured route matches this agent name and workspace",
        );
    }

    let token =
        match state
            .sessions()
            .issue_agent(peer, request.session_id, route_ids.clone(), LEASE_TTL)
        {
            Ok(token) => token,
            Err(auth::ClaimError::AlreadyClaimed) => {
                return json_error(
                    StatusCode::CONFLICT,
                    "route_claimed",
                    "A matching route is already leased to another agent session",
                )
            }
        };
    Json(CreateSessionResponse {
        token,
        lease_ttl: LEASE_TTL.as_secs(),
        routes: route_ids.into_iter().map(|id| RouteClaim { id }).collect(),
    })
    .into_response()
}

async fn heartbeat(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return session_error(auth::SessionError::Missing);
    };
    match state
        .sessions()
        .renew_agent(token, &session_id, peer, LEASE_TTL)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => session_error(error),
    }
}

async fn release_session(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return session_error(auth::SessionError::Missing);
    };
    match state.sessions().release_agent(token, &session_id, peer) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => session_error(error),
    }
}

fn claimed_routes(
    state: &ApiState,
    peer: auth::PeerIdentity,
    headers: &HeaderMap,
) -> Result<Vec<String>, auth::SessionError> {
    let token = bearer(headers).ok_or(auth::SessionError::Missing)?;
    state.sessions().agent_routes(token, peer)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InboxQuery {
    state: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateDraftRequest {
    route_id: String,
    parent_id: Option<String>,
    markdown: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApproveDraftRequest {
    sha256: String,
    approval_token: String,
}

async fn inbox(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Query(query): Query<InboxQuery>,
    headers: HeaderMap,
) -> Response {
    let route_ids = match claimed_routes(&state, peer, &headers) {
        Ok(routes) => routes,
        Err(error) => return session_error(error),
    };
    match state
        .mirror()
        .with(|db| db.deliveries(&route_ids, query.state.as_deref()))
        .await
    {
        Ok(deliveries) => Json(serde_json::json!({ "deliveries": deliveries })).into_response(),
        Err(_) => json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Inbox state is invalid or unavailable",
        ),
    }
}

async fn decide_inbox(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(delivery_id): Path<String>,
    headers: HeaderMap,
    accept: bool,
) -> Response {
    let route_ids = match claimed_routes(&state, peer, &headers) {
        Ok(routes) => routes,
        Err(error) => return session_error(error),
    };
    match state
        .mirror()
        .with(|db| db.decide_delivery(&route_ids, &delivery_id, accept))
        .await
    {
        Ok(Some(delivery)) if accept => Json(delivery).into_response(),
        Ok(Some(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(None) => json_error(
            StatusCode::CONFLICT,
            "delivery_unavailable",
            "Delivery is no longer pending",
        ),
        Err(_) => json_error(
            StatusCode::FORBIDDEN,
            "not_routed",
            "Delivery is not available to this agent session",
        ),
    }
}

async fn create_draft(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<CreateDraftRequest>,
) -> Response {
    let route_ids = match claimed_routes(&state, peer, &headers) {
        Ok(routes) => routes,
        Err(error) => return session_error(error),
    };
    if !route_ids
        .iter()
        .any(|route_id| route_id == &request.route_id)
    {
        return json_error(
            StatusCode::FORBIDDEN,
            "not_routed",
            "Route is not claimed by this agent session",
        );
    }
    match state
        .mirror()
        .with(|db| {
            db.create_draft(
                state.config(),
                &request.route_id,
                request.parent_id.as_deref(),
                &request.markdown,
            )
        })
        .await
    {
        Ok(draft) => Json(draft).into_response(),
        Err(_) => json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Draft does not meet route, approval, or message-format requirements",
        ),
    }
}

async fn approve_draft(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(draft_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ApproveDraftRequest>,
) -> Response {
    let route_ids = match claimed_routes(&state, peer, &headers) {
        Ok(routes) => routes,
        Err(error) => return session_error(error),
    };
    let Some(rest) = state.rest() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "webex_unavailable",
            "Webex is not connected; the draft remains pending",
        );
    };
    let prepared = match state
        .mirror()
        .with(|db| {
            db.approve_draft(
                state.config(),
                &route_ids,
                &draft_id,
                &request.sha256,
                &request.approval_token,
            )
        })
        .await
    {
        Ok(Some(prepared)) => prepared,
        Ok(None) => {
            return json_error(
                StatusCode::CONFLICT,
                "approval_expired",
                "Draft approval is expired, consumed, or no longer pending",
            )
        }
        Err(_) => {
            return json_error(
                StatusCode::FORBIDDEN,
                "approval_mismatch",
                "Draft approval does not match the pending draft",
            )
        }
    };
    let sent = rest
        .send_markdown(
            &prepared.room_id,
            prepared.parent_id.as_deref(),
            &prepared.markdown,
        )
        .await;
    match sent {
        Ok(message) if message.id.as_deref().is_some_and(|id| !id.is_empty()) => {
            let id = message.id.as_deref().expect("checked nonempty");
            match state.mirror().with(|db| db.mark_sent(&draft_id, id)).await {
                Ok(()) => Json(serde_json::json!({ "state": "sent" })).into_response(),
                Err(_) => json_error(
                    StatusCode::ACCEPTED,
                    "delivery_unknown",
                    "Webex accepted the request but local delivery persistence failed",
                ),
            }
        }
        Err(error) if error.to_string().contains("returned HTTP") => {
            let _ = state.mirror().with(|db| db.mark_failed(&draft_id)).await;
            Json(serde_json::json!({ "state": "failed" })).into_response()
        }
        _ => {
            let _ = state
                .mirror()
                .with(|db| db.mark_delivery_unknown(&draft_id))
                .await;
            Json(serde_json::json!({ "state": "delivery-unknown" })).into_response()
        }
    }
}

async fn outbox_status(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(draft_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let route_ids = match claimed_routes(&state, peer, &headers) {
        Ok(routes) => routes,
        Err(error) => return session_error(error),
    };
    match state
        .mirror()
        .with(|db| db.draft_status(&route_ids, &draft_id))
        .await
    {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "not_routed", "Draft was not found"),
        Err(_) => json_error(
            StatusCode::FORBIDDEN,
            "not_routed",
            "Draft is not route-scoped",
        ),
    }
}

async fn accept_inbox(
    state: State<ApiState>,
    peer: Extension<auth::PeerIdentity>,
    delivery_id: Path<String>,
    headers: HeaderMap,
) -> Response {
    decide_inbox(state, peer, delivery_id, headers, true).await
}

async fn reject_inbox(
    state: State<ApiState>,
    peer: Extension<auth::PeerIdentity>,
    delivery_id: Path<String>,
    headers: HeaderMap,
) -> Response {
    decide_inbox(state, peer, delivery_id, headers, false).await
}

/// Routes that establish, renew and release a route-scoped agent lease. Inbox
/// listing contains metadata only; acceptance is the sole content release.
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/v1/agent/sessions", post(create_session))
        .route("/v1/agent/sessions/{session_id}/heartbeat", post(heartbeat))
        .route("/v1/agent/sessions/{session_id}", delete(release_session))
        .route("/v1/agent/inbox", get(inbox))
        .route("/v1/agent/inbox/{delivery_id}/accept", post(accept_inbox))
        .route("/v1/agent/inbox/{delivery_id}/reject", post(reject_inbox))
        .route("/v1/agent/outbox", post(create_draft))
        .route("/v1/agent/outbox/{draft_id}", get(outbox_status))
        .route("/v1/agent/outbox/{draft_id}/approve", post(approve_draft))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_claims_are_limited_to_the_configured_tree() {
        assert!(workspace_matches("/work/project", "/work/project"));
        assert!(workspace_matches("/work/project", "/work/project/webex-pi"));
        assert!(!workspace_matches("/work/project", "/work/project-copy"));
        assert!(!workspace_matches(
            "/work/project",
            "/work/project/../private"
        ));
        assert!(!workspace_matches("relative/project", "/work/project"));
        assert!(!workspace_matches("/work/project", "relative/project"));
    }
}
