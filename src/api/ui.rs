//! Full-mirror UI pairing and session establishment.
//!
//! The read side is served from the encrypted mirror. An executable receives a
//! UI token only after the user has confirmed its kernel-resolved path in a
//! native dialog; only that scope can decrypt and read full-mirror content.

use super::{auth, ApiState};
use crate::dialog;
use axum::{
    extract::{Extension, Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

const UI_LEASE_TTL: Duration = Duration::from_secs(600);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairRequest {
    secret_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateSessionRequest {
    secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    token: String,
    lease_ttl: u64,
}

fn hash_secret(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

fn json_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({ "code": code, "message": message })),
    )
        .into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

fn ui_session(
    state: &ApiState,
    peer: auth::PeerIdentity,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    match state
        .sessions()
        .authorize(bearer(headers), auth::Scope::Ui, peer)
    {
        Ok(()) => Ok(()),
        Err(auth::SessionError::Scope) => Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "Session is not authorized for UI endpoints",
        ))),
        Err(auth::SessionError::Peer) => Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "forbidden_peer",
            "Session belongs to a different local process",
        ))),
        Err(auth::SessionError::Missing | auth::SessionError::Expired) => {
            Err(Box::new(json_error(
                StatusCode::UNAUTHORIZED,
                "auth_required",
                "A valid UI session is required",
            )))
        }
        Err(auth::SessionError::SessionId) => Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "forbidden_session",
            "Session is not authorized for UI endpoints",
        ))),
    }
}

fn valid_resource_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomMessagesQuery {
    before: Option<String>,
    max: Option<u32>,
}

async fn rooms(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    match state.mirror().with(|db| db.ui_rooms()).await {
        Ok(rooms) => Json(serde_json::json!({ "rooms": rooms })).into_response(),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_unavailable",
            "Mirror is temporarily unavailable",
        ),
    }
}

async fn room(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    if !valid_resource_id(&room_id) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Room ID is invalid",
        );
    }
    match state.mirror().with(|db| db.ui_room(&room_id)).await {
        Ok(Some(room)) => Json(room).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "not_found", "Room was not found"),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_unavailable",
            "Mirror is temporarily unavailable",
        ),
    }
}

async fn room_messages(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(room_id): Path<String>,
    Query(query): Query<RoomMessagesQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    if !valid_resource_id(&room_id)
        || query
            .before
            .as_deref()
            .is_some_and(|value| !valid_resource_id(value))
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Message cursor is invalid",
        );
    }
    let max = query.max.unwrap_or(50);
    match state
        .mirror()
        .with(|db| db.ui_room_messages(&room_id, query.before.as_deref(), max))
        .await
    {
        Ok(messages) => Json(serde_json::json!({ "messages": messages })).into_response(),
        Err(error)
            if error.to_string().contains("cursor") || error.to_string().contains("page size") =>
        {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Message pagination is invalid",
            )
        }
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_unavailable",
            "Mirror is temporarily unavailable",
        ),
    }
}

async fn message(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(message_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    if !valid_resource_id(&message_id) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Message ID is invalid",
        );
    }
    match state.mirror().with(|db| db.ui_message(&message_id)).await {
        Ok(Some(message)) => Json(message).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "not_found", "Message was not found"),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_unavailable",
            "Mirror is temporarily unavailable",
        ),
    }
}

async fn person(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(person_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    if !valid_resource_id(&person_id) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Person ID is invalid",
        );
    }
    match state.mirror().with(|db| db.ui_person(&person_id)).await {
        Ok(Some(person)) => Json(person).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "not_found", "Person was not found"),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_unavailable",
            "Mirror is temporarily unavailable",
        ),
    }
}

async fn pair(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Json(request): Json<PairRequest>,
) -> Response {
    if !(43..=128).contains(&request.secret_hash.len())
        || !request
            .secret_hash
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Pairing secret hash is invalid",
        );
    }
    let Some(pid) = peer.pid else {
        return json_error(
            StatusCode::FORBIDDEN,
            "forbidden_peer",
            "The local client process cannot be identified",
        );
    };
    let executable = match dialog::executable_for_pid(pid) {
        Ok(path) => path,
        Err(_) => {
            return json_error(
                StatusCode::FORBIDDEN,
                "forbidden_peer",
                "The local client executable cannot be identified",
            )
        }
    };
    if !dialog::confirm_ui_pairing(&executable)
        .await
        .unwrap_or(false)
    {
        return json_error(
            StatusCode::FORBIDDEN,
            "pairing_denied",
            "Full mirror access was not approved",
        );
    }
    match state
        .mirror()
        .with(|db| db.pair_ui_client(&request.secret_hash, &executable.display().to_string()))
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Pairing data could not be stored",
        ),
    }
}

async fn create_session(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Json(request): Json<CreateSessionRequest>,
) -> Response {
    if !(32..=1024).contains(&request.secret.len()) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "UI secret is invalid",
        );
    }
    let candidate = hash_secret(&request.secret);
    let paired = match state
        .mirror()
        .with(|db| db.ui_client_paired(&candidate))
        .await
    {
        Ok(paired) => paired,
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Pairing store is unavailable",
            )
        }
    };
    if !paired {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "A paired UI secret is required",
        );
    }
    Json(CreateSessionResponse {
        token: state.sessions().issue(auth::Scope::Ui, peer, UI_LEASE_TTL),
        lease_ttl: UI_LEASE_TTL.as_secs(),
    })
    .into_response()
}

/// Pairing, session and full-mirror read routes for the terminal UI.
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/v1/ui/pair", post(pair))
        .route("/v1/ui/sessions", post(create_session))
        .route("/v1/rooms", get(rooms))
        .route("/v1/rooms/{room_id}", get(room))
        .route("/v1/rooms/{room_id}/messages", get(room_messages))
        .route("/v1/messages/{message_id}", get(message))
        .route("/v1/people/{person_id}", get(person))
}
