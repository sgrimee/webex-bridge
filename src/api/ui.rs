//! Full-mirror UI pairing and session establishment.
//!
//! The read side is served from the encrypted mirror. An executable receives a
//! UI token only after the user has confirmed its kernel-resolved path in a
//! native dialog; only that scope can decrypt and read full-mirror content.

use super::{auth, ApiState};
use crate::{dialog, dto, dto::valid_resource_id};
use axum::{
    extract::{Extension, Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

const UI_LEASE_TTL: Duration = Duration::from_secs(600);
/// Absolute lifetime of one UI token, from initial issuance, across renewals.
const UI_SESSION_MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnpairRequest {
    /// Exact kernel-resolved executable path shown by `ui pairings`.
    executable: Option<String>,
    /// Remove every pairing. Mutually exclusive with `executable`.
    #[serde(default)]
    all: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnpairResponse {
    removed: usize,
    sessions_ended: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RenewSessionResponse {
    lease_ttl: u64,
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

/// UI bootstrap remains intentionally unauthenticated so a local UI can pair
/// or establish its first session. A valid agent bearer is the sole exception:
/// it must never be silently ignored and then reach pairing/secret processing.
fn reject_agent_bootstrap_bearer(
    state: &ApiState,
    peer: auth::PeerIdentity,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    let Some(token) = bearer(headers) else {
        return Ok(());
    };
    match state
        .sessions()
        .authorize(Some(token), auth::Scope::Agent, peer)
    {
        Ok(()) => Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "Agent sessions cannot access UI bootstrap endpoints",
        ))),
        // A known agent token replayed by another same-UID local process is
        // still agent-scoped, and must not be allowed to fall through to UI
        // pairing or paired-secret validation.
        Err(auth::SessionError::Peer) => Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "Agent sessions cannot access UI bootstrap endpoints",
        ))),
        // Missing, expired, malformed, and UI-scoped bearers retain the
        // deliberately unauthenticated local bootstrap behavior.
        Err(
            auth::SessionError::Missing
            | auth::SessionError::Expired
            | auth::SessionError::Scope
            | auth::SessionError::SessionId,
        ) => Ok(()),
    }
}

fn ui_session_error(error: auth::SessionError) -> Response {
    match error {
        auth::SessionError::Scope => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "Session is not authorized for UI endpoints",
        ),
        auth::SessionError::Peer => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_peer",
            "Session belongs to a different local process",
        ),
        auth::SessionError::Missing | auth::SessionError::Expired => json_error(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "A valid UI session is required",
        ),
        auth::SessionError::SessionId => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_session",
            "Session is not authorized for UI endpoints",
        ),
    }
}

fn ui_session(
    state: &ApiState,
    peer: auth::PeerIdentity,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    state
        .sessions()
        .authorize(bearer(headers), auth::Scope::Ui, peer)
        .map_err(|error| Box::new(ui_session_error(error)))
}

fn renew_error(error: auth::RenewError) -> Response {
    match error {
        auth::RenewError::Session(error) => ui_session_error(error),
        auth::RenewError::UnknownPeer => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_peer",
            "The local client process cannot be identified",
        ),
        auth::RenewError::NotRenewable => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_session",
            "Session cannot be renewed",
        ),
        auth::RenewError::CapReached => json_error(
            StatusCode::CONFLICT,
            "session_cap_reached",
            "UI session reached its maximum age; create a new session",
        ),
    }
}

fn continuity_dto(continuity: crate::api::events::Continuity) -> dto::Continuity {
    dto::Continuity {
        instance_id: continuity.instance_id,
        watermark: continuity.watermark,
    }
}

fn room_dto(room: crate::mirror::UiRoom) -> dto::Room {
    dto::Room {
        id: room.id,
        title: room.title,
        room_type: room.room_type,
        team_id: room.team_id,
        last_activity: room.last_activity,
        is_member: room.is_member,
        is_locked: room.is_locked,
    }
}

fn team_dto(team: crate::mirror::UiTeam) -> dto::Team {
    dto::Team {
        id: team.id,
        name: team.name,
    }
}

fn person_dto(person: crate::mirror::UiPerson) -> dto::Person {
    dto::Person {
        id: person.id,
        display_name: person.display_name,
        emails: person.emails,
    }
}

fn person_read_dto(
    id: &str,
    state: &str,
    person: Option<crate::mirror::UiPerson>,
) -> dto::PersonRead {
    dto::PersonRead {
        id: id.into(),
        state: state.into(),
        person: person.map(person_dto),
    }
}

fn message_dto(message: crate::mirror::UiMessage) -> dto::Message {
    dto::Message {
        id: message.id,
        room_id: message.room_id,
        revision: message.revision,
        parent_id: message.parent_id,
        sender_id: message.sender_id,
        created_at: message.created_at,
        updated_at: message.updated_at,
        status: message.status,
        markdown: message.markdown,
        body: message.body.map(|body| dto::MessageBody {
            kind: body.kind,
            content: body.content,
        }),
        attachment_count: message.attachment_count,
    }
}

fn message_read_dto(
    id: &str,
    state: &str,
    message: Option<crate::mirror::UiMessage>,
) -> dto::MessageRead {
    dto::MessageRead {
        id: id.into(),
        state: state.into(),
        message: message.map(message_dto),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomMessagesQuery {
    before: Option<String>,
    max: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ThreadChildrenQuery {
    before: Option<String>,
    max: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateMessageRequest {
    room_id: String,
    parent_id: Option<String>,
    markdown: Option<String>,
    body: Option<dto::MessageBodyInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EditMessageRequest {
    room_id: String,
    markdown: Option<String>,
    body: Option<dto::MessageBodyInput>,
}

fn request_body<'a>(
    body: Option<&'a dto::MessageBodyInput>,
    markdown: Option<&'a str>,
) -> Option<(&'a str, &'a str)> {
    match (body, markdown) {
        (Some(_), Some(_)) => None,
        (Some(body), None)
            if matches!(body.kind.as_str(), "plainText" | "markdown")
                && dto::valid_message_body(&body.content) =>
        {
            Some((&body.kind, &body.content))
        }
        (None, Some(markdown)) if dto::valid_message_body(markdown) => Some(("markdown", markdown)),
        _ => None,
    }
}

fn write_allowed(state: &ApiState, room_id: &str) -> Result<(), Box<Response>> {
    state.config().check_write_room(room_id).map_err(|_| {
        Box::new(json_error(
            StatusCode::FORBIDDEN,
            "write_not_allowed",
            "Writes outside the configured development allowlist are refused",
        ))
    })
}

fn ui_write_error(error: crate::sync::history::UiWriteError, action: &'static str) -> Response {
    match error {
        crate::sync::history::UiWriteError::Rejected => {
            json_error(StatusCode::BAD_GATEWAY, "webex_rejected", action)
        }
        crate::sync::history::UiWriteError::DeliveryUnknown => json_error(
            StatusCode::ACCEPTED,
            "delivery_unknown",
            "Webex may have accepted the write but delivery is not confirmed",
        ),
    }
}

async fn persisted_message(
    state: &ApiState,
    message: &webex::Message,
    event_name: &'static str,
) -> Response {
    let Some(message_id) = message.id.as_deref().filter(|id| !id.is_empty()) else {
        return json_error(
            StatusCode::ACCEPTED,
            "delivery_unknown",
            "Webex accepted the write but did not return a canonical message ID",
        );
    };
    match state
        .mirror()
        .with(|db| {
            db.upsert_message(message)?;
            db.ui_message(message_id)
        })
        .await
    {
        Ok(Some(stored)) => {
            state.events().publish_ui(
                event_name,
                serde_json::json!({
                    "roomId": stored.room_id,
                    "messageId": stored.id,
                    "revision": stored.revision,
                }),
            );
            Json(message_dto(stored)).into_response()
        }
        _ => json_error(
            StatusCode::ACCEPTED,
            "delivery_unknown",
            "Webex accepted the write but the mirror has not yet confirmed it",
        ),
    }
}

async fn me(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    let cached_identity = match state.mirror().with(|db| db.ui_account_identity()).await {
        Ok(identity) => identity,
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    };
    let Some(rest) = state.rest() else {
        return match cached_identity {
            Some(person) => Json(person_dto(person)).into_response(),
            None => json_error(
                StatusCode::CONFLICT,
                "identity_not_ready",
                "Account identity has not yet been mirrored",
            ),
        };
    };
    match rest.me().await {
        Ok(person) => match state
            .mirror()
            .with(|db| {
                db.cache_account_identity(&person)?;
                db.ui_account_identity()
            })
            .await
        {
            Ok(Some(person)) => Json(person_dto(person)).into_response(),
            _ => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ),
        },
        Err(_) => match cached_identity {
            Some(person) => Json(person_dto(person)).into_response(),
            None => json_error(
                StatusCode::BAD_GATEWAY,
                "webex_unavailable",
                "Webex current-user lookup failed",
            ),
        },
    }
}

async fn continuity(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    Json(continuity_dto(state.events().continuity())).into_response()
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
        Ok(rooms) => Json(
            serde_json::json!({ "rooms": rooms.into_iter().map(room_dto).collect::<Vec<_>>() }),
        )
        .into_response(),
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
        Ok(Some(room)) => Json(room_dto(room)).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "not_found", "Room was not found"),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_unavailable",
            "Mirror is temporarily unavailable",
        ),
    }
}

async fn team(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(team_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    if !valid_resource_id(&team_id) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Team ID is invalid",
        );
    }
    match state.mirror().with(|db| db.ui_team(&team_id)).await {
        Ok(Some(team)) => return Json(team_dto(team)).into_response(),
        Ok(None) => {}
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    }

    // A cache miss makes exactly one daemon-owned REST request. The UI never
    // receives a Webex capability or performs its own unbounded lookup.
    let Some(rest) = state.rest() else {
        return json_error(StatusCode::NOT_FOUND, "not_found", "Team was not found");
    };
    match rest.team(&team_id).await {
        Ok(Some(team)) if team.id == team_id => match state
            .mirror()
            .with(|db| {
                db.upsert_team(&team)?;
                db.ui_team(&team_id)
            })
            .await
        {
            Ok(Some(team)) => Json(team_dto(team)).into_response(),
            _ => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ),
        },
        // Webex uses both 404 and access-denied for a team that is not
        // available to this account. Either is an ordinary title-decoration
        // miss, so the UI can retain its room-title fallback.
        Ok(None) => json_error(StatusCode::NOT_FOUND, "not_found", "Team was not found"),
        Ok(Some(_)) => json_error(
            StatusCode::BAD_GATEWAY,
            "webex_unavailable",
            "Webex returned an unexpected team",
        ),
        Err(_) => json_error(
            StatusCode::BAD_GATEWAY,
            "webex_unavailable",
            "Webex team lookup failed",
        ),
    }
}

async fn leave_room(
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
    let room = match state.mirror().with(|db| db.ui_room(&room_id)).await {
        Ok(Some(room)) if room.is_member => room,
        Ok(_) => return json_error(StatusCode::NOT_FOUND, "not_found", "Room was not found"),
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    };
    if room.room_type == "direct" {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Webex does not support leaving direct rooms",
        );
    }
    if let Err(response) = write_allowed(&state, &room.id) {
        return *response;
    }
    let Some(rest) = state.rest() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "webex_unavailable",
            "Webex is not connected",
        );
    };
    if let Err(error) = rest.leave_ui_room(&room.id).await {
        return ui_write_error(error, "Webex rejected the room leave");
    }
    match state.mirror().with(|db| db.mark_room_left(&room.id)).await {
        Ok(()) => {
            state.events().publish_ui(
                "membership.changed",
                serde_json::json!({ "roomId": room.id, "isMember": false }),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => json_error(
            StatusCode::ACCEPTED,
            "delivery_unknown",
            "Webex accepted the room leave but the mirror has not yet confirmed it",
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
    let mut messages = match state
        .mirror()
        .with(|db| db.ui_room_messages(&room_id, query.before.as_deref(), max))
        .await
    {
        Ok(messages) => messages,
        Err(error)
            if error.to_string().contains("cursor") || error.to_string().contains("page size") =>
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Message pagination is invalid",
            )
        }
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    };
    // A short local page does not prove that Webex history is exhausted. Only
    // a successful, bounded remote page after a local cursor can establish
    // completeness for that cursor; callers otherwise receive an opaque
    // continuation cursor plus an explicit partial reason.
    let mut complete = false;
    let mut partial_reason = if state.rest().is_some() {
        "not_mirrored"
    } else {
        "offline"
    };
    if messages.len() < max as usize {
        if let (Some(before), Some(rest)) = (query.before.as_deref(), state.rest()) {
            match rest.messages_page(&room_id, Some(before), max).await {
                Ok(page) => {
                    let valid_page = page
                        .iter()
                        .all(|message| message.room_id.as_deref() == Some(room_id.as_str()));
                    if valid_page
                        && state
                            .mirror()
                            .with(|db| {
                                for message in &page {
                                    db.upsert_message(message)?;
                                }
                                db.ui_room_messages(&room_id, query.before.as_deref(), max)
                            })
                            .await
                            .map(|hydrated| messages = hydrated)
                            .is_ok()
                    {
                        if !page.is_empty() {
                            state.events().publish_ui(
                                "sync.progress",
                                serde_json::json!({ "roomId": room_id, "lazyHistory": true }),
                            );
                        }
                        if page.len() < max as usize && messages.len() < max as usize {
                            complete = true;
                        } else {
                            partial_reason = "page_limit";
                        }
                    } else {
                        partial_reason = "resource_mismatch";
                    }
                }
                Err(_) => partial_reason = "remote_unavailable",
            }
        }
    }
    if !complete && messages.len() == max as usize && state.rest().is_some() {
        partial_reason = "page_limit";
    }
    let next_before = (!complete)
        .then(|| messages.last().map(|message| message.id.clone()))
        .flatten();
    Json(dto::MessagePage {
        messages: messages.into_iter().map(message_dto).collect(),
        next_before,
        complete,
        partial_reason: (!complete).then(|| partial_reason.into()),
    })
    .into_response()
}

async fn create_message(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<CreateMessageRequest>,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    let Some((body_kind, body_content)) =
        request_body(request.body.as_ref(), request.markdown.as_deref())
    else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Message request is invalid",
        );
    };
    if !valid_resource_id(&request.room_id)
        || request
            .parent_id
            .as_deref()
            .is_some_and(|id| !valid_resource_id(id))
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Message request is invalid",
        );
    }
    if let Err(response) = write_allowed(&state, &request.room_id) {
        return *response;
    }
    if let Some(parent_id) = request.parent_id.as_deref() {
        match state.mirror().with(|db| db.ui_message(parent_id)).await {
            Ok(Some(parent)) if parent.room_id == request.room_id && parent.status == "active" => {}
            Ok(_) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Message parent is not active in the requested room",
                )
            }
            Err(_) => {
                return json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "bridge_unavailable",
                    "Mirror is temporarily unavailable",
                )
            }
        }
    }
    let Some(rest) = state.rest() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "webex_unavailable",
            "Webex is not connected",
        );
    };
    match rest
        .send_ui_body(
            &request.room_id,
            request.parent_id.as_deref(),
            body_kind,
            body_content,
        )
        .await
    {
        Ok(message) if message.room_id.as_deref() == Some(&request.room_id) => {
            persisted_message(&state, &message, "message.created").await
        }
        Ok(_) => json_error(
            StatusCode::ACCEPTED,
            "delivery_unknown",
            "Webex returned a message for an unexpected room",
        ),
        Err(error) => ui_write_error(error, "Webex rejected the message"),
    }
}

async fn edit_message(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(message_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<EditMessageRequest>,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    let Some((body_kind, body_content)) =
        request_body(request.body.as_ref(), request.markdown.as_deref())
    else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Message request is invalid",
        );
    };
    if !valid_resource_id(&message_id) || !valid_resource_id(&request.room_id) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Message request is invalid",
        );
    }
    let existing = match state.mirror().with(|db| db.ui_message(&message_id)).await {
        Ok(Some(message)) if message.room_id == request.room_id && message.status == "active" => {
            message
        }
        Ok(_) => return json_error(StatusCode::NOT_FOUND, "not_found", "Message was not found"),
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    };
    if let Err(response) = write_allowed(&state, &existing.room_id) {
        return *response;
    }
    let Some(rest) = state.rest() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "webex_unavailable",
            "Webex is not connected",
        );
    };
    match rest
        .edit_ui_body(&message_id, &existing.room_id, body_kind, body_content)
        .await
    {
        Ok(message)
            if message.id.as_deref() == Some(&message_id)
                && message.room_id.as_deref() == Some(existing.room_id.as_str()) =>
        {
            persisted_message(&state, &message, "message.updated").await
        }
        Ok(_) => json_error(
            StatusCode::ACCEPTED,
            "delivery_unknown",
            "Webex returned an unexpected message",
        ),
        Err(error) => ui_write_error(error, "Webex rejected the edit"),
    }
}

async fn delete_message(
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
    let existing = match state.mirror().with(|db| db.ui_message(&message_id)).await {
        Ok(Some(message)) if message.status == "active" => message,
        Ok(_) => return json_error(StatusCode::NOT_FOUND, "not_found", "Message was not found"),
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    };
    if let Err(response) = write_allowed(&state, &existing.room_id) {
        return *response;
    }
    let Some(rest) = state.rest() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "webex_unavailable",
            "Webex is not connected",
        );
    };
    if let Err(error) = rest.delete_ui_message(&message_id).await {
        return ui_write_error(error, "Webex rejected the delete");
    }
    match state
        .mirror()
        .with(|db| {
            let deleted = db.mark_deleted(&existing.room_id, &message_id)?;
            Ok((deleted, db.take_agent_events()))
        })
        .await
    {
        Ok((true, agent_events)) => {
            state.events().publish_agent_events(agent_events);
            state.events().publish_ui(
                "message.deleted",
                serde_json::json!({ "roomId": existing.room_id, "messageId": message_id }),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        _ => json_error(
            StatusCode::ACCEPTED,
            "delivery_unknown",
            "Webex accepted the delete but the mirror has not yet confirmed it",
        ),
    }
}

enum ResolvedThreadParent {
    Known(Box<crate::mirror::UiMessage>),
    Missing,
    Unavailable,
}

fn thread_parent_dto(parent: &ResolvedThreadParent, message_id: &str) -> dto::ThreadParent {
    match parent {
        ResolvedThreadParent::Known(message) => dto::ThreadParent {
            id: message.id.clone(),
            state: message.status.clone(),
            message: Some(message_dto(message.as_ref().clone())),
        },
        ResolvedThreadParent::Missing => dto::ThreadParent {
            id: message_id.into(),
            state: "missing".into(),
            message: None,
        },
        ResolvedThreadParent::Unavailable => dto::ThreadParent {
            id: message_id.into(),
            state: "unavailable".into(),
            message: None,
        },
    }
}

async fn resolve_thread_parent(
    state: &ApiState,
    message_id: &str,
) -> Result<ResolvedThreadParent, Response> {
    match state.mirror().with(|db| db.ui_message(message_id)).await {
        Ok(Some(message)) => return Ok(ResolvedThreadParent::Known(Box::new(message))),
        Ok(None) => {}
        Err(_) => {
            return Err(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ))
        }
    }
    let Some(rest) = state.rest() else {
        return Ok(ResolvedThreadParent::Unavailable);
    };
    match rest.message(message_id).await {
        Ok(Some(message)) if message.id.as_deref() == Some(message_id) => match state
            .mirror()
            .with(|db| {
                db.upsert_message(&message)?;
                db.ui_message(message_id)
            })
            .await
        {
            Ok(Some(message)) => Ok(ResolvedThreadParent::Known(Box::new(message))),
            _ => Err(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )),
        },
        Ok(None) => Ok(ResolvedThreadParent::Missing),
        Ok(Some(_)) | Err(_) => Ok(ResolvedThreadParent::Unavailable),
    }
}

fn thread_page(
    parent: dto::ThreadParent,
    children: Vec<crate::mirror::UiMessage>,
    max: u32,
    complete: bool,
    partial_reason: &str,
) -> dto::ThreadChildren {
    let next_before = (!complete && children.len() == max as usize)
        .then(|| children.last().map(|message| message.id.clone()))
        .flatten();
    dto::ThreadChildren {
        parent,
        children: children.into_iter().map(message_dto).collect(),
        next_before,
        complete,
        partial_reason: (!complete).then(|| partial_reason.into()),
    }
}

async fn thread_parent(
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
    match resolve_thread_parent(&state, &message_id).await {
        Ok(parent) => Json(thread_parent_dto(&parent, &message_id)).into_response(),
        Err(response) => response,
    }
}

async fn thread_children(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    Path(message_id): Path<String>,
    Query(query): Query<ThreadChildrenQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    if !valid_resource_id(&message_id)
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
    let mut children = match state
        .mirror()
        .with(|db| db.ui_message_children(&message_id, query.before.as_deref(), max))
        .await
    {
        Ok(children) => children,
        Err(error)
            if error.to_string().contains("cursor") || error.to_string().contains("page size") =>
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Message pagination is invalid",
            )
        }
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    };
    let parent = match resolve_thread_parent(&state, &message_id).await {
        Ok(parent) => parent,
        Err(response) => return response,
    };
    let mut complete = false;
    let mut partial_reason = match &parent {
        ResolvedThreadParent::Missing => "parent_missing",
        ResolvedThreadParent::Unavailable => "parent_unavailable",
        ResolvedThreadParent::Known(_) if state.rest().is_some() => "not_mirrored",
        ResolvedThreadParent::Known(_) => "offline",
    };
    if children.len() < max as usize {
        if let (ResolvedThreadParent::Known(parent_message), Some(rest)) = (&parent, state.rest()) {
            match rest
                .children_page(
                    &parent_message.room_id,
                    &message_id,
                    query.before.as_deref(),
                    max,
                )
                .await
            {
                Ok(page) => {
                    let valid_page = page.iter().all(|message| {
                        message.room_id.as_deref() == Some(parent_message.room_id.as_str())
                            && message.parent_id.as_deref() == Some(message_id.as_str())
                    });
                    if valid_page
                        && state
                            .mirror()
                            .with(|db| {
                                for message in &page {
                                    db.upsert_message(message)?;
                                }
                                db.ui_message_children(&message_id, query.before.as_deref(), max)
                            })
                            .await
                            .map(|hydrated| children = hydrated)
                            .is_ok()
                    {
                        if page.len() < max as usize && children.len() < max as usize {
                            complete = true;
                        } else {
                            partial_reason = "page_limit";
                        }
                    } else {
                        partial_reason = "resource_mismatch";
                    }
                }
                Err(_) => partial_reason = "remote_unavailable",
            }
        }
    }
    if !complete && children.len() == max as usize && state.rest().is_some() {
        partial_reason = "page_limit";
    }
    Json(thread_page(
        thread_parent_dto(&parent, &message_id),
        children,
        max,
        complete,
        partial_reason,
    ))
    .into_response()
}

async fn message_read(
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
    let cached = match state.mirror().with(|db| db.ui_message(&message_id)).await {
        Ok(message) => message,
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    };
    if let Some(message) = cached {
        let state = if message.status == "deleted" {
            "deleted"
        } else {
            "mirrored"
        };
        return Json(message_read_dto(&message_id, state, Some(message))).into_response();
    }
    let Some(rest) = state.rest() else {
        return match state
            .mirror()
            .with(|db| db.ui_not_found("message", &message_id))
            .await
        {
            Ok(confirmed_missing) => {
                let state = if confirmed_missing {
                    "not_found"
                } else {
                    "offline"
                };
                Json(message_read_dto(&message_id, state, None)).into_response()
            }
            Err(_) => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ),
        };
    };
    match rest.message(&message_id).await {
        Ok(Some(message)) if message.id.as_deref() == Some(message_id.as_str()) => match state
            .mirror()
            .with(|db| {
                db.upsert_message(&message)?;
                db.ui_message(&message_id)
            })
            .await
        {
            Ok(Some(message)) => {
                Json(message_read_dto(&message_id, "hydrated", Some(message))).into_response()
            }
            _ => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ),
        },
        Ok(None) => match state
            .mirror()
            .with(|db| db.cache_ui_not_found("message", &message_id))
            .await
        {
            Ok(()) => Json(message_read_dto(&message_id, "not_found", None)).into_response(),
            Err(_) => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ),
        },
        Ok(Some(_)) | Err(_) => {
            Json(message_read_dto(&message_id, "unavailable", None)).into_response()
        }
    }
}

async fn person_read(
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
    let cached = match state.mirror().with(|db| db.ui_person(&person_id)).await {
        Ok(person) => person,
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            )
        }
    };
    if let Some(person) = cached {
        return Json(person_read_dto(&person_id, "mirrored", Some(person))).into_response();
    }
    let Some(rest) = state.rest() else {
        return match state
            .mirror()
            .with(|db| db.ui_not_found("person", &person_id))
            .await
        {
            Ok(confirmed_missing) => {
                let state = if confirmed_missing {
                    "not_found"
                } else {
                    "offline"
                };
                Json(person_read_dto(&person_id, state, None)).into_response()
            }
            Err(_) => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ),
        };
    };
    match rest.person(&person_id).await {
        Ok(Some(person)) if person.id == person_id => match state
            .mirror()
            .with(|db| {
                db.upsert_person(&person)?;
                db.ui_person(&person_id)
            })
            .await
        {
            Ok(Some(person)) => {
                Json(person_read_dto(&person_id, "hydrated", Some(person))).into_response()
            }
            _ => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ),
        },
        Ok(None) => match state
            .mirror()
            .with(|db| db.cache_ui_not_found("person", &person_id))
            .await
        {
            Ok(()) => Json(person_read_dto(&person_id, "not_found", None)).into_response(),
            Err(_) => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Mirror is temporarily unavailable",
            ),
        },
        Ok(Some(_)) | Err(_) => {
            Json(person_read_dto(&person_id, "unavailable", None)).into_response()
        }
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
        Ok(Some(message)) => Json(message_dto(message)).into_response(),
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
        Ok(Some(person)) => Json(person_dto(person)).into_response(),
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
    headers: HeaderMap,
    Json(request): Json<PairRequest>,
) -> Response {
    if let Err(response) = reject_agent_bootstrap_bearer(&state, peer, &headers) {
        return *response;
    }
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
    // One pairing dialog at a time: concurrent requests would stack dialogs,
    // and a look-alike request could hide behind a genuine one. Later
    // requests are refused while one is open; the slot is held until this
    // request finishes (or is dropped, which also kills its dialog).
    let Some(_dialog_slot) = state.try_pairing_dialog() else {
        return json_error(
            StatusCode::CONFLICT,
            "pairing_in_progress",
            "Another pairing request is waiting for an answer; try again after it",
        );
    };
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
    let answer = dialog::confirm_ui_pairing(&executable).await;
    let action = match &answer {
        Ok(dialog::PairingAnswer::Allowed) => "pair_approved",
        Ok(dialog::PairingAnswer::Denied) => "pair_denied",
        Ok(dialog::PairingAnswer::GaveUp) => "pair_gave_up",
        Err(_) => "pair_dialog_failed",
    };
    // Metadata-only audit of every completed dialog: the local executable
    // path and the outcome, never the secret hash. A cancelled request (the
    // client gave up) kills its dialog and records nothing.
    let executable_ref = executable.display().to_string();
    let _ = state
        .mirror()
        .with(move |db| db.audit_ui(action, Some(&executable_ref)))
        .await;
    if !matches!(answer, Ok(dialog::PairingAnswer::Allowed)) {
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
    headers: HeaderMap,
    Json(request): Json<CreateSessionRequest>,
) -> Response {
    if let Err(response) = reject_agent_bootstrap_bearer(&state, peer, &headers) {
        return *response;
    }
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
    let token =
        state
            .sessions()
            .issue_ui(peer, candidate.clone(), UI_LEASE_TTL, UI_SESSION_MAX_AGE);
    if let Err(response) = confirm_still_paired(&state, &token, candidate).await {
        return *response;
    }
    Json(CreateSessionResponse {
        token,
        lease_ttl: UI_LEASE_TTL.as_secs(),
    })
    .into_response()
}

/// Close the race with a concurrent unpair: the pairing is re-read after the
/// token exists. An unpair that deleted the pairing before this read is seen
/// here; one that deletes it afterwards revokes the (already issued) token
/// itself. Either way no token outlives its pairing. On failure the token is
/// revoked before it is returned to anyone.
async fn confirm_still_paired(
    state: &ApiState,
    token: &str,
    candidate: String,
) -> Result<(), Box<Response>> {
    let paired = state
        .mirror()
        .with(move |db| db.ui_client_paired(&candidate))
        .await;
    if matches!(paired, Ok(true)) {
        return Ok(());
    }
    state.sessions().revoke(token);
    Err(Box::new(match paired {
        Ok(_) => json_error(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "A paired UI secret is required",
        ),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_unavailable",
            "Pairing store is unavailable",
        ),
    }))
}

/// Log out: revoke exactly the presented UI token (same process only) and
/// close its event streams. Other sessions, and the pairing, are unaffected.
async fn delete_session(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = ui_session(&state, peer, &headers) {
        return *response;
    }
    if let Some(token) = bearer(&headers) {
        state.sessions().revoke(token);
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Extend the presented UI lease in place. The same token stays valid; only
/// the issuing process may renew, the pairing must still exist, and the lease
/// never extends beyond [`UI_SESSION_MAX_AGE`] after initial issuance.
async fn renew_session(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return ui_session_error(auth::SessionError::Missing);
    };
    let pairing = match state.sessions().ui_pairing(token, peer) {
        Ok(pairing) => pairing,
        Err(error) => return renew_error(error),
    };
    let paired = match state
        .mirror()
        .with(move |db| db.ui_client_paired(&pairing))
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
        // The user removed this client's pairing: end the session now rather
        // than letting it run out its current lease.
        state.sessions().revoke(token);
        return json_error(
            StatusCode::UNAUTHORIZED,
            "pairing_removed",
            "The UI pairing for this session no longer exists",
        );
    }
    match state.sessions().renew_ui(token, peer, UI_LEASE_TTL) {
        Ok(expires_at) => Json(RenewSessionResponse {
            lease_ttl: expires_at
                .saturating_duration_since(std::time::Instant::now())
                .as_secs(),
        })
        .into_response(),
        Err(error) => renew_error(error),
    }
}

/// List paired UI executables (never their secret hashes). Like pairing,
/// this needs only the same-user socket; agent bearers are refused.
async fn pairings(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = reject_agent_bootstrap_bearer(&state, peer, &headers) {
        return *response;
    }
    match state.mirror().with(|db| db.ui_pairings()).await {
        Ok(pairings) => Json(serde_json::json!({ "pairings": pairings })).into_response(),
        Err(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_unavailable",
            "Pairing store is unavailable",
        ),
    }
}

/// Remove UI pairings and immediately end every live session issued under
/// them. Removal only drops privilege (re-pairing needs the native dialog),
/// so the same-user socket suffices; agent bearers are still refused.
async fn unpair(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<UnpairRequest>,
) -> Response {
    if let Err(response) = reject_agent_bootstrap_bearer(&state, peer, &headers) {
        return *response;
    }
    let executable = match (request.executable, request.all) {
        (Some(path), false) if path.starts_with('/') && !path.chars().any(char::is_control) => {
            Some(path)
        }
        (None, true) => None,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Give either an absolute executable path or all=true",
            )
        }
    };
    // Any same-user process may unpair: record who did, best effort (an
    // unidentifiable caller still may remove access, which is never a risk).
    let caller = peer
        .pid
        .and_then(|pid| dialog::executable_for_pid(pid).ok())
        .map(|path| path.display().to_string());
    let hashes = match state
        .mirror()
        .with(move |db| db.unpair_ui_clients(executable.as_deref(), caller.as_deref()))
        .await
    {
        Ok(hashes) => hashes,
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "bridge_unavailable",
                "Pairing store is unavailable",
            )
        }
    };
    let sessions_ended = state.sessions().revoke_ui_pairings(&hashes);
    Json(UnpairResponse {
        removed: hashes.len(),
        sessions_ended,
    })
    .into_response()
}

/// Pairing, session and full-mirror read routes for the terminal UI.
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/v1/ui/pair", post(pair))
        .route("/v1/ui/pairings", get(pairings))
        .route("/v1/ui/pairings/remove", post(unpair))
        .route(
            "/v1/ui/sessions",
            post(create_session).delete(delete_session),
        )
        .route("/v1/ui/sessions/renew", post(renew_session))
        .route("/v1/me", get(me))
        .route("/v1/ui/continuity", get(continuity))
        .route("/v1/rooms", get(rooms))
        .route("/v1/rooms/{room_id}", get(room))
        .route("/v1/teams/{team_id}", get(team))
        .route("/v1/rooms/{room_id}/membership", delete(leave_room))
        .route("/v1/rooms/{room_id}/messages", get(room_messages))
        .route("/v1/messages", post(create_message))
        .route("/v1/messages/{message_id}/thread", get(thread_parent))
        .route("/v1/messages/{message_id}/children", get(thread_children))
        .route("/v1/messages/{message_id}/read", get(message_read))
        .route(
            "/v1/messages/{message_id}",
            get(message).put(edit_message).delete(delete_message),
        )
        .route("/v1/people/{person_id}/read", get(person_read))
        .route("/v1/people/{person_id}", get(person))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{api::ConnectionStatus, mirror::Mirror, mirror::SharedMirror};
    use tokio::sync::watch;

    fn me() -> auth::PeerIdentity {
        auth::PeerIdentity {
            uid: auth::daemon_uid(),
            pid: Some(std::process::id()),
        }
    }

    #[tokio::test]
    async fn only_one_pairing_dialog_is_open_at_a_time() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([72_u8; 32]).unwrap());
        let (_tx, rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror.clone(), rx);
        // Another pairing request holds the dialog slot.
        let open_dialog = state.try_pairing_dialog().unwrap();
        assert!(state.try_pairing_dialog().is_none());
        let server = crate::api::start(&paths, state.clone()).await.unwrap();
        let body = format!(r#"{{"secretHash":"{}"}}"#, "h".repeat(43));
        let mut client = tokio::net::UnixStream::connect(&paths.socket)
            .await
            .unwrap();
        client
            .write_all(
                format!(
                    "POST /v1/ui/pair HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 409"), "{response}");
        assert!(response.contains("pairing_in_progress"));
        // Refused before any dialog: nothing audited, nothing paired.
        for action in [
            "pair_approved",
            "pair_denied",
            "pair_gave_up",
            "pair_dialog_failed",
        ] {
            assert_eq!(
                mirror
                    .with(move |db| db.audit_count_for_tests("ui", action))
                    .await
                    .unwrap(),
                0
            );
        }
        assert!(mirror.with(|db| db.ui_pairings()).await.unwrap().is_empty());
        // The slot frees when the open dialog's request finishes.
        drop(open_dialog);
        assert!(state.try_pairing_dialog().is_some());
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_session_issued_while_its_pairing_is_removed_is_revoked_at_once() {
        let mirror = SharedMirror::new(Mirror::in_memory([71_u8; 32]).unwrap());
        let (_tx, rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror.clone(), rx);
        let hash = hash_secret("a-local-ui-secret-that-is-long-enough");
        let pairing = hash.clone();
        mirror
            .with(move |db| db.pair_ui_client(&pairing, "/test/webex-tui"))
            .await
            .unwrap();

        // Still paired: the issued token is kept.
        let kept = state
            .sessions()
            .issue_ui(me(), hash.clone(), UI_LEASE_TTL, UI_SESSION_MAX_AGE);
        assert!(confirm_still_paired(&state, &kept, hash.clone())
            .await
            .is_ok());
        assert!(state
            .sessions()
            .authorize(Some(&kept), auth::Scope::Ui, me())
            .is_ok());

        // The pairing check passed, then an unpair removed the pairing (and
        // revoked the sessions that existed) before this token was issued.
        mirror
            .with(|db| db.unpair_ui_clients(None, None))
            .await
            .unwrap();
        let orphan =
            state
                .sessions()
                .issue_ui(me(), hash.clone(), UI_LEASE_TTL, UI_SESSION_MAX_AGE);
        let response = confirm_still_paired(&state, &orphan, hash)
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(state
            .sessions()
            .authorize(Some(&orphan), auth::Scope::Ui, me())
            .is_err());
    }
}
