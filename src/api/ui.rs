//! Full-mirror UI pairing and session establishment.
//!
//! The read side is served from the encrypted mirror. An executable receives a
//! UI token only after the user has confirmed its kernel-resolved path in a
//! native dialog; only that scope can decrypt and read full-mirror content.

use super::{auth, ApiState};
use crate::{dialog, dto};
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
                && !body.content.is_empty()
                && body.content.len() <= 7439
                && !body.content.contains('\0') =>
        {
            Some((&body.kind, &body.content))
        }
        (None, Some(markdown))
            if !markdown.is_empty() && markdown.len() <= 7439 && !markdown.contains('\0') =>
        {
            Some(("markdown", markdown))
        }
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
    if rest.leave_room(&room.id).await.is_err() {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "webex_unavailable",
            "Webex did not accept the room leave",
        );
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
        Err(_) => json_error(
            StatusCode::BAD_GATEWAY,
            "webex_unavailable",
            "Webex did not accept the message",
        ),
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
        Err(_) => json_error(
            StatusCode::BAD_GATEWAY,
            "webex_unavailable",
            "Webex did not accept the edit",
        ),
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
    if rest.delete_message(&message_id).await.is_err() {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "webex_unavailable",
            "Webex did not accept the delete",
        );
    }
    match state
        .mirror()
        .with(|db| db.mark_deleted(&existing.room_id, &message_id))
        .await
    {
        Ok(true) => {
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
    Known(crate::mirror::UiMessage),
    Missing,
    Unavailable,
}

fn thread_parent_dto(parent: &ResolvedThreadParent, message_id: &str) -> dto::ThreadParent {
    match parent {
        ResolvedThreadParent::Known(message) => dto::ThreadParent {
            id: message.id.clone(),
            state: message.status.clone(),
            message: Some(message_dto(message.clone())),
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
        Ok(Some(message)) => return Ok(ResolvedThreadParent::Known(message)),
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
            Ok(Some(message)) => Ok(ResolvedThreadParent::Known(message)),
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
        .route("/v1/me", get(me))
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
