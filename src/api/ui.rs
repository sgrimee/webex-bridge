//! Full-mirror UI pairing and session establishment.
//!
//! UI operations are added in a later increment. This module establishes the
//! D19 trust boundary first: an executable receives a UI token only after the
//! user has confirmed that executable's kernel-resolved path in a native dialog.

use super::{auth, ApiState};
use crate::dialog;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
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

/// Pairing and UI-session routes; mirror operations follow in a later increment.
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/v1/ui/pair", post(pair))
        .route("/v1/ui/sessions", post(create_session))
}
