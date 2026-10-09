//! Scoped HTTP-over-UDS server.
//!
//! The listener authenticates the operating-system peer before HTTP is parsed.
//! Individual routes then apply the session/scope checks introduced in later
//! Step 3 increments. `GET /v1/status` intentionally needs no session and
//! returns metadata only.

pub mod agent;
pub mod auth;
pub mod events;
pub mod ui;

use crate::{mirror::SharedMirror, paths::Paths};
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use serde::Serialize;
use std::{
    fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{oneshot, watch},
    task::JoinHandle,
};
use tower::ServiceExt;

/// Version consumed by local UI and agent clients. Increment only for a
/// deliberately incompatible local-API change.
pub const API_VERSION: u32 = 1;

/// Metadata-only connection state exposed by `GET /v1/status`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionStatus {
    /// Mercury is not currently connected (including initial startup).
    Disconnected,
    /// Mercury is connected and live events can be mirrored.
    Connected,
    /// The OAuth token was rejected and an explicit login is required.
    AuthRequired,
}

impl ConnectionStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Connected => "connected",
            Self::AuthRequired => "auth_required",
        }
    }
}

/// Shared metadata sources for the unauthenticated status endpoint.
#[derive(Clone)]
pub struct ApiState {
    mirror: SharedMirror,
    connection: watch::Receiver<ConnectionStatus>,
}

impl ApiState {
    /// Create state from the daemon's mirror and connection-status watch.
    #[must_use]
    pub fn new(mirror: SharedMirror, connection: watch::Receiver<ConnectionStatus>) -> Self {
        Self { mirror, connection }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    api_version: u32,
    connection: &'static str,
    sync: SyncStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncStatus {
    rooms: i64,
    revisions: i64,
    initial_done: i64,
    initial_pending: i64,
    gaps: i64,
    failures: i64,
}

async fn status(State(state): State<ApiState>) -> Response {
    match state.mirror.with(|db| db.stats()).await {
        Ok(stats) => Json(StatusResponse {
            api_version: API_VERSION,
            connection: (*state.connection.borrow()).as_str(),
            sync: SyncStatus {
                rooms: stats.rooms,
                revisions: stats.revisions,
                initial_done: stats.initial_done,
                initial_pending: stats.initial_pending,
                gaps: stats.gaps,
                failures: stats.failures,
            },
        })
        .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "bridge_unavailable",
                "message": "Mirror status is temporarily unavailable"
            })),
        )
            .into_response(),
    }
}

fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .with_state(state)
}

/// A running local API server. Dropping without calling [`Self::shutdown`]
/// aborts neither the daemon nor its listener; daemon shutdown must be explicit.
pub struct ApiServer {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<()>>,
}

impl ApiServer {
    /// Stop accepting new clients, wait for the listener task, and remove the
    /// filesystem socket. Existing request tasks finish independently.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.context("Local API listener task failed")?
    }
}

/// Start the HTTP/1.1 Unix-domain socket server at the protected runtime path.
///
/// The path is removed only when it is an existing socket; a file or symlink is
/// treated as tampering and causes startup to fail. The socket itself is 0600.
pub async fn start(paths: &Paths, state: ApiState) -> Result<ApiServer> {
    paths.ensure_dirs()?;
    if paths.socket.exists() {
        let metadata = fs::symlink_metadata(&paths.socket)
            .with_context(|| format!("Cannot inspect {}", paths.socket.display()))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            anyhow::bail!("{} exists but is not a Unix socket", paths.socket.display());
        }
        fs::remove_file(&paths.socket)
            .with_context(|| format!("Cannot remove stale socket {}", paths.socket.display()))?;
    }
    let listener = UnixListener::bind(&paths.socket)
        .with_context(|| format!("Cannot bind local API socket {}", paths.socket.display()))?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;
    let socket = paths.socket.clone();
    let app = router(state);
    let owner_uid = auth::daemon_uid();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted.context("Local API socket accept failed")?;
                    let app = app.clone();
                    tokio::spawn(async move {
                        serve_connection(stream, app, owner_uid).await;
                    });
                }
            }
        }
        // The runtime directory is daemon-owned and 0700. Still, never remove
        // an unexpected replacement path on shutdown.
        if let Ok(metadata) = fs::symlink_metadata(&socket) {
            if metadata.file_type().is_socket() {
                fs::remove_file(socket).context("Cannot remove local API socket")?;
            }
        }
        Ok(())
    });
    Ok(ApiServer {
        shutdown: Some(shutdown_tx),
        task,
    })
}

async fn serve_connection(stream: UnixStream, app: Router, owner_uid: u32) {
    let credentials = match stream.peer_cred() {
        Ok(credentials) => credentials,
        Err(_) => return,
    };
    let peer = auth::PeerIdentity {
        uid: credentials.uid(),
        pid: credentials.pid().map(|pid| pid as u32),
    };
    if auth::authorize_peer(peer, owner_uid).is_err() {
        return;
    }
    let service = service_fn(move |mut request| {
        let app = app.clone();
        async move {
            request.extensions_mut().insert(peer);
            app.oneshot(request).await
        }
    });
    let io = TokioIo::new(stream);
    let _ = Builder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::Mirror;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn status_is_available_only_over_a_protected_same_user_socket() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([91_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let server = start(&paths, ApiState::new(mirror, connection_rx))
            .await
            .unwrap();
        let metadata = fs::metadata(&paths.socket).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let mut client = UnixStream::connect(&paths.socket).await.unwrap();
        client
            .write_all(b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("\"apiVersion\":1"));
        assert!(response.contains("\"connection\":\"connected\""));
        assert!(response.contains("\"rooms\":0"));

        server.shutdown().await.unwrap();
        assert!(!paths.socket.exists());
    }

    #[tokio::test]
    async fn refuses_to_replace_a_non_socket_path() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        paths.ensure_dirs().unwrap();
        fs::write(&paths.socket, "not a socket").unwrap();
        fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600)).unwrap();
        let mirror = SharedMirror::new(Mirror::in_memory([92_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Disconnected);
        assert!(start(&paths, ApiState::new(mirror, connection_rx))
            .await
            .is_err());
    }
}
