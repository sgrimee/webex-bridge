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

use crate::{config::Config, mirror::SharedMirror, paths::Paths, sync::history::WebexRest};
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
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    sync::Arc,
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
    pub const fn as_str(self) -> &'static str {
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
    sessions: auth::Sessions,
    events: events::EventBus,
    config: Arc<Config>,
    rest: Option<watch::Receiver<Option<Arc<WebexRest>>>>,
}

impl ApiState {
    /// Create state from the daemon's mirror and connection-status watch.
    #[must_use]
    pub fn new(mirror: SharedMirror, connection: watch::Receiver<ConnectionStatus>) -> Self {
        Self {
            mirror,
            connection,
            sessions: auth::Sessions::default(),
            events: events::EventBus::default(),
            config: Arc::new(Config::default()),
            rest: None,
        }
    }

    /// Create state using the validated daemon configuration.
    #[must_use]
    pub fn with_config(
        mirror: SharedMirror,
        connection: watch::Receiver<ConnectionStatus>,
        config: Arc<Config>,
    ) -> Self {
        Self {
            mirror,
            connection,
            sessions: auth::Sessions::default(),
            events: events::EventBus::default(),
            config,
            rest: None,
        }
    }

    /// Create scoped API state with a daemon-owned, refreshable Webex REST
    /// client. Only an approved outbox handler can use this client to write.
    #[must_use]
    pub fn with_config_and_rest(
        mirror: SharedMirror,
        connection: watch::Receiver<ConnectionStatus>,
        config: Arc<Config>,
        rest: watch::Receiver<Option<Arc<WebexRest>>>,
    ) -> Self {
        Self {
            mirror,
            connection,
            sessions: auth::Sessions::default(),
            events: events::EventBus::default(),
            config,
            rest: Some(rest),
        }
    }

    /// Loaded, validated routing configuration used by scoped session setup.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Encrypted mirror access for handlers that already passed their scope
    /// and claimed-route checks. This does not expose a database connection.
    #[must_use]
    pub fn mirror(&self) -> SharedMirror {
        self.mirror.clone()
    }

    /// The current daemon-owned Webex REST client, if Mercury is connected.
    /// It is intentionally unavailable to all generic API handlers.
    #[must_use]
    pub fn rest(&self) -> Option<Arc<WebexRest>> {
        self.rest
            .as_ref()
            .and_then(|receiver| receiver.borrow().clone())
    }

    /// Process-local scoped session store. Sessions are intentionally lost on
    /// daemon restart, along with all other in-memory API credentials.
    #[must_use]
    pub fn sessions(&self) -> auth::Sessions {
        self.sessions.clone()
    }

    /// In-process metadata-only event fanout for scoped SSE subscribers.
    #[must_use]
    pub fn events(&self) -> events::EventBus {
        self.events.clone()
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
        .merge(events::router())
        .merge(agent::router())
        .merge(ui::router())
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
    let socket_metadata = fs::metadata(&paths.socket)?;
    let socket_identity = (socket_metadata.dev(), socket_metadata.ino());
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
            if metadata.file_type().is_socket()
                && (metadata.dev(), metadata.ino()) == socket_identity
            {
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
    use crate::{
        config::{Receive, Route},
        mirror::Mirror,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn request(socket: &std::path::Path, request: String) -> String {
        let mut client = UnixStream::connect(socket).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        response
    }

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
    async fn agent_session_is_route_scoped_and_exclusive() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([93_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let mut config = Config::default();
        config.routes.push(Route {
            id: "agents-social".into(),
            room_id: "room-id-is-not-returned".into(),
            agent_name: "sam/coder".into(),
            allowed_senders: Vec::new(),
            receive: Receive::Addressed,
            workspace: "/workspace".into(),
        });
        let server = start(
            &paths,
            ApiState::with_config(mirror, connection_rx, Arc::new(config)),
        )
        .await
        .unwrap();
        let body = r#"{"host":"pi","sessionId":"test-session","cwd":"/workspace","agentName":"sam/coder"}"#;
        let request = format!(
            "POST /v1/agent/sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut client = UnixStream::connect(&paths.socket).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("\"routes\":[{\"id\":\"agents-social\"}]"));
        assert!(!response.contains("room-id-is-not-returned"));
        let token =
            serde_json::from_str::<serde_json::Value>(response.split("\r\n\r\n").nth(1).unwrap())
                .unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned();

        let mut duplicate = UnixStream::connect(&paths.socket).await.unwrap();
        duplicate.write_all(request.as_bytes()).await.unwrap();
        let mut duplicate_response = String::new();
        duplicate
            .read_to_string(&mut duplicate_response)
            .await
            .unwrap();
        assert!(duplicate_response.starts_with("HTTP/1.1 409"));
        assert!(duplicate_response.contains("\"code\":\"route_claimed\""));

        let heartbeat = format!(
            "POST /v1/agent/sessions/test-session/heartbeat HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        let mut renewed = UnixStream::connect(&paths.socket).await.unwrap();
        renewed.write_all(heartbeat.as_bytes()).await.unwrap();
        let mut renewed_response = String::new();
        renewed.read_to_string(&mut renewed_response).await.unwrap();
        assert!(renewed_response.starts_with("HTTP/1.1 204"));

        let release = format!(
            "DELETE /v1/agent/sessions/test-session HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        );
        let mut released = UnixStream::connect(&paths.socket).await.unwrap();
        released.write_all(release.as_bytes()).await.unwrap();
        let mut released_response = String::new();
        released
            .read_to_string(&mut released_response)
            .await
            .unwrap();
        assert!(released_response.starts_with("HTTP/1.1 204"));

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn agent_inbox_keeps_text_hidden_until_the_local_acceptance() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mut config = Config::default();
        config.routes.push(Route {
            id: "agents-social".into(),
            room_id: "room-id-is-not-returned".into(),
            agent_name: "sam/coder".into(),
            allowed_senders: vec!["allowed-person".into()],
            receive: Receive::Addressed,
            workspace: "/workspace".into(),
        });
        let mirror = SharedMirror::new(Mirror::in_memory([94_u8; 32]).unwrap());
        mirror
            .with(|db| {
                db.sync_routes(&config.routes)?;
                db.upsert_message(&webex::Message {
                    id: Some("canonical-message".into()),
                    room_id: Some("room-id-is-not-returned".into()),
                    person_id: Some("allowed-person".into()),
                    text: Some("sam/coder: private remote content".into()),
                    created: Some("2099-01-01T00:00:00Z".into()),
                    ..webex::Message::default()
                })?;
                assert_eq!(db.queue_deliveries(&config)?, 1);
                Ok(())
            })
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let server = start(
            &paths,
            ApiState::with_config(mirror, connection_rx, Arc::new(config)),
        )
        .await
        .unwrap();
        let body = r#"{"host":"pi","sessionId":"test-session","cwd":"/workspace","agentName":"sam/coder"}"#;
        let session = request(
            &paths.socket,
            format!("POST /v1/agent/sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()),
        )
        .await;
        let token =
            serde_json::from_str::<serde_json::Value>(session.split("\r\n\r\n").nth(1).unwrap())
                .unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned();
        let inbox = request(
            &paths.socket,
            format!("GET /v1/agent/inbox?state=pending HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(inbox.starts_with("HTTP/1.1 200"));
        assert!(!inbox.contains("private remote content"));
        let delivery_id =
            serde_json::from_str::<serde_json::Value>(inbox.split("\r\n\r\n").nth(1).unwrap())
                .unwrap()["deliveries"][0]["id"]
                .as_str()
                .unwrap()
                .to_owned();
        let accepted = request(
            &paths.socket,
            format!("POST /v1/agent/inbox/{delivery_id}/accept HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(accepted.starts_with("HTTP/1.1 200"));
        assert!(accepted.contains("private remote content"));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_session_cannot_access_agent_scope() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use sha2::{Digest, Sha256};

        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([95_u8; 32]).unwrap());
        let secret = "a-local-ui-secret-that-is-long-enough";
        let secret_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        mirror
            .with(|db| db.pair_ui_client(&secret_hash, "/test/webex-tui"))
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let server = start(&paths, ApiState::new(mirror, connection_rx))
            .await
            .unwrap();
        let body = format!(r#"{{"secret":"{secret}"}}"#);
        let session = request(
            &paths.socket,
            format!("POST /v1/ui/sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()),
        )
        .await;
        assert!(session.starts_with("HTTP/1.1 200"));
        let token =
            serde_json::from_str::<serde_json::Value>(session.split("\r\n\r\n").nth(1).unwrap())
                .unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned();
        let agent = request(
            &paths.socket,
            format!("GET /v1/agent/inbox HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(agent.starts_with("HTTP/1.1 403"));
        assert!(agent.contains("forbidden_scope"));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn agent_session_cannot_read_full_mirror_ui_routes() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mut config = Config::default();
        config.routes.push(Route {
            id: "agents-social".into(),
            room_id: "room-id-is-not-returned".into(),
            agent_name: "sam/coder".into(),
            allowed_senders: Vec::new(),
            receive: Receive::Addressed,
            workspace: "/workspace".into(),
        });
        let mirror = SharedMirror::new(Mirror::in_memory([97_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let server = start(
            &paths,
            ApiState::with_config(mirror, connection_rx, Arc::new(config)),
        )
        .await
        .unwrap();
        let body = r#"{"host":"pi","sessionId":"test-session","cwd":"/workspace","agentName":"sam/coder"}"#;
        let session = request(
            &paths.socket,
            format!("POST /v1/agent/sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()),
        )
        .await;
        let token =
            serde_json::from_str::<serde_json::Value>(session.split("\r\n\r\n").nth(1).unwrap())
                .unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned();
        let rooms = request(
            &paths.socket,
            format!("GET /v1/rooms HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(rooms.starts_with("HTTP/1.1 403"));
        assert!(rooms.contains("forbidden_scope"));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_does_not_unlink_a_replacement_socket() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([96_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Disconnected);
        let server = start(&paths, ApiState::new(mirror, connection_rx))
            .await
            .unwrap();
        std::fs::remove_file(&paths.socket).unwrap();
        let replacement = UnixListener::bind(&paths.socket).unwrap();
        server.shutdown().await.unwrap();
        assert!(paths.socket.exists());
        drop(replacement);
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
