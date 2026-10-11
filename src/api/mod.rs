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
    /// Non-content notification threshold used by scoped agent hosts to avoid
    /// flooding the local UI during catch-up.
    catchup_notify_threshold: u32,
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
                catchup_notify_threshold: state.config().limits.catchup_notify_threshold,
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
    async fn events_require_a_scoped_local_session() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([90_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let server = start(&paths, ApiState::new(mirror, connection_rx))
            .await
            .unwrap();
        let response = request(
            &paths.socket,
            "GET /v1/events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 401"));
        assert!(response.contains("auth_required"));
        server.shutdown().await.unwrap();
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

    fn scoped_ui_request(
        method: &str,
        path: &str,
        agent_bearer: &str,
        body: Option<&str>,
    ) -> String {
        let body = body.unwrap_or_default();
        let content_headers = (!body.is_empty()).then(|| {
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            )
        });
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {agent_bearer}\r\n{}Connection: close\r\n\r\n{body}",
            content_headers.unwrap_or_default(),
        )
    }

    fn response_status(response: &str) -> Option<u16> {
        response
            .split("\r\n")
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse().ok())
    }

    fn response_code(response: &str) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(response.split("\r\n\r\n").nth(1)?)
            .ok()?
            .get("code")?
            .as_str()
            .map(str::to_owned)
    }

    #[tokio::test]
    async fn agent_bearer_is_rejected_by_every_ui_route_before_ui_work() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([98_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror, connection_rx);
        // The UDS client and this issued token have the same kernel identity,
        // making this a real, process-bound Agent bearer without any route
        // configuration, user config, pairing, or daemon startup.
        let agent_bearer = state.sessions().issue(
            auth::Scope::Agent,
            auth::PeerIdentity {
                uid: auth::daemon_uid(),
                pid: Some(std::process::id()),
            },
            std::time::Duration::from_secs(60),
        );
        let server = start(&paths, state).await.unwrap();

        // The status endpoint intentionally remains an unauthenticated,
        // metadata-only liveness check.
        let status = request(
            &paths.socket,
            "GET /v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert_eq!(response_status(&status), Some(200));

        // Empty structural request fields are sufficient for JSON extraction.
        // Each handler must classify the Agent scope first, before its mirror,
        // hydrate, paired-secret, or native-dialog logic can inspect them.
        let ui_routes = [
            ("POST", "/v1/ui/pair", Some(r#"{"secretHash":""}"#)),
            ("POST", "/v1/ui/sessions", Some(r#"{"secret":""}"#)),
            ("GET", "/v1/me", None),
            ("GET", "/v1/ui/continuity", None),
            ("GET", "/v1/rooms", None),
            ("GET", "/v1/rooms/room-id", None),
            ("GET", "/v1/teams/team-id", None),
            ("DELETE", "/v1/rooms/room-id/membership", None),
            ("GET", "/v1/rooms/room-id/messages", None),
            ("POST", "/v1/messages", Some(r#"{"roomId":""}"#)),
            ("GET", "/v1/messages/message-id/thread", None),
            ("GET", "/v1/messages/message-id/children", None),
            ("GET", "/v1/messages/message-id/read", None),
            ("GET", "/v1/messages/message-id", None),
            ("PUT", "/v1/messages/message-id", Some(r#"{"roomId":""}"#)),
            ("DELETE", "/v1/messages/message-id", None),
            ("GET", "/v1/people/person-id/read", None),
            ("GET", "/v1/people/person-id", None),
        ];
        for (method, path, body) in ui_routes {
            let response = request(
                &paths.socket,
                scoped_ui_request(method, path, &agent_bearer, body),
            )
            .await;
            // Assert only the HTTP status and fixed sanitized error
            // classification—never domain data, bearer values, or secrets.
            assert_eq!(response_status(&response), Some(403), "{method} {path}");
            assert_eq!(
                response_code(&response),
                Some("forbidden_scope".into()),
                "{method} {path}"
            );
        }

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
    async fn agent_preview_shows_text_locally_without_deciding() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mut config = Config::default();
        for (id, room, agent, workspace) in [
            ("agents-social", "room-claimed", "sam/coder", "/workspace"),
            ("other-route", "room-other", "sam/other", "/elsewhere"),
        ] {
            config.routes.push(Route {
                id: id.into(),
                room_id: room.into(),
                agent_name: agent.into(),
                allowed_senders: vec!["allowed-person".into()],
                receive: Receive::Addressed,
                workspace: workspace.into(),
            });
        }
        let mirror = SharedMirror::new(Mirror::in_memory([89_u8; 32]).unwrap());
        let other_delivery = mirror
            .with(|db| {
                db.sync_routes(&config.routes)?;
                db.upsert_room(
                    &webex::Room {
                        id: "room-claimed".into(),
                        title: Some("Agents social".into()),
                        room_type: "group".into(),
                        is_locked: false,
                        team_id: None,
                        last_activity: "2099-01-01T00:00:00Z".into(),
                        creator_id: "allowed-person".into(),
                        created: "2099-01-01T00:00:00Z".into(),
                    },
                    true,
                )?;
                db.upsert_person(&webex::Person {
                    id: "allowed-person".into(),
                    display_name: "Pat Sender".into(),
                    ..webex::Person::default()
                })?;
                for (id, room, text) in [
                    (
                        "first",
                        "room-claimed",
                        "sam/coder: private preview content",
                    ),
                    (
                        "second",
                        "room-claimed",
                        "sam/coder: rejected private content",
                    ),
                    ("third", "room-other", "sam/other: other route content"),
                ] {
                    db.upsert_message(&webex::Message {
                        id: Some(id.into()),
                        room_id: Some(room.into()),
                        person_id: Some("allowed-person".into()),
                        text: Some(text.into()),
                        parent_id: (id == "first").then(|| "thread-parent".into()),
                        created: Some(format!("2099-01-01T00:00:0{}Z", id.len())),
                        ..webex::Message::default()
                    })?;
                }
                assert_eq!(db.queue_deliveries(&config)?, 3);
                Ok(db.deliveries(&["other-route".into()], None)?[0].id.clone())
            })
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let server = start(
            &paths,
            ApiState::with_config(mirror.clone(), connection_rx, Arc::new(config)),
        )
        .await
        .unwrap();
        let body = r#"{"host":"pi","sessionId":"test-session","cwd":"/workspace","agentName":"sam/coder"}"#;
        let session = request(
            &paths.socket,
            format!("POST /v1/agent/sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()),
        )
        .await;
        let token = json_body(&session)["token"].as_str().unwrap().to_owned();
        let get = |path: String| {
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n")
        };
        let post = |path: String| {
            format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        };

        // The list carries decrypted display names but never message text.
        let inbox = request(&paths.socket, get("/v1/agent/inbox?state=pending".into())).await;
        assert_eq!(response_status(&inbox), Some(200));
        assert!(!inbox.contains("private"));
        let listed = json_body(&inbox)["deliveries"].as_array().unwrap().clone();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["senderName"], "Pat Sender");
        assert_eq!(listed[0]["roomTitle"], "Agents social");
        let first = listed[0]["id"].as_str().unwrap().to_owned();
        let second = listed[1]["id"].as_str().unwrap().to_owned();

        let preview = request(
            &paths.socket,
            get(format!("/v1/agent/inbox/{first}/preview")),
        )
        .await;
        assert_eq!(response_status(&preview), Some(200));
        let preview = json_body(&preview);
        assert_eq!(preview["id"], first.as_str());
        assert_eq!(preview["routeId"], "agents-social");
        assert_eq!(preview["revision"], 0);
        assert_eq!(preview["senderId"], "allowed-person");
        assert_eq!(preview["senderName"], "Pat Sender");
        assert_eq!(preview["roomTitle"], "Agents social");
        assert_eq!(preview["parentId"], "thread-parent");
        assert_eq!(preview["markdown"], "sam/coder: private preview content");
        assert!(preview.get("state").is_none());

        // Preview left it pending; acceptance still works and releases the same text.
        let still = request(&paths.socket, get("/v1/agent/inbox?state=pending".into())).await;
        assert_eq!(json_body(&still)["deliveries"].as_array().unwrap().len(), 2);
        let accepted = request(
            &paths.socket,
            post(format!("/v1/agent/inbox/{first}/accept")),
        )
        .await;
        assert_eq!(response_status(&accepted), Some(200));
        assert_eq!(json_body(&accepted)["markdown"], preview["markdown"]);
        assert_eq!(json_body(&accepted)["parentId"], "thread-parent");

        let rejected = request(
            &paths.socket,
            post(format!("/v1/agent/inbox/{second}/reject")),
        )
        .await;
        assert_eq!(response_status(&rejected), Some(204));
        for id in [
            first.as_str(),
            second.as_str(),
            other_delivery.as_str(),
            "dW5rbm93bg",
            "not%20an%20id",
        ] {
            let response =
                request(&paths.socket, get(format!("/v1/agent/inbox/{id}/preview"))).await;
            assert_eq!(response_status(&response), Some(404), "{id}");
            assert_eq!(response_code(&response), Some("not_found".into()), "{id}");
            assert!(!response.contains("private"), "{id}");
            assert!(!response.contains("other route"), "{id}");
        }

        // The durable audit trail records metadata only for the one preview.
        let audit = mirror
            .with(|db| {
                let mut statement = db.conn.prepare(
                    "SELECT ref,detail_redacted FROM audit WHERE action='inbox_preview'",
                )?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .unwrap();
        assert_eq!(audit, vec![("agents-social:first:0".into(), None)]);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn agent_preview_enforces_scope_lease_and_hides_unavailable_cases() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mut config = Config::default();
        config.routes.push(Route {
            id: "agents-social".into(),
            room_id: "room-claimed".into(),
            agent_name: "sam/coder".into(),
            allowed_senders: vec!["allowed-person".into()],
            receive: Receive::Addressed,
            workspace: "/workspace".into(),
        });
        const ORDER: [&str; 4] = ["edited", "deleted", "accepted", "held"];
        let config = Arc::new(config);
        let message = |id: &str, text: &str| webex::Message {
            id: Some(id.into()),
            room_id: Some("room-claimed".into()),
            person_id: Some("allowed-person".into()),
            text: Some(text.into()),
            // Creation order follows ORDER below, so listed IDs match it.
            created: Some(format!(
                "2099-01-01T00:00:0{}Z",
                ORDER.iter().position(|known| *known == id).unwrap()
            )),
            ..webex::Message::default()
        };
        let mirror = SharedMirror::new(Mirror::in_memory([88_u8; 32]).unwrap());
        let ids = {
            let config = config.clone();
            mirror
                .with(move |db| {
                    db.sync_routes(&config.routes)?;
                    for id in ORDER {
                        db.upsert_message(&message(id, "sam/coder: private content"))?;
                    }
                    assert_eq!(db.queue_deliveries(&config)?, 4);
                    Ok(db
                        .deliveries(&["agents-social".into()], None)?
                        .into_iter()
                        .map(|delivery| delivery.id)
                        .collect::<Vec<_>>())
                })
                .await
                .unwrap()
        };
        let [edited, deleted, accepted, held] = <[String; 4]>::try_from(ids).unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::with_config(mirror.clone(), connection_rx, config.clone());
        let sessions = state.sessions();
        let server = start(&paths, state).await.unwrap();
        let me = auth::PeerIdentity {
            uid: auth::daemon_uid(),
            pid: Some(std::process::id()),
        };
        let call = |method: &str, path: String, token: Option<&str>| {
            let authorization = token
                .map(|token| format!("Authorization: Bearer {token}\r\n"))
                .unwrap_or_default();
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Length: 0\r\nConnection: close\r\n\r\n")
        };
        let preview_of = |id: &str| format!("/v1/agent/inbox/{id}/preview");
        let assert_error = |response: &str, status: u16, code: &str, what: &str| {
            assert_eq!(response_status(response), Some(status), "{what}");
            assert_eq!(response_code(response), Some(code.into()), "{what}");
            assert!(!response.contains("private"), "{what}");
        };

        // (a) A UI token is refused by preview and by both decisions.
        let ui = sessions.issue(auth::Scope::Ui, me, std::time::Duration::from_secs(60));
        for (method, action) in [("GET", "preview"), ("POST", "accept"), ("POST", "reject")] {
            let response = request(
                &paths.socket,
                call(
                    method,
                    format!("/v1/agent/inbox/{held}/{action}"),
                    Some(&ui),
                ),
            )
            .await;
            assert_error(&response, 403, "forbidden_scope", action);
        }
        // Missing bearer.
        let response = request(&paths.socket, call("GET", preview_of(&held), None)).await;
        assert_error(&response, 401, "auth_required", "missing bearer");

        let body = r#"{"host":"pi","sessionId":"test-session","cwd":"/workspace","agentName":"sam/coder"}"#;
        let session = request(
            &paths.socket,
            format!("POST /v1/agent/sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()),
        )
        .await;
        let token = json_body(&session)["token"].as_str().unwrap().to_owned();
        let accept = request(
            &paths.socket,
            call(
                "POST",
                format!("/v1/agent/inbox/{accepted}/accept"),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(response_status(&accept), Some(200));

        // (c) Superseded (edit + re-queue) and deleted (tombstoned) deliveries.
        {
            let config = config.clone();
            mirror
                .with(move |db| {
                    let mut revised = message("edited", "sam/coder: private revision");
                    revised.updated = Some("2099-01-01T00:05:00Z".into());
                    db.upsert_message(&revised)?;
                    assert_eq!(db.queue_deliveries(&config)?, 1);
                    assert!(db.mark_deleted("room-claimed", "deleted")?);
                    Ok(())
                })
                .await
                .unwrap();
        }
        let other_route = URL_SAFE_NO_PAD.encode("other-route\0held\u{0}0");
        let unknown = URL_SAFE_NO_PAD.encode("agents-social\0missing\u{0}0");
        let mut bodies = Vec::new();
        for (what, id) in [
            ("superseded", edited.as_str()),
            ("deleted", deleted.as_str()),
            ("accepted", accepted.as_str()),
            ("other route", other_route.as_str()),
            ("unknown", unknown.as_str()),
            ("malformed", "not%20an%20id"),
        ] {
            let response = request(&paths.socket, call("GET", preview_of(id), Some(&token))).await;
            assert_error(&response, 404, "not_found", what);
            bodies.push(response.split("\r\n\r\n").nth(1).unwrap().to_owned());
        }
        // (d) Every unavailable case has a byte-identical body.
        assert!(
            bodies.windows(2).all(|pair| pair[0] == pair[1]),
            "{bodies:?}"
        );
        let held_preview =
            request(&paths.socket, call("GET", preview_of(&held), Some(&token))).await;
        assert_eq!(response_status(&held_preview), Some(200));

        // (b) Released lease, wrong peer and expired lease.
        let release = request(
            &paths.socket,
            call(
                "DELETE",
                "/v1/agent/sessions/test-session".into(),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(response_status(&release), Some(204));
        let response = request(&paths.socket, call("GET", preview_of(&held), Some(&token))).await;
        assert_error(&response, 401, "auth_required", "released lease");

        let routes = vec!["agents-social".to_string()];
        let other_peer = auth::PeerIdentity {
            uid: me.uid,
            pid: Some(std::process::id().wrapping_add(1)),
        };
        let stolen = sessions
            .issue_agent(
                other_peer,
                "other-session".into(),
                routes.clone(),
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        let response = request(&paths.socket, call("GET", preview_of(&held), Some(&stolen))).await;
        assert_error(&response, 403, "forbidden_peer", "wrong peer");
        sessions.revoke(&stolen);

        let expired = sessions
            .issue_agent(
                me,
                "expired-session".into(),
                routes,
                std::time::Duration::ZERO,
            )
            .unwrap();
        let response = request(
            &paths.socket,
            call("GET", preview_of(&held), Some(&expired)),
        )
        .await;
        assert_error(&response, 401, "auth_required", "expired lease");

        // None of the refused requests consumed the held delivery.
        let pending = mirror
            .with(|db| db.deliveries(&["agents-social".into()], Some("pending")))
            .await
            .unwrap();
        assert!(pending.iter().any(|delivery| delivery.id == held));
        server.shutdown().await.unwrap();
    }

    fn json_body(response: &str) -> serde_json::Value {
        serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap()).unwrap()
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
