//! Keychain-free UI pairing administration over the protected socket.
//!
//! Like [`crate::health`], this reads no Keychain item, token or mirror key:
//! the running daemon owns the mirror and applies the change, including
//! ending live sessions of a removed pairing at once.

use crate::health::{socket_request, split_response};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

/// One paired UI executable as reported by the daemon.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Pairing {
    /// Kernel-resolved executable path confirmed at pairing.
    pub executable: String,
    /// RFC 3339 pairing time.
    pub paired_at: String,
    /// RFC 3339 time of the last session creation or renewal.
    pub last_seen: Option<String>,
}

/// Outcome of a pairing removal.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Unpaired {
    /// Pairing rows removed.
    pub removed: usize,
    /// Live UI sessions ended because their pairing was removed.
    pub sessions_ended: usize,
}

#[derive(Deserialize)]
struct PairingsResponse {
    pairings: Vec<Pairing>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
}

fn decode<T: serde::de::DeserializeOwned>(response: &[u8]) -> Result<T> {
    let (status, body) = split_response(response)?;
    if status != 200 {
        let error: ErrorResponse =
            serde_json::from_slice(body).context("Bridge daemon returned a malformed error")?;
        bail!(
            "Bridge daemon refused ({status} {}): {}",
            error.code,
            error.message
        );
    }
    serde_json::from_slice(body).context("Bridge daemon response is malformed")
}

/// List paired UI executables.
pub async fn pairings(socket: &Path) -> Result<Vec<Pairing>> {
    let response = socket_request(socket, "GET", "/v1/ui/pairings", None).await?;
    Ok(decode::<PairingsResponse>(&response)?.pairings)
}

/// Remove the pairings of one exact executable path, or every pairing when
/// `executable` is `None`.
pub async fn unpair(socket: &Path, executable: Option<&str>) -> Result<Unpaired> {
    let body = match executable {
        Some(path) => serde_json::json!({ "executable": path }),
        None => serde_json::json!({ "all": true }),
    }
    .to_string();
    let response = socket_request(socket, "POST", "/v1/ui/pairings/remove", Some(&body)).await?;
    decode(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{self, auth, ApiState, ConnectionStatus},
        mirror::{Mirror, SharedMirror},
        paths::Paths,
    };
    use std::time::Duration;
    use tokio::sync::watch;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "ccccccccccccccccccccccccccccccccccccccccccc";

    fn me() -> auth::PeerIdentity {
        auth::PeerIdentity {
            uid: auth::daemon_uid(),
            pid: Some(std::process::id()),
        }
    }

    #[tokio::test]
    async fn unpair_removes_the_executable_and_ends_its_sessions_without_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([96_u8; 32]).unwrap());
        mirror
            .with(|db| {
                db.pair_ui_client(HASH_A, "/opt/tui-a")?;
                db.pair_ui_client(HASH_B, "/opt/tui-a")?;
                db.pair_ui_client(HASH_C, "/opt/tui-b")
            })
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror.clone(), connection_rx);
        let sessions = state.sessions();
        let issue = |hash: &str| {
            sessions.issue_ui(
                me(),
                hash.into(),
                Duration::from_secs(60),
                Duration::from_secs(3600),
            )
        };
        let (token_a, token_b, token_c) = (issue(HASH_A), issue(HASH_B), issue(HASH_C));
        let server = api::start(&paths, state).await.unwrap();

        let listed = pairings(&paths.socket).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|pairing| pairing.executable.as_str())
                .collect::<Vec<_>>(),
            ["/opt/tui-a", "/opt/tui-a", "/opt/tui-b"]
        );
        // Secret hashes never leave the daemon, even in the listing.
        let raw = socket_request(&paths.socket, "GET", "/v1/ui/pairings", None)
            .await
            .unwrap();
        let raw = String::from_utf8(raw).unwrap();
        assert!(!raw.contains(HASH_A) && !raw.contains(HASH_C));

        assert_eq!(
            unpair(&paths.socket, Some("/opt/tui-a")).await.unwrap(),
            Unpaired {
                removed: 2,
                sessions_ended: 2
            }
        );
        for token in [&token_a, &token_b] {
            assert_eq!(
                sessions.authorize(Some(token), auth::Scope::Ui, me()),
                Err(auth::SessionError::Missing)
            );
        }
        assert!(sessions
            .authorize(Some(&token_c), auth::Scope::Ui, me())
            .is_ok());
        assert_eq!(
            unpair(&paths.socket, Some("/opt/unknown")).await.unwrap(),
            Unpaired {
                removed: 0,
                sessions_ended: 0
            }
        );
        assert!(unpair(&paths.socket, Some("relative/path"))
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid_request"));

        assert_eq!(
            unpair(&paths.socket, None).await.unwrap(),
            Unpaired {
                removed: 1,
                sessions_ended: 1
            }
        );
        assert!(pairings(&paths.socket).await.unwrap().is_empty());
        let audited = mirror
            .with(|db| db.audit_count_for_tests("ui", "unpair"))
            .await
            .unwrap();
        assert_eq!(audited, 3);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn unpair_refuses_agent_bearers_before_removing_anything() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([95_u8; 32]).unwrap());
        mirror
            .with(|db| db.pair_ui_client(HASH_A, "/opt/tui-a"))
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror, connection_rx);
        let agent = state
            .sessions()
            .issue(auth::Scope::Agent, me(), Duration::from_secs(60));
        let server = api::start(&paths, state).await.unwrap();
        let body = r#"{"all":true}"#;
        let request = format!(
            "POST /v1/ui/pairings/remove HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {agent}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = tokio::net::UnixStream::connect(&paths.socket)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .unwrap();
        assert_eq!(split_response(&response).unwrap().0, 403);
        assert_eq!(pairings(&paths.socket).await.unwrap().len(), 1);
        server.shutdown().await.unwrap();
    }
}
