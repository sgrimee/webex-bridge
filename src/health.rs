//! Keychain-free daemon health check over the protected Unix socket.
//!
//! This only sends `GET /v1/status`, which is unauthenticated and
//! metadata-only. It reads no Keychain item, token or mirror key, so it is
//! safe from an unsigned or ad-hoc-signed CLI and from service scripts.

use crate::dto;
use anyhow::{bail, Context, Result};
use std::{os::unix::fs::FileTypeExt, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Query the running daemon's metadata-only status.
pub async fn daemon_status(socket: &Path) -> Result<dto::Status> {
    let metadata = std::fs::symlink_metadata(socket)
        .context("Bridge daemon socket is unavailable; is webex-bridged running?")?;
    if !metadata.file_type().is_socket() {
        bail!("Bridge daemon socket path is not a Unix socket");
    }
    let response = tokio::time::timeout(HEALTH_TIMEOUT, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .context("Cannot connect to the bridge daemon socket")?;
        stream
            .write_all(b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        stream
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut response)
            .await?;
        Ok::<_, anyhow::Error>(response)
    })
    .await
    .context("Timed out waiting for the bridge daemon")??;
    parse_status_response(&response)
}

/// Parse a complete `Connection: close` HTTP/1.1 status response.
fn parse_status_response(response: &[u8]) -> Result<dto::Status> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("Bridge daemon returned an incomplete response")?;
    let head = std::str::from_utf8(&response[..split])
        .context("Bridge daemon returned a malformed response")?;
    let status_line = head.lines().next().unwrap_or_default();
    if !status_line.starts_with("HTTP/1.1 200") {
        bail!("Bridge daemon status endpoint did not return 200");
    }
    if head
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:"))
    {
        bail!("Bridge daemon returned an unexpected transfer encoding");
    }
    serde_json::from_slice(&response[split + 4..]).context("Bridge daemon status is malformed")
}

/// One-line, metadata-only summary for the CLI.
#[must_use]
pub fn summary(status: &dto::Status) -> String {
    format!(
        "webex-bridged: api={} connection={} rooms={} initial_done={} initial_pending={} gaps={} failures={}",
        status.api_version,
        status.connection,
        status.sync.rooms,
        status.sync.initial_done,
        status.sync.initial_pending,
        status.sync.gaps,
        status.sync.failures,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{self, ApiState, ConnectionStatus},
        mirror::{Mirror, SharedMirror},
        paths::Paths,
    };
    use tokio::sync::watch;

    #[test]
    fn parses_only_complete_successful_status_responses() {
        let body = r#"{"apiVersion":1,"connection":"connected","sync":{"rooms":2,"revisions":3,"initialDone":2,"initialPending":0,"gaps":0,"failures":0}}"#;
        let ok = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{body}");
        let status = parse_status_response(ok.as_bytes()).unwrap();
        assert_eq!(status.connection, "connected");
        assert_eq!(
            summary(&status),
            "webex-bridged: api=1 connection=connected rooms=2 initial_done=2 initial_pending=0 gaps=0 failures=0"
        );
        for bad in [
            "HTTP/1.1 500 Internal\r\n\r\n{}".to_owned(),
            "HTTP/1.1 200 OK\r\ncontent-type: application/json".to_owned(),
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}"),
            "HTTP/1.1 200 OK\r\n\r\nnot json".to_owned(),
        ] {
            assert!(parse_status_response(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn reads_status_from_a_running_daemon_socket_without_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        assert!(daemon_status(&paths.socket).await.is_err(), "no daemon yet");
        let mirror = SharedMirror::new(Mirror::in_memory([97_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let server = api::start(&paths, ApiState::new(mirror, connection_rx))
            .await
            .unwrap();
        let status = daemon_status(&paths.socket).await.unwrap();
        assert_eq!(status.api_version, 1);
        assert_eq!(status.connection, "connected");
        server.shutdown().await.unwrap();
    }
}
