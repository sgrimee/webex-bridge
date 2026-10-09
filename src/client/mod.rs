//! Typed client for the daemon's UI-scoped HTTP-over-UDS API.
//!
//! The client deliberately has no fallback TCP transport. UI code can use this
//! module only after pairing and can only reach the local daemon socket.

pub mod events;
pub mod ui;

use anyhow::Context;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Method, Request, Response, StatusCode,
};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use serde::de::DeserializeOwned;
use std::{
    fmt,
    path::{Path, PathBuf},
};

pub(crate) type HttpClient = Client<UnixConnector, Full<Bytes>>;

/// Error returned by the local bridge API or its Unix-socket transport.
#[derive(Debug)]
pub enum ClientError {
    /// The Unix-socket connection or its HTTP body failed.
    Transport(anyhow::Error),
    /// The daemon returned a structured API error.
    Api {
        /// HTTP status returned by the daemon.
        status: StatusCode,
        /// Stable API error code.
        code: String,
        /// Human-readable, secret-free daemon message.
        message: String,
    },
    /// A successful daemon response did not match the versioned local API.
    InvalidResponse(anyhow::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "Bridge transport failed: {error}"),
            Self::Api {
                status,
                code,
                message,
            } => write!(formatter, "Bridge API {status} ({code}): {message}"),
            Self::InvalidResponse(error) => write!(formatter, "Invalid bridge response: {error}"),
        }
    }
}

impl std::error::Error for ClientError {}

pub(crate) type Result<T> = std::result::Result<T, ClientError>;

#[derive(serde::Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
}

/// Reusable, unauthenticated connection to one daemon Unix socket.
#[derive(Clone)]
pub struct BridgeClient {
    socket: PathBuf,
    http: HttpClient,
}

impl BridgeClient {
    /// Connect requests to `socket`; no request is sent until a method is called.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            http: HttpClient::unix(),
        }
    }

    /// Construct a client for the standard per-user bridge socket.
    pub fn discover() -> anyhow::Result<Self> {
        Ok(Self::new(crate::paths::Paths::discover()?.socket))
    }

    /// Socket path used by this client.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub(crate) async fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<Response<Incoming>> {
        if !path.starts_with('/') || path.contains('\r') || path.contains('\n') {
            return Err(ClientError::InvalidResponse(anyhow::anyhow!(
                "Bridge request path is invalid"
            )));
        }
        let mut builder = Request::builder()
            .method(method)
            .uri(Uri::new(&self.socket, path))
            .header(ACCEPT, "application/json");
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = if let Some(body) = body {
            builder
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body)))
        } else {
            builder.body(Full::new(Bytes::new()))
        }
        .map_err(|error| ClientError::InvalidResponse(error.into()))?;
        self.http
            .request(request)
            .await
            .map_err(|error| ClientError::Transport(error.into()))
    }

    pub(crate) async fn json<T: DeserializeOwned>(response: Response<Incoming>) -> Result<T> {
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ClientError::Transport(error.into()))?
            .to_bytes();
        if !status.is_success() {
            let error = serde_json::from_slice::<ErrorResponse>(&body).unwrap_or(ErrorResponse {
                code: "bridge_error".into(),
                message: "Bridge returned an invalid error response".into(),
            });
            return Err(ClientError::Api {
                status,
                code: error.code,
                message: error.message,
            });
        }
        serde_json::from_slice(&body)
            .context("Cannot decode bridge JSON")
            .map_err(ClientError::InvalidResponse)
    }

    pub(crate) async fn empty(response: Response<Incoming>) -> Result<()> {
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ClientError::Transport(error.into()))?
            .to_bytes();
        if status.is_success() {
            return Ok(());
        }
        let error = serde_json::from_slice::<ErrorResponse>(&body).unwrap_or(ErrorResponse {
            code: "bridge_error".into(),
            message: "Bridge returned an invalid error response".into(),
        });
        Err(ClientError::Api {
            status,
            code: error.code,
            message: error.message,
        })
    }

    pub(crate) fn json_body<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
        serde_json::to_vec(value)
            .context("Cannot encode bridge JSON")
            .map_err(ClientError::InvalidResponse)
    }
}

/// Percent-encode an opaque API path segment without ever treating remote IDs
/// as URL syntax.
pub(crate) fn path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}
