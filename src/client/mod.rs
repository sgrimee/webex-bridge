//! Typed client for the daemon's UI-scoped HTTP-over-UDS API.
//!
//! The client deliberately has no fallback TCP transport. UI code can use this
//! module only after pairing and can only reach the local daemon socket.

pub mod events;
mod secret;
pub mod ui;

use anyhow::Context;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE},
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

impl ClientError {
    /// Whether the daemon accepted a write but cannot confirm local delivery.
    ///
    /// Callers must refresh the local mirror instead of retrying the write:
    /// the remote Webex operation may already have succeeded.
    #[must_use]
    pub fn is_delivery_unknown(&self) -> bool {
        matches!(
            self,
            Self::Api {
                status: StatusCode::ACCEPTED,
                code,
                ..
            } if code == "delivery_unknown"
        )
    }

    /// Whether Webex definitely rejected a paired-UI write before the daemon
    /// could report a confirmed mirror result. This is distinct from
    /// [`Self::is_delivery_unknown`], which callers must never replay.
    #[must_use]
    pub fn is_definitely_rejected(&self) -> bool {
        matches!(
            self,
            Self::Api { code, .. } if code == "webex_rejected"
        )
    }

    /// Whether a UI renewal was refused because the client's pairing was
    /// removed. The daemon has already ended the session; re-pairing is needed.
    #[must_use]
    pub fn is_pairing_removed(&self) -> bool {
        matches!(
            self,
            Self::Api {
                status: StatusCode::UNAUTHORIZED,
                code,
                ..
            } if code == "pairing_removed"
        )
    }

    /// Whether a UI renewal was refused because the session reached its
    /// absolute lifetime. The current token remains valid until its expiry;
    /// create a new session from the paired secret.
    #[must_use]
    pub fn is_session_cap_reached(&self) -> bool {
        matches!(
            self,
            Self::Api {
                status: StatusCode::CONFLICT,
                code,
                ..
            } if code == "session_cap_reached"
        )
    }

    /// Whether the paired daemon has not yet mirrored an authoritative account
    /// identity. Callers can still show other locally available mirror data.
    #[must_use]
    pub fn is_identity_not_ready(&self) -> bool {
        matches!(
            self,
            Self::Api {
                status: StatusCode::CONFLICT,
                code,
                ..
            } if code == "identity_not_ready"
        )
    }
}

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
            // Build the header in a wiped buffer shared with hyper (no copy).
            let mut header = Vec::with_capacity(7 + token.len());
            header.extend_from_slice(b"Bearer ");
            header.extend_from_slice(token.as_bytes());
            let mut value =
                HeaderValue::from_maybe_shared(Bytes::from_owner(secret::Wiped::new(header)))
                    .map_err(|error| ClientError::InvalidResponse(error.into()))?;
            value.set_sensitive(true);
            builder = builder.header(AUTHORIZATION, value);
        }
        let request = if let Some(body) = body {
            // Request bodies (including the UI secret) are wiped when released.
            builder
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_owner(secret::Wiped::new(body))))
        } else {
            builder.body(Full::new(Bytes::new()))
        }
        .map_err(|error| ClientError::InvalidResponse(error.into()))?;
        self.http
            .request(request)
            .await
            .map_err(|error| ClientError::Transport(error.into()))
    }

    fn api_error(status: StatusCode, body: &[u8]) -> ClientError {
        let error = serde_json::from_slice::<ErrorResponse>(body).unwrap_or(ErrorResponse {
            code: "bridge_error".into(),
            message: "Bridge returned an invalid error response".into(),
        });
        ClientError::Api {
            status,
            code: error.code,
            message: error.message,
        }
    }

    fn delivery_unknown(status: StatusCode, body: &[u8]) -> Option<ClientError> {
        (status == StatusCode::ACCEPTED)
            .then(|| Self::api_error(status, body))
            .filter(ClientError::is_delivery_unknown)
    }

    fn decode_json<T: DeserializeOwned>(status: StatusCode, body: &[u8]) -> Result<T> {
        if let Some(error) = Self::delivery_unknown(status, body) {
            return Err(error);
        }
        if !status.is_success() {
            return Err(Self::api_error(status, body));
        }
        serde_json::from_slice(body)
            .context("Cannot decode bridge JSON")
            .map_err(ClientError::InvalidResponse)
    }

    fn decode_empty(status: StatusCode, body: &[u8]) -> Result<()> {
        if let Some(error) = Self::delivery_unknown(status, body) {
            return Err(error);
        }
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::api_error(status, body))
        }
    }

    pub(crate) async fn json<T: DeserializeOwned>(response: Response<Incoming>) -> Result<T> {
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ClientError::Transport(error.into()))?
            .to_bytes();
        Self::decode_json(status, &body)
    }

    /// As [`Self::json`], for a response carrying a credential: the collected
    /// body is held in a wiped buffer while it is parsed.
    pub(crate) async fn secret_json<T: DeserializeOwned>(
        response: Response<Incoming>,
    ) -> Result<T> {
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ClientError::Transport(error.into()))?
            .to_bytes();
        let body = secret::Wiped::new(Vec::from(body));
        Self::decode_json(status, body.as_ref())
    }

    pub(crate) async fn empty(response: Response<Incoming>) -> Result<()> {
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ClientError::Transport(error.into()))?
            .to_bytes();
        Self::decode_empty(status, &body)
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

#[cfg(test)]
mod tests {
    use super::*;

    const DELIVERY_UNKNOWN: &[u8] =
        br#"{"code":"delivery_unknown","message":"The write may have succeeded"}"#;

    #[test]
    fn accepted_delivery_unknown_is_an_api_error_for_json_and_empty_responses() {
        let json_error =
            BridgeClient::decode_json::<serde_json::Value>(StatusCode::ACCEPTED, DELIVERY_UNKNOWN)
                .unwrap_err();
        let empty_error =
            BridgeClient::decode_empty(StatusCode::ACCEPTED, DELIVERY_UNKNOWN).unwrap_err();

        for error in [&json_error, &empty_error] {
            assert!(error.is_delivery_unknown());
            assert!(matches!(
                error,
                ClientError::Api {
                    status: StatusCode::ACCEPTED,
                    code,
                    message,
                } if code == "delivery_unknown" && message == "The write may have succeeded"
            ));
        }
    }

    #[test]
    fn explicit_webex_rejection_is_not_delivery_unknown() {
        let error = BridgeClient::decode_json::<serde_json::Value>(
            StatusCode::BAD_GATEWAY,
            br#"{"code":"webex_rejected","message":"Webex rejected the message"}"#,
        )
        .unwrap_err();
        assert!(error.is_definitely_rejected());
        assert!(!error.is_delivery_unknown());
    }

    #[test]
    fn only_the_explicit_accepted_delivery_unknown_response_is_special() {
        let error = BridgeClient::decode_json::<serde_json::Value>(
            StatusCode::BAD_GATEWAY,
            DELIVERY_UNKNOWN,
        )
        .unwrap_err();
        assert!(!error.is_delivery_unknown());
    }

    #[test]
    fn identity_not_ready_is_an_explicit_partial_ready_error() {
        let error = BridgeClient::decode_json::<serde_json::Value>(
            StatusCode::CONFLICT,
            br#"{"code":"identity_not_ready","message":"Account identity has not yet been mirrored"}"#,
        )
        .unwrap_err();
        assert!(error.is_identity_not_ready());
    }
}
