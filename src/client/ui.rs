//! Typed UI-scope calls for the daemon's local API.

use super::{events::EventStream, path_segment, BridgeClient, Result};
use hyper::Method;
use serde::{Deserialize, Serialize};

/// Metadata-only daemon health response, available before UI pairing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub api_version: u32,
    pub connection: String,
    pub sync: SyncStatus,
}

/// Mirror progress included in [`Status`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub rooms: i64,
    pub revisions: i64,
    pub initial_done: i64,
    pub initial_pending: i64,
    pub gaps: i64,
    pub failures: i64,
}

/// Full room metadata available to a paired UI only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Room {
    pub id: String,
    pub title: Option<String>,
    pub room_type: String,
    pub team_id: Option<String>,
    pub last_activity: Option<String>,
    pub is_member: bool,
}

/// Full person metadata available to a paired UI only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    pub id: String,
    pub display_name: Option<String>,
    pub emails: Option<Vec<String>>,
}

/// Canonical message or deletion tombstone available to a paired UI only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: String,
    pub room_id: String,
    pub revision: i64,
    pub parent_id: Option<String>,
    pub sender_id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub status: String,
    pub markdown: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoomsResponse {
    rooms: Vec<Room>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessagesResponse {
    messages: Vec<Message>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairRequest<'a> {
    secret_hash: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionRequest<'a> {
    secret: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    token: String,
    lease_ttl: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateMessageRequest<'a> {
    room_id: &'a str,
    parent_id: Option<&'a str>,
    markdown: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EditMessageRequest<'a> {
    room_id: &'a str,
    markdown: &'a str,
}

impl BridgeClient {
    /// Read metadata-only bridge health without creating a UI session.
    pub async fn status(&self) -> Result<Status> {
        let response = self.request(Method::GET, "/v1/status", None, None).await?;
        Self::json(response).await
    }

    /// Ask the daemon to pair a freshly generated UI-secret hash. The daemon
    /// resolves this process from the kernel peer credentials and asks the
    /// user for native approval before accepting the hash.
    pub async fn pair_ui(&self, secret_hash: &str) -> Result<()> {
        let body = Self::json_body(&PairRequest { secret_hash })?;
        let response = self
            .request(Method::POST, "/v1/ui/pair", None, Some(body))
            .await?;
        Self::empty(response).await
    }

    /// Exchange a paired UI secret for a short-lived process-bound session.
    pub async fn create_ui_session(&self, secret: &str) -> Result<UiClient> {
        let body = Self::json_body(&SessionRequest { secret })?;
        let response = self
            .request(Method::POST, "/v1/ui/sessions", None, Some(body))
            .await?;
        let session: SessionResponse = Self::json(response).await?;
        Ok(UiClient {
            bridge: self.clone(),
            token: session.token,
            lease_ttl: session.lease_ttl,
        })
    }
}

/// Paired, process-bound full-mirror client.
///
/// The bearer token is intentionally private: callers use typed methods and
/// cannot accidentally interpolate it into URLs or logs.
#[derive(Clone)]
pub struct UiClient {
    bridge: BridgeClient,
    token: String,
    lease_ttl: u64,
}

impl UiClient {
    /// Server-issued lease duration in seconds. UI hosts recreate the session
    /// when this lease is near expiry.
    #[must_use]
    pub const fn lease_ttl(&self) -> u64 {
        self.lease_ttl
    }

    /// Resolve the daemon account and store it in the encrypted mirror.
    pub async fn me(&self) -> Result<Person> {
        let response = self
            .bridge
            .request(Method::GET, "/v1/me", Some(&self.token), None)
            .await?;
        BridgeClient::json(response).await
    }

    /// List rooms from the local encrypted mirror.
    pub async fn rooms(&self) -> Result<Vec<Room>> {
        let response = self
            .bridge
            .request(Method::GET, "/v1/rooms", Some(&self.token), None)
            .await?;
        Ok(BridgeClient::json::<RoomsResponse>(response).await?.rooms)
    }

    /// Read one mirrored room.
    pub async fn room(&self, room_id: &str) -> Result<Room> {
        let response = self
            .bridge
            .request(
                Method::GET,
                &format!("/v1/rooms/{}", path_segment(room_id)),
                Some(&self.token),
                None,
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Leave a non-direct room. The daemon enforces its development write
    /// allowlist before issuing the Webex operation.
    pub async fn leave_room(&self, room_id: &str) -> Result<()> {
        let response = self
            .bridge
            .request(
                Method::DELETE,
                &format!("/v1/rooms/{}/membership", path_segment(room_id)),
                Some(&self.token),
                None,
            )
            .await?;
        BridgeClient::empty(response).await
    }

    /// Read one reverse-chronological local page. When the daemon is online,
    /// it may hydrate one older page before returning this result.
    pub async fn room_messages(
        &self,
        room_id: &str,
        before: Option<&str>,
        max: Option<u32>,
    ) -> Result<Vec<Message>> {
        let mut path = format!("/v1/rooms/{}/messages", path_segment(room_id));
        let mut query = Vec::new();
        if let Some(before) = before {
            query.push(format!("before={}", path_segment(before)));
        }
        if let Some(max) = max {
            query.push(format!("max={max}"));
        }
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query.join("&"));
        }
        let response = self
            .bridge
            .request(Method::GET, &path, Some(&self.token), None)
            .await?;
        Ok(BridgeClient::json::<MessagesResponse>(response)
            .await?
            .messages)
    }

    /// Read one canonical message or deletion tombstone.
    pub async fn message(&self, message_id: &str) -> Result<Message> {
        let response = self
            .bridge
            .request(
                Method::GET,
                &format!("/v1/messages/{}", path_segment(message_id)),
                Some(&self.token),
                None,
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Read one mirrored person.
    pub async fn person(&self, person_id: &str) -> Result<Person> {
        let response = self
            .bridge
            .request(
                Method::GET,
                &format!("/v1/people/{}", path_segment(person_id)),
                Some(&self.token),
                None,
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Create a direct UI message after daemon-side room and parent checks.
    pub async fn create_message(
        &self,
        room_id: &str,
        parent_id: Option<&str>,
        markdown: &str,
    ) -> Result<Message> {
        let body = BridgeClient::json_body(&CreateMessageRequest {
            room_id,
            parent_id,
            markdown,
        })?;
        let response = self
            .bridge
            .request(Method::POST, "/v1/messages", Some(&self.token), Some(body))
            .await?;
        BridgeClient::json(response).await
    }

    /// Edit an active direct UI message after daemon-side mirror validation.
    pub async fn edit_message(
        &self,
        message_id: &str,
        room_id: &str,
        markdown: &str,
    ) -> Result<Message> {
        let body = BridgeClient::json_body(&EditMessageRequest { room_id, markdown })?;
        let response = self
            .bridge
            .request(
                Method::PUT,
                &format!("/v1/messages/{}", path_segment(message_id)),
                Some(&self.token),
                Some(body),
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Delete an active direct UI message after daemon-side allowlist checks.
    pub async fn delete_message(&self, message_id: &str) -> Result<()> {
        let response = self
            .bridge
            .request(
                Method::DELETE,
                &format!("/v1/messages/{}", path_segment(message_id)),
                Some(&self.token),
                None,
            )
            .await?;
        BridgeClient::empty(response).await
    }

    /// Open the metadata-only, UI-filtered bridge event stream.
    pub async fn events(&self) -> Result<EventStream> {
        EventStream::connect(self.bridge.clone(), &self.token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{self, events::EventBus, ApiState, ConnectionStatus},
        mirror::{Mirror, SharedMirror},
        paths::Paths,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    #[test]
    fn path_segments_do_not_interpret_remote_ids_as_paths_or_queries() {
        assert_eq!(path_segment("room/id?x=1"), "room%2Fid%3Fx%3D1");
    }

    async fn paired_server() -> (tempfile::TempDir, api::ApiServer, BridgeClient, EventBus) {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([42_u8; 32]).unwrap());
        let secret = "a-local-ui-secret-that-is-long-enough";
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        mirror
            .with(|db| db.pair_ui_client(&hash, "/test/webex-tui"))
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror, connection_rx);
        let events = state.events();
        let server = api::start(&paths, state).await.unwrap();
        (temp, server, BridgeClient::new(paths.socket), events)
    }

    #[tokio::test]
    async fn typed_client_uses_the_protected_uds_api_and_parses_events() {
        let (_temp, server, bridge, events) = paired_server().await;
        assert_eq!(bridge.status().await.unwrap().api_version, 1);

        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        assert_eq!(ui.rooms().await.unwrap(), Vec::<Room>::new());

        let mut stream = ui.events().await.unwrap();
        events.publish_ui(
            "connection.status",
            serde_json::json!({"connection":"connected"}),
        );
        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            crate::client::events::BridgeEvent {
                name: "connection.status".into(),
                data: serde_json::json!({"connection":"connected"}),
            }
        );
        drop(stream);
        server.shutdown().await.unwrap();
    }
}
