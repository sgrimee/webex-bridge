//! Typed UI-scope calls for the daemon's local API.

use super::{events::EventStream, path_segment, BridgeClient, Result};
use hyper::Method;
use serde::{Deserialize, Serialize};

pub use crate::dto::{
    Continuity, Message, MessageBody, MessageBodyInput, MessagePage, MessageRead, Person,
    PersonRead, Room, Status, SyncStatus, Team, ThreadChildren, ThreadParent,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoomsResponse {
    rooms: Vec<Room>,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenewResponse {
    lease_ttl: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateMessageRequest<'a> {
    room_id: &'a str,
    parent_id: Option<&'a str>,
    markdown: Option<&'a str>,
    body: Option<&'a MessageBodyInput>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EditMessageRequest<'a> {
    room_id: &'a str,
    markdown: Option<&'a str>,
    body: Option<&'a MessageBodyInput>,
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
        let session: SessionResponse = Self::secret_json(response).await?;
        Ok(UiClient {
            bridge: self.clone(),
            token: super::secret::SecretToken::new(session.token),
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
    /// Shared by every clone and wiped when the last clone is dropped.
    token: super::secret::SecretToken,
    lease_ttl: u64,
}

impl UiClient {
    /// Lease duration in seconds granted at session creation. UI hosts call
    /// [`Self::renew`] before it elapses, or recreate the session.
    #[must_use]
    pub const fn lease_ttl(&self) -> u64 {
        self.lease_ttl
    }

    /// Extend this session's lease in place and return the seconds until the
    /// new expiry. The token is unchanged, so every clone and any open event
    /// stream stays valid. Only the issuing process can renew. The daemon
    /// refuses with [`ClientError::is_pairing_removed`] (session ended) or
    /// [`ClientError::is_session_cap_reached`] (12 h absolute limit; the token
    /// stays valid until its current expiry) — then create a new session.
    ///
    /// [`ClientError::is_pairing_removed`]: super::ClientError::is_pairing_removed
    /// [`ClientError::is_session_cap_reached`]: super::ClientError::is_session_cap_reached
    pub async fn renew(&self) -> Result<u64> {
        let response = self
            .bridge
            .request(
                Method::POST,
                "/v1/ui/sessions/renew",
                Some(self.token.as_str()),
                None,
            )
            .await?;
        Ok(BridgeClient::json::<RenewResponse>(response)
            .await?
            .lease_ttl)
    }

    /// Log out: the daemon revokes this session's token (and closes its event
    /// streams). Every clone of this client stops working. The pairing stays.
    /// A repeated logout returns `auth_required`.
    pub async fn logout(&self) -> Result<()> {
        let response = self
            .bridge
            .request(
                Method::DELETE,
                "/v1/ui/sessions",
                Some(self.token.as_str()),
                None,
            )
            .await?;
        BridgeClient::empty(response).await
    }

    /// Read the daemon account from the encrypted mirror, refreshing it from
    /// Webex when available. A first-run offline daemon reports
    /// `identity_not_ready` instead of guessing an account from person rows.
    pub async fn me(&self) -> Result<Person> {
        let response = self
            .bridge
            .request(Method::GET, "/v1/me", Some(self.token.as_str()), None)
            .await?;
        BridgeClient::json(response).await
    }

    /// Read the UI-only daemon instance and snapshot boundary. Subscribe to
    /// events first, buffer them, then use this watermark while refreshing the
    /// mirror to avoid subscribe-before-snapshot loss.
    pub async fn continuity(&self) -> Result<Continuity> {
        let response = self
            .bridge
            .request(
                Method::GET,
                "/v1/ui/continuity",
                Some(self.token.as_str()),
                None,
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// List rooms from the local encrypted mirror.
    pub async fn rooms(&self) -> Result<Vec<Room>> {
        let response = self
            .bridge
            .request(Method::GET, "/v1/rooms", Some(self.token.as_str()), None)
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
                Some(self.token.as_str()),
                None,
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Read one team from the encrypted mirror. On a cache miss, the daemon
    /// may make one bounded, daemon-owned Webex lookup. `not_found` is normal
    /// when the account cannot access the team; callers should retain their
    /// room-title fallback.
    pub async fn team(&self, team_id: &str) -> Result<Team> {
        let response = self
            .bridge
            .request(
                Method::GET,
                &format!("/v1/teams/{}", path_segment(team_id)),
                Some(self.token.as_str()),
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
                Some(self.token.as_str()),
                None,
            )
            .await?;
        BridgeClient::empty(response).await
    }

    /// Read one reverse-chronological room-history page with an honest
    /// completeness signal. `next_before` stays opaque to the UI.
    pub async fn room_messages_page(
        &self,
        room_id: &str,
        before: Option<&str>,
        max: Option<u32>,
    ) -> Result<MessagePage> {
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
            .request(Method::GET, &path, Some(self.token.as_str()), None)
            .await?;
        BridgeClient::json(response).await
    }

    /// Compatibility convenience for callers that do not yet consume page
    /// cursors/completeness. New UI projection code should use
    /// [`Self::room_messages_page`].
    pub async fn room_messages(
        &self,
        room_id: &str,
        before: Option<&str>,
        max: Option<u32>,
    ) -> Result<Vec<Message>> {
        Ok(self
            .room_messages_page(room_id, before, max)
            .await?
            .messages)
    }

    /// Resolve one canonical thread parent. A cache miss may hydrate exactly
    /// that parent through the daemon; `missing` and `unavailable` are normal
    /// explicit placeholders rather than reasons to discard mirrored replies.
    pub async fn thread_parent(&self, message_id: &str) -> Result<ThreadParent> {
        let response = self
            .bridge
            .request(
                Method::GET,
                &format!("/v1/messages/{}/thread", path_segment(message_id)),
                Some(self.token.as_str()),
                None,
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Read one bounded reverse-chronological reply page. `next_before` is an
    /// opaque reply cursor; a false `complete` means a short local page does
    /// not prove the thread is exhausted.
    pub async fn thread_children(
        &self,
        parent_id: &str,
        before: Option<&str>,
        max: Option<u32>,
    ) -> Result<ThreadChildren> {
        let mut path = format!("/v1/messages/{}/children", path_segment(parent_id));
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
            .request(Method::GET, &path, Some(self.token.as_str()), None)
            .await?;
        BridgeClient::json(response).await
    }

    /// Read one message with bounded daemon-side cache-miss hydration. The
    /// result explicitly distinguishes mirrored/hydrated content, tombstones,
    /// confirmed misses, offline, and temporary remote unavailability.
    pub async fn message_read(&self, message_id: &str) -> Result<MessageRead> {
        let response = self
            .bridge
            .request(
                Method::GET,
                &format!("/v1/messages/{}/read", path_segment(message_id)),
                Some(self.token.as_str()),
                None,
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Read one canonical message or deletion tombstone.
    pub async fn message(&self, message_id: &str) -> Result<Message> {
        let response = self
            .bridge
            .request(
                Method::GET,
                &format!("/v1/messages/{}", path_segment(message_id)),
                Some(self.token.as_str()),
                None,
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Read one person with bounded daemon-side cache-miss hydration. Offline
    /// and remote failures return a typed placeholder so callers can keep an
    /// ID/unknown-name view and allow an explicit retry.
    pub async fn person_read(&self, person_id: &str) -> Result<PersonRead> {
        let response = self
            .bridge
            .request(
                Method::GET,
                &format!("/v1/people/{}/read", path_segment(person_id)),
                Some(self.token.as_str()),
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
                Some(self.token.as_str()),
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
            markdown: Some(markdown),
            body: None,
        })?;
        let response = self
            .bridge
            .request(
                Method::POST,
                "/v1/messages",
                Some(self.token.as_str()),
                Some(body),
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Create a direct UI message with explicit plain-text or Markdown kind.
    /// `legacyUnknown` is rejected by the daemon because it is read provenance,
    /// not a Webex write format.
    pub async fn create_message_body(
        &self,
        room_id: &str,
        parent_id: Option<&str>,
        body: &MessageBodyInput,
    ) -> Result<Message> {
        let body = BridgeClient::json_body(&CreateMessageRequest {
            room_id,
            parent_id,
            markdown: None,
            body: Some(body),
        })?;
        let response = self
            .bridge
            .request(
                Method::POST,
                "/v1/messages",
                Some(self.token.as_str()),
                Some(body),
            )
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
        let body = BridgeClient::json_body(&EditMessageRequest {
            room_id,
            markdown: Some(markdown),
            body: None,
        })?;
        let response = self
            .bridge
            .request(
                Method::PUT,
                &format!("/v1/messages/{}", path_segment(message_id)),
                Some(self.token.as_str()),
                Some(body),
            )
            .await?;
        BridgeClient::json(response).await
    }

    /// Edit one direct UI message with explicit plain-text or Markdown kind.
    pub async fn edit_message_body(
        &self,
        message_id: &str,
        room_id: &str,
        body: &MessageBodyInput,
    ) -> Result<Message> {
        let body = BridgeClient::json_body(&EditMessageRequest {
            room_id,
            markdown: None,
            body: Some(body),
        })?;
        let response = self
            .bridge
            .request(
                Method::PUT,
                &format!("/v1/messages/{}", path_segment(message_id)),
                Some(self.token.as_str()),
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
                Some(self.token.as_str()),
                None,
            )
            .await?;
        BridgeClient::empty(response).await
    }

    /// Open the metadata-only, UI-filtered bridge event stream.
    pub async fn events(&self) -> Result<EventStream> {
        EventStream::connect(self.bridge.clone(), self.token.as_str()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_body_payload_preserves_plain_text_provenance() {
        let body = MessageBodyInput {
            kind: "plainText".into(),
            content: "plain UI text".into(),
        };
        let encoded = BridgeClient::json_body(&CreateMessageRequest {
            room_id: "room-1",
            parent_id: None,
            markdown: None,
            body: Some(&body),
        })
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
            serde_json::json!({
                "roomId": "room-1",
                "parentId": null,
                "markdown": null,
                "body": {"kind": "plainText", "content": "plain UI text"}
            })
        );
    }

    #[test]
    fn path_segments_do_not_interpret_remote_ids_as_paths_or_queries() {
        assert_eq!(path_segment("room/id?x=1"), "room%2Fid%3Fx%3D1");
    }
}

#[cfg(all(test, feature = "server"))]
mod server_tests {
    use super::*;
    use crate::{
        api::{self, events::EventBus, ApiState, ConnectionStatus},
        mirror::{Mirror, SharedMirror},
        paths::Paths,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    use std::{sync::Arc, time::Duration};
    use tokio::sync::watch;
    use tokio_stream::StreamExt;
    use wiremock::{
        matchers::{body_json, method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    async fn paired_server() -> (tempfile::TempDir, api::ApiServer, BridgeClient, EventBus) {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([42_u8; 32]).unwrap());
        let secret = "a-local-ui-secret-that-is-long-enough";
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        mirror
            .with(|db| {
                db.pair_ui_client(&hash, "/test/webex-tui")?;
                db.upsert_team(&webex::Team {
                    id: "team-1".into(),
                    name: Some("Project team".into()),
                    created: "2026-10-08T12:00:00Z".into(),
                    description: None,
                })
            })
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror, connection_rx);
        let events = state.events();
        let server = api::start(&paths, state).await.unwrap();
        (temp, server, BridgeClient::new(paths.socket), events)
    }

    async fn hydrated_rest_server(
        rest: Arc<crate::sync::history::WebexRest>,
    ) -> (tempfile::TempDir, api::ApiServer, BridgeClient) {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([45_u8; 32]).unwrap());
        let secret = "a-local-ui-secret-that-is-long-enough";
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        mirror
            .with(|db| db.pair_ui_client(&hash, "/test/webex-tui"))
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let (_rest_tx, rest_rx) = watch::channel(Some(rest));
        let state = ApiState::with_config_and_rest(
            mirror,
            connection_rx,
            Arc::new(crate::config::Config::default()),
            rest_rx,
        );
        let server = api::start(&paths, state).await.unwrap();
        (temp, server, BridgeClient::new(paths.socket))
    }

    async fn writable_rest_server(
        rest: Arc<crate::sync::history::WebexRest>,
        room_id: &str,
    ) -> (tempfile::TempDir, api::ApiServer, BridgeClient) {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([47_u8; 32]).unwrap());
        let secret = "a-local-ui-secret-that-is-long-enough";
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        mirror
            .with(|db| {
                db.pair_ui_client(&hash, "/test/webex-tui")?;
                db.upsert_room(
                    &webex::Room {
                        id: room_id.into(),
                        title: Some("Writable room".into()),
                        room_type: "group".into(),
                        is_locked: false,
                        team_id: None,
                        last_activity: "2026-10-08T12:00:00Z".into(),
                        creator_id: "person-1".into(),
                        created: "2026-10-08T12:00:00Z".into(),
                    },
                    true,
                )?;
                db.upsert_message(&webex::Message {
                    id: Some("Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDA0".into()),
                    room_id: Some(room_id.into()),
                    created: Some("2026-10-08T12:00:00Z".into()),
                    text: Some("seed message".into()),
                    ..webex::Message::default()
                })
            })
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let (_rest_tx, rest_rx) = watch::channel(Some(rest));
        let mut config = crate::config::Config::default();
        config.dev.as_mut().unwrap().write_allowlist = vec![room_id.into()];
        let state =
            ApiState::with_config_and_rest(mirror, connection_rx, Arc::new(config), rest_rx);
        let server = api::start(&paths, state).await.unwrap();
        (temp, server, BridgeClient::new(paths.socket))
    }

    async fn offline_thread_server() -> (tempfile::TempDir, api::ApiServer, BridgeClient) {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([46_u8; 32]).unwrap());
        let secret = "a-local-ui-secret-that-is-long-enough";
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        mirror
            .with(|db| {
                db.pair_ui_client(&hash, "/test/webex-tui")?;
                db.upsert_message(&webex::Message {
                    id: Some("deleted-parent".into()),
                    room_id: Some("room-1".into()),
                    created: Some("2026-10-08T12:00:00Z".into()),
                    text: Some("private deleted parent".into()),
                    ..webex::Message::default()
                })?;
                db.mark_deleted("room-1", "deleted-parent")?;
                db.cache_ui_not_found("person", "confirmed-missing-person")?;
                db.cache_ui_not_found("message", "confirmed-missing-message")?;
                for (id, parent_id, created) in [
                    ("orphan-reply", "missing-parent", "2026-10-08T12:01:00Z"),
                    (
                        "deleted-parent-reply",
                        "deleted-parent",
                        "2026-10-08T12:02:00Z",
                    ),
                ] {
                    let mut message = webex::Message {
                        id: Some(id.into()),
                        room_id: Some("room-1".into()),
                        parent_id: Some(parent_id.into()),
                        created: Some(created.into()),
                        text: Some("private reply".into()),
                        ..webex::Message::default()
                    };
                    if id == "orphan-reply" {
                        message.files = Some(vec!["https://files.example.test/private.pdf".into()]);
                    }
                    db.upsert_message(&message)?;
                }
                Ok(())
            })
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Disconnected);
        let server = api::start(&paths, ApiState::new(mirror, connection_rx))
            .await
            .unwrap();
        (temp, server, BridgeClient::new(paths.socket))
    }

    async fn cached_identity_server() -> (tempfile::TempDir, api::ApiServer, BridgeClient) {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([44_u8; 32]).unwrap());
        let secret = "a-local-ui-secret-that-is-long-enough";
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        mirror
            .with(|db| {
                db.cache_account_identity(&webex::Person {
                    id: "account-person".into(),
                    display_name: "Account Owner".into(),
                    emails: vec!["owner@example.test".into()],
                    ..webex::Person::default()
                })?;
                db.pair_ui_client(&hash, "/test/webex-tui")
            })
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Disconnected);
        let server = api::start(&paths, ApiState::new(mirror, connection_rx))
            .await
            .unwrap();
        (temp, server, BridgeClient::new(paths.socket))
    }

    async fn agent_server() -> (
        tempfile::TempDir,
        api::ApiServer,
        BridgeClient,
        String,
        EventBus,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([43_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror, connection_rx);
        let token = state
            .sessions()
            .issue_agent(
                crate::api::auth::PeerIdentity {
                    uid: crate::api::auth::daemon_uid(),
                    pid: Some(std::process::id()),
                },
                "test-agent".into(),
                vec!["route-a".into()],
                Duration::from_secs(60),
            )
            .unwrap();
        let events = state.events();
        let server = api::start(&paths, state).await.unwrap();
        (temp, server, BridgeClient::new(paths.socket), token, events)
    }

    async fn expiring_ui_server() -> (
        tempfile::TempDir,
        api::ApiServer,
        BridgeClient,
        String,
        EventBus,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([48_u8; 32]).unwrap());
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror, connection_rx);
        let token = state.sessions().issue(
            crate::api::auth::Scope::Ui,
            crate::api::auth::PeerIdentity {
                uid: crate::api::auth::daemon_uid(),
                pid: Some(std::process::id()),
            },
            Duration::from_millis(100),
        );
        let events = state.events();
        let server = api::start(&paths, state).await.unwrap();
        (temp, server, BridgeClient::new(paths.socket), token, events)
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
        assert_eq!(
            ui.team("team-1").await.unwrap(),
            Team {
                id: "team-1".into(),
                name: Some("Project team".into()),
            }
        );

        let mut stream = ui.events().await.unwrap();
        let ready = stream.next().await.unwrap().unwrap();
        assert_eq!(ready.name, crate::client::events::CONTINUITY_READY_EVENT);
        let ready_continuity = ready.continuity().unwrap();
        let snapshot = ui.continuity().await.unwrap();
        assert_eq!(snapshot.instance_id, ready_continuity.instance_id);
        assert!(snapshot.watermark >= ready_continuity.watermark);
        events.publish_ui(
            "connection.status",
            serde_json::json!({"connection":"connected"}),
        );
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.name, "connection.status");
        assert_eq!(event.data["connection"], "connected");
        assert_eq!(
            event.continuity().unwrap().instance_id,
            snapshot.instance_id
        );
        assert!(event.continuity().unwrap().watermark > snapshot.watermark);
        drop(stream);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn typed_ui_create_payload_preserves_plain_text_body_kind() {
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let remote = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(body_json(serde_json::json!({
                "roomId": room_id,
                "text": "plain UI text"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": message_id,
                "roomId": room_id,
                "created": "2026-10-08T12:00:00Z",
                "text": "plain UI text"
            })))
            .expect(1)
            .mount(&remote)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", remote.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = writable_rest_server(rest, room_id).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        let sent = ui
            .create_message_body(
                room_id,
                None,
                &MessageBodyInput {
                    kind: "plainText".into(),
                    content: "plain UI text".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(sent.body.as_ref().unwrap().kind, "plainText");
        assert_eq!(sent.attachment_count, 0);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_writes_never_confirm_post_dispatch_ambiguity() {
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDA0";
        let person_id =
            "Y2lzY29zcGFyazovL3VzL1BFT1BMRS8wMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMGIwMDE";
        let membership_id =
            "Y2lzY29zcGFyazovL3VzL01FTUJFUlNISVAvODc2NTQzMjEtNDMyMS00MzIxLTQzMjEtMjEwOTg3NjU0MzIx";
        let remote = MockServer::start().await;
        for (method_name, path_value) in [
            ("POST", "/v1/messages".to_owned()),
            ("PUT", format!("/v1/messages/{message_id}")),
            ("DELETE", format!("/v1/messages/{message_id}")),
            ("DELETE", format!("/v1/memberships/{membership_id}")),
        ] {
            Mock::given(method(method_name))
                .and(path(path_value))
                .respond_with(ResponseTemplate::new(500))
                .expect(1)
                .mount(&remote)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/v1/people/me"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": person_id})),
            )
            .expect(1)
            .mount(&remote)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/memberships"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"items": [{
                    "id": membership_id,
                    "roomId": room_id,
                    "personId": person_id,
                    "isModerator": false,
                    "isMonitor": false,
                    "created": "2026-10-08T12:00:00Z"
                }]})),
            )
            .expect(1)
            .mount(&remote)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", remote.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = writable_rest_server(rest, room_id).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        let body = MessageBodyInput {
            kind: "plainText".into(),
            content: "write once".into(),
        };
        for error in [
            ui.create_message_body(room_id, None, &body)
                .await
                .unwrap_err(),
            ui.edit_message_body(message_id, room_id, &body)
                .await
                .unwrap_err(),
            ui.delete_message(message_id).await.unwrap_err(),
            ui.leave_room(room_id).await.unwrap_err(),
        ] {
            assert!(error.is_delivery_unknown());
            assert!(!error.is_definitely_rejected());
        }
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn point_reads_hydrate_once_then_serve_the_encrypted_mirror() {
        let person_id =
            "Y2lzY29zcGFyazovL3VzL1BFT1BMRS8wMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMGIwMDE";
        let message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let remote = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/people/{person_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": person_id,
                "displayName": "Hydrated person",
                "emails": ["person@example.test"]
            })))
            .expect(1)
            .mount(&remote)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{message_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": message_id,
                "roomId": room_id,
                "created": "2026-10-08T12:00:00Z",
                "text": "private hydrated message"
            })))
            .expect(1)
            .mount(&remote)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", remote.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = hydrated_rest_server(rest).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        let person = ui.person_read(person_id).await.unwrap();
        assert_eq!(person.state, "hydrated");
        assert_eq!(
            person.person.unwrap().display_name.as_deref(),
            Some("Hydrated person")
        );
        let message = ui.message_read(message_id).await.unwrap();
        assert_eq!(message.state, "hydrated");
        assert_eq!(message.message.unwrap().room_id, room_id);
        assert_eq!(ui.person_read(person_id).await.unwrap().state, "mirrored");
        assert_eq!(ui.message_read(message_id).await.unwrap().state, "mirrored");
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn point_reads_keep_confirmed_not_found_distinct_from_unavailable() {
        let person_id =
            "Y2lzY29zcGFyazovL3VzL1BFT1BMRS8wMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMGIwMDE";
        let message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let unavailable_message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDA0";
        let remote = MockServer::start().await;
        for path_value in [
            format!("/v1/people/{person_id}"),
            format!("/v1/messages/{message_id}"),
        ] {
            Mock::given(method("GET"))
                .and(path(path_value))
                .respond_with(ResponseTemplate::new(404))
                .expect(1)
                .mount(&remote)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{unavailable_message_id}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&remote)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", remote.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = hydrated_rest_server(rest).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        assert_eq!(ui.person_read(person_id).await.unwrap().state, "not_found");
        assert_eq!(
            ui.message_read(message_id).await.unwrap().state,
            "not_found"
        );
        assert_eq!(
            ui.message_read(unavailable_message_id).await.unwrap().state,
            "unavailable"
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn thread_parent_and_children_hydrate_once_with_explicit_page_state() {
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let parent_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let child_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDA0";
        let remote = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{parent_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": parent_id,
                "roomId": room_id,
                "created": "2026-10-08T12:00:00Z",
                "text": "private parent"
            })))
            .expect(1)
            .mount(&remote)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .and(query_param("roomId", room_id))
            .and(query_param("parentId", parent_id))
            .and(query_param("max", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{
                    "id": child_id,
                    "roomId": room_id,
                    "parentId": parent_id,
                    "created": "2026-10-08T12:01:00Z",
                    "text": "private child"
                }]
            })))
            .expect(1)
            .mount(&remote)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", remote.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = hydrated_rest_server(rest).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        let parent = ui.thread_parent(parent_id).await.unwrap();
        assert_eq!(parent.state, "active");
        assert_eq!(parent.message.as_ref().unwrap().room_id, room_id);
        let page = ui.thread_children(parent_id, None, Some(2)).await.unwrap();
        assert_eq!(page.parent.state, "active");
        assert_eq!(
            page.parent.message.as_ref().unwrap().room_id,
            room_id,
            "the parent retains canonical room ownership"
        );
        assert_eq!(page.children[0].id, child_id);
        assert_eq!(page.children[0].room_id, room_id);
        assert!(page.complete);
        assert_eq!(page.next_before, None);
        assert_eq!(page.partial_reason, None);
        // The second point read is mirror-backed; the REST parent fixture permits one call.
        assert_eq!(ui.thread_parent(parent_id).await.unwrap().state, "active");
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn thread_parent_reports_a_remote_missing_placeholder() {
        let parent_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let remote = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{parent_id}")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&remote)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", remote.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = hydrated_rest_server(rest).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        assert_eq!(
            ui.thread_parent(parent_id).await.unwrap(),
            ThreadParent {
                id: parent_id.into(),
                state: "missing".into(),
                message: None,
            }
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn offline_missing_parent_remains_a_placeholder_without_hiding_replies() {
        let (_temp, server, bridge) = offline_thread_server().await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        let page = ui
            .thread_children("missing-parent", None, Some(10))
            .await
            .unwrap();
        assert_eq!(page.parent.state, "unavailable");
        assert!(page.parent.message.is_none());
        assert_eq!(page.children.len(), 1);
        assert_eq!(page.children[0].id, "orphan-reply");
        assert!(!page.complete);
        assert_eq!(page.partial_reason.as_deref(), Some("parent_unavailable"));
        let history = ui
            .room_messages_page("room-1", None, Some(10))
            .await
            .unwrap();
        assert_eq!(
            history
                .messages
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            ["deleted-parent-reply", "orphan-reply"]
        );
        assert!(!history.complete);
        assert_eq!(history.partial_reason.as_deref(), Some("offline"));
        assert_eq!(history.next_before.as_deref(), Some("orphan-reply"));
        let orphan = history
            .messages
            .iter()
            .find(|message| message.id == "orphan-reply")
            .unwrap();
        assert_eq!(orphan.body.as_ref().unwrap().kind, "plainText");
        assert_eq!(orphan.attachment_count, 1);
        let deleted = ui
            .thread_children("deleted-parent", None, Some(10))
            .await
            .unwrap();
        assert_eq!(deleted.parent.state, "deleted");
        assert_eq!(deleted.children[0].id, "deleted-parent-reply");
        assert!(!deleted.complete);
        assert_eq!(deleted.partial_reason.as_deref(), Some("offline"));
        assert_eq!(
            ui.message_read("deleted-parent").await.unwrap().state,
            "deleted"
        );
        assert_eq!(
            ui.message_read("confirmed-missing-message")
                .await
                .unwrap()
                .state,
            "not_found"
        );
        assert_eq!(
            ui.message_read("unseen-message").await.unwrap().state,
            "offline"
        );
        assert_eq!(
            ui.person_read("confirmed-missing-person")
                .await
                .unwrap()
                .state,
            "not_found"
        );
        assert_eq!(
            ui.person_read("unseen-person").await.unwrap().state,
            "offline"
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn team_cache_miss_hydrates_once_and_inaccessible_team_is_a_fallback() {
        let team_id =
            "Y2lzY29zcGFyazovL3VzL1RFQU0vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDEx";
        let remote = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/teams/{team_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": team_id,
                "name": "Hydrated team",
                "created": "2026-10-08T12:00:00Z"
            })))
            .expect(1)
            .mount(&remote)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", remote.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = hydrated_rest_server(rest).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        assert_eq!(
            ui.team(team_id).await.unwrap(),
            Team {
                id: team_id.into(),
                name: Some("Hydrated team".into()),
            }
        );
        // The second read is mirror-backed; the daemon does not repeat the REST lookup.
        assert_eq!(
            ui.team(team_id).await.unwrap().name.as_deref(),
            Some("Hydrated team")
        );
        server.shutdown().await.unwrap();

        let inaccessible = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/teams/{team_id}")))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&inaccessible)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", inaccessible.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = hydrated_rest_server(rest).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        // Asked twice (a UI re-asks after every snapshot): one REST call, the
        // second answer comes from the negative cache.
        for _ in 0..2 {
            let error = ui.team(team_id).await.unwrap_err();
            assert!(matches!(
                error,
                crate::client::ClientError::Api {
                    status: hyper::StatusCode::NOT_FOUND,
                    code,
                    ..
                } if code == "not_found"
            ));
        }
        server.shutdown().await.unwrap();

        // A failed lookup is remembered briefly too, with the same answer.
        let failing = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/teams/{team_id}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&failing)
            .await;
        let rest = Arc::new(
            crate::sync::history::WebexRest::for_tests(
                reqwest::Url::parse(&format!("{}/v1/", failing.uri())).unwrap(),
            )
            .unwrap(),
        );
        let (_temp, server, bridge) = hydrated_rest_server(rest).await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        for _ in 0..2 {
            let error = ui.team(team_id).await.unwrap_err();
            assert!(matches!(
                error,
                crate::client::ClientError::Api {
                    status: hyper::StatusCode::BAD_GATEWAY,
                    code,
                    ..
                } if code == "webex_unavailable"
            ));
        }
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn offline_daemon_serves_the_cached_account_identity() {
        let (_temp, server, bridge) = cached_identity_server().await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        assert_eq!(
            ui.me().await.unwrap(),
            Person {
                id: "account-person".into(),
                display_name: Some("Account Owner".into()),
                emails: Some(vec!["owner@example.test".into()]),
            }
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn first_run_offline_identity_is_explicitly_not_ready() {
        let (_temp, server, bridge, _events) = paired_server().await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        let error = ui.me().await.unwrap_err();
        assert!(error.is_identity_not_ready());
        assert!(matches!(
            error,
            crate::client::ClientError::Api {
                status: hyper::StatusCode::CONFLICT,
                code,
                ..
            } if code == "identity_not_ready"
        ));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn agent_scope_cannot_reach_ui_thread_reads_or_hydration() {
        let (_temp, server, bridge, token, _events) = agent_server().await;
        for path in [
            "/v1/me",
            "/v1/ui/continuity",
            "/v1/teams/team-1",
            "/v1/messages/missing-parent",
            "/v1/messages/missing-parent/thread",
            "/v1/messages/missing-parent/children",
            "/v1/messages/missing-parent/read",
            "/v1/people/missing-person/read",
        ] {
            let response = bridge
                .request(Method::GET, path, Some(&token), None)
                .await
                .unwrap();
            let error = BridgeClient::json::<serde_json::Value>(response)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                crate::client::ClientError::Api {
                    status: hyper::StatusCode::FORBIDDEN,
                    code,
                    ..
                } if code == "forbidden_scope"
            ));
        }
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn expired_ui_event_session_gets_terminal_event_then_closes() {
        let (_temp, server, bridge, token, _events) = expiring_ui_server().await;
        let mut stream = crate::client::events::EventStream::connect(bridge, &token)
            .await
            .unwrap();
        let ready = stream.next().await.unwrap().unwrap();
        assert_eq!(ready.name, crate::client::events::CONTINUITY_READY_EVENT);
        tokio::time::sleep(Duration::from_millis(120)).await;
        // No daemon event is published here: a quiet SSE must still expire.
        let expired = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("quiet expiry should wake the stream")
            .unwrap()
            .unwrap();
        assert!(expired.is_session_expired());
        assert!(tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("expired stream should close")
            .is_none());
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn broadcast_lag_requires_a_metadata_only_ui_resync() {
        let (_temp, server, bridge, events) = paired_server().await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        let mut stream = ui.events().await.unwrap();
        let _ready = stream.next().await.unwrap().unwrap();

        // Do not poll the subscription while overflowing the daemon's bounded
        // fanout. The next item must make loss explicit, not silently skip it.
        for sequence in 0..300 {
            events.publish_ui("message.updated", serde_json::json!({"sequence": sequence}));
        }
        let event = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("lag signal should arrive")
            .expect("stream should stay open")
            .expect("lag signal should parse");
        assert!(event.requires_resync());
        assert_eq!(event.name, crate::client::events::RESYNC_REQUIRED_EVENT);
        assert_eq!(event.data["reason"], "event_lag");
        assert!(event.data["instanceId"].is_string());
        assert!(event.data["watermark"].is_u64());
        assert!(event.continuity().is_some());

        drop(stream);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn broadcast_lag_requires_a_metadata_only_agent_resync() {
        let (_temp, server, bridge, token, events) = agent_server().await;
        let mut stream = crate::client::events::EventStream::connect(bridge, &token)
            .await
            .unwrap();

        for sequence in 0..300 {
            events.publish_agent_route(
                "route-a",
                "inbox.new",
                serde_json::json!({"sequence": sequence}),
            );
        }
        let event = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("lag signal should arrive")
            .expect("stream should stay open")
            .expect("lag signal should parse");
        assert!(event.requires_resync());
        assert_eq!(event.data, serde_json::json!({"reason":"event_lag"}));

        drop(stream);
        server.shutdown().await.unwrap();
    }

    const RENEW_SECRET: &str = "a-local-ui-secret-that-is-long-enough";

    struct RenewableServer {
        _temp: tempfile::TempDir,
        server: api::ApiServer,
        bridge: BridgeClient,
        sessions: crate::api::auth::Sessions,
        mirror: SharedMirror,
        events: EventBus,
        hash: String,
    }

    async fn renewable_server() -> RenewableServer {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let mirror = SharedMirror::new(Mirror::in_memory([49_u8; 32]).unwrap());
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(RENEW_SECRET.as_bytes()));
        let pairing = hash.clone();
        mirror
            .with(move |db| db.pair_ui_client(&pairing, "/test/webex-tui"))
            .await
            .unwrap();
        let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
        let state = ApiState::new(mirror.clone(), connection_rx);
        let sessions = state.sessions();
        let events = state.events();
        let server = api::start(&paths, state).await.unwrap();
        RenewableServer {
            _temp: temp,
            server,
            bridge: BridgeClient::new(paths.socket),
            sessions,
            mirror,
            events,
            hash,
        }
    }

    fn this_process() -> crate::api::auth::PeerIdentity {
        crate::api::auth::PeerIdentity {
            uid: crate::api::auth::daemon_uid(),
            pid: Some(std::process::id()),
        }
    }

    fn api_code(error: &crate::client::ClientError) -> Option<(u16, &str)> {
        match error {
            crate::client::ClientError::Api { status, code, .. } => {
                Some((status.as_u16(), code.as_str()))
            }
            _ => None,
        }
    }

    async fn renew_raw(bridge: &BridgeClient, token: Option<&str>) -> Result<u64> {
        let response = bridge
            .request(Method::POST, "/v1/ui/sessions/renew", token, None)
            .await?;
        Ok(BridgeClient::json::<RenewResponse>(response)
            .await?
            .lease_ttl)
    }

    #[tokio::test]
    async fn ui_renewal_extends_the_same_token_in_place() {
        let env = renewable_server().await;
        let ui = env.bridge.create_ui_session(RENEW_SECRET).await.unwrap();
        let token = ui.token.as_str().to_owned();
        let before = env
            .sessions
            .expires_at(&token, crate::api::auth::Scope::Ui, this_process())
            .unwrap();
        // Shorten the lease so the extension is observable.
        env.sessions.set_ui_lease_for_tests(
            &token,
            std::time::Instant::now() + Duration::from_secs(5),
            before + Duration::from_secs(3600),
        );
        let lease_ttl = ui.renew().await.unwrap();
        assert!((590..=600).contains(&lease_ttl), "{lease_ttl}");
        let after = env
            .sessions
            .expires_at(&token, crate::api::auth::Scope::Ui, this_process())
            .unwrap();
        assert!(after > std::time::Instant::now() + Duration::from_secs(590));
        // Same token (and every clone) keeps working; no new token issued.
        let clone = ui.clone();
        assert_eq!(clone.token.as_str(), token);
        assert_eq!(clone.rooms().await.unwrap(), Vec::<Room>::new());
        env.server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_renewal_requires_the_issuing_process() {
        let env = renewable_server().await;
        let me = this_process();
        let other = env.sessions.issue_ui(
            crate::api::auth::PeerIdentity {
                uid: me.uid,
                pid: me.pid.map(|pid| pid + 1),
            },
            env.hash.clone(),
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        let error = renew_raw(&env.bridge, Some(&other)).await.unwrap_err();
        assert_eq!(api_code(&error), Some((403, "forbidden_peer")));
        // Issued without a kernel PID: never renewable.
        let unknown = env.sessions.issue_ui(
            crate::api::auth::PeerIdentity {
                uid: me.uid,
                pid: None,
            },
            env.hash.clone(),
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        let error = renew_raw(&env.bridge, Some(&unknown)).await.unwrap_err();
        assert_eq!(api_code(&error), Some((403, "forbidden_peer")));
        // A UI token not issued from a paired secret cannot be renewed.
        let plain = env
            .sessions
            .issue(crate::api::auth::Scope::Ui, me, Duration::from_secs(60));
        let error = renew_raw(&env.bridge, Some(&plain)).await.unwrap_err();
        assert_eq!(api_code(&error), Some((403, "forbidden_session")));
        let error = renew_raw(&env.bridge, None).await.unwrap_err();
        assert_eq!(api_code(&error), Some((401, "auth_required")));
        let error = renew_raw(&env.bridge, Some("not-a-session"))
            .await
            .unwrap_err();
        assert_eq!(api_code(&error), Some((401, "auth_required")));
        env.server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_renewal_is_refused_for_agent_bearers() {
        let env = renewable_server().await;
        let agent = env
            .sessions
            .issue_agent(
                this_process(),
                "test-agent".into(),
                vec!["route-a".into()],
                Duration::from_secs(60),
            )
            .unwrap();
        let before = env
            .sessions
            .expires_at(&agent, crate::api::auth::Scope::Agent, this_process())
            .unwrap();
        let error = renew_raw(&env.bridge, Some(&agent)).await.unwrap_err();
        assert_eq!(api_code(&error), Some((403, "forbidden_scope")));
        assert_eq!(
            env.sessions
                .expires_at(&agent, crate::api::auth::Scope::Agent, this_process()),
            Ok(before)
        );
        env.server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_renewal_ends_the_session_when_pairing_was_removed() {
        let env = renewable_server().await;
        let ui = env.bridge.create_ui_session(RENEW_SECRET).await.unwrap();
        let hash = env.hash.clone();
        env.mirror
            .with(move |db| db.unpair_ui_client(&hash))
            .await
            .unwrap();
        let error = ui.renew().await.unwrap_err();
        assert!(error.is_pairing_removed());
        assert_eq!(api_code(&error), Some((401, "pairing_removed")));
        // Revoked immediately, not left to run out its current lease.
        let error = ui.rooms().await.unwrap_err();
        assert_eq!(api_code(&error), Some((401, "auth_required")));
        env.server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_renewal_never_passes_the_absolute_cap() {
        let env = renewable_server().await;
        let ui = env.bridge.create_ui_session(RENEW_SECRET).await.unwrap();
        let token = ui.token.as_str().to_owned();
        let now = std::time::Instant::now();
        env.sessions.set_ui_lease_for_tests(
            &token,
            now + Duration::from_secs(5),
            now + Duration::from_secs(30),
        );
        let lease_ttl = ui.renew().await.unwrap();
        assert!(lease_ttl <= 30, "{lease_ttl}");
        let error = ui.renew().await.unwrap_err();
        assert!(error.is_session_cap_reached());
        assert_eq!(api_code(&error), Some((409, "session_cap_reached")));
        // The capped token stays valid until its current expiry.
        assert_eq!(ui.rooms().await.unwrap(), Vec::<Room>::new());
        env.server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ui_event_stream_follows_a_renewed_lease_then_expires_at_the_cap() {
        let env = renewable_server().await;
        let ui = env.bridge.create_ui_session(RENEW_SECRET).await.unwrap();
        let token = ui.token.as_str().to_owned();
        let mut stream = ui.events().await.unwrap();
        let ready = stream.next().await.unwrap().unwrap();
        assert_eq!(ready.name, crate::client::events::CONTINUITY_READY_EVENT);

        // The stream armed its timer at the original deadline. Shorten it,
        // renew, and check that the old deadline passing does not close it.
        let now = std::time::Instant::now();
        env.sessions.set_ui_lease_for_tests(
            &token,
            now + Duration::from_millis(150),
            now + Duration::from_secs(3600),
        );
        // Wake the stream so its timer is not left at the original deadline:
        // a quiet UI stream must also notice the shorter one.
        let mut short = crate::client::events::EventStream::connect(env.bridge.clone(), &token)
            .await
            .unwrap();
        let _ready = short.next().await.unwrap().unwrap();
        ui.renew().await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        env.events.publish_ui(
            "connection.status",
            serde_json::json!({"connection":"connected"}),
        );
        for active in [&mut stream, &mut short] {
            let event = tokio::time::timeout(Duration::from_secs(1), active.next())
                .await
                .expect("renewed stream should stay open")
                .unwrap()
                .unwrap();
            assert_eq!(event.name, "connection.status");
        }

        // At the cap renewal is refused, and a quiet stream ends there. (A
        // lease only ever grows in production, so a stream armed earlier is
        // re-checked at its own deadline; this one is armed at the cap.)
        let now = std::time::Instant::now();
        let cap = now + Duration::from_millis(150);
        env.sessions.set_ui_lease_for_tests(&token, cap, cap);
        assert!(ui.renew().await.unwrap_err().is_session_cap_reached());
        drop(short);
        let mut short = crate::client::events::EventStream::connect(env.bridge.clone(), &token)
            .await
            .unwrap();
        let _ready = short.next().await.unwrap().unwrap();
        let expired = tokio::time::timeout(Duration::from_secs(1), short.next())
            .await
            .expect("capped stream should expire")
            .unwrap()
            .unwrap();
        assert!(expired.is_session_expired());
        assert!(tokio::time::timeout(Duration::from_secs(1), short.next())
            .await
            .expect("expired stream should close")
            .is_none());
        drop(stream);
        env.server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn revoking_a_ui_session_closes_its_quiet_event_stream_at_once() {
        let env = renewable_server().await;
        let ui = env.bridge.create_ui_session(RENEW_SECRET).await.unwrap();
        let other = env.bridge.create_ui_session(RENEW_SECRET).await.unwrap();
        let mut stream = ui.events().await.unwrap();
        let _ready = stream.next().await.unwrap().unwrap();

        // Revoking another token wakes the stream, which re-checks its own
        // still-valid lease and stays open.
        env.sessions.revoke(other.token.as_str());
        env.events.publish_ui(
            "connection.status",
            serde_json::json!({"connection":"connected"}),
        );
        let event = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("unrelated revoke must not close the stream")
            .unwrap()
            .unwrap();
        assert_eq!(event.name, "connection.status");

        // Unpair-style revocation: no bus event and a 600 s lease, yet the
        // quiet stream ends immediately with the terminal event.
        assert_eq!(
            env.sessions
                .revoke_ui_pairings(std::slice::from_ref(&env.hash)),
            1
        );
        let expired = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("revoked stream should wake at once")
            .unwrap()
            .unwrap();
        assert!(expired.is_session_expired());
        assert!(tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("revoked stream should close")
            .is_none());
        env.server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn logout_revokes_only_the_presenting_session_and_closes_its_stream() {
        let env = renewable_server().await;
        let ui = env.bridge.create_ui_session(RENEW_SECRET).await.unwrap();
        let other = env.bridge.create_ui_session(RENEW_SECRET).await.unwrap();
        let mut stream = ui.events().await.unwrap();
        let _ready = stream.next().await.unwrap().unwrap();
        let clone = ui.clone();

        ui.logout().await.unwrap();
        // Its quiet stream ends at once with the terminal event.
        let expired = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("logout should close the stream at once")
            .unwrap()
            .unwrap();
        assert!(expired.is_session_expired());
        // Every clone is logged out; a second logout is auth_required.
        let error = clone.rooms().await.unwrap_err();
        assert_eq!(api_code(&error), Some((401, "auth_required")));
        let error = ui.logout().await.unwrap_err();
        assert_eq!(api_code(&error), Some((401, "auth_required")));
        // Another session of the same pairing is unaffected.
        assert_eq!(other.rooms().await.unwrap(), Vec::<Room>::new());

        // Another process cannot log a session out.
        let me = this_process();
        let foreign = env.sessions.issue_ui(
            crate::api::auth::PeerIdentity {
                uid: me.uid,
                pid: me.pid.map(|pid| pid + 1),
            },
            env.hash.clone(),
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        let response = env
            .bridge
            .request(Method::DELETE, "/v1/ui/sessions", Some(&foreign), None)
            .await
            .unwrap();
        let error = BridgeClient::empty(response).await.unwrap_err();
        assert_eq!(api_code(&error), Some((403, "forbidden_peer")));
        assert!(env
            .sessions
            .authorize(
                Some(&foreign),
                crate::api::auth::Scope::Ui,
                crate::api::auth::PeerIdentity {
                    uid: me.uid,
                    pid: me.pid.map(|pid| pid + 1),
                },
            )
            .is_ok());
        env.server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn every_pairing_dialog_outcome_is_audited_without_the_secret() {
        let env = renewable_server().await;
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(b"another-local-ui-secret-long-enough"));
        for (answer, expected) in [
            (crate::dialog::PairingAnswer::GaveUp, "pair_gave_up"),
            (crate::dialog::PairingAnswer::Denied, "pair_denied"),
            (crate::dialog::PairingAnswer::Allowed, "pair_approved"),
        ] {
            *crate::dialog::TEST_ANSWER.lock().unwrap() = Some(answer);
            let result = env.bridge.pair_ui(&hash).await;
            if answer == crate::dialog::PairingAnswer::Allowed {
                result.unwrap();
            } else {
                assert_eq!(
                    api_code(&result.unwrap_err()),
                    Some((403, "pairing_denied")),
                    "{expected}"
                );
            }
            let (count, reference): (i64, Option<String>) = env
                .mirror
                .with(move |db| {
                    Ok(db.conn.query_row(
                        "SELECT COUNT(*),MAX(ref) FROM audit WHERE scope='ui' AND action=?1",
                        [expected],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?)
                })
                .await
                .unwrap();
            assert_eq!(count, 1, "{expected}");
            let reference = reference.unwrap();
            assert!(
                reference.starts_with('/'),
                "the executable path: {reference}"
            );
            assert!(!reference.contains(&hash));
        }
        *crate::dialog::TEST_ANSWER.lock().unwrap() = None;
        let pairings = env.mirror.with(|db| db.ui_pairings()).await.unwrap();
        assert_eq!(
            pairings.len(),
            2,
            "the fixture pairing plus the approved one"
        );
        env.server.shutdown().await.unwrap();
    }
}
