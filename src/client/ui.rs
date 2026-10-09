//! Typed UI-scope calls for the daemon's local API.

use super::{events::EventStream, path_segment, BridgeClient, Result};
use hyper::Method;
use serde::{Deserialize, Serialize};

pub use crate::dto::{
    Message, MessagePage, Person, Room, Status, SyncStatus, Team, ThreadChildren, ThreadParent,
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

    /// Read the daemon account from the encrypted mirror, refreshing it from
    /// Webex when available. A first-run offline daemon reports
    /// `identity_not_ready` instead of guessing an account from person rows.
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
            .request(Method::GET, &path, Some(&self.token), None)
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
                Some(&self.token),
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
            .request(Method::GET, &path, Some(&self.token), None)
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
        matchers::{method, path, query_param},
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
                for (id, parent_id, created) in [
                    ("orphan-reply", "missing-parent", "2026-10-08T12:01:00Z"),
                    (
                        "deleted-parent-reply",
                        "deleted-parent",
                        "2026-10-08T12:02:00Z",
                    ),
                ] {
                    db.upsert_message(&webex::Message {
                        id: Some(id.into()),
                        room_id: Some("room-1".into()),
                        parent_id: Some(parent_id.into()),
                        created: Some(created.into()),
                        text: Some("private reply".into()),
                        ..webex::Message::default()
                    })?;
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
        let deleted = ui
            .thread_children("deleted-parent", None, Some(10))
            .await
            .unwrap();
        assert_eq!(deleted.parent.state, "deleted");
        assert_eq!(deleted.children[0].id, "deleted-parent-reply");
        assert!(!deleted.complete);
        assert_eq!(deleted.partial_reason.as_deref(), Some("offline"));
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
        let error = ui.team(team_id).await.unwrap_err();
        assert!(matches!(
            error,
            crate::client::ClientError::Api {
                status: hyper::StatusCode::NOT_FOUND,
                code,
                ..
            } if code == "not_found"
        ));
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
            "/v1/teams/team-1",
            "/v1/messages/missing-parent/children",
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
    async fn broadcast_lag_requires_a_metadata_only_ui_resync() {
        let (_temp, server, bridge, events) = paired_server().await;
        let ui = bridge
            .create_ui_session("a-local-ui-secret-that-is-long-enough")
            .await
            .unwrap();
        let mut stream = ui.events().await.unwrap();

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
        assert_eq!(event.data, serde_json::json!({"reason":"event_lag"}));

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
}
