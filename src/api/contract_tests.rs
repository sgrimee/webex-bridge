//! Agent-scope wire contract fixtures (`contract/agent/*.json`).
//!
//! Every fixture is produced by the real daemon: real handlers, real
//! serializers and the real SSE stream over the protected Unix socket, fed
//! with synthetic IDs and text only. The test fails when the committed
//! fixtures drift from what the daemon now emits. Regenerate deliberately:
//!
//! ```sh
//! WEBEX_BRIDGE_UPDATE_CONTRACT=1 cargo test --features client contract
//! ```
//!
//! Random values (bearer and approval tokens, draft IDs, expiry/decision
//! timestamps) are replaced by fixed placeholders; everything else is the
//! exact JSON the daemon returned.

use super::{start, ApiState, ConnectionStatus};
use crate::{
    client::{events::EventStream, BridgeClient},
    config::{Config, DevConfig, Receive, Route},
    mirror::{Mirror, SharedMirror},
    paths::Paths,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use http_body_util::BodyExt;
use hyper::Method;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::watch;
use tokio_stream::StreamExt;
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

const ROUTE: &str = "agents-social";
const AGENT: &str = "sam/coder";
const WORKSPACE: &str = "/synthetic/workspace";
const SESSION: &str = "synthetic-host-session";
const UPDATE_ENV: &str = "WEBEX_BRIDGE_UPDATE_CONTRACT";

/// A syntactically valid, obviously synthetic Webex geo-ID.
fn geo(kind: &str, n: u32) -> String {
    STANDARD_NO_PAD.encode(format!(
        "ciscospark://us/{kind}/00000000-0000-4000-8000-{n:012}"
    ))
}

fn room() -> String {
    geo("ROOM", 1)
}
fn sender() -> String {
    geo("PEOPLE", 2)
}
fn account() -> String {
    geo("PEOPLE", 3)
}
fn message_id(n: u32) -> String {
    geo("MESSAGE", 100 + n)
}

fn synthetic_message(n: u32, parent: Option<u32>, text: &str) -> webex::Message {
    webex::Message {
        id: Some(message_id(n)),
        room_id: Some(room()),
        person_id: Some(sender()),
        parent_id: parent.map(message_id),
        text: Some(text.into()),
        created: Some(format!("2099-01-01T00:00:{n:02}Z")),
        ..webex::Message::default()
    }
}

fn config() -> Config {
    let mut config = Config::default();
    config.dev = Some(DevConfig {
        write_allowlist: vec![room()],
        secret_source: crate::config::DevSecretSource::Keychain,
    });
    config.routes.push(Route {
        id: ROUTE.into(),
        room_id: room(),
        agent_name: AGENT.into(),
        allowed_senders: vec![sender()],
        receive: Receive::Addressed,
        workspace: WORKSPACE.into(),
    });
    config
}

/// Replace random or clock-derived values by stable placeholders.
fn normalize(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                let placeholder = match key.as_str() {
                    "token" | "approvalToken" => Some("<token>"),
                    "draftId" => Some("<draft-id>"),
                    "expiresAt" | "decidedAt" => Some("<timestamp>"),
                    _ => None,
                };
                match placeholder {
                    Some(placeholder) if value.is_string() => *value = json!(placeholder),
                    _ => normalize(value),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize),
        _ => {}
    }
}

struct Recorder {
    fixtures: BTreeMap<String, Value>,
}

impl Recorder {
    fn http(
        &mut self,
        name: &str,
        route: &str,
        status: u16,
        body: Option<Value>,
        sent: Option<Value>,
    ) {
        let mut request = Map::new();
        request.insert("route".into(), json!(route));
        if let Some(mut sent) = sent {
            normalize(&mut sent);
            request.insert("body".into(), sent);
        }
        let mut response = Map::new();
        response.insert("status".into(), json!(status));
        if let Some(mut body) = body {
            normalize(&mut body);
            response.insert("body".into(), body);
        }
        let fixture = json!({
            "kind": "http",
            "request": Value::Object(request),
            "response": Value::Object(response),
        });
        assert!(
            self.fixtures.insert(name.into(), fixture).is_none(),
            "duplicate fixture {name}"
        );
    }

    /// Every agent SSE frame one daemon change produced, in wire order.
    fn events(&mut self, name: &str, events: &[crate::client::events::BridgeEvent]) {
        assert!(!events.is_empty(), "{name}: no event was emitted");
        let frames = events
            .iter()
            .map(|event| {
                let mut data = event.data.clone();
                normalize(&mut data);
                json!({ "event": event.name, "data": data })
            })
            .collect::<Vec<_>>();
        let fixture = json!({ "kind": "sse", "frames": frames });
        assert!(
            self.fixtures.insert(name.into(), fixture).is_none(),
            "duplicate fixture {name}"
        );
    }
}

/// One real request over the UDS; returns status and parsed JSON body.
async fn call(
    bridge: &BridgeClient,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (u16, Option<Value>, Option<Value>) {
    let response = bridge
        .request(
            method,
            path,
            token,
            body.as_ref().map(|body| body.to_string().into_bytes()),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let received = (!bytes.is_empty()).then(|| serde_json::from_slice(&bytes).unwrap());
    (status, received, body)
}

/// One synthetic change applied the way the daemon's sync loop would.
type MirrorChange = Box<dyn FnOnce(&mut Mirror) -> anyhow::Result<()> + Send>;

const SENTINEL: &str = "contract.sentinel";

/// Collect the frames one change produced: publish a test-only sentinel on
/// the same bus after it, then read up to (not including) the sentinel.
async fn frames(
    events: &crate::api::events::EventBus,
    stream: &mut EventStream,
) -> Vec<crate::client::events::BridgeEvent> {
    events.publish_agent_route(ROUTE, SENTINEL, json!({}));
    let mut frames = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("agent event should arrive")
            .expect("agent stream should stay open")
            .expect("agent event should parse");
        if event.name == SENTINEL {
            return frames;
        }
        frames.push(event);
    }
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contract/agent")
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn agent_contract_fixtures_match_the_real_daemon_output() {
    let temp = tempfile::tempdir().unwrap();
    let paths = Paths::under(temp.path().join("bridge"));
    let config = config();
    let mirror = SharedMirror::new(Mirror::in_memory([77_u8; 32]).unwrap());
    let routes = config.routes.iter().map(|route| Route {
        id: route.id.clone(),
        room_id: route.room_id.clone(),
        agent_name: route.agent_name.clone(),
        allowed_senders: route.allowed_senders.clone(),
        receive: Receive::Addressed,
        workspace: route.workspace.clone(),
    });
    let routes = routes.collect::<Vec<_>>();
    mirror
        .with(move |db| {
            db.sync_routes(&routes)?;
            db.cache_account_identity(&webex::Person {
                id: account(),
                display_name: "Synthetic Account".into(),
                emails: vec!["account@example.test".into()],
                ..webex::Person::default()
            })?;
            db.upsert_person(&webex::Person {
                id: sender(),
                display_name: "Synthetic Sender".into(),
                emails: vec!["sender@example.test".into()],
                ..webex::Person::default()
            })?;
            db.upsert_room(
                &webex::Room {
                    id: room(),
                    title: Some("Synthetic Room".into()),
                    room_type: "group".into(),
                    is_locked: false,
                    team_id: None,
                    last_activity: "2099-01-01T00:00:00Z".into(),
                    creator_id: sender(),
                    created: "2099-01-01T00:00:00Z".into(),
                },
                true,
            )?;
            // A thread root (not addressed, so not routed), an addressed
            // reply to it (accepted below) and a second addressed message
            // (rejected below).
            db.upsert_message(&synthetic_message(1, None, "Synthetic thread root"))?;
            db.upsert_message(&synthetic_message(
                2,
                Some(1),
                "sam/coder: synthetic question in a thread",
            ))?;
            db.upsert_message(&synthetic_message(3, None, "sam/coder: synthetic request"))?;
            Ok(())
        })
        .await
        .unwrap();
    let config = Arc::new(config);
    {
        let config = Arc::clone(&config);
        mirror
            .with(move |db| {
                assert_eq!(db.queue_deliveries(&config)?, 2);
                let _ = db.take_agent_events();
                Ok(())
            })
            .await
            .unwrap();
    }

    let remote = MockServer::start().await;
    // Specific cases first: a definite Webex rejection, and an ambiguous
    // 200 without a message ID (delivery-unknown).
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(body_string_contains("synthetic failure case"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "synthetic"})))
        .mount(&remote)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(body_string_contains("synthetic unknown case"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&remote)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": message_id(50),
            "roomId": room(),
            "created": "2099-01-01T00:01:00Z",
        })))
        .mount(&remote)
        .await;
    let rest = Arc::new(
        crate::sync::history::WebexRest::for_tests(
            reqwest::Url::parse(&format!("{}/v1/", remote.uri())).unwrap(),
        )
        .unwrap(),
    );
    let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
    let (_rest_tx, rest_rx) = watch::channel(Some(rest));
    let state =
        ApiState::with_config_and_rest(mirror.clone(), connection_rx, Arc::clone(&config), rest_rx);
    let events = state.events();
    let server = start(&paths, state).await.unwrap();
    let bridge = BridgeClient::new(paths.socket.clone());
    let mut rec = Recorder {
        fixtures: BTreeMap::new(),
    };

    // --- Status and claim/lease -------------------------------------------
    let (status, body, sent) = call(&bridge, Method::GET, "/v1/status", None, None).await;
    rec.http("status", "GET /v1/status", status, body, sent);

    let claim = json!({"host":"pi","sessionId":SESSION,"cwd":WORKSPACE,"agentName":AGENT});
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        "/v1/agent/sessions",
        None,
        Some(claim.clone()),
    )
    .await;
    assert_eq!(status, 200);
    let token = body.as_ref().unwrap()["token"].as_str().unwrap().to_owned();
    rec.http(
        "session-claim",
        "POST /v1/agent/sessions",
        status,
        body,
        sent,
    );

    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        "/v1/agent/sessions",
        None,
        Some(claim.clone()),
    )
    .await;
    rec.http(
        "error-route-claimed",
        "POST /v1/agent/sessions",
        status,
        body,
        sent,
    );
    let mut unrouted = claim.clone();
    unrouted["agentName"] = json!("sam/unrouted");
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        "/v1/agent/sessions",
        None,
        Some(unrouted),
    )
    .await;
    rec.http(
        "error-not-routed",
        "POST /v1/agent/sessions",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        "/v1/agent/sessions",
        None,
        Some(json!({"host":"","sessionId":SESSION,"cwd":WORKSPACE,"agentName":AGENT})),
    )
    .await;
    rec.http(
        "error-invalid-request",
        "POST /v1/agent/sessions",
        status,
        body,
        sent,
    );

    let heartbeat = format!("/v1/agent/sessions/{SESSION}/heartbeat");
    let (status, body, sent) = call(&bridge, Method::POST, &heartbeat, Some(&token), None).await;
    rec.http(
        "session-heartbeat",
        "POST /v1/agent/sessions/{sessionId}/heartbeat",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        "/v1/agent/sessions/another-session/heartbeat",
        Some(&token),
        None,
    )
    .await;
    rec.http(
        "error-forbidden-session",
        "POST /v1/agent/sessions/{sessionId}/heartbeat",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(&bridge, Method::GET, "/v1/agent/inbox", None, None).await;
    rec.http(
        "error-auth-required",
        "GET /v1/agent/inbox",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(&bridge, Method::GET, "/v1/rooms", Some(&token), None).await;
    rec.http("error-forbidden-scope", "GET /v1/rooms", status, body, sent);

    // --- Events: subscribe before the changes it should report -------------
    let mut stream = EventStream::connect(bridge.clone(), &token).await.unwrap();

    // --- Inbox -------------------------------------------------------------
    let (status, body, sent) = call(
        &bridge,
        Method::GET,
        "/v1/agent/inbox?state=pending",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let deliveries = body.as_ref().unwrap()["deliveries"].as_array().unwrap();
    assert_eq!(deliveries.len(), 2);
    let by_revision = |first: bool| {
        let mut ids = deliveries
            .iter()
            .map(|delivery| {
                (
                    delivery["revision"].as_i64().unwrap(),
                    delivery["id"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        ids.sort();
        if first {
            ids[0].1.clone()
        } else {
            ids[1].1.clone()
        }
    };
    let (reply_delivery, other_delivery) = (by_revision(true), by_revision(false));
    rec.http(
        "inbox-list",
        "GET /v1/agent/inbox?state=pending",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(
        &bridge,
        Method::GET,
        "/v1/agent/inbox?state=bogus",
        Some(&token),
        None,
    )
    .await;
    rec.http(
        "error-inbox-invalid-state",
        "GET /v1/agent/inbox?state=bogus",
        status,
        body,
        sent,
    );

    let preview = format!("/v1/agent/inbox/{reply_delivery}/preview");
    let (status, body, sent) = call(&bridge, Method::GET, &preview, Some(&token), None).await;
    rec.http(
        "inbox-preview",
        "GET /v1/agent/inbox/{deliveryId}/preview",
        status,
        body,
        sent,
    );
    let accept = format!("/v1/agent/inbox/{reply_delivery}/accept");
    let (status, body, sent) = call(&bridge, Method::POST, &accept, Some(&token), None).await;
    assert_eq!(status, 200);
    rec.http(
        "inbox-accept",
        "POST /v1/agent/inbox/{deliveryId}/accept",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(&bridge, Method::POST, &accept, Some(&token), None).await;
    rec.http(
        "error-delivery-unavailable",
        "POST /v1/agent/inbox/{deliveryId}/accept",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(&bridge, Method::GET, &preview, Some(&token), None).await;
    rec.http(
        "error-preview-not-found",
        "GET /v1/agent/inbox/{deliveryId}/preview",
        status,
        body,
        sent,
    );
    let reject = format!("/v1/agent/inbox/{other_delivery}/reject");
    let (status, body, sent) = call(&bridge, Method::POST, &reject, Some(&token), None).await;
    rec.http(
        "inbox-reject",
        "POST /v1/agent/inbox/{deliveryId}/reject",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(
        &bridge,
        Method::GET,
        "/v1/agent/inbox?state=accepted",
        Some(&token),
        None,
    )
    .await;
    rec.http(
        "inbox-list-accepted",
        "GET /v1/agent/inbox?state=accepted",
        status,
        body,
        sent,
    );

    // --- Inbox events, produced the way the daemon's sync loop does --------
    let sync = |operation: MirrorChange| {
        let mirror = mirror.clone();
        let config = Arc::clone(&config);
        let events = events.clone();
        async move {
            let batch = mirror
                .with(move |db| {
                    operation(db)?;
                    db.queue_deliveries(&config)?;
                    Ok(db.take_agent_events())
                })
                .await
                .unwrap();
            events.publish_agent_events(batch);
        }
    };
    sync(Box::new(|db| {
        db.upsert_message(&synthetic_message(4, None, "sam/coder: synthetic new"))
            .map(|_| ())
    }))
    .await;
    rec.events("event-inbox-new", &frames(&events, &mut stream).await);
    sync(Box::new(|db| {
        let mut edited = synthetic_message(4, None, "sam/coder: synthetic edited");
        edited.updated = Some("2099-01-01T00:10:00Z".into());
        db.upsert_message(&edited).map(|_| ())
    }))
    .await;
    rec.events("event-inbox-revised", &frames(&events, &mut stream).await);
    sync(Box::new(|db| {
        db.mark_deleted(&room(), &message_id(4)).map(|_| ())
    }))
    .await;
    rec.events("event-inbox-deleted", &frames(&events, &mut stream).await);

    // --- Outbox ------------------------------------------------------------
    let draft_body = json!({
        "routeId": ROUTE,
        "parentId": message_id(1),
        "markdown": "Synthetic agent reply\n— 🤖 sam/coder",
    });
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        "/v1/agent/outbox",
        Some(&token),
        Some(draft_body),
    )
    .await;
    assert_eq!(status, 200);
    let draft = body.clone().unwrap();
    let draft_id = draft["draftId"].as_str().unwrap().to_owned();
    rec.http("outbox-draft", "POST /v1/agent/outbox", status, body, sent);
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        "/v1/agent/outbox",
        Some(&token),
        Some(json!({"routeId": ROUTE, "markdown": "no trailer"})),
    )
    .await;
    rec.http(
        "error-outbox-invalid",
        "POST /v1/agent/outbox",
        status,
        body,
        sent,
    );
    let status_path = format!("/v1/agent/outbox/{draft_id}");
    let (status, body, sent) = call(&bridge, Method::GET, &status_path, Some(&token), None).await;
    rec.http(
        "outbox-status-pending",
        "GET /v1/agent/outbox/{draftId}",
        status,
        body,
        sent,
    );
    let approve_path = format!("/v1/agent/outbox/{draft_id}/approve");
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        &approve_path,
        Some(&token),
        Some(json!({"sha256": draft["sha256"], "approvalToken": "synthetic-wrong-token"})),
    )
    .await;
    rec.http(
        "error-approval-mismatch",
        "POST /v1/agent/outbox/{draftId}/approve",
        status,
        body,
        sent,
    );
    let approval = json!({"sha256": draft["sha256"], "approvalToken": draft["approvalToken"]});
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        &approve_path,
        Some(&token),
        Some(approval.clone()),
    )
    .await;
    assert_eq!(status, 200);
    rec.http(
        "outbox-approve-sent",
        "POST /v1/agent/outbox/{draftId}/approve",
        status,
        body,
        sent,
    );
    rec.events("event-outbox-status", &frames(&events, &mut stream).await);
    let (status, body, sent) = call(
        &bridge,
        Method::POST,
        &approve_path,
        Some(&token),
        Some(approval),
    )
    .await;
    rec.http(
        "error-approval-expired",
        "POST /v1/agent/outbox/{draftId}/approve",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(&bridge, Method::GET, &status_path, Some(&token), None).await;
    rec.http(
        "outbox-status-sent",
        "GET /v1/agent/outbox/{draftId}",
        status,
        body,
        sent,
    );
    let (status, body, sent) = call(
        &bridge,
        Method::GET,
        "/v1/agent/outbox/synthetic-unknown-draft",
        Some(&token),
        None,
    )
    .await;
    rec.http(
        "error-outbox-not-found",
        "GET /v1/agent/outbox/{draftId}",
        status,
        body,
        sent,
    );

    // Approve outcomes other than sent: a definite rejection and an
    // ambiguous delivery, each with its status read-back and SSE frame.
    for (case, outcome) in [
        ("synthetic failure case", "failed"),
        ("synthetic unknown case", "delivery-unknown"),
    ] {
        let (_, draft, _) = call(
            &bridge,
            Method::POST,
            "/v1/agent/outbox",
            Some(&token),
            Some(json!({"routeId": ROUTE, "markdown": format!("{case}\n— 🤖 sam/coder")})),
        )
        .await;
        let draft = draft.unwrap();
        let draft_id = draft["draftId"].as_str().unwrap().to_owned();
        let (status, body, sent) = call(
            &bridge,
            Method::POST,
            &format!("/v1/agent/outbox/{draft_id}/approve"),
            Some(&token),
            Some(json!({"sha256": draft["sha256"], "approvalToken": draft["approvalToken"]})),
        )
        .await;
        assert_eq!(body.as_ref().unwrap()["state"], outcome);
        rec.http(
            &format!("outbox-approve-{outcome}"),
            "POST /v1/agent/outbox/{draftId}/approve",
            status,
            body,
            sent,
        );
        rec.events(
            &format!("event-outbox-status-{outcome}"),
            &frames(&events, &mut stream).await,
        );
        let (status, body, sent) = call(
            &bridge,
            Method::GET,
            &format!("/v1/agent/outbox/{draft_id}"),
            Some(&token),
            None,
        )
        .await;
        rec.http(
            &format!("outbox-status-{outcome}"),
            "GET /v1/agent/outbox/{draftId}",
            status,
            body,
            sent,
        );
    }

    // Discard: a cancelled approval dialog withdraws a pending draft.
    let (_, draft, _) = call(
        &bridge,
        Method::POST,
        "/v1/agent/outbox",
        Some(&token),
        Some(json!({"routeId": ROUTE, "markdown": "Synthetic cancelled reply\n— 🤖 sam/coder"})),
    )
    .await;
    let draft = draft.unwrap();
    let discard_path = format!("/v1/agent/outbox/{}", draft["draftId"].as_str().unwrap());
    let (status, body, sent) =
        call(&bridge, Method::DELETE, &discard_path, Some(&token), None).await;
    assert_eq!(status, 200);
    rec.http(
        "outbox-discard",
        "DELETE /v1/agent/outbox/{draftId}",
        status,
        body,
        sent,
    );
    rec.events(
        "event-outbox-status-discarded",
        &frames(&events, &mut stream).await,
    );
    let (status, body, sent) = call(&bridge, Method::GET, &discard_path, Some(&token), None).await;
    rec.http(
        "outbox-status-discarded",
        "GET /v1/agent/outbox/{draftId}",
        status,
        body,
        sent,
    );
    let (status, body, sent) =
        call(&bridge, Method::DELETE, &discard_path, Some(&token), None).await;
    rec.http(
        "error-draft-not-pending",
        "DELETE /v1/agent/outbox/{draftId}",
        status,
        body,
        sent,
    );
    let (status, _, _) = call(
        &bridge,
        Method::POST,
        &format!("{discard_path}/approve"),
        Some(&token),
        Some(json!({"sha256": draft["sha256"], "approvalToken": draft["approvalToken"]})),
    )
    .await;
    assert_eq!(status, 409, "a discarded draft can never be approved");
    let (status, body, sent) = call(
        &bridge,
        Method::DELETE,
        "/v1/agent/outbox/synthetic-unknown-draft",
        Some(&token),
        None,
    )
    .await;
    rec.http(
        "error-discard-not-found",
        "DELETE /v1/agent/outbox/{draftId}",
        status,
        body,
        sent,
    );

    // --- Daemon-wide events ------------------------------------------------
    events.publish_both(
        "connection.status",
        json!({ "connection": ConnectionStatus::Connected.as_str() }),
    );
    rec.events(
        "event-connection-status",
        &frames(&events, &mut stream).await,
    );
    for sequence in 0..300 {
        events.publish_agent_route(ROUTE, "inbox.new", json!({ "sequence": sequence }));
    }
    // Only the lag signal itself: the retained flood behind it is synthetic.
    let lagged = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("lag signal should arrive")
        .expect("agent stream should stay open")
        .expect("lag signal should parse");
    assert_eq!(lagged.name, "resync.required");
    rec.events("event-resync-required", &[lagged]);
    drop(stream);

    // --- Release -----------------------------------------------------------
    let release = format!("/v1/agent/sessions/{SESSION}");
    let (status, body, sent) = call(&bridge, Method::DELETE, &release, Some(&token), None).await;
    rec.http(
        "session-release",
        "DELETE /v1/agent/sessions/{sessionId}",
        status,
        body,
        sent,
    );
    server.shutdown().await.unwrap();

    // --- Webex not connected: a daemon without a REST client ---------------
    let offline_paths = Paths::under(temp.path().join("offline"));
    let (_offline_tx, offline_rx) = watch::channel(ConnectionStatus::Disconnected);
    let offline = start(
        &offline_paths,
        ApiState::with_config(mirror.clone(), offline_rx, Arc::clone(&config)),
    )
    .await
    .unwrap();
    let offline_bridge = BridgeClient::new(offline_paths.socket.clone());
    let (_, claimed, _) = call(
        &offline_bridge,
        Method::POST,
        "/v1/agent/sessions",
        None,
        Some(claim),
    )
    .await;
    let offline_token = claimed.unwrap()["token"].as_str().unwrap().to_owned();
    let (_, draft, _) = call(
        &offline_bridge,
        Method::POST,
        "/v1/agent/outbox",
        Some(&offline_token),
        Some(json!({"routeId": ROUTE, "markdown": "Synthetic offline reply\n— 🤖 sam/coder"})),
    )
    .await;
    let draft = draft.unwrap();
    let (status, body, sent) = call(
        &offline_bridge,
        Method::POST,
        &format!(
            "/v1/agent/outbox/{}/approve",
            draft["draftId"].as_str().unwrap()
        ),
        Some(&offline_token),
        Some(json!({"sha256": draft["sha256"], "approvalToken": draft["approvalToken"]})),
    )
    .await;
    assert_eq!(status, 503);
    rec.http(
        "error-webex-unavailable",
        "POST /v1/agent/outbox/{draftId}/approve",
        status,
        body,
        sent,
    );
    offline.shutdown().await.unwrap();

    // --- Synthetic-only guard, then compare or regenerate -------------------
    let rendered = rec
        .fixtures
        .iter()
        .map(|(name, fixture)| {
            (
                format!("{name}.json"),
                format!("{}\n", serde_json::to_string_pretty(fixture).unwrap()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (name, text) in &rendered {
        assert!(!text.contains(&token), "{name} contains a live bearer");
        assert!(
            !text.contains(draft["approvalToken"].as_str().unwrap()),
            "{name} contains an approval token"
        );
    }
    let dir = fixture_dir();
    if std::env::var_os(UPDATE_ENV).is_some() {
        if dir.exists() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    std::fs::remove_file(path).unwrap();
                }
            }
        }
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in &rendered {
            std::fs::write(dir.join(name), text).unwrap();
        }
        return;
    }
    let committed = std::fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("missing {}; run with {UPDATE_ENV}=1", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&path).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let names = |map: &BTreeMap<String, String>| map.keys().cloned().collect::<Vec<_>>();
    assert_eq!(
        names(&committed),
        names(&rendered),
        "agent contract fixture set drifted; review, then rerun with {UPDATE_ENV}=1"
    );
    for (name, text) in &rendered {
        let expected: Value = serde_json::from_str(&committed[name]).unwrap();
        let actual: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            actual, expected,
            "agent contract fixture {name} drifted; review, then rerun with {UPDATE_ENV}=1"
        );
    }
}

/// Discard is scoped to the session's claimed routes, audited once, purges
/// the encrypted body, and needs a valid agent bearer.
#[tokio::test]
async fn discard_is_route_scoped_audited_and_purges_the_body() {
    let temp = tempfile::tempdir().unwrap();
    let paths = Paths::under(temp.path().join("bridge"));
    let mut config = config();
    config.routes.push(Route {
        id: "other-route".into(),
        room_id: room(),
        agent_name: "sam/other".into(),
        allowed_senders: vec![sender()],
        receive: Receive::Addressed,
        workspace: "/synthetic/elsewhere".into(),
    });
    let mirror = SharedMirror::new(Mirror::in_memory([78_u8; 32]).unwrap());
    let config = Arc::new(config);
    let other_draft = {
        let config = Arc::clone(&config);
        mirror
            .with(move |db| {
                db.sync_routes(&config.routes)?;
                db.create_draft(
                    &config,
                    "other-route",
                    None,
                    "Synthetic other reply\n— 🤖 sam/other",
                )
            })
            .await
            .unwrap()
    };
    let (_connection_tx, connection_rx) = watch::channel(ConnectionStatus::Connected);
    let server = start(
        &paths,
        ApiState::with_config(mirror.clone(), connection_rx, Arc::clone(&config)),
    )
    .await
    .unwrap();
    let bridge = BridgeClient::new(paths.socket.clone());
    let (_, claimed, _) = call(
        &bridge,
        Method::POST,
        "/v1/agent/sessions",
        None,
        Some(json!({"host":"pi","sessionId":SESSION,"cwd":WORKSPACE,"agentName":AGENT})),
    )
    .await;
    let token = claimed.unwrap()["token"].as_str().unwrap().to_owned();
    let other_path = format!("/v1/agent/outbox/{}", other_draft.draft_id);
    let (status, body, _) = call(&bridge, Method::DELETE, &other_path, Some(&token), None).await;
    assert_eq!(status, 403);
    assert_eq!(body.unwrap()["code"], "not_routed");
    let (status, _, _) = call(&bridge, Method::DELETE, &other_path, None, None).await;
    assert_eq!(status, 401);

    let (_, own, _) = call(
        &bridge,
        Method::POST,
        "/v1/agent/outbox",
        Some(&token),
        Some(json!({"routeId": ROUTE, "markdown": "Synthetic own reply\n— 🤖 sam/coder"})),
    )
    .await;
    let own_id = own.unwrap()["draftId"].as_str().unwrap().to_owned();
    let (status, _, _) = call(
        &bridge,
        Method::DELETE,
        &format!("/v1/agent/outbox/{own_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let other_id = other_draft.draft_id.clone();
    let (own_state, other_state, body_len, audits) = mirror
        .with(move |db| {
            let state = |id: &str| -> anyhow::Result<String> {
                Ok(db.conn.query_row(
                    "SELECT state FROM outbox WHERE draft_id=?1",
                    [id],
                    |row| row.get(0),
                )?)
            };
            let own_state = state(&own_id)?;
            let other_state = state(&other_id)?;
            let body_len: i64 = db.conn.query_row(
                "SELECT length(body_ct)+length(body_nonce) FROM outbox WHERE draft_id=?1",
                [&own_id],
                |row| row.get(0),
            )?;
            let audits: i64 = db.conn.query_row(
                "SELECT COUNT(*) FROM audit WHERE action='outbox_discard' AND ref=?1",
                [&own_id],
                |row| row.get(0),
            )?;
            Ok((own_state, other_state, body_len, audits))
        })
        .await
        .unwrap();
    assert_eq!(own_state, "discarded");
    assert_eq!(other_state, "pending", "another route's draft is untouched");
    assert_eq!(body_len, 0, "the discarded body is purged");
    assert_eq!(audits, 1);
    server.shutdown().await.unwrap();
}
