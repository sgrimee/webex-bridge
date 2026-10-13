//! Scoped server-sent events for local UI and agent clients.
//!
//! The bus carries only event metadata. Remote Webex content remains in the
//! encrypted mirror and is released through the normal scope-checked endpoints.
//! Agent subscribers receive only events addressed to routes their current
//! process-bound lease owns.

use super::{auth, ApiState};
use axum::{
    extract::{Extension, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{sse::Event as SseEvent, IntoResponse, Response, Sse},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{sync::broadcast, time::Sleep};
use tokio_stream::{
    wrappers::{errors::BroadcastStreamRecvError, BroadcastStream},
    StreamExt,
};

const EVENT_QUEUE_CAPACITY: usize = 256;
const RESYNC_REQUIRED_EVENT: &str = "resync.required";
const EVENT_LAG_REASON: &str = "event_lag";
const CONTINUITY_READY_EVENT: &str = "continuity.ready";
const SESSION_EXPIRED_EVENT: &str = "session.expired";

#[derive(Clone, Debug)]
enum Audience {
    Ui,
    AgentRoute(String),
    /// Every agent subscriber, whatever its routes (metadata-only signals).
    Agents,
    Both,
}

#[derive(Clone, Debug)]
struct PublishedEvent {
    audience: Audience,
    name: String,
    data: String,
}

/// Event recipient established from a checked bearer token.
#[derive(Clone, Debug)]
enum Subscriber {
    Ui,
    Agent { route_ids: Vec<String> },
}

impl Audience {
    fn permits(&self, subscriber: &Subscriber) -> bool {
        match (self, subscriber) {
            (Self::Ui | Self::Both, Subscriber::Ui) => true,
            (Self::Both | Self::Agents, Subscriber::Agent { .. }) => true,
            (Self::AgentRoute(route_id), Subscriber::Agent { route_ids }) => {
                route_ids.iter().any(|owned| owned == route_id)
            }
            _ => false,
        }
    }
}

impl Audience {
    /// Route label for agent-visible events in metadata-only debug logs:
    /// `*` for all-agent events, `None` for UI-only events.
    fn agent_log_route(&self) -> Option<String> {
        match self {
            Self::Ui => None,
            Self::Agents | Self::Both => Some("*".into()),
            Self::AgentRoute(route_id) => Some(log_route(route_id)),
        }
    }
}

/// Route IDs are local config names, not Webex IDs; still keep the log line
/// to a bounded, inert character set.
fn log_route(route_id: &str) -> String {
    route_id
        .chars()
        .take(64)
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '?'
            }
        })
        .collect()
}

impl Subscriber {
    const fn required_scope(&self) -> auth::Scope {
        match self {
            Self::Ui => auth::Scope::Ui,
            Self::Agent { .. } => auth::Scope::Agent,
        }
    }
}

/// A bounded in-process event fanout. It intentionally has no durable queue:
/// clients reconnect and query the mirror/inbox after a daemon restart or lag.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<PublishedEvent>,
    instance_id: Arc<str>,
    watermark: Arc<AtomicU64>,
}

/// A UI-only daemon identity plus monotonic change watermark. It lets a
/// subscriber buffer events after subscribing, fetch snapshots, then apply
/// only events newer than the snapshot boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Continuity {
    pub instance_id: String,
    pub watermark: u64,
}

impl Default for EventBus {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(EVENT_QUEUE_CAPACITY);
        let mut bytes = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self {
            sender,
            instance_id: Arc::from(URL_SAFE_NO_PAD.encode(bytes)),
            watermark: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl EventBus {
    fn publish(&self, audience: Audience, name: &'static str, data: Value) {
        // Serializing a serde_json::Value cannot fail. If this invariant changes,
        // dropping the event is safer than exposing data through an error path.
        let Ok(data) = serde_json::to_string(&data) else {
            return;
        };
        let agent_route = audience.agent_log_route();
        let receivers = self
            .sender
            .send(PublishedEvent {
                audience,
                name: name.into(),
                data,
            })
            .unwrap_or(0);
        if let Some(route) = agent_route {
            // Metadata only: a static event name, a sanitized route name and
            // the bus receiver count (all scopes). Never IDs or payloads.
            crate::diagnostics::debug(format_args!(
                "agent.event_published name={name} route={route} receivers={receivers}"
            ));
        }
    }

    /// Notify paired UIs of a metadata-only mirror or connection change.
    /// Each UI event receives the daemon instance and an increasing watermark;
    /// agent events deliberately do not inherit this UI continuity contract.
    pub fn publish_ui(&self, name: &'static str, mut data: Value) {
        let watermark = self.watermark.fetch_add(1, Ordering::SeqCst) + 1;
        let continuity = json!({
            "instanceId": self.instance_id.as_ref(),
            "watermark": watermark,
        });
        if let Some(object) = data.as_object_mut() {
            object.insert("continuity".into(), continuity);
        } else {
            data = json!({ "continuity": continuity });
        }
        self.publish(Audience::Ui, name, data);
    }

    /// Current UI snapshot boundary. This does not disclose mirror content and
    /// is intentionally unavailable through unauthenticated status/agent APIs.
    #[must_use]
    pub fn continuity(&self) -> Continuity {
        Continuity {
            instance_id: self.instance_id.to_string(),
            watermark: self.watermark.load(Ordering::SeqCst),
        }
    }

    /// Notify the current holder of exactly one configured agent route.
    pub fn publish_agent_route(&self, route_id: &str, name: &'static str, data: Value) {
        self.publish(Audience::AgentRoute(route_id.into()), name, data);
    }

    /// Publish drained agent notifications, each to exactly its route:
    /// `inbox.new` / `inbox.revised` (with the superseded delivery IDs),
    /// `inbox.deleted` and `outbox.status`. A bounded-backlog overflow becomes
    /// one `resync.required` for agents, who then reload their inbox.
    pub fn publish_agent_events(&self, batch: crate::routing::AgentEventBatch) {
        use crate::routing::AgentEvent;
        if batch.lagged {
            self.publish(
                Audience::Agents,
                RESYNC_REQUIRED_EVENT,
                json!({ "reason": EVENT_LAG_REASON }),
            );
        }
        for event in batch.events {
            match event {
                AgentEvent::Queued {
                    delivery,
                    supersedes,
                } => {
                    let (name, data) = if supersedes.is_empty() {
                        (
                            "inbox.new",
                            json!({ "deliveryId": delivery.id, "revision": delivery.revision }),
                        )
                    } else {
                        (
                            "inbox.revised",
                            json!({
                                "deliveryId": delivery.id,
                                "revision": delivery.revision,
                                "supersedes": supersedes,
                            }),
                        )
                    };
                    self.publish_agent_route(&delivery.route_id, name, data);
                }
                AgentEvent::Removed {
                    route_id,
                    delivery_id,
                    revision,
                    reason,
                } => self.publish_agent_route(
                    &route_id,
                    "inbox.deleted",
                    json!({ "deliveryId": delivery_id, "revision": revision, "reason": reason }),
                ),
                AgentEvent::Outbox {
                    route_id,
                    draft_id,
                    state,
                } => self.publish_agent_route(
                    &route_id,
                    "outbox.status",
                    json!({ "draftId": draft_id, "state": state }),
                ),
            }
        }
    }

    /// Notify both scopes of a non-content daemon state change.
    pub fn publish_both(&self, name: &'static str, data: Value) {
        self.publish(Audience::Both, name, data);
    }

    fn subscribe(&self) -> broadcast::Receiver<PublishedEvent> {
        self.sender.subscribe()
    }
}

fn json_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(json!({ "code": code, "message": message }))).into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

fn session_error(error: auth::SessionError) -> Response {
    match error {
        auth::SessionError::Scope => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "Session is not authorized for these events",
        ),
        auth::SessionError::Peer => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_peer",
            "Session belongs to a different local process",
        ),
        auth::SessionError::Missing | auth::SessionError::Expired => json_error(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "A valid local session is required",
        ),
        auth::SessionError::SessionId => json_error(
            StatusCode::FORBIDDEN,
            "forbidden_session",
            "Session is not authorized for these events",
        ),
    }
}

fn subscriber(
    state: &ApiState,
    peer: auth::PeerIdentity,
    headers: &HeaderMap,
) -> Result<(String, Subscriber), Box<Response>> {
    let Some(token) = bearer(headers) else {
        return Err(Box::new(session_error(auth::SessionError::Missing)));
    };
    match state
        .sessions()
        .authorize(Some(token), auth::Scope::Ui, peer)
    {
        Ok(()) => Ok((token.into(), Subscriber::Ui)),
        Err(auth::SessionError::Scope) => match state.sessions().agent_routes(token, peer) {
            Ok(route_ids) => Ok((token.into(), Subscriber::Agent { route_ids })),
            Err(error) => Err(Box::new(session_error(error))),
        },
        Err(error) => Err(Box::new(session_error(error))),
    }
}

/// Event names are code-defined constants; bound them anyway.
fn log_event_name(name: &str) -> String {
    log_route(name)
}

/// Yield a terminal session-expired SSE event once, then close on the next
/// poll without waiting for another daemon event or keepalive interval.
struct CloseAfterTerminal<S> {
    inner: S,
    closing: Arc<AtomicU64>,
    /// UI-only session deadline. Agent SSE behavior remains unchanged.
    expiry: Option<Pin<Box<Sleep>>>,
    /// UI-only lease identity, re-read when the deadline fires: a renewal
    /// extends the same token in place, so the stream re-arms rather than
    /// closing a still-valid subscription.
    lease: Option<UiLease>,
    /// UI-only revocation wake-ups (logout, unpair). A quiet stream whose
    /// token was revoked ends at once rather than at its old lease deadline.
    revocations: Option<tokio_stream::wrappers::WatchStream<u64>>,
}

struct UiLease {
    sessions: auth::Sessions,
    token: String,
    peer: auth::PeerIdentity,
}

impl UiLease {
    /// The current, still-in-the-future deadline of this verified lease.
    fn live_deadline(&self) -> Option<std::time::Instant> {
        self.sessions
            .expires_at(&self.token, auth::Scope::Ui, self.peer)
            .ok()
            .filter(|deadline| *deadline > std::time::Instant::now())
    }
}

impl<S: Unpin> Unpin for CloseAfterTerminal<S> {}

impl<S> tokio_stream::Stream for CloseAfterTerminal<S>
where
    S: tokio_stream::Stream<Item = Result<SseEvent, Infallible>> + Unpin,
{
    type Item = Result<SseEvent, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closing.load(Ordering::SeqCst) == 2 {
            return Poll::Ready(None);
        }
        let this = &mut *self;
        if let Some(revocations) = this.revocations.as_mut() {
            loop {
                match Pin::new(&mut *revocations).poll_next(context) {
                    Poll::Ready(Some(_)) => {
                        if this
                            .lease
                            .as_ref()
                            .and_then(UiLease::live_deadline)
                            .is_none()
                        {
                            this.closing.store(2, Ordering::SeqCst);
                            return Poll::Ready(Some(Ok(SseEvent::default()
                                .event(SESSION_EXPIRED_EVENT)
                                .data(r#"{"reason":"session_expired"}"#))));
                        }
                    }
                    Poll::Ready(None) => {
                        this.revocations = None;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }
        if let Some(expiry) = this.expiry.as_mut() {
            while expiry.as_mut().poll(context).is_ready() {
                // Re-arm on a renewed lease; polling again registers the
                // waker for the new deadline.
                if let Some(deadline) = this.lease.as_ref().and_then(UiLease::live_deadline) {
                    expiry
                        .as_mut()
                        .reset(tokio::time::Instant::from_std(deadline));
                    continue;
                }
                this.closing.store(2, Ordering::SeqCst);
                return Poll::Ready(Some(Ok(SseEvent::default()
                    .event(SESSION_EXPIRED_EVENT)
                    .data(r#"{"reason":"session_expired"}"#))));
            }
        }
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(item)) => {
                if self.closing.load(Ordering::SeqCst) == 1 {
                    self.closing.store(2, Ordering::SeqCst);
                }
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }
}

async fn stream(
    State(state): State<ApiState>,
    Extension(peer): Extension<auth::PeerIdentity>,
    headers: HeaderMap,
) -> Response {
    // Subscribe to revocations before authorizing, so a revoke racing this
    // request still wakes the stream.
    let revocation_rx = state.sessions().revocations();
    let (token, subscriber) = match subscriber(&state, peer, &headers) {
        Ok(subscriber) => subscriber,
        Err(response) => return *response,
    };
    let sessions = state.sessions();
    let events = state.events();
    let receiver = events.subscribe();
    let ready = events.continuity();
    let ui_subscriber = matches!(subscriber, Subscriber::Ui);
    let expiry = if ui_subscriber {
        sessions
            .expires_at(&token, auth::Scope::Ui, peer)
            .ok()
            .map(|deadline| {
                Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                    deadline,
                )))
            })
    } else {
        None
    };
    let revocations =
        ui_subscriber.then(|| tokio_stream::wrappers::WatchStream::from_changes(revocation_rx));
    let lease = ui_subscriber.then(|| UiLease {
        sessions: sessions.clone(),
        token: token.clone(),
        peer,
    });
    let stream_is_ui = ui_subscriber;
    let closing = Arc::new(AtomicU64::new(0));
    let closing_events = Arc::clone(&closing);
    let events = BroadcastStream::new(receiver).filter_map(move |received| {
        // A lag signal is itself scoped output, so it receives the same
        // per-item lease and peer revalidation as normal events. A terminal
        // expiry event is emitted once; the next poll closes the stream.
        if sessions
            .authorize(Some(&token), subscriber.required_scope(), peer)
            .is_err()
        {
            // B8 continuity is UI-only. Preserve the existing agent stream
            // behavior; it carries no instance/watermark or expiry signal.
            if !stream_is_ui {
                return None;
            }
            if closing_events
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(Ok::<SseEvent, Infallible>(
                    SseEvent::default()
                        .event(SESSION_EXPIRED_EVENT)
                        .data(r#"{"reason":"session_expired"}"#),
                ));
            }
            return None;
        }
        match received {
            Ok(event) if event.audience.permits(&subscriber) => {
                if !stream_is_ui {
                    if let Some(route) = event.audience.agent_log_route() {
                        crate::diagnostics::debug(format_args!(
                            "agent.sse_emitted name={} route={route}",
                            log_event_name(&event.name)
                        ));
                    }
                }
                Some(Ok::<SseEvent, Infallible>(
                    SseEvent::default().event(event.name).data(event.data),
                ))
            }
            // The broadcast channel intentionally has no replay. Make loss
            // explicit for both scopes so their hosts reload their authorized
            // state rather than silently applying a partial event sequence.
            Err(BroadcastStreamRecvError::Lagged(_)) => {
                if !stream_is_ui {
                    crate::diagnostics::debug(format_args!(
                        "agent.sse_emitted name={RESYNC_REQUIRED_EVENT} route=*"
                    ));
                }
                let data = if stream_is_ui {
                    let continuity = events.continuity();
                    serde_json::json!({
                        "reason": EVENT_LAG_REASON,
                        "instanceId": continuity.instance_id,
                        "watermark": continuity.watermark,
                    })
                } else {
                    serde_json::json!({ "reason": EVENT_LAG_REASON })
                };
                Some(Ok(SseEvent::default()
                    .event(RESYNC_REQUIRED_EVENT)
                    .data(data.to_string())))
            }
            Ok(_) => None,
        }
    });
    let events = CloseAfterTerminal {
        inner: events,
        closing,
        expiry,
        lease,
        revocations,
    };
    let initial = if ui_subscriber {
        vec![Ok::<SseEvent, Infallible>(
            SseEvent::default().event(CONTINUITY_READY_EVENT).data(
                serde_json::json!({
                    "instanceId": ready.instance_id,
                    "watermark": ready.watermark,
                })
                .to_string(),
            ),
        )]
    } else {
        Vec::new()
    };
    Sse::new(tokio_stream::iter(initial).chain(events))
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

/// Shared event stream. A token selects either full-mirror UI events or only
/// the route-specific agent events for its claimed routes.
pub fn router() -> Router<ApiState> {
    Router::new().route("/v1/events", get(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_debug_log_labels_are_route_names_only() {
        assert_eq!(Audience::Ui.agent_log_route(), None);
        assert_eq!(Audience::Agents.agent_log_route().as_deref(), Some("*"));
        assert_eq!(Audience::Both.agent_log_route().as_deref(), Some("*"));
        assert_eq!(
            Audience::AgentRoute("agents-social".into())
                .agent_log_route()
                .as_deref(),
            Some("agents-social")
        );
        // Spaces, `=`, newlines and controls cannot forge extra log fields
        // or lines, and the label is bounded.
        assert_eq!(log_route("a b=c\nlevel=WARN\u{1b}"), "a?b?c?level?WARN?");
        assert_eq!(log_route(&"r".repeat(200)).len(), 64);
        assert_eq!(log_event_name("inbox.new"), "inbox.new");
    }

    #[tokio::test]
    async fn routes_events_only_to_their_authorized_audience() {
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        events.publish_ui("message.created", json!({"messageId":"message-1"}));
        events.publish_agent_route("route-a", "inbox.new", json!({"deliveryId":"delivery-1"}));
        events.publish_both("connection.status", json!({"connection":"connected"}));

        let events = (0..3)
            .map(|_| receiver.try_recv().unwrap())
            .collect::<Vec<_>>();
        let ui = Subscriber::Ui;
        let route_a = Subscriber::Agent {
            route_ids: vec!["route-a".into()],
        };
        let route_b = Subscriber::Agent {
            route_ids: vec!["route-b".into()],
        };
        assert_eq!(
            events
                .iter()
                .filter(|event| event.audience.permits(&ui))
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.audience.permits(&route_a))
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.audience.permits(&route_b))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn agent_events_map_to_named_route_scoped_sse_events() {
        use crate::routing::{AgentEvent, AgentEventBatch, Delivery};
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let delivery = |id: &str| Delivery {
            id: id.into(),
            route_id: "route-a".into(),
            sender_id: Some("person".into()),
            created_at: "2099-01-01T00:00:00Z".into(),
            revision: 7,
            state: "pending".into(),
            edited: false,
            sender_name: Some("Private Name".into()),
            room_title: Some("Private Room".into()),
        };
        events.publish_agent_events(AgentEventBatch {
            events: vec![
                AgentEvent::Queued {
                    delivery: delivery("new"),
                    supersedes: Vec::new(),
                },
                AgentEvent::Queued {
                    delivery: delivery("revised"),
                    supersedes: vec!["old".into()],
                },
                AgentEvent::Removed {
                    route_id: "route-a".into(),
                    delivery_id: "gone".into(),
                    revision: 3,
                    reason: "deleted",
                },
                AgentEvent::Outbox {
                    route_id: "route-a".into(),
                    draft_id: "draft".into(),
                    state: "delivery-unknown",
                },
            ],
            lagged: true,
        });
        let published = (0..5)
            .map(|_| receiver.try_recv().unwrap())
            .collect::<Vec<_>>();
        let names: Vec<_> = published.iter().map(|event| event.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "resync.required",
                "inbox.new",
                "inbox.revised",
                "inbox.deleted",
                "outbox.status"
            ]
        );
        let route_a = Subscriber::Agent {
            route_ids: vec!["route-a".into()],
        };
        let route_b = Subscriber::Agent {
            route_ids: vec!["route-b".into()],
        };
        assert!(published
            .iter()
            .all(|event| event.audience.permits(&route_a)));
        // Only the metadata-only lag signal reaches other routes; nothing reaches the UI.
        assert_eq!(
            published
                .iter()
                .filter(|event| event.audience.permits(&route_b))
                .count(),
            1
        );
        assert!(!published
            .iter()
            .any(|event| event.audience.permits(&Subscriber::Ui)));
        assert!(published[2].data.contains(r#""supersedes":["old"]"#));
        assert!(published[3].data.contains(r#""reason":"deleted""#));
        assert!(published[4].data.contains(r#""draftId":"draft""#));
        // Display names never travel in events.
        assert!(!published.iter().any(|event| event.data.contains("Private")));
    }
}
