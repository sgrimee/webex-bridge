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
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::broadcast;
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
            (Self::Both, Subscriber::Agent { .. }) => true,
            (Self::AgentRoute(route_id), Subscriber::Agent { route_ids }) => {
                route_ids.iter().any(|owned| owned == route_id)
            }
            _ => false,
        }
    }
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
        let _ = self.sender.send(PublishedEvent {
            audience,
            name: name.into(),
            data,
        });
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

/// Yield a terminal session-expired SSE event once, then close on the next
/// poll without waiting for another daemon event or keepalive interval.
struct CloseAfterTerminal<S> {
    inner: S,
    closing: Arc<AtomicU64>,
}

impl<S: Unpin> Unpin for CloseAfterTerminal<S> {}

impl<S> tokio_stream::Stream for CloseAfterTerminal<S>
where
    S: tokio_stream::Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closing.load(Ordering::SeqCst) == 2 {
            return Poll::Ready(None);
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
    let (token, subscriber) = match subscriber(&state, peer, &headers) {
        Ok(subscriber) => subscriber,
        Err(response) => return *response,
    };
    let sessions = state.sessions();
    let events = state.events();
    let receiver = events.subscribe();
    let ready = events.continuity();
    let ui_subscriber = matches!(subscriber, Subscriber::Ui);
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
            Ok(event) if event.audience.permits(&subscriber) => Some(Ok::<SseEvent, Infallible>(
                SseEvent::default().event(event.name).data(event.data),
            )),
            // The broadcast channel intentionally has no replay. Make loss
            // explicit for both scopes so their hosts reload their authorized
            // state rather than silently applying a partial event sequence.
            Err(BroadcastStreamRecvError::Lagged(_)) => {
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
}
