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
use serde_json::{json, Value};
use std::{convert::Infallible, time::Duration};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

const EVENT_QUEUE_CAPACITY: usize = 256;

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

/// A bounded in-process event fanout. It intentionally has no durable queue:
/// clients reconnect and query the mirror/inbox after a daemon restart or lag.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<PublishedEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(EVENT_QUEUE_CAPACITY);
        Self { sender }
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
    pub fn publish_ui(&self, name: &'static str, data: Value) {
        self.publish(Audience::Ui, name, data);
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
    let receiver = state.events().subscribe();
    let stream = BroadcastStream::new(receiver).filter_map(move |received| {
        let event = received.ok()?;
        if sessions
            .authorize(
                Some(&token),
                match subscriber {
                    Subscriber::Ui => auth::Scope::Ui,
                    Subscriber::Agent { .. } => auth::Scope::Agent,
                },
                peer,
            )
            .is_err()
            || !event.audience.permits(&subscriber)
        {
            return None;
        }
        Some(Ok::<SseEvent, Infallible>(
            SseEvent::default().event(event.name).data(event.data),
        ))
    });
    Sse::new(stream)
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
