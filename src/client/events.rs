//! Parser for the daemon's metadata-only server-sent event stream.

use super::{BridgeClient, ClientError, Result};
use http_body_util::{BodyDataStream, BodyExt};
use hyper::{body::Incoming, Method};
use serde_json::Value;
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};
use tokio_stream::Stream;

const MAX_EVENT_BYTES: usize = 64 * 1024;

/// Event name sent when the daemon's bounded fanout dropped one or more events.
///
/// There is no replay cursor. Callers must reload their authoritative scoped
/// state before relying on subsequent events.
pub const RESYNC_REQUIRED_EVENT: &str = "resync.required";
/// Initial UI-only daemon identity/watermark emitted immediately after an SSE subscription.
pub const CONTINUITY_READY_EVENT: &str = "continuity.ready";
/// Terminal UI stream event emitted when the session lease has elapsed.
pub const SESSION_EXPIRED_EVENT: &str = "session.expired";

/// One scope-filtered event from `GET /v1/events`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeEvent {
    /// Daemon event name, such as `message.updated` or `connection.status`.
    pub name: String,
    /// Metadata-only JSON payload. Message text is never present in this stream.
    pub data: Value,
}

impl BridgeEvent {
    /// Whether this event requires a full scoped-state refresh before applying
    /// later events. The daemon cannot replay its bounded SSE fanout.
    #[must_use]
    pub fn requires_resync(&self) -> bool {
        self.name == RESYNC_REQUIRED_EVENT
    }

    /// Whether the daemon has terminated this subscription because its
    /// process-bound UI session elapsed. Recreate the session and stream.
    #[must_use]
    pub fn is_session_expired(&self) -> bool {
        self.name == SESSION_EXPIRED_EVENT
    }

    /// UI continuity marker carried by normal UI events, lag signals and the
    /// initial ready event. Agent events intentionally have no such marker.
    #[must_use]
    pub fn continuity(&self) -> Option<crate::dto::Continuity> {
        let value = if self.name == CONTINUITY_READY_EVENT {
            &self.data
        } else {
            self.data.get("continuity").unwrap_or(&self.data)
        };
        serde_json::from_value(value.clone()).ok()
    }
}

/// A live, parsed SSE response. Dropping it closes only this subscription.
pub struct EventStream {
    stream: BodyDataStream<Incoming>,
    buffer: Vec<u8>,
    name: Option<String>,
    data: Vec<String>,
    pending: VecDeque<BridgeEvent>,
}

impl Unpin for EventStream {}

impl EventStream {
    pub(crate) async fn connect(bridge: BridgeClient, token: &str) -> Result<Self> {
        let response = bridge
            .request(Method::GET, "/v1/events", Some(token), None)
            .await?;
        if !response.status().is_success() {
            return match BridgeClient::json::<Value>(response).await {
                Err(error) => Err(error),
                Ok(_) => Err(ClientError::InvalidResponse(anyhow::anyhow!(
                    "Bridge event endpoint accepted an error response"
                ))),
            };
        }
        Ok(Self {
            stream: response.into_body().into_data_stream(),
            buffer: Vec::new(),
            name: None,
            data: Vec::new(),
            pending: VecDeque::new(),
        })
    }

    /// Receive the next event, or `None` once the daemon closed the stream.
    ///
    /// Cancel-safe: all parser state (partial lines, the current event and
    /// already-parsed events) lives in `self`, and the future holds nothing
    /// else. Dropping a pending call (e.g. in `tokio::select!`) and calling it
    /// again loses no bytes or events. This is a thin wrapper over
    /// [`Stream::poll_next`], so no stream-extension crate is needed.
    pub async fn next_event(&mut self) -> Option<Result<BridgeEvent>> {
        std::future::poll_fn(|context| Pin::new(&mut *self).poll_next(context)).await
    }

    fn consume_line(&mut self, mut line: &[u8]) -> Result<()> {
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            if let Some(name) = self.name.take() {
                let data = self.data.join("\n");
                self.data.clear();
                let data = serde_json::from_str(&data)
                    .map_err(|error| ClientError::InvalidResponse(error.into()))?;
                self.pending.push_back(BridgeEvent { name, data });
            } else {
                self.data.clear();
            }
            return Ok(());
        }
        if line.starts_with(b":") {
            return Ok(());
        }
        let (field, value) = match line.iter().position(|byte| *byte == b':') {
            Some(index) => {
                let value = &line[index + 1..];
                (&line[..index], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &b""[..]),
        };
        match field {
            b"event" => {
                let name = std::str::from_utf8(value)
                    .map_err(|error| ClientError::InvalidResponse(error.into()))?;
                if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                    return Err(ClientError::InvalidResponse(anyhow::anyhow!(
                        "Bridge SSE event name is invalid"
                    )));
                }
                self.name = Some(name.into());
            }
            b"data" => {
                let data = std::str::from_utf8(value)
                    .map_err(|error| ClientError::InvalidResponse(error.into()))?;
                self.data.push(data.into());
            }
            _ => {}
        }
        Ok(())
    }

    fn consume_buffer(&mut self) -> Result<()> {
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line = self.buffer.drain(..=newline).collect::<Vec<_>>();
            self.consume_line(&line[..line.len() - 1])?;
        }
        if self.buffer.len() > MAX_EVENT_BYTES {
            return Err(ClientError::InvalidResponse(anyhow::anyhow!(
                "Bridge SSE event exceeds the local size limit"
            )));
        }
        Ok(())
    }
}

impl Stream for EventStream {
    type Item = Result<BridgeEvent>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(event) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(event)));
            }
            match Pin::new(&mut this.stream).poll_next(context) {
                Poll::Ready(Some(Ok(bytes))) => {
                    this.buffer.extend_from_slice(&bytes);
                    if let Err(error) = this.consume_buffer() {
                        return Poll::Ready(Some(Err(error)));
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Some(Err(ClientError::Transport(error.into()))));
                }
                Poll::Ready(None) => {
                    if !this.buffer.is_empty() || this.name.is_some() || !this.data.is_empty() {
                        return Poll::Ready(Some(Err(ClientError::InvalidResponse(
                            anyhow::anyhow!("Bridge closed an incomplete SSE event"),
                        ))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resync_event_is_detectable_without_the_daemon_feature() {
        let event = BridgeEvent {
            name: RESYNC_REQUIRED_EVENT.into(),
            data: serde_json::json!({"reason": "event_lag"}),
        };
        assert!(event.requires_resync());
    }
}

#[cfg(all(test, feature = "server"))]
mod cancel_tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
        sync::oneshot,
    };

    fn chunk(data: &str) -> String {
        format!("{:x}\r\n{data}\r\n", data.len())
    }

    #[tokio::test]
    async fn dropping_a_pending_next_event_loses_no_event() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("events.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (first_sent_tx, first_sent_rx) = oneshot::channel::<()>();
        let (resume_tx, resume_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .unwrap();
            // An event split mid-way: the parser must keep this partial state.
            stream
                .write_all(chunk("event: one\ndata: {\"n\":").as_bytes())
                .await
                .unwrap();
            stream.flush().await.unwrap();
            first_sent_tx.send(()).unwrap();
            resume_rx.await.unwrap();
            stream
                .write_all(chunk("1}\n\nevent: two\ndata: {\"n\":2}\n\n").as_bytes())
                .await
                .unwrap();
            stream.write_all(b"0\r\n\r\n").await.unwrap();
            stream.flush().await.unwrap();
        });
        let mut events = EventStream::connect(BridgeClient::new(&socket), "token")
            .await
            .unwrap();
        first_sent_rx.await.unwrap();
        // Poll until the partial bytes are buffered, then drop the pending future.
        for _ in 0..50 {
            let pending =
                tokio::time::timeout(std::time::Duration::from_millis(10), events.next_event())
                    .await;
            assert!(pending.is_err(), "no complete event can be ready yet");
            if !events.buffer.is_empty() || events.name.is_some() {
                break;
            }
        }
        assert_eq!(events.name.as_deref(), Some("one"));
        resume_tx.send(()).unwrap();
        let one = events.next_event().await.unwrap().unwrap();
        assert_eq!(one.name, "one");
        assert_eq!(one.data, serde_json::json!({"n": 1}));
        let two = events.next_event().await.unwrap().unwrap();
        assert_eq!(two.name, "two");
        assert!(events.next_event().await.is_none());
        server.await.unwrap();
    }
}
