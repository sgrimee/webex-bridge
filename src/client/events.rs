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

/// One scope-filtered event from `GET /v1/events`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeEvent {
    /// Daemon event name, such as `message.updated` or `connection.status`.
    pub name: String,
    /// Metadata-only JSON payload. Message text is never present in this stream.
    pub data: Value,
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
