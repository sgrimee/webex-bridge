//! Bounded, read-only Webex REST hydration and paged history.
//! Webex response bodies and bearer tokens are never logged.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use reqwest::{header, Client, Response, StatusCode, Url};
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;
use webex::{GlobalId, GlobalIdType, Message, Person, Room};

const REST_BASE: &str = "https://webexapis.com/v1/";

/// A token-bearing Webex REST client, owned by the daemon sync engine.
/// No Debug implementation: accidental diagnostics must not print its token.
pub struct WebexRest {
    client: Client,
    base: Url,
    token: String,
}

#[derive(Deserialize)]
struct Page<T> {
    items: Vec<T>,
}

impl WebexRest {
    /// Create a production REST client with bounded requests and no redirects.
    pub fn new(token: String) -> Result<Self> {
        Self::with_base(token, Url::parse(REST_BASE)?)
    }

    fn with_base(token: String, base: Url) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            base,
            token,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests(base: Url) -> Result<Self> {
        Self::with_base("fake-token-never-logged".into(), base)
    }

    fn endpoint(&self, resource: &str, id: Option<&str>) -> Result<Url> {
        let mut url = self.base.join(resource)?;
        if let Some(id) = id {
            url.path_segments_mut()
                .map_err(|()| anyhow::anyhow!("Invalid Webex REST URL"))?
                .push(id);
        }
        Ok(url)
    }

    async fn get(&self, url: Url) -> Result<Option<Response>> {
        for attempt in 0..5 {
            let response = self
                .client
                .get(url.clone())
                .bearer_auth(&self.token)
                .send()
                .await?;
            let status = response.status();
            if status.is_success() {
                return Ok(Some(response));
            }
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if matches!(status.as_u16(), 401 | 403) {
                bail!("auth_required: Webex REST returned HTTP {status}");
            }
            if status != StatusCode::TOO_MANY_REQUESTS || attempt == 4 {
                bail!("Webex REST returned HTTP {status}");
            }
            let wait = retry_after(response.headers())?
                .unwrap_or_else(|| Duration::from_secs(1 << attempt));
            if wait > Duration::from_secs(300) {
                bail!("Webex Retry-After exceeds five minutes; postpone this room");
            }
            sleep(wait).await;
        }
        unreachable!("last retry returns or errors")
    }

    /// Get a room page sorted by most recent activity; follow only same-origin links.
    pub async fn rooms_page(&self, next: Option<&Url>) -> Result<(Vec<Room>, Option<Url>)> {
        let url = if let Some(next) = next {
            self.validate_next(next, "rooms")?;
            next.clone()
        } else {
            let mut url = self.endpoint("rooms", None)?;
            url.query_pairs_mut()
                .append_pair("sortBy", "lastactivity")
                .append_pair("max", "1000");
            url
        };
        let response = self
            .get(url)
            .await?
            .context("Webex room list returned 404")?;
        let next = response
            .headers()
            .get(header::LINK)
            .map(|header| header.to_str().context("Invalid Webex Link header"))
            .transpose()?
            .map(|link| self.parse_next(link, "rooms"))
            .transpose()?
            .flatten();
        let rooms = response
            .json::<Page<Room>>()
            .await
            .context("Invalid Webex room list response")?
            .items;
        Ok((rooms, next))
    }

    /// List one page of messages in reverse chronological order.
    pub async fn messages_page(
        &self,
        room_id: &str,
        before_message: Option<&str>,
        max: u32,
    ) -> Result<Vec<Message>> {
        let _ = GlobalId::new(GlobalIdType::Room, room_id.to_owned())?;
        if !(1..=100).contains(&max) {
            bail!("Webex message page size must be 1..=100");
        }
        let mut url = self.endpoint("messages", None)?;
        url.query_pairs_mut()
            .append_pair("roomId", room_id)
            .append_pair("max", &max.to_string());
        if let Some(before) = before_message {
            let _ = GlobalId::new(GlobalIdType::Message, before.to_owned())?;
            url.query_pairs_mut().append_pair("beforeMessage", before);
        }
        let response = self
            .get(url)
            .await?
            .context("Webex message list returned 404")?;
        Ok(response
            .json::<Page<Message>>()
            .await
            .context("Invalid Webex message list response")?
            .items)
    }

    /// Hydrate one canonical message; a 404 is a verified deletion only for a known ID.
    pub async fn message(&self, id: &str) -> Result<Option<Message>> {
        let id = GlobalId::new(GlobalIdType::Message, id.to_owned())?;
        let url = self.endpoint("messages", Some(id.id()))?;
        let Some(response) = self.get(url).await? else {
            return Ok(None);
        };
        Ok(Some(
            response
                .json::<Message>()
                .await
                .context("Invalid Webex message response")?,
        ))
    }

    /// Hydrate one room for membership verification, not just a Mercury verb.
    pub async fn room(&self, id: &str) -> Result<Option<Room>> {
        let id = GlobalId::new(GlobalIdType::Room, id.to_owned())?;
        let Some(response) = self.get(self.endpoint("rooms", Some(id.id()))?).await? else {
            return Ok(None);
        };
        Ok(Some(
            response
                .json::<Room>()
                .await
                .context("Invalid Webex room response")?,
        ))
    }

    /// Hydrate one person for encrypted UI metadata.
    pub async fn person(&self, id: &str) -> Result<Option<Person>> {
        let id = GlobalId::new(GlobalIdType::Person, id.to_owned())?;
        let Some(response) = self.get(self.endpoint("people", Some(id.id()))?).await? else {
            return Ok(None);
        };
        Ok(Some(
            response
                .json::<Person>()
                .await
                .context("Invalid Webex person response")?,
        ))
    }

    fn validate_next(&self, url: &Url, resource: &str) -> Result<()> {
        let path = self.base.join(resource)?.path().to_owned();
        if url.scheme() != self.base.scheme()
            || url.host_str() != self.base.host_str()
            || url.port_or_known_default() != self.base.port_or_known_default()
            || url.path() != path
        {
            bail!("Unsafe Webex pagination URL rejected");
        }
        Ok(())
    }

    fn parse_next(&self, link: &str, resource: &str) -> Result<Option<Url>> {
        for part in link.split(',') {
            let (Some(start), Some(end)) = (part.find('<'), part.find('>')) else {
                continue;
            };
            if !part[end + 1..].contains("rel=\"next\"") && !part[end + 1..].contains("rel=next") {
                continue;
            }
            let url = Url::parse(&part[start + 1..end])?;
            self.validate_next(&url, resource)?;
            return Ok(Some(url));
        }
        Ok(None)
    }
}

fn retry_after(headers: &header::HeaderMap) -> Result<Option<Duration>> {
    let Some(value) = headers.get(header::RETRY_AFTER) else {
        return Ok(None);
    };
    let value = value.to_str().context("Invalid Retry-After header")?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Ok(Some(Duration::from_secs(seconds)));
    }
    let date = chrono::DateTime::parse_from_rfc2822(value).context("Invalid Retry-After date")?;
    let wait = date
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or(Duration::ZERO);
    Ok(Some(wait))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn messages_page_retries_429_without_exposing_body() {
        let server = MockServer::start().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&attempts);
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(move |_: &wiremock::Request| {
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(429).insert_header("Retry-After", "0")
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "items": [{"id":"id-1","roomId":"room-1","text":"private test content"}]
                    }))
                }
            })
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/v1/", server.uri())).unwrap();
        let rest = WebexRest::for_tests(base).unwrap();
        let room = "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let page = rest.messages_page(room, None, 50).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rejects_cross_origin_pagination() {
        let server = MockServer::start().await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        assert!(rest
            .rooms_page(Some(
                &Url::parse("https://evil.example/v1/rooms?next=1").unwrap()
            ))
            .await
            .is_err());
    }

    #[test]
    fn parses_retry_after_seconds_and_http_date() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::RETRY_AFTER, "3".parse().unwrap());
        assert_eq!(retry_after(&headers).unwrap(), Some(Duration::from_secs(3)));
        headers.insert(
            header::RETRY_AFTER,
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&headers).unwrap(), Some(Duration::ZERO));
    }
}
