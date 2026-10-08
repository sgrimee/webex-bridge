//! Read-only, paginated room discovery for Step 1's test-space allowlist.

use anyhow::{bail, Context, Result};
use reqwest::{header, Client, Url};
use serde::Deserialize;
use std::{collections::HashSet, time::Duration};
use tokio::time::sleep;
use webex::{GlobalId, GlobalIdType};

const ROOMS_URL: &str = "https://webexapis.com/v1/rooms?sortBy=lastactivity&max=1000";

#[derive(Deserialize)]
struct RoomPage {
    items: Vec<RoomCandidate>,
}

/// Limited room metadata used only to find an exact title match.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomCandidate {
    /// Room ID, never a display name.
    pub id: String,
    /// Display title (never printed for non-matching spaces).
    pub title: Option<String>,
    /// Room type, for disambiguation.
    #[serde(rename = "type")]
    pub room_type: Option<String>,
    /// Last activity date, for disambiguation.
    pub last_activity: Option<String>,
}

fn next_page(link: &str) -> Result<Option<Url>> {
    for item in link.split(',') {
        let (Some(left), Some(right)) = (item.find('<'), item.find('>')) else {
            continue;
        };
        if !item[right + 1..].contains("rel=\"next\"") {
            continue;
        }
        let url = Url::parse(&item[left + 1..right])?;
        if url.scheme() != "https"
            || url.host_str() != Some("webexapis.com")
            || url.path() != "/v1/rooms"
        {
            bail!("Webex returned an unsafe room pagination URL");
        }
        return Ok(Some(url));
    }
    Ok(None)
}

fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// Validate a Webex app space link and return its UUID or geo-ID.
pub fn id_from_space_url(link: &str) -> Result<String> {
    let url = Url::parse(link).context("Invalid Webex space URL")?;
    if url.scheme() != "webexteams" || url.host_str() != Some("im") || !url.path().is_empty() {
        bail!("Expected a webexteams://im?space=... link");
    }
    let mut ids = url.query_pairs().filter(|(key, _)| key == "space");
    let id = ids
        .next()
        .context("Webex link has no space ID")?
        .1
        .into_owned();
    if ids.next().is_some() {
        bail!("Webex link has multiple space IDs");
    }
    let _ = GlobalId::new(GlobalIdType::Room, id.clone()).context("Invalid Webex room ID")?;
    Ok(id)
}

/// Read the authorized user's immutable Webex person ID for route sender matching.
pub async fn own_person_id(token: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Me {
        id: String,
    }
    let response = http_client()?
        .get("https://webexapis.com/v1/people/me")
        .bearer_auth(token)
        .send()
        .await?;
    if matches!(response.status().as_u16(), 401 | 403) {
        bail!("auth_required: Webex rejected identity lookup; stop and ask before changing scopes");
    }
    if !response.status().is_success() {
        bail!("Webex identity lookup returned HTTP {}", response.status());
    }
    let id = response
        .json::<Me>()
        .await
        .context("Invalid Webex person response")?
        .id;
    let _ = GlobalId::new(GlobalIdType::Person, id.clone()).context("Invalid Webex person ID")?;
    Ok(id)
}

/// Verify the exact room title via an authenticated, read-only GET by ID.
/// Return its canonical API ID for config/allowlist use, never the URL's UUID.
pub async fn verify_space(token: &str, link: &str, expected_title: &str) -> Result<RoomCandidate> {
    let id = id_from_space_url(link)?;
    let id = GlobalId::new(GlobalIdType::Room, id)?;
    let mut url = Url::parse("https://webexapis.com/v1/rooms/")?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("Invalid rooms API URL"))?
        .push(id.id());
    let response = http_client()?.get(url).bearer_auth(token).send().await?;
    if matches!(response.status().as_u16(), 401 | 403) {
        bail!("auth_required: Webex rejected room lookup; stop and ask before changing scopes");
    }
    if !response.status().is_success() {
        bail!(
            "Webex room lookup returned HTTP {}; check space membership",
            response.status()
        );
    }
    let room: RoomCandidate = response
        .json()
        .await
        .context("Invalid Webex room response")?;
    if room.title.as_deref() != Some(expected_title) {
        bail!(
            "Room ID resolved to title {:?}, not {:?}; do not set the allowlist",
            room.title,
            expected_title
        );
    }
    let _ =
        GlobalId::new(GlobalIdType::Room, room.id.clone()).context("Invalid canonical room ID")?;
    Ok(room)
}

async fn get_page(client: &Client, url: &Url, token: &str) -> Result<reqwest::Response> {
    for attempt in 0..4 {
        let response = client.get(url.clone()).bearer_auth(token).send().await?;
        let status = response.status();
        if matches!(status.as_u16(), 401 | 403) {
            bail!(
                "auth_required: Webex rejected room listing; stop and ask before changing scopes"
            );
        }
        if status.is_success() {
            return Ok(response);
        }
        if !matches!(status.as_u16(), 429 | 502 | 503 | 504) || attempt == 3 {
            bail!("Webex room listing returned HTTP {status}");
        }
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let wait = retry_after.unwrap_or(1 << attempt);
        if wait > 60 {
            bail!("Webex asked to retry in more than 60 seconds; retry the command later");
        }
        sleep(Duration::from_secs(wait)).await;
    }
    unreachable!("the last attempt returns or errors")
}

/// Find all exact title matches, following Webex's Link pagination headers.
/// Never print or log other people's room titles or response bodies.
pub async fn find_by_title(token: &str, title: &str) -> Result<Vec<RoomCandidate>> {
    let client = http_client()?;
    let mut url = Url::parse(ROOMS_URL)?;
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    let mut scanned = 0_usize;
    loop {
        if !seen.insert(url.to_string()) || seen.len() > 1000 {
            bail!("Webex rooms pagination repeated or exceeded the safe page limit");
        }
        if seen.len() % 10 == 0 {
            eprintln!(
                "Scanned {} room pages (no titles or messages logged)",
                seen.len()
            );
        }
        let response = get_page(&client, &url, token).await?;
        let next = response
            .headers()
            .get(header::LINK)
            .map(|value| value.to_str().context("Invalid Webex pagination header"))
            .transpose()?
            .map(next_page)
            .transpose()?
            .flatten();
        let page: RoomPage = response
            .json()
            .await
            .context("Invalid Webex rooms response")?;
        scanned += page.items.len();
        found.extend(
            page.items
                .into_iter()
                .filter(|room| room.title.as_deref() == Some(title)),
        );
        match next {
            Some(next) => url = next,
            None => break,
        }
    }
    eprintln!(
        "Room discovery scanned {} pages and {scanned} room records",
        seen.len()
    );
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_must_stay_on_rooms_endpoint() {
        assert!(next_page("<https://evil.test/v1/rooms>; rel=\"next\"").is_err());
        assert!(
            next_page("<https://webexapis.com/v1/rooms?before=x>; rel=\"next\"")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn parses_space_link_without_trusting_other_urls() {
        assert_eq!(
            id_from_space_url("webexteams://im?space=00000000-0000-4000-8000-00000000a001")
                .unwrap(),
            "00000000-0000-4000-8000-00000000a001"
        );
        assert!(id_from_space_url(
            "https://example.com?space=00000000-0000-4000-8000-00000000a001"
        )
        .is_err());
    }
}
