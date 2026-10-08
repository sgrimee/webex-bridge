//! Read-only, paginated room discovery for Step 1's test-space allowlist.

use anyhow::{bail, Context, Result};
use reqwest::{header, Client, Url};
use serde::Deserialize;
use std::{collections::HashSet, time::Duration};
use tokio::time::sleep;

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
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
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
}
