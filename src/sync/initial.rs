//! Two-phase first-install/newly-joined-room sync.
//! Latest messages become available before the six-month background backfill.

use crate::{
    mirror::{SharedMirror, Upsert},
    sync::history::WebexRest,
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use webex::Room;

/// Counts for a completed latest-page or background batch.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InitialResult {
    /// Malformed or incomplete REST entries skipped without advancing cursors.
    pub skipped: usize,
    /// New canonical message rows.
    pub created: usize,
    /// New edit revisions.
    pub edited: usize,
    /// Whether the whole six-month backfill is complete.
    pub done: bool,
}

fn created_at(message: &webex::Message) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(
        message
            .created
            .as_deref()
            .context("Message has no created time")?,
    )
    .context("Invalid Webex creation time")?
    .with_timezone(&Utc))
}

/// First, store only the latest page; do not pretend the older history is complete.
pub async fn latest_page(
    mirror: &SharedMirror,
    rest: &WebexRest,
    room: &Room,
    page_size: u32,
    cutoff: DateTime<Utc>,
) -> Result<InitialResult> {
    mirror.with(|db| db.upsert_room(room, true)).await?;
    let state = mirror
        .with(|db| db.room_sync(&room.id))
        .await?
        .context("Room sync row missing")?;
    if state.boundary_created_at.is_some() {
        return Ok(InitialResult {
            skipped: 0,
            created: 0,
            edited: 0,
            done: state.initial_done,
        });
    }
    let page = rest.messages_page(&room.id, None, page_size).await?;
    let mut counts = InitialResult {
        skipped: 0,
        created: 0,
        edited: 0,
        done: false,
    };
    let mut newest: Option<(String, String)> = None;
    let mut oldest: Option<String> = None;
    for message in &page {
        let (Some(created), Some(id)) = (message.created.as_deref(), message.id.as_deref()) else {
            counts.skipped += 1;
            continue;
        };
        let Ok(created_at) = created_at(message) else {
            counts.skipped += 1;
            continue;
        };
        if newest.is_none() {
            newest = Some((created.to_owned(), id.to_owned()));
        }
        if created_at < cutoff {
            break;
        }
        match mirror.with(|db| db.upsert_message(message)).await? {
            Upsert::Created(_) => counts.created += 1,
            Upsert::Edited(_) => counts.edited += 1,
            Upsert::Unchanged | Upsert::IgnoredDeleted => {}
        }
        oldest = Some(created.to_owned());
    }
    if let Some((created, id)) = newest {
        mirror
            .with(|db| db.record_boundary(&room.id, &created, &id))
            .await?;
    }
    if let Some(oldest) = oldest {
        mirror
            .with(|db| db.record_oldest(&room.id, &oldest))
            .await?;
    }
    counts.done = page.len() < page_size as usize
        || page
            .last()
            .is_some_and(|message| created_at(message).is_ok_and(|created| created < cutoff));
    if counts.done {
        mirror.with(|db| db.mark_initial_done(&room.id)).await?;
    }
    mirror
        .with(|db| db.mark_room_observed(&room.id, &room.last_activity))
        .await?;
    Ok(counts)
}

/// Continue older pages from the durable oldest stored ID; safe to restart after a crash.
pub async fn backfill(
    mirror: &SharedMirror,
    rest: &WebexRest,
    room_id: &str,
    page_size: u32,
    cutoff: DateTime<Utc>,
) -> Result<InitialResult> {
    let state = mirror
        .with(|db| db.room_sync(room_id))
        .await?
        .context("Room must be initialized first")?;
    if state.initial_done {
        return Ok(InitialResult {
            skipped: 0,
            created: 0,
            edited: 0,
            done: true,
        });
    }
    let mut before = mirror
        .with(|db| db.oldest_message_id(room_id))
        .await?
        .context("Backfill cursor missing; retry latest-page sync")?;
    let mut counts = InitialResult {
        skipped: 0,
        created: 0,
        edited: 0,
        done: false,
    };
    loop {
        let page = rest
            .messages_page(room_id, Some(&before), page_size)
            .await?;
        if page.is_empty() {
            counts.done = true;
            break;
        }
        let page_len = page.len();
        let mut reached_cutoff = false;
        for message in &page {
            let Ok(created_at) = created_at(message) else {
                counts.skipped += 1;
                continue;
            };
            if created_at < cutoff {
                reached_cutoff = true;
                break;
            }
            match mirror.with(|db| db.upsert_message(message)).await? {
                Upsert::Created(_) => counts.created += 1,
                Upsert::Edited(_) => counts.edited += 1,
                Upsert::Unchanged | Upsert::IgnoredDeleted => {}
            }
            if let Some(created) = message.created.as_deref() {
                mirror.with(|db| db.record_oldest(room_id, created)).await?;
            }
        }
        if reached_cutoff || page_len < page_size as usize {
            counts.done = true;
            break;
        }
        let last = page
            .last()
            .and_then(|message| message.id.as_deref())
            .context("Backfill page has no cursor")?;
        if last == before {
            bail!("Webex backfill pagination repeated its cursor")
        }
        before = last.to_owned();
    }
    if counts.done {
        mirror.with(|db| db.mark_initial_done(room_id)).await?;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::Mirror;
    use chrono::Duration as ChronoDuration;
    use reqwest::Url;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn fixture(id: &str, room_id: &str, created: &str) -> webex::Message {
        webex::Message {
            id: Some(id.into()),
            room_id: Some(room_id.into()),
            created: Some(created.into()),
            text: Some("private test".into()),
            ..webex::Message::default()
        }
    }

    #[tokio::test]
    async fn latest_first_then_background_backfills() {
        let server = MockServer::start().await;
        let room_id = "00000000-0000-4000-8000-00000000a001";
        let ids = [
            "00000000-0000-4000-8000-000000000031",
            "00000000-0000-4000-8000-000000000032",
            "00000000-0000-4000-8000-000000000033",
        ];
        let now = Utc::now();
        let recent = now.to_rfc3339();
        let earlier = (now - ChronoDuration::days(1)).to_rfc3339();
        let oldest = (now - ChronoDuration::days(2)).to_rfc3339();
        let page_a = serde_json::json!({"items": [fixture(ids[0], room_id, &recent), fixture(ids[1], room_id, &earlier)]});
        let page_b = serde_json::json!({"items": [fixture(ids[2], room_id, &oldest)]});
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(move |request: &wiremock::Request| {
                if request
                    .url
                    .query_pairs()
                    .any(|(key, _)| key == "beforeMessage")
                {
                    ResponseTemplate::new(200).set_body_json(page_b.clone())
                } else {
                    ResponseTemplate::new(200).set_body_json(page_a.clone())
                }
            })
            .mount(&server)
            .await;
        let room = Room {
            id: room_id.into(),
            title: Some("private title".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: None,
            last_activity: recent,
            creator_id: "person".into(),
            created: earlier,
        };
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mirror = SharedMirror::new(Mirror::in_memory([20_u8; 32]).unwrap());
        let cutoff = now - ChronoDuration::days(180);
        let latest = latest_page(&mirror, &rest, &room, 2, cutoff).await.unwrap();
        assert_eq!(latest.created, 2);
        assert!(!latest.done);
        let state = mirror
            .with(|db| db.room_sync(room_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.boundary_message_id.as_deref(), Some(ids[0]));
        let background = backfill(&mirror, &rest, room_id, 2, cutoff).await.unwrap();
        assert_eq!(background.created, 1);
        assert!(background.done);
        let state = mirror
            .with(|db| db.room_sync(room_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.oldest_stored_at.as_deref(), Some(oldest.as_str()));
    }
}
