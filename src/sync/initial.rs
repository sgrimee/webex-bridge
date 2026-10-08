//! Two-phase first-install/newly-joined-room sync.
//! Latest messages become available before the six-month background backfill.

use crate::{
    mirror::{Mirror, Upsert},
    sync::history::WebexRest,
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use webex::Room;

/// Counts for a completed latest-page or background batch.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InitialResult {
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
    mirror: &mut Mirror,
    rest: &WebexRest,
    room: &Room,
    page_size: u32,
    cutoff: DateTime<Utc>,
) -> Result<InitialResult> {
    mirror.upsert_room(room, true)?;
    let state = mirror
        .room_sync(&room.id)?
        .context("Room sync row missing")?;
    if state.boundary_created_at.is_some() {
        return Ok(InitialResult {
            created: 0,
            edited: 0,
            done: state.initial_done,
        });
    }
    let page = rest.messages_page(&room.id, None, page_size).await?;
    let mut counts = InitialResult {
        created: 0,
        edited: 0,
        done: false,
    };
    let mut newest: Option<(String, String)> = None;
    let mut oldest: Option<String> = None;
    for message in &page {
        let created = message
            .created
            .as_deref()
            .context("Message has no created time")?;
        let id = message
            .id
            .as_deref()
            .context("Message has no canonical ID")?;
        if newest.is_none() {
            newest = Some((created.to_owned(), id.to_owned()));
        }
        if created_at(message)? < cutoff {
            break;
        }
        match mirror.upsert_message(message)? {
            Upsert::Created(_) => counts.created += 1,
            Upsert::Edited(_) => counts.edited += 1,
            Upsert::Unchanged | Upsert::IgnoredDeleted => {}
        }
        oldest = Some(created.to_owned());
    }
    if let Some((created, id)) = newest {
        mirror.record_boundary(&room.id, &created, &id)?;
    }
    if let Some(oldest) = oldest {
        mirror.record_oldest(&room.id, &oldest)?;
    }
    counts.done = page.len() < page_size as usize
        || page
            .last()
            .is_some_and(|message| created_at(message).is_ok_and(|created| created < cutoff));
    if counts.done {
        mirror.mark_initial_done(&room.id)?;
    }
    mirror.mark_room_observed(&room.id, &room.last_activity)?;
    Ok(counts)
}

/// Continue older pages from the durable oldest stored ID; safe to restart after a crash.
pub async fn backfill(
    mirror: &mut Mirror,
    rest: &WebexRest,
    room_id: &str,
    page_size: u32,
    cutoff: DateTime<Utc>,
) -> Result<InitialResult> {
    let state = mirror
        .room_sync(room_id)?
        .context("Room must be initialized first")?;
    if state.initial_done {
        return Ok(InitialResult {
            created: 0,
            edited: 0,
            done: true,
        });
    }
    let mut before = mirror
        .oldest_message_id(room_id)?
        .context("Backfill cursor missing; retry latest-page sync")?;
    let mut counts = InitialResult {
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
            if created_at(message)? < cutoff {
                reached_cutoff = true;
                break;
            }
            match mirror.upsert_message(message)? {
                Upsert::Created(_) => counts.created += 1,
                Upsert::Edited(_) => counts.edited += 1,
                Upsert::Unchanged | Upsert::IgnoredDeleted => {}
            }
            mirror.record_oldest(
                room_id,
                message
                    .created
                    .as_deref()
                    .context("Message has no created time")?,
            )?;
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
        mirror.mark_initial_done(room_id)?;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut mirror = Mirror::in_memory([20_u8; 32]).unwrap();
        let cutoff = now - ChronoDuration::days(180);
        let latest = latest_page(&mut mirror, &rest, &room, 2, cutoff)
            .await
            .unwrap();
        assert_eq!(latest.created, 2);
        assert!(!latest.done);
        assert_eq!(
            mirror
                .room_sync(room_id)
                .unwrap()
                .unwrap()
                .boundary_message_id
                .as_deref(),
            Some(ids[0])
        );
        let background = backfill(&mut mirror, &rest, room_id, 2, cutoff)
            .await
            .unwrap();
        assert_eq!(background.created, 1);
        assert!(background.done);
        assert_eq!(
            mirror
                .room_sync(room_id)
                .unwrap()
                .unwrap()
                .oldest_stored_at
                .as_deref(),
            Some(oldest.as_str())
        );
    }
}
