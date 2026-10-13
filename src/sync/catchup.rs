//! Reconnect catch-up: page backwards to a durable boundary, with explicit gaps.
//! Never move the boundary past an unvisited page; a crash simply replays safely.

use crate::{
    mirror::{RoomSync, SharedMirror, Upsert},
    sync::history::WebexRest,
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use webex::Room;

/// Counts and a detectable gap; no message bodies leave the sync engine.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CatchupResult {
    /// REST messages visited since the previous durable boundary.
    pub visited: usize,
    /// Newly inserted canonical messages.
    pub created: usize,
    /// Newly appended edit revisions.
    pub edited: usize,
    /// The previous boundary (or a known older stored message) was reached.
    pub boundary_reached: bool,
    /// A missing range beyond age limit or deleted boundary requires user notice.
    pub gap: Option<(String, String)>,
}

/// Parse the `180d` config limit. Reject malformed or unbounded values.
pub fn max_age(setting: &str) -> Result<ChronoDuration> {
    let days = setting
        .strip_suffix('d')
        .context("catchup_max_age must be days, e.g. 180d")?
        .parse::<i64>()
        .context("Invalid catchup_max_age")?;
    if !(1..=3650).contains(&days) {
        bail!("catchup_max_age must be between 1 and 3650 days");
    }
    Ok(ChronoDuration::days(days))
}

fn parsed(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .context("Invalid Webex activity timestamp")?
        .with_timezone(&Utc))
}

/// Whether room metadata indicates possible unseen activity since the boundary.
/// Initial rooms are handled by `initial`, not by this predicate.
pub fn changed_room(room: &Room, state: &RoomSync) -> Result<bool> {
    let Some(watermark) = state
        .observed_last_activity
        .as_deref()
        .or(state.boundary_created_at.as_deref())
    else {
        return Ok(false);
    };
    Ok(parsed(&room.last_activity)? > parsed(watermark)?)
}

/// Reconcile newer messages for one already-initialized room.
/// If interrupted, the old boundary remains, and replay deduplicates safely.
pub async fn catch_up_room(
    mirror: &SharedMirror,
    rest: &WebexRest,
    room: &Room,
    cutoff: DateTime<Utc>,
    page_size: u32,
) -> Result<CatchupResult> {
    let state = mirror
        .with(|db| db.room_sync(&room.id))
        .await?
        .context("Room must be mirrored before catch-up")?;
    let boundary_id = state
        .boundary_message_id
        .as_deref()
        .context("Initial sync boundary missing")?;
    let boundary_time = parsed(
        state
            .boundary_created_at
            .as_deref()
            .context("Initial sync time missing")?,
    )?;
    let mut result = CatchupResult {
        visited: 0,
        created: 0,
        edited: 0,
        boundary_reached: false,
        gap: None,
    };
    let mut before: Option<String> = None;
    let mut newest: Option<(String, String)> = None;
    let mut oldest_new: Option<String> = None;
    loop {
        let page = rest
            .messages_page(&room.id, before.as_deref(), page_size)
            .await?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        let mut reached_age = false;
        for message in &page {
            let id = message
                .id
                .as_deref()
                .context("Webex page message missing ID")?;
            let created = message
                .created
                .as_deref()
                .context("Webex page message missing created")?;
            let created_dt = parsed(created)?;
            if newest.is_none() {
                newest = Some((created.to_owned(), id.to_owned()));
            }
            if created_dt < cutoff {
                reached_age = true;
                break;
            }
            // A deleted boundary ID may no longer be listed. A known older
            // message proves we crossed the old boundary without skipping new posts.
            let at_old_boundary = id == boundary_id
                || (created_dt <= boundary_time
                    && mirror.with(|db| db.contains_message(id)).await?);
            match mirror.with(|db| db.upsert_message(message)).await? {
                Upsert::Created(_) => result.created += 1,
                Upsert::Edited(_) => result.edited += 1,
                Upsert::Unchanged | Upsert::IgnoredDeleted => {}
            }
            result.visited += 1;
            oldest_new = Some(created.to_owned());
            if at_old_boundary {
                result.boundary_reached = true;
                break;
            }
        }
        if reached_age || result.boundary_reached {
            break;
        }
        if page_len < page_size as usize {
            break;
        }
        let last = page
            .last()
            .and_then(|msg| msg.id.as_deref())
            .context("Webex page has no cursor message")?;
        if before.as_deref() == Some(last) {
            bail!("Webex message pagination repeated its cursor")
        }
        before = Some(last.to_owned());
    }
    if let Some(oldest) = oldest_new {
        mirror
            .with(|db| db.record_oldest(&room.id, &oldest))
            .await?;
    }
    if let Some((latest_time, latest_id)) = newest {
        // All pages must be durable before advancing this boundary. On crash,
        // the old cursor safely replays any partial page set.
        mirror
            .with(|db| db.record_boundary(&room.id, &latest_time, &latest_id))
            .await?;
        if !result.boundary_reached {
            let from = state.boundary_created_at.context("Boundary time missing")?;
            mirror
                .with(|db| db.record_gap(&room.id, &from, &latest_time))
                .await?;
            result.gap = Some((from, latest_time));
        }
    } else if !result.boundary_reached {
        let from = state.boundary_created_at.context("Boundary time missing")?;
        mirror
            .with(|db| db.record_gap(&room.id, &from, &room.last_activity))
            .await?;
        result.gap = Some((from, room.last_activity.clone()));
    }
    mirror
        .with(|db| db.mark_room_observed(&room.id, &room.last_activity))
        .await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::Mirror;
    use reqwest::Url;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn room(id: &str, last: &str) -> Room {
        Room {
            id: id.into(),
            title: Some("test room".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: None,
            last_activity: last.into(),
            creator_id: "person".into(),
            created: "2026-10-01T00:00:00Z".into(),
        }
    }
    fn msg(id: &str, room_id: &str, created: &str) -> webex::Message {
        webex::Message {
            id: Some(id.into()),
            room_id: Some(room_id.into()),
            created: Some(created.into()),
            text: Some("private fixture".into()),
            ..webex::Message::default()
        }
    }

    #[tokio::test]
    async fn stores_pages_then_advances_boundary_and_deduplicates() {
        let server = MockServer::start().await;
        let room_id = "00000000-0000-4000-8000-00000000a001";
        let old_id = "00000000-0000-4000-8000-000000000001";
        let new_a = "00000000-0000-4000-8000-000000000002";
        let new_b = "00000000-0000-4000-8000-000000000003";
        let now = Utc::now();
        let old_time = (now - ChronoDuration::days(2)).to_rfc3339();
        let new_a_time = (now - ChronoDuration::hours(2)).to_rfc3339();
        let new_b_time = (now - ChronoDuration::hours(1)).to_rfc3339();
        let pages = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&pages);
        let first = serde_json::json!({"items": [msg(new_b, room_id, &new_b_time), msg(new_a, room_id, &new_a_time)]});
        let second = serde_json::json!({"items": [msg(old_id, room_id, &old_time)]});
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(move |request: &wiremock::Request| {
                seen.fetch_add(1, Ordering::SeqCst);
                if request
                    .url
                    .query_pairs()
                    .any(|(key, _)| key == "beforeMessage")
                {
                    ResponseTemplate::new(200).set_body_json(second.clone())
                } else {
                    ResponseTemplate::new(200).set_body_json(first.clone())
                }
            })
            .mount(&server)
            .await;
        let mut mirror = Mirror::in_memory([5_u8; 32]).unwrap();
        let room = room(room_id, &new_b_time);
        mirror.upsert_room(&room, true).unwrap();
        mirror
            .upsert_message(&msg(old_id, room_id, &old_time))
            .unwrap();
        mirror.record_boundary(room_id, &old_time, old_id).unwrap();
        mirror.record_oldest(room_id, &old_time).unwrap();
        assert!(changed_room(&room, &mirror.room_sync(room_id).unwrap().unwrap()).unwrap());
        let mirror = SharedMirror::new(mirror);
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let result = catch_up_room(&mirror, &rest, &room, now - ChronoDuration::days(180), 2)
            .await
            .unwrap();
        assert_eq!(result.created, 2);
        assert!(result.boundary_reached);
        assert!(result.gap.is_none());
        assert_eq!(pages.load(Ordering::SeqCst), 2);
        let state = mirror
            .with(|db| db.room_sync(room_id))
            .await
            .unwrap()
            .unwrap();
        assert!(!changed_room(&room, &state).unwrap());
    }

    #[tokio::test]
    async fn crash_before_old_boundary_replays_without_skipping() {
        let server = MockServer::start().await;
        let room_id = "00000000-0000-4000-8000-00000000a001";
        let old_id = "00000000-0000-4000-8000-000000000011";
        let new_id = "00000000-0000-4000-8000-000000000012";
        let now = Utc::now();
        let old_time = (now - ChronoDuration::days(2)).to_rfc3339();
        let new_time = now.to_rfc3339();
        let second_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&second_calls);
        let first_page = serde_json::json!({"items": [msg(new_id, room_id, &new_time)]});
        let old_page = serde_json::json!({"items": [msg(old_id, room_id, &old_time)]});
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(move |request: &wiremock::Request| {
                if request
                    .url
                    .query_pairs()
                    .any(|(key, _)| key == "beforeMessage")
                {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        ResponseTemplate::new(503)
                    } else {
                        ResponseTemplate::new(200).set_body_json(old_page.clone())
                    }
                } else {
                    ResponseTemplate::new(200).set_body_json(first_page.clone())
                }
            })
            .mount(&server)
            .await;
        let mut mirror = Mirror::in_memory([13_u8; 32]).unwrap();
        let room = room(room_id, &new_time);
        mirror.upsert_room(&room, true).unwrap();
        mirror
            .upsert_message(&msg(old_id, room_id, &old_time))
            .unwrap();
        mirror.record_boundary(room_id, &old_time, old_id).unwrap();
        let mirror = SharedMirror::new(mirror);
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        assert!(
            catch_up_room(&mirror, &rest, &room, now - ChronoDuration::days(180), 1)
                .await
                .is_err()
        );
        assert!(mirror.with(|db| db.contains_message(new_id)).await.unwrap());
        let state = mirror
            .with(|db| db.room_sync(room_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.boundary_message_id.as_deref(), Some(old_id));
        let result = catch_up_room(&mirror, &rest, &room, now - ChronoDuration::days(180), 1)
            .await
            .unwrap();
        assert_eq!(result.created, 0); // deduplicated the page stored before the crash
        assert!(result.boundary_reached);
        let state = mirror
            .with(|db| db.room_sync(room_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.boundary_message_id.as_deref(), Some(new_id));
    }

    #[tokio::test]
    async fn age_limit_records_gap_instead_of_claiming_contiguity() {
        let server = MockServer::start().await;
        let room_id = "00000000-0000-4000-8000-00000000a001";
        let old_id = "00000000-0000-4000-8000-000000000021";
        let new_id = "00000000-0000-4000-8000-000000000022";
        let aged_id = "00000000-0000-4000-8000-000000000023";
        let now = Utc::now();
        let old_time = (now - ChronoDuration::days(300)).to_rfc3339();
        let aged_time = (now - ChronoDuration::days(190)).to_rfc3339();
        let new_time = now.to_rfc3339();
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [msg(new_id, room_id, &new_time), msg(aged_id, room_id, &aged_time)]
            })))
            .mount(&server)
            .await;
        let mut mirror = Mirror::in_memory([14_u8; 32]).unwrap();
        let room = room(room_id, &new_time);
        mirror.upsert_room(&room, true).unwrap();
        mirror
            .upsert_message(&msg(old_id, room_id, &old_time))
            .unwrap();
        mirror.record_boundary(room_id, &old_time, old_id).unwrap();
        let mirror = SharedMirror::new(mirror);
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let result = catch_up_room(&mirror, &rest, &room, now - ChronoDuration::days(180), 2)
            .await
            .unwrap();
        assert_eq!(result.created, 1);
        assert!(!result.boundary_reached);
        assert!(result.gap.is_some());
        let state = mirror
            .with(|db| db.room_sync(room_id))
            .await
            .unwrap()
            .unwrap();
        assert!(state.last_result.unwrap().starts_with("gap:"));
    }

    #[tokio::test]
    async fn live_write_is_not_blocked_by_slow_catchup_http() {
        let server = MockServer::start().await;
        let room_id = "00000000-0000-4000-8000-00000000a001";
        let old_id = "00000000-0000-4000-8000-000000000041";
        let new_id = "00000000-0000-4000-8000-000000000042";
        let live_id = "00000000-0000-4000-8000-000000000043";
        let now = Utc::now();
        let old_time = (now - ChronoDuration::days(1)).to_rfc3339();
        let new_time = now.to_rfc3339();
        let started = Arc::new(AtomicBool::new(false));
        let notify = Arc::clone(&started);
        let page = serde_json::json!({"items": [msg(new_id, room_id, &new_time), msg(old_id, room_id, &old_time)]});
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(move |_: &wiremock::Request| {
                notify.store(true, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_json(page.clone())
                    .set_delay(std::time::Duration::from_millis(500))
            })
            .mount(&server)
            .await;
        let mut db = Mirror::in_memory([15_u8; 32]).unwrap();
        let room = room(room_id, &new_time);
        db.upsert_room(&room, true).unwrap();
        db.upsert_message(&msg(old_id, room_id, &old_time)).unwrap();
        db.record_boundary(room_id, &old_time, old_id).unwrap();
        let mirror = SharedMirror::new(db);
        let background = mirror.clone();
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let task = tokio::spawn(async move {
            catch_up_room(
                &background,
                &rest,
                &room,
                now - ChronoDuration::days(180),
                50,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !started.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let live = msg(live_id, room_id, &new_time);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            mirror.with(|db| db.upsert_message(&live)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(result, Upsert::Created(_)));
        assert!(task.await.unwrap().unwrap().boundary_reached);
    }

    #[test]
    fn age_setting_rejects_unbounded_values() {
        assert_eq!(max_age("180d").unwrap(), ChronoDuration::days(180));
        assert!(max_age("0d").is_err());
        assert!(max_age("10000d").is_err());
        assert!(max_age("6months").is_err());
    }
}
