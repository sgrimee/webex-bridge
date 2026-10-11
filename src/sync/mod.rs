//! Mercury live sync plus restart reconciliation and two-phase initial history.
//! There is no steady-state polling: scans run on startup/reconnect/join only.

pub mod catchup;
pub mod history;
pub mod initial;
pub mod live;
pub mod recovery;

use crate::{config::Config, mirror::SharedMirror};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use history::WebexRest;
use std::collections::HashSet;
use webex::Room;

/// Metadata-only progress summary, safe for daemon logs/status.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct SyncSummary {
    /// Rooms discovered in the account or explicitly selected in dev mode.
    pub rooms: usize,
    /// Latest-page initial syncs completed.
    pub initial_rooms: usize,
    /// Messages newly stored during catch-up/initial/backfill.
    pub created: usize,
    /// Edit revisions discovered during catch-up/revalidation.
    pub edited: usize,
    /// Malformed/incomplete REST messages skipped without storing content.
    pub skipped: usize,
    /// Verified deleted messages whose ciphertext was purged.
    pub deleted: usize,
    /// Explicit unbridgeable time gaps.
    pub gaps: usize,
    /// Rooms whose background backfill finished.
    pub backfilled_rooms: usize,
    /// Room phases that failed with sanitized metadata and will retry on reconnect.
    pub failed_rooms: usize,
    /// Opaque room IDs whose committed history/metadata changed during this run.
    pub changed_rooms: Vec<String>,
    /// Opaque room IDs whose membership was committed as departed.
    pub departed_rooms: Vec<String>,
}

fn activity(room: &Room) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(&room.last_activity)
        .context("Webex room has invalid lastActivity")?
        .with_timezone(&Utc))
}

/// Persist only a small, non-sensitive failure category; never response text.
fn failure_kind(error: &anyhow::Error) -> &'static str {
    let detail = error.to_string();
    if detail.contains("auth_required") {
        "auth"
    } else if detail.contains("HTTP 429") {
        "rate_limited"
    } else if detail.contains("HTTP 5") {
        "server"
    } else if detail.contains("404") {
        "not_found"
    } else if detail.contains("timed out") || detail.contains("timeout") {
        "timeout"
    } else if detail.contains("pagination") {
        "pagination"
    } else if detail.contains("timestamp") {
        "timestamp"
    } else {
        "other"
    }
}

/// Start after Mercury is connected, prioritize recent rooms, then backfill.
/// Pass `dev_room` only with a configured development allowlist for limited tests.
/// A reconnect cancels this run and starts a fresh one with a new token.
pub async fn synchronize_once(
    mirror: &SharedMirror,
    rest: &WebexRest,
    config: &Config,
    dev_room: Option<&str>,
) -> Result<SyncSummary> {
    if let Some(room_id) = dev_room {
        config.check_write_room(room_id)?;
    }
    let page_size = config.webex.initial_page_size;
    if !(1..=100).contains(&page_size) {
        bail!("initial_page_size must be 1..=100");
    }
    let cutoff = Utc::now() - catchup::max_age(&config.webex.catchup_max_age)?;
    let mut rooms = Vec::new();
    let mut next = None;
    let mut seen = HashSet::new();
    loop {
        let (page, next_url) = rest.rooms_page(next.as_ref()).await?;
        rooms.extend(
            page.into_iter()
                .filter(|room| dev_room.is_none_or(|id| room.id == id)),
        );
        match next_url {
            Some(url) => {
                if !seen.insert(url.to_string()) || seen.len() > 1000 {
                    bail!("Webex room pagination repeated or exceeded 1000 pages");
                }
                next = Some(url);
            }
            None => break,
        }
    }
    if dev_room.is_some() && rooms.len() != 1 {
        bail!("Dev test room missing or duplicated in authorized Webex rooms");
    }
    // The REST listing is authoritative only after every page completed. In
    // normal mode, retain history for departed rooms but exclude them from
    // active sync progress and retry counts. Never do this for a dev-room
    // scan, which deliberately filters the authoritative listing.
    let departed_rooms = if dev_room.is_none() {
        let observed_room_ids = rooms
            .iter()
            .map(|room| room.id.clone())
            .collect::<HashSet<_>>();
        mirror
            .with(|db| db.mark_unobserved_rooms_left_ids(&observed_room_ids))
            .await?
    } else {
        Vec::new()
    };
    let mut prioritized = rooms
        .into_iter()
        .map(|room| Ok((activity(&room)?, room)))
        .collect::<Result<Vec<_>>>()?;
    prioritized.sort_by(|(a, _), (b, _)| b.cmp(a));
    let rooms: Vec<Room> = prioritized.into_iter().map(|(_, room)| room).collect();
    let mut summary = SyncSummary {
        rooms: rooms.len(),
        departed_rooms,
        ..SyncSummary::default()
    };
    // Stage 1: room metadata and the latest page before any deep backfill.
    for room in &rooms {
        let state = mirror
            .with(|db| {
                db.upsert_room(room, true)?;
                db.room_sync(&room.id)
            })
            .await?
            .context("Room sync row missing")?;
        if state.boundary_created_at.is_none() {
            match initial::latest_page(mirror, rest, room, page_size, cutoff).await {
                Ok(outcome) => {
                    summary.initial_rooms += 1;
                    summary.created += outcome.created;
                    summary.edited += outcome.edited;
                    summary.skipped += outcome.skipped;
                    if outcome.created != 0 || outcome.edited != 0 {
                        summary.changed_rooms.push(room.id.clone());
                    }
                }
                Err(error) => {
                    mirror
                        .with(|db| {
                            db.record_sync_failure(&room.id, "initial", failure_kind(&error))
                        })
                        .await?;
                    summary.failed_rooms += 1;
                }
            }
        }
    }
    // Stage 2: changed rooms recover the newest gaps. Revalidation discovers
    // old edits/deletes that message-created-at boundaries cannot detect.
    for room in &rooms {
        let state = mirror
            .with(|db| db.room_sync(&room.id))
            .await?
            .context("Room sync row missing")?;
        if state.boundary_created_at.is_some() && catchup::changed_room(room, &state)? {
            match catchup::catch_up_room(mirror, rest, room, cutoff, page_size).await {
                Ok(outcome) => {
                    summary.created += outcome.created;
                    summary.edited += outcome.edited;
                    summary.gaps += usize::from(outcome.gap.is_some());
                    if outcome.created != 0 || outcome.edited != 0 || outcome.gap.is_some() {
                        summary.changed_rooms.push(room.id.clone());
                    }
                    match live::reconcile_room(mirror, rest, &room.id).await {
                        Ok(checked) => {
                            summary.edited += checked.edited;
                            summary.deleted += checked.deleted;
                            if checked.edited != 0 || checked.deleted != 0 {
                                summary.changed_rooms.push(room.id.clone());
                            }
                        }
                        Err(error) => {
                            mirror
                                .with(|db| {
                                    db.record_sync_failure(
                                        &room.id,
                                        "reconcile",
                                        failure_kind(&error),
                                    )
                                })
                                .await?;
                            summary.failed_rooms += 1;
                        }
                    }
                }
                Err(error) => {
                    mirror
                        .with(|db| {
                            db.record_sync_failure(&room.id, "catchup", failure_kind(&error))
                        })
                        .await?;
                    summary.failed_rooms += 1;
                }
            }
        }
    }
    // Stage 3: background pages, most recently active rooms first.
    for room in &rooms {
        let state = mirror
            .with(|db| db.room_sync(&room.id))
            .await?
            .context("Room sync row missing")?;
        // A failed latest-page request has no durable oldest cursor. Do not
        // misclassify that retryable initial failure as a backfill failure.
        if !state.initial_done && state.boundary_created_at.is_some() {
            match initial::backfill(mirror, rest, &room.id, page_size, cutoff).await {
                Ok(outcome) => {
                    summary.created += outcome.created;
                    summary.edited += outcome.edited;
                    summary.skipped += outcome.skipped;
                    summary.backfilled_rooms += usize::from(outcome.done);
                    if outcome.created != 0 || outcome.edited != 0 {
                        summary.changed_rooms.push(room.id.clone());
                    }
                }
                Err(error) => {
                    mirror
                        .with(|db| {
                            db.record_sync_failure(&room.id, "backfill", failure_kind(&error))
                        })
                        .await?;
                    summary.failed_rooms += 1;
                }
            }
        }
    }
    if let Some(retention) = config.webex.retention_max_age.as_deref() {
        let retention_cutoff = (Utc::now() - catchup::max_age(retention)?).to_rfc3339();
        let _ = mirror.with(|db| db.prune_before(&retention_cutoff)).await?;
    }
    summary.changed_rooms.sort();
    summary.changed_rooms.dedup();
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::DevConfig, mirror::Mirror};
    use reqwest::Url;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    fn room(id: &str, last: &str) -> Room {
        Room {
            id: id.into(),
            title: Some("private title".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: None,
            last_activity: last.into(),
            creator_id: "person".into(),
            created: last.into(),
        }
    }

    #[tokio::test]
    async fn dev_room_sync_stores_only_allowed_room_with_encrypted_message() {
        let server = MockServer::start().await;
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let other = "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDk5";
        let message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let now = Utc::now().to_rfc3339();
        Mock::given(method("GET"))
            .and(path("/v1/rooms"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [room(room_id, &now), room(other, &now)]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{"id":message_id,"roomId":room_id,"created":now,"text":"private test body"}]
            }))).expect(1).mount(&server).await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mirror = SharedMirror::new(Mirror::in_memory([77_u8; 32]).unwrap());
        let config = Config {
            dev: Some(DevConfig {
                write_allowlist: vec![room_id.into()],
                secret_source: crate::config::DevSecretSource::Keychain,
            }),
            ..Config::default()
        };
        let summary = synchronize_once(&mirror, &rest, &config, Some(room_id))
            .await
            .unwrap();
        assert_eq!(summary.rooms, 1);
        assert_eq!(summary.created, 1);
        assert_eq!(summary.changed_rooms, vec![room_id.to_owned()]);
        assert!(summary.departed_rooms.is_empty());
        assert!(!mirror.with(|db| db.has_room(other)).await.unwrap());
        assert_eq!(
            mirror
                .with(|db| db.message_body(message_id))
                .await
                .unwrap()
                .as_deref(),
            Some("private test body")
        );
    }

    #[tokio::test]
    async fn unchanged_room_is_not_paged_again() {
        let server = MockServer::start().await;
        let ready_room =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDk5";
        let new_room =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let now = Utc::now().to_rfc3339();
        let ready = room(ready_room, &now);
        let newly_joined = room(new_room, &now);
        Mock::given(method("GET"))
            .and(path("/v1/rooms"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [ready.clone(), newly_joined.clone()]
            })))
            .mount(&server)
            .await;
        // If the unchanged room were paged, no mock would match and the sync
        // would fail. The new room alone must fetch its first page.
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .and(query_param("roomId", new_room))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{"id": message_id, "roomId": new_room, "created": now, "text": "private fixture"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mut db = Mirror::in_memory([78_u8; 32]).unwrap();
        db.upsert_room(&ready, true).unwrap();
        db.record_boundary(ready_room, &now, "already-mirrored")
            .unwrap();
        db.record_oldest(ready_room, &now).unwrap();
        db.mark_initial_done(ready_room).unwrap();
        db.mark_room_observed(ready_room, &now).unwrap();
        let mirror = SharedMirror::new(db);

        let summary = synchronize_once(&mirror, &rest, &Config::default(), None)
            .await
            .unwrap();
        assert_eq!(summary.rooms, 2);
        assert_eq!(summary.initial_rooms, 1);
        assert_eq!(summary.created, 1);
        assert_eq!(summary.changed_rooms, vec![new_room.to_owned()]);
        assert!(
            mirror
                .with(|db| db.room_sync(ready_room))
                .await
                .unwrap()
                .unwrap()
                .initial_done
        );
        assert!(
            mirror
                .with(|db| db.room_sync(new_room))
                .await
                .unwrap()
                .unwrap()
                .initial_done
        );
    }

    #[tokio::test]
    async fn complete_room_listing_reports_committed_departures() {
        let server = MockServer::start().await;
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        Mock::given(method("GET"))
            .and(path("/v1/rooms"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"items": []})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mut db = Mirror::in_memory([80_u8; 32]).unwrap();
        db.upsert_room(&room(room_id, "2026-10-08T12:00:00Z"), true)
            .unwrap();
        let mirror = SharedMirror::new(db);
        let summary = synchronize_once(&mirror, &rest, &Config::default(), None)
            .await
            .unwrap();
        assert_eq!(summary.departed_rooms, vec![room_id.to_owned()]);
        assert_eq!(
            mirror.with(|db| db.is_member(room_id)).await.unwrap(),
            Some(false)
        );
    }

    #[tokio::test]
    async fn failed_initial_room_is_preserved_while_later_rooms_sync() {
        let server = MockServer::start().await;
        let failed_room =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDk5";
        let succeeding_room =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let now = Utc::now().to_rfc3339();
        Mock::given(method("GET"))
            .and(path("/v1/rooms"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [room(failed_room, &now), room(succeeding_room, &now)]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .and(query_param("roomId", failed_room))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .and(query_param("roomId", succeeding_room))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{"id": message_id, "roomId": succeeding_room, "created": now, "text": "private fixture"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mirror = SharedMirror::new(Mirror::in_memory([79_u8; 32]).unwrap());

        let summary = synchronize_once(&mirror, &rest, &Config::default(), None)
            .await
            .unwrap();
        assert_eq!(summary.rooms, 2);
        assert_eq!(summary.failed_rooms, 1);
        assert_eq!(summary.created, 1);
        let failed = mirror
            .with(|db| db.room_sync(failed_room))
            .await
            .unwrap()
            .unwrap();
        assert!(!failed.initial_done);
        assert_eq!(failed.last_result.as_deref(), Some("initial_server_error"));
        assert!(
            mirror
                .with(|db| db.room_sync(succeeding_room))
                .await
                .unwrap()
                .unwrap()
                .initial_done
        );
    }
}
