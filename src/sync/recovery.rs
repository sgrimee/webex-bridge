//! Explicit, one-room recovery of a previously recorded catch-up gap.
//!
//! This is intentionally separate from normal sync: callers must opt into an
//! extended read window after seeing the affected room and range. It never
//! writes to Webex, and it clears a gap only after reaching a known message at
//! or before the recorded old boundary.

use crate::{
    mirror::{SharedMirror, Upsert},
    sync::{catchup::max_age, history::WebexRest},
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};

/// Hard upper bound for the user-approved one-room recovery. It is not a new
/// normal catch-up default.
const RECOVERY_MAX_AGE: &str = "365d";

/// Metadata-only outcome suitable for the CLI and audit logs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecoveryResult {
    pub room_id: String,
    pub from: String,
    pub to: String,
    pub visited: usize,
    pub created: usize,
    pub edited: usize,
    pub boundary_reached: bool,
}

fn parsed(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .context("Invalid recovery gap timestamp")?
        .with_timezone(&Utc))
}

/// Recover the named currently persisted gap using at most 365 days of
/// read-only history. `page_size` follows the normal 1..=100 Webex limit.
pub async fn recover_gap(
    mirror: &SharedMirror,
    rest: &WebexRest,
    room_id: &str,
    page_size: u32,
) -> Result<RecoveryResult> {
    if !(1..=100).contains(&page_size) {
        bail!("Recovery page size must be 1..=100");
    }
    let gap = mirror
        .with(|db| db.recovery_gap(room_id))
        .await?
        .context("No unresolved gap exists for this room")?;
    let from = parsed(&gap.from)?;
    let cutoff = Utc::now() - max_age(RECOVERY_MAX_AGE)?;
    if from < cutoff {
        bail!("Recorded gap starts beyond the approved 365-day recovery window");
    }
    let mut result = RecoveryResult {
        room_id: room_id.into(),
        from: gap.from.clone(),
        to: gap.to.clone(),
        visited: 0,
        created: 0,
        edited: 0,
        boundary_reached: false,
    };
    let mut before: Option<String> = None;
    let mut crossed_old_boundary_time = false;
    loop {
        let page = rest
            .messages_page(room_id, before.as_deref(), page_size)
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
                .context("Recovery message has no ID")?;
            let created = message
                .created
                .as_deref()
                .context("Recovery message has no created timestamp")?;
            let created_at = parsed(created)?;
            if created_at < cutoff {
                reached_age = true;
                break;
            }
            let old_known = created_at <= from && mirror.with(|db| db.contains_message(id)).await?;
            crossed_old_boundary_time |= created_at <= from;
            match mirror.with(|db| db.upsert_message(message)).await? {
                Upsert::Created(_) => result.created += 1,
                Upsert::Edited(_) => result.edited += 1,
                Upsert::Unchanged | Upsert::IgnoredDeleted => {}
            }
            result.visited += 1;
            if old_known {
                result.boundary_reached = true;
                break;
            }
        }
        // A short page is the authoritative end of Webex's available room
        // history. If it crosses the recorded time, recovery is complete even
        // when the original canonical boundary row was absent locally.
        if page_len < page_size as usize && crossed_old_boundary_time {
            result.boundary_reached = true;
            break;
        }
        if reached_age || result.boundary_reached || page_len < page_size as usize {
            break;
        }
        let cursor = page
            .last()
            .and_then(|message| message.id.as_deref())
            .context("Recovery page has no cursor message")?;
        if before.as_deref() == Some(cursor) {
            bail!("Webex recovery pagination repeated its cursor");
        }
        before = Some(cursor.into());
    }
    if result.boundary_reached {
        mirror.with(|db| db.clear_recovery_gap(&gap)).await?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::Mirror;
    use reqwest::Url;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    fn message(id: &str, room_id: &str, created: &str) -> webex::Message {
        webex::Message {
            id: Some(id.into()),
            room_id: Some(room_id.into()),
            created: Some(created.into()),
            text: Some("private fixture".into()),
            ..webex::Message::default()
        }
    }

    #[tokio::test]
    async fn extended_recovery_clears_only_after_reaching_old_known_boundary() {
        let server = MockServer::start().await;
        let room = "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let old =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let newer =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAy";
        let old_time = (Utc::now() - chrono::Duration::days(300)).to_rfc3339();
        let new_time = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .and(query_param("roomId", room))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [message(newer, room, &new_time), message(old, room, &old_time)]
            })))
            .mount(&server)
            .await;
        let mut db = Mirror::in_memory([99; 32]).unwrap();
        db.upsert_message(&message(old, room, &old_time)).unwrap();
        db.record_gap(room, &old_time, &new_time).unwrap();
        let mirror = SharedMirror::new(db);
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let outcome = recover_gap(&mirror, &rest, room, 50).await.unwrap();
        assert!(outcome.boundary_reached);
        assert_eq!(outcome.created, 1);
        assert!(mirror
            .with(|db| db.recovery_gap(room))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn complete_history_page_recovers_when_the_old_boundary_row_was_missing() {
        let server = MockServer::start().await;
        let room = "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let old =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let newer =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAx";
        let old_time = (Utc::now() - chrono::Duration::days(300)).to_rfc3339();
        let new_time = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [message(newer, room, &new_time), message(old, room, &old_time)]
            })))
            .mount(&server)
            .await;
        let mut db = Mirror::in_memory([101; 32]).unwrap();
        // The previous implementation advanced a gap cursor without retaining
        // its exact canonical boundary row. The timestamp remains sufficient
        // once Webex confirms this is the complete available history page.
        db.upsert_message(&message(newer, room, &new_time)).unwrap();
        db.record_gap(room, &old_time, &new_time).unwrap();
        let mirror = SharedMirror::new(db);
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let outcome = recover_gap(&mirror, &rest, room, 50).await.unwrap();
        assert!(outcome.boundary_reached);
        assert_eq!(outcome.created, 1);
        assert!(mirror
            .with(|db| db.recovery_gap(room))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn incomplete_recovery_keeps_the_gap_visible() {
        let server = MockServer::start().await;
        let room = "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let old =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let old_time = (Utc::now() - chrono::Duration::days(300)).to_rfc3339();
        let new_time = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "items": [] })),
            )
            .mount(&server)
            .await;
        let mut db = Mirror::in_memory([100; 32]).unwrap();
        db.upsert_message(&message(old, room, &old_time)).unwrap();
        db.record_gap(room, &old_time, &new_time).unwrap();
        let mirror = SharedMirror::new(db);
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let outcome = recover_gap(&mirror, &rest, room, 50).await.unwrap();
        assert!(!outcome.boundary_reached);
        assert!(mirror
            .with(|db| db.recovery_gap(room))
            .await
            .unwrap()
            .is_some());
    }
}
