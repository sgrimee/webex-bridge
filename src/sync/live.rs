//! Event-driven Mercury hydration and room-scoped delete reconciliation.
//! Do not treat an event's text or a `leave` verb as an instruction/state change.

use crate::{
    diagnostics,
    mirror::{SharedMirror, Upsert},
    sync::history::WebexRest,
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::time::Duration;
use tokio::time::sleep;
use webex::{ActivityType, Event, GlobalId, GlobalIdType, MessageActivity, SpaceActivity};

/// Outcome for a single live event, without message bodies.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LiveResult {
    /// Canonical message created/edited/deduplicated.
    Message(LiveMessage),
    /// Room-scoped reconciliation after a delete signal.
    Reconciled {
        room_id: String,
        result: ReconcileResult,
    },
    /// Room metadata or membership verified by REST.
    RoomUpdated { room_id: String },
    /// Room membership was confirmed absent by REST.
    RoomLeft { room_id: String },
    /// Typing, acknowledgement and unrelated control events.
    Ignored,
}

/// Metadata-only result for a hydrated canonical message. The body remains in
/// the encrypted mirror; callers can use this only to name a UI SSE event.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LiveMessage {
    /// Canonical room ID.
    pub room_id: String,
    /// Canonical REST message ID.
    pub message_id: String,
    /// Whether this observation created, edited or deduplicated a revision.
    pub upsert: Upsert,
}

/// Counts from checking known canonical messages after a room-scoped signal.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ReconcileResult {
    /// Active canonical IDs verified against REST.
    pub checked: usize,
    /// Bodies/revisions updated for old edits.
    pub edited: usize,
    /// Known missing IDs tombstoned and fully purged.
    pub deleted: usize,
}

/// One metadata-only UI invalidation emitted only for a committed mirror change.
#[derive(Debug, Clone, PartialEq)]
pub struct UiInvalidation {
    pub name: &'static str,
    pub data: Value,
}

/// Convert a committed live outcome into narrow UI invalidations. Reconciliation
/// intentionally requests a room resync rather than inventing individual
/// message IDs from a room-scoped Mercury delete signal.
pub fn ui_invalidations(result: &LiveResult) -> Vec<UiInvalidation> {
    match result {
        LiveResult::Message(message) => match message.upsert {
            Upsert::Created(revision) => vec![UiInvalidation {
                name: "message.created",
                data: serde_json::json!({
                    "roomId": message.room_id,
                    "messageId": message.message_id,
                    "revision": revision,
                }),
            }],
            Upsert::Edited(revision) => vec![UiInvalidation {
                name: "message.updated",
                data: serde_json::json!({
                    "roomId": message.room_id,
                    "messageId": message.message_id,
                    "revision": revision,
                }),
            }],
            Upsert::Unchanged | Upsert::IgnoredDeleted => Vec::new(),
        },
        LiveResult::Reconciled { room_id, result } if result.edited != 0 || result.deleted != 0 => {
            vec![UiInvalidation {
                name: "room.resync",
                data: serde_json::json!({ "roomId": room_id, "reason": "reconciled" }),
            }]
        }
        LiveResult::RoomUpdated { room_id } => vec![UiInvalidation {
            name: "room.updated",
            data: serde_json::json!({ "roomId": room_id }),
        }],
        LiveResult::RoomLeft { room_id } => vec![UiInvalidation {
            name: "membership.changed",
            data: serde_json::json!({ "roomId": room_id, "isMember": false }),
        }],
        LiveResult::Reconciled { .. } | LiveResult::Ignored => Vec::new(),
    }
}

fn event_room_id(event: &Event, from_delete_target: bool) -> Result<String> {
    let raw = if from_delete_target {
        event
            .data
            .activity
            .as_ref()
            .and_then(|activity| activity.target.as_ref())
            .and_then(|target| target.global_id.as_deref())
            .context("Mercury delete has no room target")?
    } else {
        event
            .data
            .conversation_id
            .as_deref()
            .context("Mercury event has no room ID")?
    };
    let room = GlobalId::new(GlobalIdType::Room, raw.to_owned())
        .context("Mercury room target is not a room ID")?;
    Ok(room.id().to_owned())
}

/// Recheck active messages in a room after a delete signal or reconnect.
/// A room REST check prevents misclassifying loss of membership as mass deletion.
/// HTTP 404 for a known message is checked twice before irreversible body purge.
pub async fn reconcile_room(
    mirror: &SharedMirror,
    rest: &WebexRest,
    room_id: &str,
) -> Result<ReconcileResult> {
    let started = std::time::Instant::now();
    let outcome = reconcile_room_inner(mirror, rest, room_id).await;
    let elapsed_ms = started.elapsed().as_millis();
    // Counts and timing only: never room/message IDs or bodies.
    match &outcome {
        Ok(result) => diagnostics::debug(format_args!(
            "sync.reconcile checked={} edited={} deleted={} elapsed_ms={elapsed_ms}",
            result.checked, result.edited, result.deleted
        )),
        Err(_) => diagnostics::debug(format_args!(
            "sync.reconcile_failed elapsed_ms={elapsed_ms}"
        )),
    }
    outcome
}

async fn reconcile_room_inner(
    mirror: &SharedMirror,
    rest: &WebexRest,
    room_id: &str,
) -> Result<ReconcileResult> {
    let room = rest
        .room(room_id)
        .await?
        .context("Room unavailable; cannot infer message deletions")?;
    mirror.with(|db| db.upsert_room(&room, true)).await?;
    let ids = mirror.with(|db| db.active_message_ids(room_id)).await?;
    let mut result = ReconcileResult {
        checked: 0,
        edited: 0,
        deleted: 0,
    };
    for id in ids {
        let current = match rest.message(&id).await? {
            Some(message) => Some(message),
            None => {
                sleep(Duration::from_millis(200)).await;
                rest.message(&id).await?
            }
        };
        if let Some(message) = current {
            if message.room_id.as_deref() != Some(room_id) {
                bail!("REST message room mismatch during reconciliation");
            }
            if matches!(
                mirror.with(|db| db.upsert_message(&message)).await?,
                Upsert::Edited(_)
            ) {
                result.edited += 1;
            }
        } else if mirror.with(|db| db.mark_deleted(room_id, &id)).await? {
            result.deleted += 1;
        }
        result.checked += 1;
    }
    Ok(result)
}

/// Hydrate one Mercury event, encrypt changes, and return metadata-only outcome.
pub async fn ingest_event(
    mirror: &SharedMirror,
    rest: &WebexRest,
    event: &Event,
    only_room: Option<&str>,
) -> Result<LiveResult> {
    match event.activity_type() {
        ActivityType::Message(MessageActivity::Posted | MessageActivity::Shared) => {
            let activity_id = event.try_global_id()?;
            let Some(message) = rest.message(activity_id.id()).await? else {
                // A post can race a deletion. Never persist the event's body;
                // reconcile known messages in its room instead.
                let room_id = event_room_id(event, false)?;
                return Ok(LiveResult::Reconciled {
                    result: reconcile_room(mirror, rest, &room_id).await?,
                    room_id,
                });
            };
            let room_id = message
                .room_id
                .as_deref()
                .context("Hydrated message has no room")?;
            if only_room.is_some_and(|allowed| allowed != room_id) {
                return Ok(LiveResult::Ignored);
            }
            if !mirror.with(|db| db.has_room(room_id)).await? {
                let room = rest
                    .room(room_id)
                    .await?
                    .context("New message's room is unavailable")?;
                mirror.with(|db| db.upsert_room(&room, true)).await?;
            }
            if let Some(person_id) = message.person_id.as_deref() {
                if !mirror.with(|db| db.has_person(person_id)).await? {
                    if let Some(person) = rest.person(person_id).await? {
                        mirror.with(|db| db.upsert_person(&person)).await?;
                    }
                }
            }
            // Mention presence is transport metadata only; log its count in
            // debug mode so the Step 1 probe can distinguish mention/no-mention
            // without recording a person ID or message body.
            diagnostics::debug(format!(
                "sync.live_message mentioned_people={}",
                message.mentioned_people.as_ref().map_or(0, Vec::len)
            ));
            Ok(LiveResult::Message(LiveMessage {
                room_id: room_id.into(),
                message_id: message
                    .id
                    .clone()
                    .context("Hydrated message has no canonical ID")?,
                upsert: mirror.with(|db| db.upsert_message(&message)).await?,
            }))
        }
        ActivityType::Message(MessageActivity::Deleted) => {
            diagnostics::debug("sync.delete_received");
            // `event.try_global_id()` mislabels this room target as a Message ID.
            let room_id = event_room_id(event, true)?;
            if only_room.is_some_and(|allowed| allowed != room_id) {
                return Ok(LiveResult::Ignored);
            }
            Ok(LiveResult::Reconciled {
                result: reconcile_room(mirror, rest, &room_id).await?,
                room_id,
            })
        }
        ActivityType::Space(
            SpaceActivity::Changed
            | SpaceActivity::Created
            | SpaceActivity::Joined
            | SpaceActivity::Left,
        ) => {
            let was_left_verb = matches!(
                event.activity_type(),
                ActivityType::Space(SpaceActivity::Left)
            );
            let id = event.try_global_id()?;
            let id = GlobalId::new(GlobalIdType::Room, id.id().to_owned())?;
            if only_room.is_some_and(|allowed| allowed != id.id()) {
                return Ok(LiveResult::Ignored);
            }
            if let Some(room) = rest.room(id.id()).await? {
                mirror.with(|db| db.upsert_room(&room, true)).await?;
                Ok(LiveResult::RoomUpdated {
                    room_id: id.id().into(),
                })
            } else if was_left_verb {
                mirror
                    .with(|db| {
                        if db.has_room(id.id())? {
                            db.mark_room_left(id.id())?;
                        }
                        Ok(())
                    })
                    .await?;
                Ok(LiveResult::RoomLeft {
                    room_id: id.id().into(),
                })
            } else {
                bail!("Mercury room event could not be verified by REST")
            }
        }
        _ => Ok(LiveResult::Ignored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::Mirror;
    use reqwest::Url;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn room(id: &str) -> webex::Room {
        webex::Room {
            id: id.into(),
            title: Some("private title".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: None,
            last_activity: "2026-10-08T12:00:00Z".into(),
            creator_id: "person".into(),
            created: "2026-10-01T00:00:00Z".into(),
        }
    }
    fn msg(id: &str, room_id: &str, body: &str, updated: Option<&str>) -> webex::Message {
        webex::Message {
            id: Some(id.into()),
            room_id: Some(room_id.into()),
            text: Some(body.into()),
            created: Some("2026-10-08T12:00:00Z".into()),
            updated: updated.map(str::to_owned),
            ..webex::Message::default()
        }
    }

    #[test]
    fn committed_live_results_emit_only_metadata_invalidations() {
        let message = LiveResult::Message(LiveMessage {
            room_id: "room-1".into(),
            message_id: "message-1".into(),
            upsert: Upsert::Edited(2),
        });
        assert_eq!(
            ui_invalidations(&message),
            vec![UiInvalidation {
                name: "message.updated",
                data: serde_json::json!({
                    "roomId": "room-1", "messageId": "message-1", "revision": 2
                }),
            }]
        );
        let reconciled = LiveResult::Reconciled {
            room_id: "room-1".into(),
            result: ReconcileResult {
                checked: 3,
                edited: 0,
                deleted: 1,
            },
        };
        assert_eq!(
            ui_invalidations(&reconciled),
            vec![UiInvalidation {
                name: "room.resync",
                data: serde_json::json!({"roomId": "room-1", "reason": "reconciled"}),
            }]
        );
        assert_eq!(
            ui_invalidations(&LiveResult::RoomLeft {
                room_id: "room-1".into(),
            }),
            vec![UiInvalidation {
                name: "membership.changed",
                data: serde_json::json!({"roomId": "room-1", "isMember": false}),
            }]
        );
        assert!(ui_invalidations(&LiveResult::Ignored).is_empty());
    }

    #[tokio::test]
    async fn post_verb_with_new_activity_id_updates_canonical_revision() {
        let server = MockServer::start().await;
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let canonical =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let activity_uuid = "00000000-0000-4000-8000-00000000d001";
        let activity_id = GlobalId::new(GlobalIdType::Message, activity_uuid.to_owned()).unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{}", activity_id.id())))
            .respond_with(ResponseTemplate::new(200).set_body_json(msg(
                canonical,
                room_id,
                "edited",
                Some("2026-10-08T12:05:00Z"),
            )))
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mut mirror = Mirror::in_memory([34_u8; 32]).unwrap();
        mirror.upsert_room(&room(room_id), true).unwrap();
        mirror
            .upsert_message(&msg(canonical, room_id, "original", None))
            .unwrap();
        let mirror = SharedMirror::new(mirror);
        let event = Event {
            data: webex::EventData {
                event_type: "conversation.activity".into(),
                activity: Some(webex::Activity {
                    id: activity_uuid.into(),
                    verb: "post".into(),
                    ..webex::Activity::default()
                }),
                ..webex::EventData::default()
            },
            ..Event::default()
        };
        assert_eq!(
            ingest_event(&mirror, &rest, &event, None).await.unwrap(),
            LiveResult::Message(LiveMessage {
                room_id: room_id.into(),
                message_id: canonical.into(),
                upsert: Upsert::Edited(1),
            })
        );
        assert_eq!(
            mirror
                .with(|db| db.message_body(canonical))
                .await
                .unwrap()
                .as_deref(),
            Some("edited")
        );
    }

    #[tokio::test]
    async fn dev_room_filter_never_stores_other_room_message() {
        let server = MockServer::start().await;
        let allowed_room =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let other_room =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAy";
        let canonical =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAz";
        let activity_uuid = "00000000-0000-4000-8000-00000000d001";
        let activity_id = GlobalId::new(GlobalIdType::Message, activity_uuid.to_owned()).unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{}", activity_id.id())))
            .respond_with(ResponseTemplate::new(200).set_body_json(msg(
                canonical,
                other_room,
                "must not store",
                None,
            )))
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mirror = SharedMirror::new(Mirror::in_memory([37_u8; 32]).unwrap());
        let event = Event {
            data: webex::EventData {
                event_type: "conversation.activity".into(),
                activity: Some(webex::Activity {
                    id: activity_uuid.into(),
                    verb: "post".into(),
                    ..webex::Activity::default()
                }),
                ..webex::EventData::default()
            },
            ..Event::default()
        };
        assert_eq!(
            ingest_event(&mirror, &rest, &event, Some(allowed_room))
                .await
                .unwrap(),
            LiveResult::Ignored
        );
        assert!(!mirror.with(|db| db.has_room(other_room)).await.unwrap());
    }

    #[tokio::test]
    async fn leave_verb_does_not_remove_a_verified_member() {
        let server = MockServer::start().await;
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        Mock::given(method("GET"))
            .and(path(format!("/v1/rooms/{room_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(room(room_id)))
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mut mirror = Mirror::in_memory([35_u8; 32]).unwrap();
        mirror.upsert_room(&room(room_id), true).unwrap();
        let mirror = SharedMirror::new(mirror);
        let event = Event {
            data: webex::EventData {
                event_type: "conversation.activity".into(),
                activity: Some(webex::Activity {
                    verb: "leave".into(),
                    target: Some(webex::Target {
                        id: String::new(),
                        object_type: "conversation".into(),
                        url: String::new(),
                        participants: None,
                        activities: None,
                        tags: Vec::new(),
                        global_id: Some(room_id.into()),
                    }),
                    ..webex::Activity::default()
                }),
                ..webex::EventData::default()
            },
            ..Event::default()
        };
        assert_eq!(
            ingest_event(&mirror, &rest, &event, None).await.unwrap(),
            LiveResult::RoomUpdated {
                room_id: room_id.into(),
            }
        );
        assert_eq!(
            mirror.with(|db| db.is_member(room_id)).await.unwrap(),
            Some(true)
        );
    }

    #[tokio::test]
    async fn transient_404_never_purges_a_restored_message() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let server = MockServer::start().await;
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let message_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAy";
        Mock::given(method("GET"))
            .and(path(format!("/v1/rooms/{room_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(room(room_id)))
            .mount(&server)
            .await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&attempts);
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{message_id}")))
            .respond_with(move |_: &wiremock::Request| {
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(404)
                } else {
                    ResponseTemplate::new(200).set_body_json(msg(
                        message_id,
                        room_id,
                        "restored",
                        Some("2026-10-08T12:05:00Z"),
                    ))
                }
            })
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mut mirror = Mirror::in_memory([36_u8; 32]).unwrap();
        mirror.upsert_room(&room(room_id), true).unwrap();
        mirror
            .upsert_message(&msg(message_id, room_id, "original", None))
            .unwrap();
        let mirror = SharedMirror::new(mirror);
        let result = reconcile_room(&mirror, &rest, room_id).await.unwrap();
        assert_eq!(
            result,
            ReconcileResult {
                checked: 1,
                edited: 1,
                deleted: 0
            }
        );
        assert_eq!(
            mirror
                .with(|db| db.message_body(message_id))
                .await
                .unwrap()
                .as_deref(),
            Some("restored")
        );
    }

    #[tokio::test]
    async fn delete_signal_reconciles_room_and_purges_only_missing_message() {
        let server = MockServer::start().await;
        let room_id =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let deleted_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDAy";
        let edited_id =
            "Y2lzY29zcGFyazovL3VzL01FU1NBR0UvMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBjMDA1";
        Mock::given(method("GET"))
            .and(path(format!("/v1/rooms/{room_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(room(room_id)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{deleted_id}")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/messages/{edited_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(msg(
                edited_id,
                room_id,
                "revised body",
                Some("2026-10-08T12:05:00Z"),
            )))
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(Url::parse(&format!("{}/v1/", server.uri())).unwrap()).unwrap();
        let mut mirror = Mirror::in_memory([33_u8; 32]).unwrap();
        mirror.upsert_room(&room(room_id), true).unwrap();
        mirror
            .upsert_message(&msg(deleted_id, room_id, "delete me", None))
            .unwrap();
        mirror
            .upsert_message(&msg(edited_id, room_id, "original body", None))
            .unwrap();
        let mirror = SharedMirror::new(mirror);
        let result = reconcile_room(&mirror, &rest, room_id).await.unwrap();
        assert_eq!(
            result,
            ReconcileResult {
                checked: 2,
                edited: 1,
                deleted: 1
            }
        );
        assert!(mirror
            .with(|db| db.message_body(deleted_id))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            mirror
                .with(|db| db.message_body(edited_id))
                .await
                .unwrap()
                .as_deref(),
            Some("revised body")
        );
    }
}
