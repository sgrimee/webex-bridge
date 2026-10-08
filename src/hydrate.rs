//! Read-only transport probe: hydrate event message IDs without logging bodies.

use anyhow::{bail, Context, Result as AnyResult};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use webex::{
    error::Error, ActivityType, Event, GlobalId, GlobalIdType, Message, MessageActivity, Webex,
};

/// Print only normalized metadata and whether REST returned message content.
pub async fn probe_event(
    event: Event,
    client: Webex,
    room_filter: Option<&str>,
) -> Result<(), Error> {
    let verb = event
        .data
        .activity
        .as_ref()
        .map(|activity| activity.verb.as_str())
        .unwrap_or(event.data.event_type.as_str());
    let verb: String = verb
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(32)
        .collect();
    // Typing and receipts do not carry a REST message ID. Unknown conversation
    // activities may be edit/delete protocol changes: record metadata only.
    let activity = event.activity_type();
    if matches!(activity, ActivityType::Unknown(_))
        && event.data.event_type == "conversation.activity"
    {
        let room = event.data.conversation_id.as_ref().and_then(|raw| {
            GlobalId::new(GlobalIdType::Room, raw.clone())
                .ok()
                .map(|id| id.id().to_owned())
        });
        if room_filter.is_none_or(|filter| room.as_deref().is_none_or(|id| id == filter)) {
            let raw = event.data.activity.as_ref();
            println!(
                "{}",
                json!({
                    "diagnostic": "unknown_conversation_activity",
                    "verb": verb,
                    "roomId": room,
                    "activityId": raw.and_then(|a| safe_id(&a.id)),
                    "targetId": raw.and_then(|a| a.target.as_ref()).and_then(|t| safe_id(&t.id)),
                    "targetGlobalId": raw.and_then(|a| a.target.as_ref()).and_then(|t| t.global_id.as_deref()).and_then(safe_id),
                })
            );
        }
    }
    if !matches!(
        activity,
        ActivityType::Message(
            MessageActivity::Posted | MessageActivity::Shared | MessageActivity::Deleted
        ) | ActivityType::Space(_)
    ) {
        return Ok(());
    }
    let mut room_id = event.data.conversation_id.as_ref().and_then(|raw| {
        GlobalId::new(GlobalIdType::Room, raw.clone())
            .ok()
            .map(|id| id.id().to_owned())
    });
    if room_filter.is_some_and(|filter| room_id.as_deref().is_some_and(|room| room != filter)) {
        return Ok(());
    }
    let id = match event.try_global_id() {
        Ok(id) => id,
        Err(_) => {
            if room_filter.is_none_or(|filter| room_id.as_deref().is_none_or(|room| room == filter))
            {
                let activity = event.data.activity.as_ref();
                println!(
                    "{}",
                    json!({
                        "diagnostic": "message_id_unavailable",
                        "verb": verb,
                        "roomId": room_id,
                        "activityId": activity.and_then(|a| safe_id(&a.id)),
                        "targetId": activity.and_then(|a| a.target.as_ref()).and_then(|t| safe_id(&t.id)),
                        "targetGlobalId": activity.and_then(|a| a.target.as_ref()).and_then(|t| t.global_id.as_deref()).and_then(safe_id),
                    })
                );
            }
            return Ok(());
        }
    };
    if let Some(target_room) = target_room_id(&activity, &id)? {
        room_id = Some(target_room);
        if room_filter.is_some_and(|filter| room_id.as_deref() != Some(filter)) {
            return Ok(());
        }
    }
    let mut sender_id = event.data.actor.as_ref().map(|actor| actor.id.clone());
    let mut body_len = None;
    let mut created_at_ms = None;
    let mut updated_at_ms = None;
    let mut api_message_id = None;
    let mut parent_id = None;
    if matches!(
        activity,
        ActivityType::Message(MessageActivity::Posted | MessageActivity::Shared)
    ) {
        let message: Message = client.get(&id).await?;
        room_id = message.room_id;
        sender_id = message.person_id;
        api_message_id = message.id;
        parent_id = message.parent_id;
        created_at_ms = parse_time(message.created.as_deref());
        updated_at_ms = parse_time(message.updated.as_deref());
        body_len = message.markdown.or(message.text).map(|body| body.len());
    }
    if room_filter.is_none_or(|filter| room_id.as_deref().is_none_or(|room| room == filter)) {
        let observed_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| i64::try_from(time.as_millis()).ok());
        let latency_ms = observed_at_ms
            .zip(updated_at_ms.or(created_at_ms))
            .map(|(observed, changed)| observed - changed);
        let semantic = match activity {
            ActivityType::Message(MessageActivity::Posted | MessageActivity::Shared)
                if updated_at_ms
                    .zip(created_at_ms)
                    .is_some_and(|(updated, created)| updated > created) =>
            {
                "edited"
            }
            ActivityType::Message(MessageActivity::Posted | MessageActivity::Shared) => "created",
            ActivityType::Message(MessageActivity::Deleted) => "deleted",
            _ => "room",
        };
        let delete_activity = (semantic == "deleted")
            .then_some(event.data.activity.as_ref())
            .flatten();
        let delete_target = delete_activity.and_then(|a| a.target.as_ref());
        println!(
            "{}",
            json!({
                "verb": verb,
                "semantic": semantic,
                "eventActivityId": delete_activity.and_then(|a| safe_id(&a.id)),
                "eventTargetId": delete_target.and_then(|t| safe_id(&t.id)),
                "eventTargetGlobalId": delete_target.and_then(|t| t.global_id.as_deref()).and_then(safe_id),
                "eventParentId": delete_activity.and_then(|a| a.parent.as_ref()).and_then(|p| safe_id(&p.id)),
                "eventTargetType": delete_target.map(|t| match t.object_type.as_str() { "comment" => "comment", "activity" => "activity", "conversation" => "conversation", _ => "other" }),
                "roomId": room_id,
                "messageId": matches!(activity, ActivityType::Message(MessageActivity::Posted | MessageActivity::Shared)).then(|| id.id()),
                "reconcileRoom": semantic == "deleted",
                "apiMessageId": api_message_id,
                "parentId": parent_id,
                "senderId": sender_id,
                "len": body_len,
                "observedAtMs": observed_at_ms,
                "createdAtMs": created_at_ms,
                "updatedAtMs": updated_at_ms,
                "latencyMs": latency_ms,
            })
        );
    }
    Ok(())
}

fn target_room_id(activity: &ActivityType, id: &GlobalId) -> Result<Option<String>, Error> {
    if matches!(
        activity,
        ActivityType::Space(_) | ActivityType::Message(MessageActivity::Deleted)
    ) {
        // Mercury `delete` targets the ROOM, not the deleted message. Do not
        // tombstone the room ID as though it were a message ID.
        let room = GlobalId::new(GlobalIdType::Room, id.id().to_owned())
            .map_err(|_| Error::Api("Delete/space event target is not a room ID"))?;
        Ok(Some(room.id().to_owned()))
    } else {
        Ok(None)
    }
}

fn safe_id(value: &str) -> Option<String> {
    if value.len() > 256
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '+' | '='))
    {
        return None;
    }
    [
        GlobalIdType::Message,
        GlobalIdType::Room,
        GlobalIdType::Person,
    ]
    .into_iter()
    .any(|kind| GlobalId::new(kind, value.to_owned()).is_ok())
    .then(|| value.to_owned())
}

fn parse_time(value: Option<&str>) -> Option<i64> {
    value
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
        .map(|time| time.timestamp_millis())
}

/// Inspect one authorized Webex message by ID, printing metadata only.
pub async fn inspect_message(token: &str, message_id: &str) -> AnyResult<()> {
    let id = GlobalId::new(GlobalIdType::Message, message_id.to_owned())?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut url = reqwest::Url::parse("https://webexapis.com/v1/messages/")?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("Invalid messages API URL"))?
        .push(id.id());
    let response = client.get(url).bearer_auth(token).send().await?;
    if !response.status().is_success() {
        bail!("Webex message lookup returned HTTP {}", response.status());
    }
    let message: Message = response
        .json()
        .await
        .context("Invalid Webex message response")?;
    println!(
        "{}",
        json!({
            "id": message.id,
            "roomId": message.room_id,
            "senderId": message.person_id,
            "parentId": message.parent_id,
            "createdAtMs": parse_time(message.created.as_deref()),
            "updatedAtMs": parse_time(message.updated.as_deref()),
            "len": message.markdown.or(message.text).map(|body| body.len()),
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{safe_id, target_room_id};
    use webex::{ActivityType, GlobalId, GlobalIdType, MessageActivity};

    #[test]
    fn delete_event_targets_room_not_message() {
        let raw_room =
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let mislabeled =
            GlobalId::new_with_cluster_unchecked(GlobalIdType::Message, raw_room.to_owned(), None);
        assert_eq!(
            target_room_id(
                &ActivityType::Message(MessageActivity::Deleted),
                &mislabeled
            )
            .unwrap(),
            Some(raw_room.to_owned())
        );
        assert!(
            target_room_id(&ActivityType::Message(MessageActivity::Posted), &mislabeled)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn diagnostic_ids_reject_control_characters_and_text() {
        let id = "00000000-0000-4000-8000-00000000a001";
        assert_eq!(safe_id(id), Some(id.to_owned()));
        assert_eq!(safe_id("secret\u{1b}[31m"), None);
        assert_eq!(safe_id("some message body"), None);
    }
}
