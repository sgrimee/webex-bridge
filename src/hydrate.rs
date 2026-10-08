//! Read-only transport probe: hydrate event message IDs without logging bodies.

use serde_json::json;
use webex::{error::Error, ActivityType, Event, Message, MessageActivity, Webex};

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
    let id = event.try_global_id()?;
    let mut room_id = event.data.conversation_id.clone();
    let mut sender_id = event.data.actor.as_ref().map(|actor| actor.id.clone());
    let mut body_len = None;
    if matches!(
        event.activity_type(),
        ActivityType::Message(MessageActivity::Posted | MessageActivity::Shared)
    ) {
        let message: Message = client.get(&id).await?;
        room_id = message.room_id;
        sender_id = message.person_id;
        body_len = message.markdown.or(message.text).map(|body| body.len());
    }
    if room_filter.is_none_or(|filter| room_id.as_deref() == Some(filter)) {
        println!(
            "{}",
            json!({
                "verb": verb,
                "roomId": room_id,
                "messageId": id.id(),
                "senderId": sender_id,
                "len": body_len,
            })
        );
    }
    Ok(())
}
