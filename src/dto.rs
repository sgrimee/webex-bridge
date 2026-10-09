//! Wire-safe v1 UI DTOs independent of the daemon mirror and Webex crates.
//!
//! These types preserve the existing camelCase JSON field names. The daemon
//! converts its mirror rows to them only at its authorized UI API boundary.

use serde::{Deserialize, Serialize};

/// Metadata-only daemon health response, available before UI pairing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub api_version: u32,
    pub connection: String,
    pub sync: SyncStatus,
}

/// Mirror progress included in [`Status`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub rooms: i64,
    pub revisions: i64,
    pub initial_done: i64,
    pub initial_pending: i64,
    pub gaps: i64,
    pub failures: i64,
}

/// Full room metadata available to a paired UI only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Room {
    pub id: String,
    pub title: Option<String>,
    pub room_type: String,
    pub team_id: Option<String>,
    pub last_activity: Option<String>,
    pub is_member: bool,
    /// `None` means the mirror has not received authoritative lock metadata.
    /// It must not be interpreted as unlocked.
    pub is_locked: Option<bool>,
}

/// Team identity and name available to a paired UI only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    pub id: String,
    pub name: Option<String>,
}

/// Full person metadata available to a paired UI only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    pub id: String,
    pub display_name: Option<String>,
    pub emails: Option<Vec<String>>,
}

/// Result of a cache-miss-capable UI person point read. `state` is one of
/// `mirrored`, `hydrated`, `not_found`, `offline`, or `unavailable`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonRead {
    pub id: String,
    pub state: String,
    pub person: Option<Person>,
}

/// Canonical message or deletion tombstone available to a paired UI only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: String,
    pub room_id: String,
    pub revision: i64,
    pub parent_id: Option<String>,
    pub sender_id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub status: String,
    /// Compatibility projection; use `body` for authoritative provenance.
    pub markdown: Option<String>,
    pub body: Option<MessageBody>,
    /// Count only: attachment URLs/bytes are never released by this API.
    pub attachment_count: u32,
}

/// Content with an authoritative kind for new rows or `legacyUnknown` for
/// rows written before the kind was mirrored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageBody {
    /// `plainText`, `markdown`, or `legacyUnknown`.
    pub kind: String,
    pub content: String,
}

/// UI create/edit body. The daemon rejects `legacyUnknown`: it is read-only
/// provenance for old mirrored rows, never a Webex write format.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageBodyInput {
    /// `plainText` or `markdown`.
    pub kind: String,
    pub content: String,
}

/// Result of a cache-miss-capable UI message point read. `state` is one of
/// `mirrored`, `hydrated`, `deleted`, `not_found`, `offline`, or `unavailable`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRead {
    pub id: String,
    pub state: String,
    pub message: Option<Message>,
}

/// One reverse-chronological room-history page. `next_before` is an opaque
/// message ID for a subsequent request. A false `complete` means the mirror
/// may contain only a prefix of the remote room history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePage {
    pub messages: Vec<Message>,
    pub next_before: Option<String>,
    pub complete: bool,
    /// Stable reason for a false `complete`, or `None` when complete.
    pub partial_reason: Option<String>,
}

/// A canonical thread parent or an explicit placeholder when it cannot be
/// read from the mirror/Webex. `state` is one of `active`, `deleted`,
/// `missing`, or `unavailable`; only the first two carry `message`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadParent {
    pub id: String,
    pub state: String,
    pub message: Option<Message>,
}

/// One reverse-chronological thread-reply page. `next_before` is an opaque
/// reply ID for a subsequent request. A false `complete` means the caller must
/// not infer that a short page exhausts the remote thread.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadChildren {
    pub parent: ThreadParent,
    pub children: Vec<Message>,
    pub next_before: Option<String>,
    pub complete: bool,
    /// Stable reason for a false `complete`, or `None` when complete.
    pub partial_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_wire_names_match_the_v1_ui_contract() {
        let room = Room {
            id: "room-1".into(),
            title: Some("Project".into()),
            room_type: "group".into(),
            team_id: Some("team-1".into()),
            last_activity: Some("2026-10-09T12:00:00Z".into()),
            is_member: true,
            is_locked: None,
        };
        assert_eq!(
            serde_json::to_value(room).unwrap(),
            serde_json::json!({
                "id": "room-1",
                "title": "Project",
                "roomType": "group",
                "teamId": "team-1",
                "lastActivity": "2026-10-09T12:00:00Z",
                "isMember": true,
                "isLocked": null,
            })
        );
    }

    #[test]
    fn body_kind_wire_contract_preserves_legacy_provenance() {
        let body = MessageBody {
            kind: "legacyUnknown".into(),
            content: "ambiguous historic body".into(),
        };
        let input = MessageBodyInput {
            kind: "plainText".into(),
            content: "new plain body".into(),
        };
        assert_eq!(
            serde_json::to_value(body).unwrap(),
            serde_json::json!({"kind": "legacyUnknown", "content": "ambiguous historic body"})
        );
        assert_eq!(
            serde_json::to_value(input).unwrap(),
            serde_json::json!({"kind": "plainText", "content": "new plain body"})
        );
    }

    #[test]
    fn point_read_wire_contract_distinguishes_offline_from_confirmed_missing() {
        let person = PersonRead {
            id: "person-1".into(),
            state: "offline".into(),
            person: None,
        };
        let message = MessageRead {
            id: "message-1".into(),
            state: "not_found".into(),
            message: None,
        };
        assert_eq!(
            serde_json::to_value(person).unwrap(),
            serde_json::json!({"id": "person-1", "state": "offline", "person": null})
        );
        assert_eq!(
            serde_json::to_value(message).unwrap(),
            serde_json::json!({"id": "message-1", "state": "not_found", "message": null})
        );
    }

    #[test]
    fn message_page_wire_contract_keeps_partial_history_explicit() {
        let page = MessagePage {
            messages: Vec::new(),
            next_before: None,
            complete: false,
            partial_reason: Some("not_mirrored".into()),
        };
        assert_eq!(
            serde_json::to_value(page).unwrap(),
            serde_json::json!({
                "messages": [],
                "nextBefore": null,
                "complete": false,
                "partialReason": "not_mirrored"
            })
        );
    }

    #[test]
    fn thread_children_wire_contract_keeps_placeholders_and_completeness_explicit() {
        let page = ThreadChildren {
            parent: ThreadParent {
                id: "parent-1".into(),
                state: "unavailable".into(),
                message: None,
            },
            children: Vec::new(),
            next_before: None,
            complete: false,
            partial_reason: Some("parent_unavailable".into()),
        };
        assert_eq!(
            serde_json::to_value(page).unwrap(),
            serde_json::json!({
                "parent": {"id": "parent-1", "state": "unavailable", "message": null},
                "children": [],
                "nextBefore": null,
                "complete": false,
                "partialReason": "parent_unavailable"
            })
        );
    }

    #[test]
    fn team_wire_names_match_the_v1_ui_contract() {
        let team = Team {
            id: "team-1".into(),
            name: Some("Project team".into()),
        };
        assert_eq!(
            serde_json::to_value(team).unwrap(),
            serde_json::json!({"id": "team-1", "name": "Project team"})
        );
    }
}
