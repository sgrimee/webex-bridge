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
    pub markdown: Option<String>,
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
