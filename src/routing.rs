//! Durable, allow-listed routing from mirrored messages to agent deliveries.
//!
//! Routing runs entirely in the daemon after mirror writes. Message text is
//! treated solely as data for the narrowly defined address-prefix comparison;
//! it is never executed, interpolated into a path, or used to alter routing.

use crate::{
    config::{Config, Receive, Route},
    diagnostics,
    mirror::Mirror,
};
use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Metadata for a delivery. Text is deliberately absent until `accept`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delivery {
    /// Opaque, URL-safe local identifier for this route/message/revision tuple.
    pub id: String,
    /// Configured route, which reveals no room ID.
    pub route_id: String,
    /// Canonical sender Webex person ID.
    pub sender_id: Option<String>,
    /// Canonical message creation time.
    pub created_at: String,
    /// Monotonic revision of the canonical Webex message.
    pub revision: i64,
    /// Pending, accepted or rejected; only requested states are returned.
    pub state: String,
    /// Decrypted sender display name from the people mirror, when known.
    /// Local display metadata only; never message text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
    /// Decrypted title of the route's room for local display only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_title: Option<String>,
}

/// Local-display preview of a still-pending delivery. It carries exactly the
/// text `accept` would release but changes no delivery state, so the agent host
/// can show it to the human without adding it to model context.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryPreview {
    /// Stable opaque delivery ID.
    pub id: String,
    /// Configured route, not a room ID.
    pub route_id: String,
    /// Revision being previewed.
    pub revision: i64,
    /// Canonical message creation time.
    pub created_at: String,
    /// Canonical sender Webex person ID.
    pub sender_id: Option<String>,
    /// Decrypted sender display name, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
    /// Decrypted room title for local display only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_title: Option<String>,
    /// Thread parent message ID, when the message is a reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Sanitized untrusted remote text, identical to the accept release.
    pub markdown: String,
}

/// Content released only after an explicit local acceptance.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedDelivery {
    /// Stable opaque delivery ID.
    pub id: String,
    /// Configured route, not a room ID.
    pub route_id: String,
    /// Canonical sender Webex person ID.
    pub sender_id: Option<String>,
    /// Creation time retained for provenance in the agent host.
    pub created_at: String,
    /// Revision accepted by the local user.
    pub revision: i64,
    /// Sanitized untrusted remote text. It is never logged by this crate.
    pub markdown: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DeliveryKey {
    route_id: String,
    message_id: String,
    revision: i64,
}

/// Decrypted, sanitized release material shared by preview and accept.
struct ReleasedMessage {
    sender_id: Option<String>,
    created_at: String,
    parent_id: Option<String>,
    markdown: String,
}

type StoredReleasedMessage = (
    Option<String>,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

impl DeliveryKey {
    fn encode(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.encode(format!(
            "{}\0{}\0{}",
            self.route_id, self.message_id, self.revision
        ))
    }

    fn decode(value: &str) -> Result<Self> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .context("Invalid delivery ID")?;
        let decoded = String::from_utf8(decoded).context("Invalid delivery ID")?;
        let mut fields = decoded.split('\0');
        let route_id = fields
            .next()
            .filter(|value| !value.is_empty())
            .context("Invalid delivery ID")?;
        let message_id = fields
            .next()
            .filter(|value| !value.is_empty())
            .context("Invalid delivery ID")?;
        let revision = fields
            .next()
            .context("Invalid delivery ID")?
            .parse::<i64>()
            .context("Invalid delivery ID")?;
        if fields.next().is_some() || revision < 0 {
            bail!("Invalid delivery ID");
        }
        Ok(Self {
            route_id: route_id.into(),
            message_id: message_id.into(),
            revision,
        })
    }
}

fn config_hash(route: &Route) -> String {
    let encoded = serde_json::to_vec(route).expect("route serialization cannot fail");
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(Sha256::digest(encoded))
}

impl Mirror {
    /// Persist configured routes. A route keeps its original delivery boundary
    /// while its room is unchanged; moving it to another room creates a new
    /// boundary, as required by D16.
    pub fn sync_routes(&mut self, routes: &[Route]) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.transaction()?;
        for route in routes {
            let existing_room = tx
                .query_row(
                    "SELECT room_id FROM routes WHERE route_id=?1",
                    [&route.id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let created_at = if existing_room.as_deref() == Some(&route.room_id) {
                None
            } else {
                Some(now.as_str())
            };
            if let Some(created_at) = created_at {
                tx.execute(
                    "INSERT INTO routes(route_id,room_id,agent_name,created_at,config_hash)
                     VALUES (?1,?2,?3,?4,?5)
                     ON CONFLICT(route_id) DO UPDATE SET room_id=excluded.room_id,
                       agent_name=excluded.agent_name,created_at=excluded.created_at,
                       config_hash=excluded.config_hash",
                    params![
                        route.id,
                        route.room_id,
                        route.agent_name,
                        created_at,
                        config_hash(route)
                    ],
                )?;
            } else {
                tx.execute(
                    "UPDATE routes SET agent_name=?2,config_hash=?3 WHERE route_id=?1",
                    params![route.id, route.agent_name, config_hash(route)],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Evaluate all unprocessed latest revisions against the current route
    /// configuration and enqueue only messages that pass every delivery rule.
    /// Returns the number newly made pending.
    pub fn queue_deliveries(&mut self, config: &Config) -> Result<usize> {
        Ok(self.queue_new_deliveries(config)?.len())
    }

    /// As [`Self::queue_deliveries`], but returns only newly queued metadata so
    /// the daemon can emit a route-scoped `inbox.new` event without querying or
    /// exposing already-pending deliveries.
    pub fn queue_new_deliveries(&mut self, config: &Config) -> Result<Vec<Delivery>> {
        let routes = config
            .routes
            .iter()
            .map(|route| (route.id.as_str(), route))
            .collect::<HashMap<_, _>>();
        let mut statement = self.conn.prepare(
            "SELECT r.route_id,r.created_at,m.message_id,m.revision,m.sender_id,m.created_at,
                    m.body_ct,m.body_nonce
             FROM routes r JOIN messages m ON m.room_id=r.room_id
             WHERE m.status='active'
               AND m.revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)
               AND m.created_at >= r.created_at
               AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.webex_message_id=m.message_id)
             ORDER BY m.created_at,m.message_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
            ))
        })?;
        let candidates = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let mut queued = Vec::new();
        for (
            route_id,
            _route_created_at,
            message_id,
            revision,
            sender_id,
            created_at,
            body_ct,
            body_nonce,
        ) in candidates
        {
            let Some(route) = routes.get(route_id.as_str()) else {
                continue;
            };
            let key = DeliveryKey {
                route_id: route_id.clone(),
                message_id: message_id.clone(),
                revision,
            };
            if self.delivery_exists(&key)? {
                continue;
            }
            // An edit invalidates older decisions before its new revision is
            // evaluated, even when its new body no longer matches the route.
            self.conn.execute(
                "UPDATE deliveries SET state='superseded',decided_at=?4
                 WHERE route_id=?1 AND message_id=?2 AND revision<?3 AND state IN ('pending','accepted','rejected')",
                params![route_id, message_id, revision, Utc::now().to_rfc3339()],
            )?;
            let Some(sender_id) = sender_id else {
                self.audit_filtered_once(&key, "missing_sender")?;
                continue;
            };
            if !route
                .allowed_senders
                .iter()
                .any(|allowed| allowed == &sender_id)
            {
                self.audit_filtered_once(&key, "sender_not_allowed")?;
                continue;
            }
            let (Some(body_ct), Some(body_nonce)) = (body_ct, body_nonce) else {
                self.audit_filtered_once(&key, "empty_body")?;
                continue;
            };
            let body = String::from_utf8(self.crypto.open(
                &body_ct,
                &body_nonce,
                &super::mirror::message_aad("body", &message_id, revision),
            )?)
            .context("Invalid encrypted message body")?;
            if body.len() > config.limits.agent_inbound_max_bytes {
                self.audit_filtered_once(&key, "inbound_too_large")?;
                continue;
            }
            if matches!(route.receive, Receive::Addressed)
                && !body.starts_with(&format!("{}:", route.agent_name))
            {
                self.audit_filtered_once(&key, "not_addressed")?;
                continue;
            }
            let cutoff = (Utc::now() - Duration::minutes(1)).to_rfc3339();
            let per_minute: u32 = self.conn.query_row(
                "SELECT count(DISTINCT message_id) FROM messages
                 WHERE sender_id=?1 AND created_at>=?2",
                params![sender_id, cutoff],
                |row| row.get(0),
            )?;
            if per_minute > config.limits.sender_rate_per_min {
                self.audit_filtered_once(&key, "sender_rate_limited")?;
                continue;
            }
            let pending: i64 = self.conn.query_row(
                "SELECT count(*) FROM deliveries WHERE route_id=?1 AND state='pending'",
                [&route_id],
                |row| row.get(0),
            )?;
            if pending
                >= i64::try_from(config.limits.route_queue_cap)
                    .context("Route queue cap is too large")?
            {
                self.audit_filtered_once(&key, "route_queue_full")?;
                continue;
            }
            self.conn.execute(
                "INSERT INTO deliveries(route_id,message_id,revision,state,decided_at)
                 VALUES (?1,?2,?3,'pending',NULL)",
                params![route_id, message_id, revision],
            )?;
            queued.push(Delivery {
                id: key.encode(),
                route_id,
                sender_id: Some(sender_id),
                created_at,
                revision,
                state: "pending".into(),
                sender_name: None,
                room_title: None,
            });
        }
        Ok(queued)
    }

    /// List metadata only for claimed route deliveries. No body leaves the
    /// mirror until the user explicitly accepts an item.
    pub fn deliveries(&self, route_ids: &[String], state: Option<&str>) -> Result<Vec<Delivery>> {
        if route_ids.is_empty() {
            return Ok(Vec::new());
        }
        if let Some(state) = state {
            if !matches!(state, "pending" | "accepted" | "rejected") {
                bail!("Invalid delivery state");
            }
        }
        let placeholders = std::iter::repeat_n("?", route_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut query = format!(
            "SELECT d.route_id,d.message_id,d.revision,d.state,m.sender_id,m.created_at,r.room_id
             FROM deliveries d JOIN messages m ON m.message_id=d.message_id AND m.revision=d.revision
             JOIN routes r ON r.route_id=d.route_id
             WHERE d.route_id IN ({placeholders})"
        );
        if state.is_some() {
            query.push_str(" AND d.state=?");
        }
        query.push_str(" ORDER BY m.created_at,m.message_id");
        let mut values = route_ids.iter().map(String::as_str).collect::<Vec<_>>();
        if let Some(state) = state {
            values.push(state);
        }
        let mut statement = self.conn.prepare(&query)?;
        let rows = statement.query_map(rusqlite::params_from_iter(values), |row| {
            let key = DeliveryKey {
                route_id: row.get(0)?,
                message_id: row.get(1)?,
                revision: row.get(2)?,
            };
            Ok((
                Delivery {
                    id: key.encode(),
                    route_id: key.route_id.clone(),
                    revision: key.revision,
                    state: row.get(3)?,
                    sender_id: row.get(4)?,
                    created_at: row.get(5)?,
                    sender_name: None,
                    room_title: None,
                },
                row.get::<_, String>(6)?,
            ))
        })?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        // Display metadata is decrypted once per distinct room/sender.
        let mut titles = HashMap::<String, Option<String>>::new();
        let mut names = HashMap::<String, Option<String>>::new();
        let mut deliveries = Vec::with_capacity(rows.len());
        for (mut delivery, room_id) in rows {
            delivery.room_title = match titles.get(&room_id) {
                Some(title) => title.clone(),
                None => {
                    let title = self.display_room_title(&room_id);
                    titles.insert(room_id, title.clone());
                    title
                }
            };
            if let Some(sender_id) = delivery.sender_id.clone() {
                delivery.sender_name = match names.get(&sender_id) {
                    Some(name) => name.clone(),
                    None => {
                        let name = self.display_sender_name(&sender_id);
                        names.insert(sender_id, name.clone());
                        name
                    }
                };
            }
            deliveries.push(delivery);
        }
        Ok(deliveries)
    }

    /// Return the exact sanitized text `accept` would release for one pending
    /// delivery on a claimed route, without changing its state. Returns `None`
    /// (indistinguishably) for malformed, unknown, unclaimed or non-pending
    /// deliveries. Records a metadata-only audit row; never logs content.
    pub fn preview_delivery(
        &self,
        route_ids: &[String],
        encoded_id: &str,
    ) -> Result<Option<DeliveryPreview>> {
        let Ok(key) = DeliveryKey::decode(encoded_id) else {
            return Ok(None);
        };
        if !route_ids.iter().any(|route_id| route_id == &key.route_id) {
            return Ok(None);
        }
        let room_id = self
            .conn
            .query_row(
                "SELECT r.room_id FROM deliveries d JOIN routes r ON r.route_id=d.route_id
                 WHERE d.route_id=?1 AND d.message_id=?2 AND d.revision=?3 AND d.state='pending'",
                params![key.route_id, key.message_id, key.revision],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(room_id) = room_id else {
            return Ok(None);
        };
        let Some(released) = self.released_message(&key)? else {
            return Ok(None);
        };
        let sender_name = match released.sender_id.as_deref() {
            Some(sender_id) => self.display_sender_name(sender_id),
            None => None,
        };
        let room_title = self.display_room_title(&room_id);
        self.conn.execute(
            "INSERT INTO audit(ts,scope,action,ref,detail_redacted) VALUES (?1,'agent','inbox_preview',?2,NULL)",
            params![
                Utc::now().to_rfc3339(),
                format!("{}:{}:{}", key.route_id, key.message_id, key.revision)
            ],
        )?;
        Ok(Some(DeliveryPreview {
            id: key.encode(),
            route_id: key.route_id,
            revision: key.revision,
            created_at: released.created_at,
            sender_id: released.sender_id,
            sender_name,
            room_title,
            parent_id: released.parent_id,
            markdown: released.markdown,
        }))
    }

    /// Decrypt and sanitize the active body of one delivery revision. This is
    /// the single release path shared by preview and accept.
    fn released_message(&self, key: &DeliveryKey) -> Result<Option<ReleasedMessage>> {
        let stored: Option<StoredReleasedMessage> = self
            .conn
            .query_row(
                "SELECT sender_id,created_at,parent_id,body_ct,body_nonce FROM messages
                 WHERE message_id=?1 AND revision=?2 AND status='active'",
                params![key.message_id, key.revision],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((sender_id, created_at, parent_id, Some(body_ct), Some(body_nonce))) = stored
        else {
            return Ok(None);
        };
        let body = self.crypto.open(
            &body_ct,
            &body_nonce,
            &super::mirror::message_aad("body", &key.message_id, key.revision),
        )?;
        let markdown = sanitize_terminal_text(
            &String::from_utf8(body).context("Invalid encrypted message body")?,
        );
        Ok(Some(ReleasedMessage {
            sender_id,
            created_at,
            parent_id,
            markdown,
        }))
    }

    /// Best-effort display title: an unreadable title is omitted rather than
    /// failing the inbox list or a valid preview.
    fn display_room_title(&self, room_id: &str) -> Option<String> {
        best_effort_display(self.room_title(room_id))
    }

    /// Best-effort sender display name, as [`Self::display_room_title`].
    fn display_sender_name(&self, sender_id: &str) -> Option<String> {
        best_effort_display(self.person_display_name(sender_id))
    }

    /// Change one claimed delivery's decision. Only acceptance decrypts and
    /// returns text, so model delivery remains an explicit local action.
    pub fn decide_delivery(
        &mut self,
        route_ids: &[String],
        encoded_id: &str,
        accept: bool,
    ) -> Result<Option<AcceptedDelivery>> {
        let key = DeliveryKey::decode(encoded_id)?;
        if !route_ids.iter().any(|route_id| route_id == &key.route_id) {
            bail!("Delivery is not claimed by this session");
        }
        let target = if accept { "accepted" } else { "rejected" };
        let changed = self.conn.execute(
            "UPDATE deliveries SET state=?4,decided_at=?5
             WHERE route_id=?1 AND message_id=?2 AND revision=?3 AND state='pending'",
            params![
                key.route_id,
                key.message_id,
                key.revision,
                target,
                Utc::now().to_rfc3339()
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        if !accept {
            return Ok(Some(AcceptedDelivery {
                id: key.encode(),
                route_id: key.route_id,
                sender_id: None,
                created_at: String::new(),
                revision: key.revision,
                markdown: String::new(),
            }));
        }
        let Some(ReleasedMessage {
            sender_id,
            created_at,
            markdown,
            ..
        }) = self.released_message(&key)?
        else {
            bail!("Accepted delivery no longer has a body");
        };
        Ok(Some(AcceptedDelivery {
            id: key.encode(),
            route_id: key.route_id,
            sender_id,
            created_at,
            revision: key.revision,
            markdown,
        }))
    }

    fn delivery_exists(&self, key: &DeliveryKey) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM deliveries WHERE route_id=?1 AND message_id=?2 AND revision=?3",
                params![key.route_id, key.message_id, key.revision],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    fn audit_filtered_once(&self, key: &DeliveryKey, reason: &str) -> Result<()> {
        let reference = format!("{}:{}:{}", key.route_id, key.message_id, key.revision);
        let known = self
            .conn
            .query_row(
                "SELECT 1 FROM audit WHERE scope='agent' AND action='route_filtered' AND ref=?1",
                [&reference],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !known {
            self.conn.execute(
                "INSERT INTO audit(ts,scope,action,ref,detail_redacted) VALUES (?1,'agent','route_filtered',?2,?3)",
                params![Utc::now().to_rfc3339(), reference, reason],
            )?;
        }
        Ok(())
    }
}

/// Bidirectional embedding/override (U+202A–U+202E) and isolate
/// (U+2066–U+2069) controls can visually reorder text ("Trojan Source").
fn is_bidi_control(ch: char) -> bool {
    matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Remove terminal control introducers and bidi overrides/isolates before any
/// released remote text crosses the local API boundary. Newlines and tabs
/// remain ordinary message data; Unicode line/paragraph separators become
/// explicit `\n`. Zero-width joiners and LRM/RLM are kept in message text
/// because emoji sequences and right-to-left scripts legitimately need them.
fn sanitize_terminal_text(input: &str) -> String {
    input
        .chars()
        .filter(|ch| {
            !matches!(
                *ch,
                '\u{1b}' | '\u{009b}' | '\u{009d}' | '\u{0090}' | '\u{0098}'
            ) && !is_bidi_control(*ch)
                && (!ch.is_control() || matches!(*ch, '\n' | '\r' | '\t'))
        })
        .map(|ch| match ch {
            '\u{2028}' | '\u{2029}' => '\n',
            other => other,
        })
        .collect()
}

fn best_effort_display(value: Result<Option<String>>) -> Option<String> {
    value
        .inspect_err(|_| {
            // Constant, content-free: never the error, IDs or ciphertext.
            diagnostics::debug("agent.display_metadata_unavailable");
        })
        .ok()
        .flatten()
        .map(|text| sanitize_display_line(&text))
}

/// Display metadata (names, titles) is remote free text shown on one UI line:
/// strip terminal controls, bidi overrides/isolates and invisible zero-width
/// characters (U+200B–U+200F, U+2060, U+FEFF), and replace line breaks, tabs
/// and U+2028/U+2029 with spaces so a name cannot forge or reorder UI text.
fn sanitize_display_line(input: &str) -> String {
    sanitize_terminal_text(input)
        .chars()
        .filter(|ch| !matches!(*ch, '\u{200b}'..='\u{200f}' | '\u{2060}' | '\u{feff}'))
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Route, mirror::Mirror};
    use webex::Message;

    fn config() -> Config {
        Config {
            routes: vec![Route {
                id: "r".into(),
                room_id: "room".into(),
                agent_name: "sam/coder".into(),
                allowed_senders: vec!["person".into()],
                receive: Receive::Addressed,
                workspace: "/workspace".into(),
            }],
            ..Config::default()
        }
    }
    fn message(body: &str) -> Message {
        Message {
            id: Some("message".into()),
            room_id: Some("room".into()),
            person_id: Some("person".into()),
            text: Some(body.into()),
            created: Some("2099-01-01T00:00:00Z".into()),
            ..Message::default()
        }
    }

    #[test]
    fn only_addressed_allowed_new_messages_are_released_after_acceptance() {
        let config = config();
        let mut mirror = Mirror::in_memory([6; 32]).unwrap();
        mirror.sync_routes(&config.routes).unwrap();
        mirror
            .upsert_message(&message("sam/coder: please review"))
            .unwrap();
        let queued = mirror.queue_new_deliveries(&config).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].route_id, "r");
        assert_eq!(queued[0].state, "pending");
        let pending = mirror.deliveries(&["r".into()], Some("pending")).unwrap();
        assert_eq!(pending.len(), 1);
        let accepted = mirror
            .decide_delivery(&["r".into()], &pending[0].id, true)
            .unwrap()
            .unwrap();
        assert_eq!(accepted.markdown, "sam/coder: please review");
        assert!(mirror
            .deliveries(&["other".into()], None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn non_addressed_message_is_never_queued_and_controls_are_stripped() {
        let config = config();
        let mut mirror = Mirror::in_memory([7; 32]).unwrap();
        mirror.sync_routes(&config.routes).unwrap();
        mirror
            .upsert_message(&message("ignore me\u{1b}[2J"))
            .unwrap();
        assert_eq!(mirror.queue_deliveries(&config).unwrap(), 0);
        assert_eq!(sanitize_terminal_text("ok\u{1b}[2J\n"), "ok[2J\n");
    }

    #[test]
    fn edits_supersede_prior_delivery_and_preroute_history_stays_hidden() {
        let config = config();
        let mut mirror = Mirror::in_memory([8; 32]).unwrap();
        mirror.sync_routes(&config.routes).unwrap();
        let mut old = message("sam/coder: before the route");
        old.id = Some("old-message".into());
        old.created = Some("2000-01-01T00:00:00Z".into());
        mirror.upsert_message(&old).unwrap();
        assert_eq!(mirror.queue_deliveries(&config).unwrap(), 0);

        mirror
            .upsert_message(&message("sam/coder: original"))
            .unwrap();
        assert_eq!(mirror.queue_deliveries(&config).unwrap(), 1);
        let mut edited = message("sam/coder: revised");
        edited.updated = Some("2099-01-01T00:05:00Z".into());
        mirror.upsert_message(&edited).unwrap();
        assert_eq!(mirror.queue_deliveries(&config).unwrap(), 1);
        let deliveries = mirror.deliveries(&["r".into()], None).unwrap();
        assert_eq!(deliveries.len(), 2);
        assert_eq!(deliveries[0].state, "superseded");
        assert_eq!(deliveries[1].state, "pending");
        assert_eq!(deliveries[1].revision, 1);
    }

    #[test]
    fn preview_releases_accept_text_without_changing_state_and_hides_others() {
        let config = config();
        let mut mirror = Mirror::in_memory([9; 32]).unwrap();
        mirror.sync_routes(&config.routes).unwrap();
        mirror
            .upsert_room(
                &webex::Room {
                    id: "room".into(),
                    title: Some("Route\nroom\u{1b}[2J".into()),
                    room_type: "group".into(),
                    is_locked: false,
                    team_id: None,
                    last_activity: "2099-01-01T00:00:00Z".into(),
                    creator_id: "person".into(),
                    created: "2099-01-01T00:00:00Z".into(),
                },
                true,
            )
            .unwrap();
        mirror
            .upsert_person(&webex::Person {
                id: "person".into(),
                display_name: "Pat Sender".into(),
                ..webex::Person::default()
            })
            .unwrap();
        let mut reply = message("sam/coder: look\u{1b}[2J here");
        reply.parent_id = Some("parent-message".into());
        mirror.upsert_message(&reply).unwrap();
        let mut second = message("sam/coder: second");
        second.id = Some("second".into());
        mirror.upsert_message(&second).unwrap();
        assert_eq!(mirror.queue_deliveries(&config).unwrap(), 2);
        let pending = mirror.deliveries(&["r".into()], Some("pending")).unwrap();
        assert_eq!(pending[0].sender_name.as_deref(), Some("Pat Sender"));
        assert_eq!(pending[0].room_title.as_deref(), Some("Route room[2J"));
        let routes = ["r".to_string()];

        let preview = mirror
            .preview_delivery(&routes, &pending[0].id)
            .unwrap()
            .unwrap();
        assert_eq!(preview.markdown, "sam/coder: look[2J here");
        assert_eq!(preview.parent_id.as_deref(), Some("parent-message"));
        assert_eq!(preview.sender_name.as_deref(), Some("Pat Sender"));
        assert_eq!(preview.room_title.as_deref(), Some("Route room[2J"));
        assert_eq!(
            mirror.deliveries(&routes, Some("pending")).unwrap().len(),
            2
        );
        let accepted = mirror
            .decide_delivery(&routes, &pending[0].id, true)
            .unwrap()
            .unwrap();
        assert_eq!(accepted.markdown, preview.markdown);

        // Accepted, rejected, other-route, unknown and malformed: all `None`.
        assert!(mirror
            .preview_delivery(&routes, &pending[0].id)
            .unwrap()
            .is_none());
        mirror
            .decide_delivery(&routes, &pending[1].id, false)
            .unwrap();
        assert!(mirror
            .preview_delivery(&routes, &pending[1].id)
            .unwrap()
            .is_none());
        assert!(mirror
            .preview_delivery(&["other".into()], &pending[0].id)
            .unwrap()
            .is_none());
        let unknown = DeliveryKey {
            route_id: "r".into(),
            message_id: "missing".into(),
            revision: 0,
        }
        .encode();
        assert!(mirror
            .preview_delivery(&routes, &unknown)
            .unwrap()
            .is_none());
        assert!(mirror
            .preview_delivery(&routes, "not base64!")
            .unwrap()
            .is_none());
    }

    #[test]
    fn unreadable_display_metadata_is_omitted_not_fatal() {
        let config = config();
        let mut mirror = Mirror::in_memory([10; 32]).unwrap();
        mirror.sync_routes(&config.routes).unwrap();
        mirror
            .upsert_person(&webex::Person {
                id: "person".into(),
                display_name: "Pat Sender".into(),
                ..webex::Person::default()
            })
            .unwrap();
        mirror
            .upsert_message(&message("sam/coder: still readable"))
            .unwrap();
        assert_eq!(mirror.queue_deliveries(&config).unwrap(), 1);
        mirror
            .conn
            .execute(
                "UPDATE people SET display_name_ct=x'00112233445566778899' WHERE person_id='person'",
                [],
            )
            .unwrap();
        let routes = ["r".to_string()];
        let listed = mirror.deliveries(&routes, Some("pending")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sender_name, None);
        let preview = mirror
            .preview_delivery(&routes, &listed[0].id)
            .unwrap()
            .unwrap();
        assert_eq!(preview.sender_name, None);
        assert_eq!(preview.markdown, "sam/coder: still readable");
    }

    #[test]
    fn bidi_and_invisible_characters_are_neutralised() {
        // An RLO in a name could render "Pat\u{202e}gnp.exe" as "Patexe.png".
        assert_eq!(
            sanitize_display_line("Pat\u{202e}gnp.exe\u{2066}x\u{2069}"),
            "Patgnp.exex"
        );
        assert_eq!(
            sanitize_display_line("a\u{200b}b\u{200d}c\u{200e}d\u{2060}e\u{feff}f"),
            "abcdef"
        );
        assert_eq!(
            sanitize_display_line("a\u{2028}b\u{2029}c\nd\te"),
            "a b c d e"
        );
        // Released text keeps newlines, ZWJ emoji and RTL marks, but drops overrides.
        assert_eq!(
            sanitize_terminal_text("x\u{202e}y\u{2067}z\u{2069}\n👩\u{200d}💻\u{200f}\u{2028}w"),
            "xyz\n👩\u{200d}💻\u{200f}\nw"
        );

        let config = config();
        let mut mirror = Mirror::in_memory([11; 32]).unwrap();
        mirror.sync_routes(&config.routes).unwrap();
        mirror
            .upsert_person(&webex::Person {
                id: "person".into(),
                display_name: "Pat\u{202e}gnp.exe".into(),
                ..webex::Person::default()
            })
            .unwrap();
        mirror
            .upsert_message(&message("sam/coder: see \u{202e}fdp.exe"))
            .unwrap();
        assert_eq!(mirror.queue_deliveries(&config).unwrap(), 1);
        let routes = ["r".to_string()];
        let listed = mirror.deliveries(&routes, Some("pending")).unwrap();
        assert_eq!(listed[0].sender_name.as_deref(), Some("Patgnp.exe"));
        let preview = mirror
            .preview_delivery(&routes, &listed[0].id)
            .unwrap()
            .unwrap();
        assert_eq!(preview.sender_name.as_deref(), Some("Patgnp.exe"));
        assert_eq!(preview.markdown, "sam/coder: see fdp.exe");
        let accepted = mirror
            .decide_delivery(&routes, &listed[0].id, true)
            .unwrap()
            .unwrap();
        assert_eq!(accepted.markdown, preview.markdown);
    }
}
