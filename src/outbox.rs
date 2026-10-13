//! Draft-only agent outbox with cryptographic, single-use local approvals.
//!
//! A Webex write can be prepared only for a configured route. The mirror stores
//! its text encrypted, and the approval credential is stored only as a hash.
//! Nothing in this module turns inbound Webex text into an instruction.

use crate::{
    config::{Config, Route},
    mirror::{crypto::aad, Mirror},
    routing::AgentEvent,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

const WEBEX_MAX_MESSAGE_BYTES: usize = crate::dto::MAX_MESSAGE_BODY_BYTES;
type StoredDraft = (
    String,
    String,
    Option<String>,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    String,
);

/// Draft details returned only to the local agent host. The host, never its
/// model, retains `approval_token` to bind its subsequent confirmation click.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    pub draft_id: String,
    pub sha256: String,
    pub preview: String,
    /// Decrypted only for the local extension's approval dialog. It is never
    /// returned from a model tool or exposed as a room-listing API.
    pub room_title: Option<String>,
    pub approval_token: String,
    pub expires_at: String,
}

/// Metadata used to make exactly one Webex send after a valid approval.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreparedSend {
    pub draft_id: String,
    pub room_id: String,
    pub parent_id: Option<String>,
    pub markdown: String,
}

/// Metadata returned by the agent outbox status endpoint. Never includes body
/// text, an approval credential, or a Webex room ID.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftStatus {
    pub draft_id: String,
    pub route_id: String,
    pub state: String,
    pub sha256: String,
    pub expires_at: String,
}

fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Prefix of the mandatory agent trailer line (`— 🤖 <agentName> · …`).
const AGENT_TRAILER_PREFIX: &str = "— 🤖 ";

/// How recent an attempt must be for the account + exact-trailer echo rule.
const OWN_ECHO_TRAILER_MINUTES: i64 = 10;

/// How long normalised (not byte-exact) own-echo matching looks back.
const OWN_ECHO_NORMALIZED_DAYS: i64 = 7;

fn normalize_echo(body: &str) -> String {
    body.replace("\r\n", "\n").trim_end().to_owned()
}

fn digest(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value))
}

fn parse_ttl(value: &str) -> Result<Duration> {
    let Some(number) = value.strip_suffix('m') else {
        bail!("approval_ttl must use whole minutes, for example 10m");
    };
    let minutes = number
        .parse::<i64>()
        .context("approval_ttl has an invalid minute count")?;
    if !(1..=60).contains(&minutes) {
        bail!("approval_ttl must be between 1m and 60m");
    }
    Ok(Duration::minutes(minutes))
}

fn route<'a>(config: &'a Config, id: &str) -> Result<&'a Route> {
    config
        .routes
        .iter()
        .find(|route| route.id == id)
        .context("Unknown configured route")
}

fn validate_markdown(route: &Route, markdown: &str) -> Result<()> {
    if markdown.is_empty() || markdown.len() > WEBEX_MAX_MESSAGE_BYTES {
        bail!("Markdown must be between 1 and {WEBEX_MAX_MESSAGE_BYTES} bytes");
    }
    if markdown.chars().any(|ch| ch == '\0') {
        bail!("Markdown contains a NUL byte");
    }
    let Some(last_line) = markdown.lines().last() else {
        bail!("Markdown has no content");
    };
    if !is_agent_trailer(last_line, &route.agent_name) {
        bail!("Agent Markdown must end with its required trailer");
    }
    Ok(())
}

/// Whether `line` is exactly the trailer of `agent_name`: `— 🤖 <name>`
/// followed by end of line or whitespace, so `sam/coder2` is not `sam/coder`.
pub(crate) fn is_agent_trailer(line: &str, agent_name: &str) -> bool {
    line.strip_prefix(AGENT_TRAILER_PREFIX)
        .and_then(|rest| rest.strip_prefix(agent_name))
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
}

impl Mirror {
    /// Create an encrypted, approval-bound draft for exactly one configured
    /// route. The caller cannot select a room independently of that route.
    pub fn create_draft(
        &mut self,
        config: &Config,
        route_id: &str,
        parent_id: Option<&str>,
        markdown: &str,
    ) -> Result<Draft> {
        let route = route(config, route_id)?;
        config.check_write_room(&route.room_id)?;
        validate_markdown(route, markdown)?;
        if let Some(parent_id) = parent_id {
            let parent_room = self
                .conn
                .query_row(
                    "SELECT room_id FROM messages WHERE message_id=?1 ORDER BY revision DESC LIMIT 1",
                    [parent_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if parent_room.as_deref() != Some(route.room_id.as_str()) {
                bail!("Draft parent is not a mirrored message in this route room");
            }
            if self.agent_hops(&route.room_id, parent_id)?
                >= i64::from(config.limits.thread_agent_hop_limit)
            {
                bail!("Agent thread hop limit reached");
            }
        }
        let draft_id = random_secret();
        let approval_token = random_secret();
        let sha256 = digest(markdown.as_bytes());
        let expires_at = (Utc::now() + parse_ttl(&config.limits.approval_ttl)?).to_rfc3339();
        let (body_ct, body_nonce) = self
            .crypto
            .seal(markdown.as_bytes(), &aad("outbox", "body", &draft_id))?;
        self.conn.execute(
            "INSERT INTO outbox(draft_id,route_id,room_id,parent_id,body_ct,body_nonce,sha256,
             approval_hash,expires_at,state,webex_message_id,attempts,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending',NULL,0,?10)",
            params![
                draft_id,
                route.id,
                route.room_id,
                parent_id,
                body_ct,
                body_nonce,
                sha256,
                digest(approval_token.as_bytes()),
                expires_at,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(Draft {
            draft_id,
            sha256,
            preview: markdown.into(),
            room_title: self.room_title(&route.room_id)?,
            approval_token,
            expires_at,
        })
    }

    /// Consume exactly one still-valid approval and return the encrypted draft
    /// material for the daemon's one send attempt.
    pub fn approve_draft(
        &mut self,
        config: &Config,
        route_ids: &[String],
        draft_id: &str,
        sha256: &str,
        approval_token: &str,
    ) -> Result<Option<PreparedSend>> {
        let row: Option<StoredDraft> = self
            .conn
            .query_row(
                "SELECT route_id,room_id,parent_id,body_ct,body_nonce,sha256,approval_hash,expires_at,state
                 FROM outbox WHERE draft_id=?1",
                [draft_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
            )
            .optional()?;
        let Some((
            route_id,
            room_id,
            parent_id,
            body_ct,
            body_nonce,
            stored_sha,
            approval_hash,
            expires_at,
            state,
        )) = row
        else {
            return Ok(None);
        };
        if !route_ids.iter().any(|claimed| claimed == &route_id) {
            bail!("Draft is not available to this agent session");
        }
        if state != "pending" {
            return Ok(None);
        }
        if stored_sha != sha256 || approval_hash != digest(approval_token.as_bytes()) {
            bail!("Draft approval does not match");
        }
        let expires_at = DateTime::parse_from_rfc3339(&expires_at)
            .context("Stored draft expiry is invalid")?
            .with_timezone(&Utc);
        if expires_at <= Utc::now() {
            self.conn.execute(
                "UPDATE outbox SET state='expired' WHERE draft_id=?1 AND state='pending'",
                [draft_id],
            )?;
            return Ok(None);
        }
        let configured_route = route(config, &route_id)?;
        if configured_route.room_id != room_id {
            bail!("Draft route destination changed; create a new draft");
        }
        config.check_write_room(&room_id)?;
        let markdown = String::from_utf8(self.crypto.open(
            &body_ct,
            &body_nonce,
            &aad("outbox", "body", draft_id),
        )?)
        .context("Invalid encrypted draft body")?;
        if digest(markdown.as_bytes()) != stored_sha {
            bail!("Draft body checksum mismatch");
        }
        validate_markdown(configured_route, &markdown)?;
        let changed = self.conn.execute(
            "UPDATE outbox SET state='sending',attempts=attempts+1
             WHERE draft_id=?1 AND state='pending'",
            [draft_id],
        )?;
        if changed != 1 {
            return Ok(None);
        }
        Ok(Some(PreparedSend {
            draft_id: draft_id.into(),
            room_id,
            parent_id,
            markdown,
        }))
    }

    /// Mark a one-shot outbound attempt as confirmed by Webex.
    /// Any delivery already created for this Webex message (an echo routed
    /// through a fingerprint false negative) is superseded in the same
    /// transaction, so the agent's own send never stays an inbound delivery.
    pub fn mark_sent(&mut self, draft_id: &str, webex_message_id: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        if tx.execute(
            "UPDATE outbox SET state='sent',webex_message_id=?2
             WHERE draft_id=?1 AND state='sending'",
            params![draft_id, webex_message_id],
        )? != 1
        {
            bail!("Draft is not in the sending state");
        }
        let removed = {
            let mut statement = tx.prepare(
                "SELECT route_id,revision FROM deliveries
                 WHERE message_id=?1 AND state IN ('pending','accepted','rejected')",
            )?;
            let rows = statement
                .query_map([webex_message_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        tx.execute(
            "UPDATE deliveries SET state='superseded',decided_at=?2
             WHERE message_id=?1 AND state IN ('pending','accepted','rejected')",
            params![webex_message_id, Utc::now().to_rfc3339()],
        )?;
        let route_id: String = tx.query_row(
            "SELECT route_id FROM outbox WHERE draft_id=?1",
            [draft_id],
            |row| row.get(0),
        )?;
        tx.commit()?;
        for (delivery_route, revision) in removed {
            self.agent_events.push(AgentEvent::removed(
                delivery_route,
                webex_message_id,
                revision,
                "own_send",
            ));
        }
        self.agent_events.push(AgentEvent::Outbox {
            route_id,
            draft_id: draft_id.into(),
            state: "sent",
        });
        Ok(())
    }

    /// Record a definitive rejected Webex response without retrying it.
    pub fn mark_failed(&mut self, draft_id: &str) -> Result<()> {
        if self.conn.execute(
            "UPDATE outbox SET state='failed' WHERE draft_id=?1 AND state='sending'",
            [draft_id],
        )? != 1
        {
            bail!("Draft is not in the sending state");
        }
        self.push_outbox_event(draft_id, "failed")
    }

    /// Preserve ambiguous delivery instead of retrying a possibly sent message.
    pub fn mark_delivery_unknown(&mut self, draft_id: &str) -> Result<()> {
        if self.conn.execute(
            "UPDATE outbox SET state='delivery-unknown' WHERE draft_id=?1 AND state='sending'",
            [draft_id],
        )? != 1
        {
            bail!("Draft is not in the sending state");
        }
        self.push_outbox_event(draft_id, "delivery-unknown")
    }

    /// Return status only for drafts belonging to routes claimed by this host.
    pub fn draft_status(
        &self,
        route_ids: &[String],
        draft_id: &str,
    ) -> Result<Option<DraftStatus>> {
        let row: Option<(String, String, String, String, String)> = self
            .conn
            .query_row(
                "SELECT route_id,state,sha256,expires_at,draft_id FROM outbox WHERE draft_id=?1",
                [draft_id],
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
        let Some((route_id, state, sha256, expires_at, draft_id)) = row else {
            return Ok(None);
        };
        if !route_ids.iter().any(|claimed| claimed == &route_id) {
            bail!("Draft is not available to this agent session");
        }
        Ok(Some(DraftStatus {
            draft_id,
            route_id,
            state,
            sha256,
            expires_at,
        }))
    }

    /// Promote one `delivery-unknown` draft to `sent` when its own echo is
    /// mirrored: the ambiguous attempt demonstrably reached Webex. The match is
    /// the same fingerprint used for echo exclusion (exact body hash, or the
    /// CRLF/trailing-whitespace-normalised decrypted draft), in the same room,
    /// from the daemon account when known, with an agent trailer, and never
    /// for a message created before the draft. Identical drafts are matched
    /// oldest first, one per echo. Returns whether a draft was promoted.
    pub(crate) fn reconcile_delivery_unknown(
        &mut self,
        room_id: &str,
        sender_id: &str,
        body: &str,
        account_id: Option<&str>,
        message_id: &str,
        message_created_at: &str,
    ) -> Result<bool> {
        if account_id.is_some_and(|account| account != sender_id)
            || !body
                .trim_end()
                .lines()
                .last()
                .is_some_and(|line| line.starts_with(AGENT_TRAILER_PREFIX))
        {
            return Ok(false);
        }
        let Ok(message_created) = DateTime::parse_from_rfc3339(message_created_at) else {
            return Ok(false);
        };
        let candidates = {
            let mut statement = self.conn.prepare(
                "SELECT draft_id,sha256,body_ct,body_nonce,created_at FROM outbox
                 WHERE room_id=?1 AND state='delivery-unknown' AND webex_message_id IS NULL
                 ORDER BY created_at,draft_id",
            )?;
            let rows = statement
                .query_map([room_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let exact = digest(body.as_bytes());
        let normalized = normalize_echo(body);
        for (draft_id, sha256, body_ct, body_nonce, created_at) in candidates {
            let drafted_before = DateTime::parse_from_rfc3339(&created_at)
                .is_ok_and(|drafted| drafted <= message_created);
            if !drafted_before {
                continue;
            }
            let matches = sha256 == exact || {
                let draft =
                    self.crypto
                        .open(&body_ct, &body_nonce, &aad("outbox", "body", &draft_id))?;
                std::str::from_utf8(&draft).is_ok_and(|draft| normalize_echo(draft) == normalized)
            };
            if !matches {
                continue;
            }
            let promoted = self.conn.execute(
                "UPDATE outbox SET state='sent',webex_message_id=?2
                 WHERE draft_id=?1 AND state='delivery-unknown' AND webex_message_id IS NULL",
                params![draft_id, message_id],
            )?;
            if promoted == 1 {
                self.push_outbox_event(&draft_id, "sent")?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn push_outbox_event(&mut self, draft_id: &str, state: &'static str) -> Result<()> {
        let route_id: String = self.conn.query_row(
            "SELECT route_id FROM outbox WHERE draft_id=?1",
            [draft_id],
            |row| row.get(0),
        )?;
        self.agent_events.push(AgentEvent::Outbox {
            route_id,
            draft_id: draft_id.into(),
            state,
        });
        Ok(())
    }

    /// Whether a mirrored message is this bridge's own agent send echoing back.
    ///
    /// `approve_draft` persists the draft's room and body hash as `sending`
    /// before the one Webex request, so an echo routed before `mark_sent`
    /// (Mercury race) or after a `delivery-unknown` attempt still matches. Such
    /// messages never route: the fingerprint has no expiry. A known daemon
    /// account must be the sender; with no cached account identity the match
    /// fails closed on room + body alone.
    ///
    /// When the account is known, a normalisation-robust rule also applies:
    /// an account message whose last line is exactly a route's trailer is an
    /// echo if that route has an attempt (sending/sent/delivery-unknown) in
    /// this room within the last 10 minutes, whatever Webex did to the body.
    /// The attempt time is bounded by the draft's approval expiry, so the check
    /// uses `expires_at`. User edits of agent-sent messages never route either:
    /// routing excludes every revision of a recorded `webex_message_id`.
    pub(crate) fn is_own_outbound(
        &self,
        room_id: &str,
        sender_id: &str,
        body: &str,
        account_id: Option<&str>,
    ) -> Result<bool> {
        if account_id.is_some_and(|account| account != sender_id) {
            return Ok(false);
        }
        // Every stored draft hash covers Markdown that `validate_markdown`
        // required to end with the route's `— 🤖 <agent>` trailer, so only a
        // body carrying an agent trailer can match; a short human "yes" never
        // collides with an agent send. Check it explicitly before any lookup.
        if !body
            .trim_end()
            .lines()
            .last()
            .is_some_and(|line| line.starts_with(AGENT_TRAILER_PREFIX))
        {
            return Ok(false);
        }
        if account_id.is_some() {
            let last_line = body.trim_end().lines().last().unwrap_or_default();
            let since = (Utc::now() - Duration::minutes(OWN_ECHO_TRAILER_MINUTES)).to_rfc3339();
            let mut statement = self.conn.prepare(
                "SELECT DISTINCT r.agent_name FROM outbox o JOIN routes r ON r.route_id=o.route_id
                 WHERE o.room_id=?1 AND o.expires_at>=?2
                   AND o.state IN ('sending','sent','delivery-unknown')",
            )?;
            let agents = statement
                .query_map(params![room_id, since], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if agents
                .iter()
                .any(|agent| is_agent_trailer(last_line, agent))
            {
                return Ok(true);
            }
        }
        let exact = self
            .conn
            .query_row(
                "SELECT 1 FROM outbox WHERE room_id=?1 AND sha256=?2
                   AND state IN ('sending','sent','delivery-unknown')",
                params![room_id, digest(body.as_bytes())],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if exact {
            return Ok(true);
        }
        // Tolerate Webex echo normalisation (CRLF, trailing whitespace) for
        // recent attempts in this room by comparing decrypted draft bodies.
        let since = (Utc::now() - Duration::days(OWN_ECHO_NORMALIZED_DAYS)).to_rfc3339();
        let mut statement = self.conn.prepare(
            "SELECT draft_id,body_ct,body_nonce FROM outbox
             WHERE room_id=?1 AND created_at>=?2
               AND state IN ('sending','sent','delivery-unknown')",
        )?;
        let rows = statement
            .query_map(params![room_id, since], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let wanted = normalize_echo(body);
        for (draft_id, body_ct, body_nonce) in rows {
            let draft =
                self.crypto
                    .open(&body_ct, &body_nonce, &aad("outbox", "body", &draft_id))?;
            if std::str::from_utf8(&draft).is_ok_and(|draft| normalize_echo(draft) == wanted) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn agent_hops(&self, room_id: &str, parent_id: &str) -> Result<i64> {
        let mut statement = self.conn.prepare(
            "SELECT message_id,revision,body_ct,body_nonce FROM messages
             WHERE room_id=?1 AND status='active' AND (message_id=?2 OR parent_id=?2)
               AND revision=(SELECT MAX(revision) FROM messages WHERE message_id=messages.message_id)
             ORDER BY created_at DESC,message_id DESC",
        )?;
        let rows = statement.query_map(params![room_id, parent_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })?;
        let messages = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut hops = 0;
        for (id, revision, body_ct, body_nonce) in messages {
            let (Some(body_ct), Some(body_nonce)) = (body_ct, body_nonce) else {
                break;
            };
            let body = self.crypto.open(
                &body_ct,
                &body_nonce,
                &crate::mirror::message_aad("body", &id, revision),
            )?;
            let body = String::from_utf8(body).context("Invalid encrypted message body")?;
            if body
                .lines()
                .last()
                .is_some_and(|line| line.starts_with("— 🤖 "))
            {
                hops += 1;
            } else {
                break;
            }
        }
        Ok(hops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{DevConfig, Receive},
        mirror::Mirror,
    };
    use webex::{Message, Room};

    fn config() -> Config {
        Config {
            dev: Some(DevConfig {
                write_allowlist: vec!["room".into()],
                secret_source: crate::config::DevSecretSource::Keychain,
            }),
            routes: vec![Route {
                id: "r".into(),
                room_id: "room".into(),
                agent_name: "sam/coder".into(),
                allowed_senders: vec![],
                receive: Receive::Addressed,
                workspace: "/workspace".into(),
            }],
            ..Config::default()
        }
    }

    #[test]
    fn draft_approval_binds_text_destination_and_is_single_use() {
        let config = config();
        let mut mirror = Mirror::in_memory([41; 32]).unwrap();
        mirror
            .upsert_room(
                &Room {
                    id: "room".into(),
                    title: Some("Approved room".into()),
                    room_type: "group".into(),
                    is_locked: false,
                    team_id: None,
                    last_activity: "2026-10-08T12:00:00Z".into(),
                    creator_id: "person".into(),
                    created: "2026-10-08T12:00:00Z".into(),
                },
                true,
            )
            .unwrap();
        let body = "Hello humans\n\n— 🤖 sam/coder · ref abc";
        let draft = mirror.create_draft(&config, "r", None, body).unwrap();
        assert_eq!(draft.preview, body);
        assert_eq!(draft.room_title.as_deref(), Some("Approved room"));
        assert!(mirror
            .approve_draft(
                &config,
                &["r".into()],
                &draft.draft_id,
                "wrong",
                &draft.approval_token
            )
            .is_err());
        let prepared = mirror
            .approve_draft(
                &config,
                &["r".into()],
                &draft.draft_id,
                &draft.sha256,
                &draft.approval_token,
            )
            .unwrap()
            .unwrap();
        assert_eq!(prepared.markdown, body);
        assert!(mirror
            .approve_draft(
                &config,
                &["r".into()],
                &draft.draft_id,
                &draft.sha256,
                &draft.approval_token
            )
            .unwrap()
            .is_none());
        mirror.mark_delivery_unknown(&draft.draft_id).unwrap();
        assert_eq!(
            mirror
                .draft_status(&["r".into()], &draft.draft_id)
                .unwrap()
                .unwrap()
                .state,
            "delivery-unknown"
        );
    }

    #[test]
    fn draft_refuses_other_route_parent_and_missing_trailer() {
        let config = config();
        let mut mirror = Mirror::in_memory([42; 32]).unwrap();
        assert!(mirror
            .create_draft(&config, "other", None, "x\n— 🤖 sam/coder")
            .is_err());
        assert!(mirror
            .create_draft(&config, "r", None, "no trailer")
            .is_err());
        mirror
            .upsert_message(&Message {
                id: Some("parent".into()),
                room_id: Some("other".into()),
                text: Some("body".into()),
                created: Some("2099-01-01T00:00:00Z".into()),
                ..Message::default()
            })
            .unwrap();
        assert!(mirror
            .create_draft(&config, "r", Some("parent"), "x\n— 🤖 sam/coder")
            .is_err());
    }
}
