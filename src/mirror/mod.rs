//! Encrypted SQLite mirror. There is no plaintext fallback.

pub mod crypto;
pub mod migrations;
pub mod schema;

use crate::{
    paths::{check_mode, Paths},
    secrets,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use crypto::{aad, MirrorCrypto};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use webex::{Message, Person, Room};
use zeroize::Zeroizing;

const KEY_CHECK: &[u8] = b"webex-bridge-mirror-v1";

type UpsertPrevious = (
    i64,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
type StoredBody = (i64, String, Option<Vec<u8>>, Option<Vec<u8>>);
type DeletePrevious = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Result of a canonical message upsert.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Upsert {
    /// New message, revision zero.
    Created(i64),
    /// Existing canonical message changed, new revision.
    Edited(i64),
    /// This body, update timestamp and files are already stored.
    Unchanged,
    /// A stale REST response cannot resurrect a deleted message or its body.
    IgnoredDeleted,
}

/// Durable per-room boundary and initial/backfill progress.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RoomSync {
    /// Latest contiguous known message creation time.
    pub boundary_created_at: Option<String>,
    /// ID of the message at the boundary.
    pub boundary_message_id: Option<String>,
    /// Oldest stored message time (background backfill cursor).
    pub oldest_stored_at: Option<String>,
    /// Initial six-month backfill completed.
    pub initial_done: bool,
    /// Last catch-up completion time.
    pub last_catchup_at: Option<String>,
    /// Redacted result code, never a body.
    pub last_result: Option<String>,
    /// Last observed Webex room activity watermark (not a message timestamp).
    pub observed_last_activity: Option<String>,
}

/// Shared access that holds the DB lock only for synchronous operations.
/// Never await a Webex REST call while this lock is held: live Mercury writes
/// must proceed while background catch-up/backfill fetches remote pages.
#[derive(Clone)]
pub struct SharedMirror(Arc<Mutex<Mirror>>);

impl SharedMirror {
    /// Wrap one encrypted SQLite connection for live and background tasks.
    #[must_use]
    pub fn new(mirror: Mirror) -> Self {
        Self(Arc::new(Mutex::new(mirror)))
    }

    /// Execute a short, synchronous DB operation under the shared lock.
    pub async fn with<R>(&self, operation: impl FnOnce(&mut Mirror) -> Result<R>) -> Result<R> {
        let mut mirror = self.0.lock().await;
        operation(&mut mirror)
    }
}

/// Metadata-only mirror status for CLI/daemon health reporting.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MirrorStats {
    /// Known room rows.
    pub rooms: i64,
    /// All message revisions/tombstones.
    pub revisions: i64,
    /// Rooms whose initial six-month sync completed.
    pub initial_done: i64,
    /// Rooms with a recorded recovery gap.
    pub gaps: i64,
}

/// A local encrypted mirror; callers serialize writes through one owner.
pub struct Mirror {
    conn: Connection,
    crypto: MirrorCrypto,
}

impl Mirror {
    /// Open/create a 0600 WAL database using a 256-bit key in the user's Keychain.
    /// An existing DB without its key or verification sentinel is never re-keyed silently.
    pub fn open(paths: &Paths) -> Result<Self> {
        paths.ensure_dirs()?;
        let existed = match fs::symlink_metadata(&paths.mirror) {
            Ok(_) => {
                check_mode(&paths.mirror, 0o600)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let key = load_or_create_key(existed)?;
        if !existed {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&paths.mirror)
                .context("Cannot securely create mirror database")?;
        }
        check_mode(&paths.mirror, 0o600)?;
        let conn = Connection::open(&paths.mirror)?;
        Self::initialize(conn, key, !existed)
    }

    fn initialize(mut conn: Connection, key: [u8; 32], new_db: bool) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        migrations::migrate(&mut conn)?;
        let crypto = MirrorCrypto::new(key);
        let key_aad = aad("mirror_meta", "value", "key_check");
        if new_db {
            let value = crypto.seal_prefixed(KEY_CHECK, &key_aad)?;
            conn.execute(
                "INSERT INTO mirror_meta(key, value) VALUES ('key_check', ?1)",
                [value],
            )?;
        } else {
            let value: Vec<u8> = conn
                .query_row(
                    "SELECT value FROM mirror_meta WHERE key='key_check'",
                    [],
                    |row| row.get(0),
                )
                .context("Existing mirror has no encryption key check; refusing to open")?;
            if crypto.open_prefixed(&value, &key_aad)? != KEY_CHECK {
                bail!("Mirror encryption key check failed");
            }
        }
        Ok(Self { conn, crypto })
    }

    /// Create an encrypted in-memory mirror for tests; never touches Keychain.
    #[cfg(test)]
    pub(crate) fn in_memory(key: [u8; 32]) -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?, key, true)
    }

    /// Read counts only; no encrypted free text is decrypted.
    pub fn stats(&self) -> Result<MirrorStats> {
        Ok(MirrorStats {
            rooms: self
                .conn
                .query_row("SELECT count(*) FROM rooms", [], |row| row.get(0))?,
            revisions: self
                .conn
                .query_row("SELECT count(*) FROM messages", [], |row| row.get(0))?,
            initial_done: self.conn.query_row(
                "SELECT count(*) FROM room_sync WHERE initial_done=1",
                [],
                |row| row.get(0),
            )?,
            gaps: self.conn.query_row(
                "SELECT count(*) FROM room_sync WHERE last_result LIKE 'gap:%'",
                [],
                |row| row.get(0),
            )?,
        })
    }

    /// Upsert room metadata; title is encrypted, IDs/activity dates are indexed.
    pub fn upsert_room(&mut self, room: &Room, is_member: bool) -> Result<()> {
        let title_ct = room
            .title
            .as_ref()
            .map(|title| {
                self.crypto
                    .seal_prefixed(title.as_bytes(), &aad("rooms", "title", &room.id))
            })
            .transpose()?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO rooms(room_id,title_ct,type,team_id,last_activity,is_member,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(room_id) DO UPDATE SET
             title_ct=excluded.title_ct,type=excluded.type,team_id=excluded.team_id,
             last_activity=excluded.last_activity,is_member=excluded.is_member,updated_at=excluded.updated_at",
            params![room.id, title_ct, room.room_type, room.team_id, room.last_activity,
                is_member, Utc::now().to_rfc3339()],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO room_sync(room_id) VALUES (?1)",
            [&room.id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Check room identity without decrypting a possibly absent title.
    pub fn has_room(&self, room_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM rooms WHERE room_id=?1", [room_id], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .is_some())
    }

    /// Read verified room membership without revealing title or message contents.
    pub fn is_member(&self, room_id: &str) -> Result<Option<bool>> {
        self.conn
            .query_row(
                "SELECT is_member FROM rooms WHERE room_id=?1",
                [room_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Mark membership only after a REST check, never from a Mercury `leave` verb alone.
    pub fn mark_room_left(&mut self, room_id: &str) -> Result<()> {
        if self.conn.execute(
            "UPDATE rooms SET is_member=0,updated_at=?2 WHERE room_id=?1",
            params![room_id, Utc::now().to_rfc3339()],
        )? != 1
        {
            bail!("Cannot leave a room not in the mirror");
        }
        Ok(())
    }

    /// Read a title for an authorized UI client (not for agent routing).
    pub fn room_title(&self, room_id: &str) -> Result<Option<String>> {
        let encrypted: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT title_ct FROM rooms WHERE room_id=?1",
                [room_id],
                |row| row.get(0),
            )
            .optional()?;
        encrypted
            .flatten()
            .map(|blob| {
                self.crypto
                    .open_prefixed(&blob, &aad("rooms", "title", room_id))
                    .and_then(|bytes| {
                        String::from_utf8(bytes).context("Invalid encrypted room title")
                    })
            })
            .transpose()
    }

    /// Upsert encrypted person name and email addresses for UI display only.
    pub fn upsert_person(&mut self, person: &Person) -> Result<()> {
        if person.id.is_empty() {
            bail!("REST person has no ID");
        }
        let name_ct = self.crypto.seal_prefixed(
            person.display_name.as_bytes(),
            &aad("people", "display_name", &person.id),
        )?;
        let emails_ct = self.crypto.seal_prefixed(
            &serde_json::to_vec(&person.emails)?,
            &aad("people", "emails", &person.id),
        )?;
        self.conn.execute(
            "INSERT INTO people(person_id,display_name_ct,emails_ct,updated_at)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(person_id) DO UPDATE SET
             display_name_ct=excluded.display_name_ct,emails_ct=excluded.emails_ct,
             updated_at=excluded.updated_at",
            params![person.id, name_ct, emails_ct, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Check cached person identity without decrypting free text.
    pub fn has_person(&self, person_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM people WHERE person_id=?1",
                [person_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    /// Decrypt a person's display name for an authorized UI client.
    pub fn person_display_name(&self, person_id: &str) -> Result<Option<String>> {
        let encrypted: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT display_name_ct FROM people WHERE person_id=?1",
                [person_id],
                |row| row.get(0),
            )
            .optional()?;
        encrypted
            .map(|blob| {
                self.crypto
                    .open_prefixed(&blob, &aad("people", "display_name", person_id))
                    .and_then(|bytes| {
                        String::from_utf8(bytes).context("Invalid encrypted display name")
                    })
            })
            .transpose()
    }

    /// Insert a new canonical message/revision or deduplicate an identical REST result.
    /// Only the returned revision, never the Mercury activity ID, identifies an edit.
    pub fn upsert_message(&mut self, message: &Message) -> Result<Upsert> {
        let id = message
            .id
            .as_deref()
            .context("REST message has no canonical ID")?;
        let room_id = message
            .room_id
            .as_deref()
            .context("REST message has no room ID")?;
        let created_at = message
            .created
            .as_deref()
            .context("REST message has no creation time")?;
        parse_timestamp(created_at)?;
        let body = message.markdown.as_ref().or(message.text.as_ref());
        let files = message.files.as_ref().map(serde_json::to_vec).transpose()?;
        let previous: Option<UpsertPrevious> = self
            .conn
            .query_row(
                "SELECT revision,status,updated_at,body_ct,body_nonce,files_meta_ct
                 FROM messages WHERE message_id=?1 ORDER BY revision DESC LIMIT 1",
                [id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some((revision, status, updated, old_ct, old_nonce, old_files)) = &previous {
            if status == "deleted" {
                return Ok(Upsert::IgnoredDeleted);
            }
            if status == "active" && updated == &message.updated {
                let old_body = match (old_ct, old_nonce) {
                    (Some(ct), Some(nonce)) => Some(self.crypto.open(
                        ct,
                        nonce,
                        &message_aad("body", id, *revision),
                    )?),
                    (None, None) => None,
                    _ => bail!("Mirror body ciphertext/nonce mismatch"),
                };
                let old_files = old_files
                    .as_ref()
                    .map(|blob| {
                        self.crypto
                            .open_prefixed(blob, &message_aad("files", id, *revision))
                    })
                    .transpose()?;
                if old_body.as_deref() == body.map(|text| text.as_bytes()) && old_files == files {
                    return Ok(Upsert::Unchanged);
                }
            }
        }
        let revision = previous.as_ref().map_or(Ok(0), |(rev, ..)| {
            rev.checked_add(1).context("Message revision overflow")
        })?;
        let encrypted_body = body
            .map(|text| {
                self.crypto
                    .seal(text.as_bytes(), &message_aad("body", id, revision))
            })
            .transpose()?;
        let (body_ct, body_nonce) =
            encrypted_body.map_or((None, None), |(ct, nonce)| (Some(ct), Some(nonce)));
        let files_ct = files
            .as_ref()
            .map(|data| {
                self.crypto
                    .seal_prefixed(data, &message_aad("files", id, revision))
            })
            .transpose()?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO rooms(room_id,type,is_member,updated_at) VALUES (?1,'unknown',1,?2)",
            params![room_id, Utc::now().to_rfc3339()],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO room_sync(room_id) VALUES (?1)",
            [room_id],
        )?;
        tx.execute(
            "INSERT INTO messages(room_id,message_id,revision,parent_id,sender_id,created_at,updated_at,
                                  status,body_ct,body_nonce,files_meta_ct)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'active',?8,?9,?10)",
            params![room_id,id,revision,message.parent_id,message.person_id,created_at,
                message.updated,body_ct,body_nonce,files_ct],
        )?;
        tx.commit()?;
        Ok(if revision == 0 {
            Upsert::Created(0)
        } else {
            Upsert::Edited(revision)
        })
    }

    /// Fetch the latest active body for an authorized UI/accepted agent delivery.
    pub fn message_body(&self, id: &str) -> Result<Option<String>> {
        let latest: Option<StoredBody> = self
            .conn
            .query_row(
                "SELECT revision,status,body_ct,body_nonce FROM messages
                 WHERE message_id=?1 ORDER BY revision DESC LIMIT 1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        match latest {
            None | Some((_, _, None, None)) => Ok(None),
            Some((revision, status, Some(ct), Some(nonce))) if status == "active" => {
                let bytes = self
                    .crypto
                    .open(&ct, &nonce, &message_aad("body", id, revision))?;
                Ok(Some(
                    String::from_utf8(bytes).context("Invalid encrypted message body")?,
                ))
            }
            Some((_, status, _, _)) if status == "deleted" => Ok(None),
            _ => bail!("Mirror body ciphertext/nonce mismatch"),
        }
    }

    /// Tombstone a known canonical message and purge every stored revision's body/files.
    /// Returns false for unknown or already deleted messages.
    pub fn mark_deleted(&mut self, room_id: &str, message_id: &str) -> Result<bool> {
        let previous: Option<DeletePrevious> = self
            .conn
            .query_row(
                "SELECT revision,status,room_id,parent_id,sender_id,created_at FROM messages
                        WHERE message_id=?1 ORDER BY revision DESC LIMIT 1",
                [message_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((revision, status, stored_room, parent, sender, created)) = previous else {
            return Ok(false);
        };
        if stored_room != room_id {
            bail!("Delete room does not match mirrored message room");
        }
        if status == "deleted" {
            return Ok(false);
        }
        let new_revision = revision
            .checked_add(1)
            .context("Message revision overflow")?;
        let tx = self.conn.transaction()?;
        tx.execute("UPDATE messages SET body_ct=NULL, body_nonce=NULL, files_meta_ct=NULL WHERE message_id=?1", [message_id])?;
        tx.execute("INSERT INTO messages(room_id,message_id,revision,parent_id,sender_id,created_at,updated_at,status)
                    VALUES (?1,?2,?3,?4,?5,?6,?7,'deleted')",
            params![room_id,message_id,new_revision,parent,sender,created,Utc::now().to_rfc3339()])?;
        tx.execute(
            "UPDATE deliveries SET state='deleted' WHERE message_id=?1",
            [message_id],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Read persisted sync cursors. Newly stored rooms start with `initial_done=false`.
    pub fn room_sync(&self, room_id: &str) -> Result<Option<RoomSync>> {
        self.conn
            .query_row(
                "SELECT boundary_created_at,boundary_message_id,oldest_stored_at,
                    initial_done,last_catchup_at,last_result,observed_last_activity
             FROM room_sync WHERE room_id=?1",
                [room_id],
                |row| {
                    Ok(RoomSync {
                        boundary_created_at: row.get(0)?,
                        boundary_message_id: row.get(1)?,
                        oldest_stored_at: row.get(2)?,
                        initial_done: row.get(3)?,
                        last_catchup_at: row.get(4)?,
                        last_result: row.get(5)?,
                        observed_last_activity: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Advance the live/catch-up boundary only after the corresponding page is stored.
    pub fn record_boundary(
        &mut self,
        room_id: &str,
        created_at: &str,
        message_id: &str,
    ) -> Result<()> {
        let Some(state) = self.room_sync(room_id)? else {
            bail!("Cannot advance boundary for a room not in the mirror");
        };
        let new = parse_timestamp(created_at)?;
        if let Some(old_time) = state.boundary_created_at.as_deref() {
            if new <= parse_timestamp(old_time)? {
                return Ok(());
            }
        }
        self.conn.execute(
            "UPDATE room_sync SET boundary_created_at=?2,boundary_message_id=?3,
             last_catchup_at=?4,last_result='ok' WHERE room_id=?1",
            params![room_id, created_at, message_id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Record the oldest stored message without moving a cursor forwards.
    pub fn record_oldest(&mut self, room_id: &str, created_at: &str) -> Result<()> {
        let Some(state) = self.room_sync(room_id)? else {
            bail!("Cannot backfill a room not in the mirror");
        };
        let new = parse_timestamp(created_at)?;
        if let Some(old) = state.oldest_stored_at.as_deref() {
            if new >= parse_timestamp(old)? {
                return Ok(());
            }
        }
        self.conn.execute(
            "UPDATE room_sync SET oldest_stored_at=?2 WHERE room_id=?1",
            params![room_id, created_at],
        )?;
        Ok(())
    }

    /// Persist the room's lastActivity only after reconciliation finished.
    pub fn mark_room_observed(&mut self, room_id: &str, last_activity: &str) -> Result<()> {
        parse_timestamp(last_activity)?;
        if self.conn.execute(
            "UPDATE room_sync SET observed_last_activity=?2 WHERE room_id=?1",
            params![room_id, last_activity],
        )? != 1
        {
            bail!("Cannot mark an unknown room observed");
        }
        Ok(())
    }

    /// Record an explicit, auditable catch-up gap when the old boundary is unreachable.
    pub fn record_gap(&mut self, room_id: &str, from: &str, to: &str) -> Result<()> {
        parse_timestamp(from)?;
        parse_timestamp(to)?;
        let detail = format!("gap:{from}:{to}");
        if self.conn.execute(
            "UPDATE room_sync SET last_result=?2,last_catchup_at=?3 WHERE room_id=?1",
            params![room_id, detail, Utc::now().to_rfc3339()],
        )? != 1
        {
            bail!("Cannot record a gap for unknown room");
        }
        Ok(())
    }

    /// True if this canonical ID is already in the mirror (including tombstones).
    pub fn contains_message(&self, message_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM messages WHERE message_id=?1 LIMIT 1",
                [message_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    /// Mark background initial backfill complete for this room.
    pub fn mark_initial_done(&mut self, room_id: &str) -> Result<()> {
        if self.conn.execute(
            "UPDATE room_sync SET initial_done=1 WHERE room_id=?1",
            [room_id],
        )? != 1
        {
            bail!("Cannot finish initial sync for unknown room");
        }
        Ok(())
    }

    /// Optional retention: remove every revision/tombstone before cutoff.
    /// Disabled by default; callers must record the user-selected policy.
    pub fn prune_before(&mut self, cutoff: &str) -> Result<usize> {
        parse_timestamp(cutoff)?;
        let tx = self.conn.transaction()?;
        let removed = tx.execute("DELETE FROM messages WHERE created_at < ?1", [cutoff])?;
        tx.execute("INSERT INTO audit(ts,scope,action,ref,detail_redacted) VALUES (?1,'system','retention',NULL,?2)",
            params![Utc::now().to_rfc3339(), format!("removed={removed}")])?;
        tx.commit()?;
        Ok(removed)
    }

    /// Cursor for background initial backfill, recovered from durable rows after a crash.
    pub fn oldest_message_id(&self, room_id: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT m.message_id FROM messages m WHERE m.room_id=?1 AND m.status='active'
             AND m.revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)
             ORDER BY m.created_at ASC, m.message_id ASC LIMIT 1",
                [room_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Canonical IDs whose latest revision is active in a room. Reconcile only on events/outage.
    pub fn active_message_ids(&self, room_id: &str) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT m.message_id FROM messages m WHERE m.room_id=?1 AND m.status='active'
             AND m.revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)",
        )?;
        let rows = statement.query_map([room_id], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
}

fn parse_timestamp(value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(value).context("Invalid Webex message timestamp")
}

fn message_aad(column: &str, id: &str, revision: i64) -> Vec<u8> {
    aad("messages", column, &format!("{id}/{revision}"))
}

fn load_or_create_key(existing_db: bool) -> Result<[u8; 32]> {
    match secrets::get_mirror_key()? {
        Some(encoded) => {
            let mut decoded = Zeroizing::new(
                STANDARD
                    .decode(encoded)
                    .context("Invalid mirror Keychain value")?,
            );
            if decoded.len() != 32 {
                bail!("Mirror Keychain key must be 256 bits")
            }
            let mut key = [0_u8; 32];
            key.copy_from_slice(&decoded);
            decoded.fill(0);
            Ok(key)
        }
        None if existing_db => {
            bail!("Existing mirror is missing its Keychain encryption key; refusing to regenerate")
        }
        None => {
            let mut key = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut key)
                .context("Secure random generator unavailable")?;
            let encoded = STANDARD.encode(key);
            secrets::set_mirror_key(&encoded)?;
            Ok(key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, text: &str, updated: Option<&str>) -> Message {
        Message {
            id: Some(id.into()),
            room_id: Some("room-1".into()),
            text: Some(text.into()),
            created: Some("2026-10-08T12:00:00Z".into()),
            updated: updated.map(str::to_owned),
            ..Message::default()
        }
    }

    #[test]
    fn revisions_dedupe_and_delete_purges_all_bodies() {
        let mut mirror = Mirror::in_memory([3_u8; 32]).unwrap();
        assert_eq!(
            mirror
                .upsert_message(&message("msg-1", "private original", None))
                .unwrap(),
            Upsert::Created(0)
        );
        assert_eq!(
            mirror
                .upsert_message(&message("msg-1", "private original", None))
                .unwrap(),
            Upsert::Unchanged
        );
        assert_eq!(
            mirror
                .upsert_message(&message(
                    "msg-1",
                    "private edit",
                    Some("2026-10-08T12:05:00Z")
                ))
                .unwrap(),
            Upsert::Edited(1)
        );
        assert_eq!(
            mirror.message_body("msg-1").unwrap().as_deref(),
            Some("private edit")
        );
        assert_eq!(mirror.active_message_ids("room-1").unwrap(), vec!["msg-1"]);
        assert!(mirror.mark_deleted("room-1", "msg-1").unwrap());
        assert!(!mirror.mark_deleted("room-1", "msg-1").unwrap());
        assert!(mirror.message_body("msg-1").unwrap().is_none());
        assert_eq!(
            mirror
                .upsert_message(&message("msg-1", "stale plaintext", None))
                .unwrap(),
            Upsert::IgnoredDeleted
        );
        assert!(mirror.message_body("msg-1").unwrap().is_none());
        assert!(mirror.active_message_ids("room-1").unwrap().is_empty());
        let remaining: i64 = mirror
            .conn
            .query_row(
                "SELECT count(*) FROM messages WHERE body_ct IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn disk_mirror_never_contains_private_text() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bridge.db");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let mut mirror =
            Mirror::initialize(Connection::open(&path).unwrap(), [12_u8; 32], true).unwrap();
        let room = Room {
            id: "room-1".into(),
            title: Some("Private room title".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: None,
            last_activity: "2026-10-08T12:00:00Z".into(),
            creator_id: "person-1".into(),
            created: "2026-10-08T12:00:00Z".into(),
        };
        mirror.upsert_room(&room, true).unwrap();
        assert_eq!(
            mirror.room_title("room-1").unwrap().as_deref(),
            Some("Private room title")
        );
        let person = Person {
            id: "person-1".into(),
            display_name: "Private Person".into(),
            emails: vec!["private@example.test".into()],
            ..Person::default()
        };
        mirror.upsert_person(&person).unwrap();
        assert_eq!(
            mirror.person_display_name("person-1").unwrap().as_deref(),
            Some("Private Person")
        );
        mirror
            .upsert_message(&message("msg-1", "Private message content", None))
            .unwrap();
        drop(mirror);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let bytes = fs::read(&path).unwrap();
        for secret in [
            b"Private room title".as_slice(),
            b"Private Person",
            b"private@example.test",
            b"Private message content",
        ] {
            assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        }
    }

    #[test]
    fn optional_retention_removes_old_revisions() {
        let mut mirror = Mirror::in_memory([10_u8; 32]).unwrap();
        mirror
            .upsert_message(&message("old", "private", None))
            .unwrap();
        let mut new = message("new", "private", None);
        new.created = Some("2026-10-09T12:00:00Z".into());
        mirror.upsert_message(&new).unwrap();
        assert_eq!(mirror.prune_before("2026-10-08T12:00:01Z").unwrap(), 1);
        assert!(!mirror.contains_message("old").unwrap());
        assert!(mirror.contains_message("new").unwrap());
    }

    #[test]
    fn sync_boundaries_advance_monotonically_and_persist() {
        let mut mirror = Mirror::in_memory([4_u8; 32]).unwrap();
        mirror
            .upsert_message(&message("msg-1", "body", None))
            .unwrap();
        assert!(!mirror.room_sync("room-1").unwrap().unwrap().initial_done);
        mirror
            .record_boundary("room-1", "2026-10-08T12:00:00Z", "msg-1")
            .unwrap();
        mirror
            .record_boundary("room-1", "2026-10-08T11:00:00Z", "older")
            .unwrap();
        assert_eq!(
            mirror
                .room_sync("room-1")
                .unwrap()
                .unwrap()
                .boundary_message_id
                .as_deref(),
            Some("msg-1")
        );
        mirror
            .record_boundary("room-1", "2026-10-08T13:00:00Z", "msg-2")
            .unwrap();
        mirror
            .record_oldest("room-1", "2026-10-08T11:00:00Z")
            .unwrap();
        mirror
            .record_oldest("room-1", "2026-10-08T12:00:00Z")
            .unwrap();
        mirror.mark_initial_done("room-1").unwrap();
        let state = mirror.room_sync("room-1").unwrap().unwrap();
        assert_eq!(state.boundary_message_id.as_deref(), Some("msg-2"));
        assert_eq!(
            state.oldest_stored_at.as_deref(),
            Some("2026-10-08T11:00:00Z")
        );
        assert!(state.initial_done);
    }

    #[test]
    fn rejects_wrong_room_deletion_and_wrong_key() {
        let mut mirror = Mirror::in_memory([9_u8; 32]).unwrap();
        mirror
            .upsert_message(&message("msg", "private", None))
            .unwrap();
        assert!(mirror.mark_deleted("other-room", "msg").is_err());
        let conn = mirror.conn;
        assert!(Mirror::initialize(conn, [8_u8; 32], false).is_err());
    }
}
