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
use serde::Serialize;
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
type UiRoomRow = (
    Option<Vec<u8>>,
    String,
    Option<String>,
    Option<String>,
    bool,
);
type UiPersonRow = (Option<Vec<u8>>, Option<Vec<u8>>);
type UiMessageRow = (
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
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

/// Full room metadata released only to an authorized UI session.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiRoom {
    pub id: String,
    pub title: Option<String>,
    pub room_type: String,
    pub team_id: Option<String>,
    pub last_activity: Option<String>,
    pub is_member: bool,
}

/// Full person metadata released only to an authorized UI session.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiPerson {
    pub id: String,
    pub display_name: Option<String>,
    pub emails: Option<Vec<String>>,
}

/// Canonical mirror message released only to an authorized UI session.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiMessage {
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
    /// Known rooms whose initial sync/backfill has not finished.
    pub initial_pending: i64,
    /// Rooms with a recorded recovery gap.
    pub gaps: i64,
    /// Room phases with a sanitized failure that retry on reconnect.
    pub failures: i64,
}

/// A room whose last sync attempt failed. Names are decrypted only for the
/// explicit local CLI request; this type is never written to daemon logs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SyncFailure {
    pub room_id: String,
    pub title: Option<String>,
    pub is_member: bool,
    pub result: String,
}

/// A persisted interval whose continuity was not proven within the normal
/// catch-up limit. It contains timestamps only, never message content.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecoveryGap {
    pub room_id: String,
    pub from: String,
    pub to: String,
}

/// A local encrypted mirror; callers serialize writes through one owner.
pub struct Mirror {
    // Internal bridge modules implement durable routing/outbox operations on
    // this connection; the fields remain unavailable outside this crate.
    pub(crate) conn: Connection,
    pub(crate) crypto: MirrorCrypto,
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
            rooms: self.conn.query_row(
                "SELECT count(*) FROM rooms WHERE is_member=1",
                [],
                |row| row.get(0),
            )?,
            revisions: self
                .conn
                .query_row("SELECT count(*) FROM messages", [], |row| row.get(0))?,
            initial_done: self.conn.query_row(
                "SELECT count(*) FROM room_sync AS sync
                 JOIN rooms ON rooms.room_id=sync.room_id
                 WHERE rooms.is_member=1 AND sync.initial_done=1",
                [],
                |row| row.get(0),
            )?,
            initial_pending: self.conn.query_row(
                "SELECT count(*) FROM room_sync AS sync
                 JOIN rooms ON rooms.room_id=sync.room_id
                 WHERE rooms.is_member=1 AND sync.initial_done=0",
                [],
                |row| row.get(0),
            )?,
            gaps: self.conn.query_row(
                "SELECT count(*) FROM room_sync AS sync
                 JOIN rooms ON rooms.room_id=sync.room_id
                 WHERE rooms.is_member=1 AND sync.last_result LIKE 'gap:%'",
                [],
                |row| row.get(0),
            )?,
            failures: self.conn.query_row(
                "SELECT count(*) FROM room_sync AS sync
                 JOIN rooms ON rooms.room_id=sync.room_id
                 WHERE rooms.is_member=1 AND sync.last_result LIKE '%_error'",
                [],
                |row| row.get(0),
            )?,
        })
    }

    /// List retryable room failures for an explicit, local diagnostic request.
    /// Room titles remain encrypted at rest and are never written to daemon logs.
    pub fn sync_failures(&self) -> Result<Vec<SyncFailure>> {
        let mut statement = self.conn.prepare(
            "SELECT sync.room_id,rooms.title_ct,rooms.is_member,sync.last_result
             FROM room_sync AS sync
             LEFT JOIN rooms ON rooms.room_id=sync.room_id
             WHERE sync.last_result LIKE '%_error'
             ORDER BY sync.last_result,sync.room_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut failures = Vec::new();
        for row in rows {
            let (room_id, encrypted_title, is_member, result) = row?;
            let title = encrypted_title
                .map(|blob| {
                    self.crypto
                        .open_prefixed(&blob, &aad("rooms", "title", &room_id))
                        .and_then(|bytes| {
                            String::from_utf8(bytes).context("Invalid encrypted room title")
                        })
                })
                .transpose()?;
            failures.push(SyncFailure {
                room_id,
                title,
                is_member,
                result,
            });
        }
        Ok(failures)
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

    /// Mark rooms absent from a complete REST room listing as no longer joined.
    /// Call only after every pagination page was fetched successfully.
    pub fn mark_unobserved_rooms_left(
        &mut self,
        observed_room_ids: &std::collections::HashSet<String>,
    ) -> Result<usize> {
        let mut statement = self
            .conn
            .prepare("SELECT room_id FROM rooms WHERE is_member=1")?;
        let current_members = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let mut left = 0;
        for room_id in current_members {
            if !observed_room_ids.contains(&room_id) {
                left += self.conn.execute(
                    "UPDATE rooms SET is_member=0,updated_at=?2 WHERE room_id=?1",
                    params![room_id, Utc::now().to_rfc3339()],
                )?;
            }
        }
        Ok(left)
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

    /// List all room metadata for an authorized UI session, newest first.
    pub fn ui_rooms(&self) -> Result<Vec<UiRoom>> {
        let mut statement = self.conn.prepare(
            "SELECT room_id,title_ct,type,team_id,last_activity,is_member FROM rooms
             ORDER BY last_activity DESC,room_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, bool>(5)?,
            ))
        })?;
        rows.map(|row| {
            let (id, title_ct, room_type, team_id, last_activity, is_member) = row?;
            let title = title_ct
                .map(|blob| {
                    self.crypto
                        .open_prefixed(&blob, &aad("rooms", "title", &id))
                        .and_then(|bytes| {
                            String::from_utf8(bytes).context("Invalid encrypted room title")
                        })
                })
                .transpose()?;
            Ok(UiRoom {
                id,
                title,
                room_type,
                team_id,
                last_activity,
                is_member,
            })
        })
        .collect::<Result<Vec<_>>>()
    }

    /// Get one room's metadata for an authorized UI session.
    pub fn ui_room(&self, room_id: &str) -> Result<Option<UiRoom>> {
        let row: Option<UiRoomRow> = self
            .conn
            .query_row(
                "SELECT title_ct,type,team_id,last_activity,is_member FROM rooms WHERE room_id=?1",
                [room_id],
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
        row.map(|(title_ct, room_type, team_id, last_activity, is_member)| {
            let title = title_ct
                .map(|blob| {
                    self.crypto
                        .open_prefixed(&blob, &aad("rooms", "title", room_id))
                        .and_then(|bytes| {
                            String::from_utf8(bytes).context("Invalid encrypted room title")
                        })
                })
                .transpose()?;
            Ok(UiRoom {
                id: room_id.into(),
                title,
                room_type,
                team_id,
                last_activity,
                is_member,
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

    /// Get one person's decrypted metadata for an authorized UI session.
    pub fn ui_person(&self, person_id: &str) -> Result<Option<UiPerson>> {
        let row: Option<UiPersonRow> = self
            .conn
            .query_row(
                "SELECT display_name_ct,emails_ct FROM people WHERE person_id=?1",
                [person_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(name_ct, emails_ct)| {
            let display_name = name_ct
                .map(|blob| {
                    self.crypto
                        .open_prefixed(&blob, &aad("people", "display_name", person_id))
                        .and_then(|bytes| {
                            String::from_utf8(bytes).context("Invalid encrypted display name")
                        })
                })
                .transpose()?;
            let emails = emails_ct
                .map(|blob| {
                    self.crypto
                        .open_prefixed(&blob, &aad("people", "emails", person_id))
                        .and_then(|bytes| {
                            serde_json::from_slice(&bytes)
                                .context("Invalid encrypted person emails")
                        })
                })
                .transpose()?;
            Ok(UiPerson {
                id: person_id.into(),
                display_name,
                emails,
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

    /// Get one canonical message (including a tombstone) for an authorized UI session.
    pub fn ui_message(&self, message_id: &str) -> Result<Option<UiMessage>> {
        self.ui_message_row(message_id, None)
    }

    /// List one reverse-chronological page of active canonical messages from the mirror.
    /// `before_message_id`, when supplied, is resolved locally and never used as SQL syntax.
    pub fn ui_room_messages(
        &self,
        room_id: &str,
        before_message_id: Option<&str>,
        max: u32,
    ) -> Result<Vec<UiMessage>> {
        if !(1..=100).contains(&max) {
            bail!("Mirror message page size must be 1..=100");
        }
        let before = before_message_id
            .map(|message_id| {
                self.conn
                    .query_row(
                        "SELECT created_at,message_id FROM messages
                         WHERE room_id=?1 AND message_id=?2
                         ORDER BY revision DESC LIMIT 1",
                        params![room_id, message_id],
                        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?
                    .context("Message cursor is not in this room")
            })
            .transpose()?;
        let mut statement = if before.is_some() {
            self.conn.prepare(
                "SELECT message_id FROM messages AS m
                 WHERE room_id=?1 AND status='active'
                   AND revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)
                   AND (created_at < ?2 OR (created_at = ?2 AND message_id < ?3))
                 ORDER BY created_at DESC,message_id DESC LIMIT ?4",
            )?
        } else {
            self.conn.prepare(
                "SELECT message_id FROM messages AS m
                 WHERE room_id=?1 AND status='active'
                   AND revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)
                 ORDER BY created_at DESC,message_id DESC LIMIT ?2",
            )?
        };
        let ids = if let Some((created_at, id)) = before {
            let created_at = created_at.context("Message cursor has no creation time")?;
            statement
                .query_map(params![room_id, created_at, id, max], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            statement
                .query_map(params![room_id, max], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        ids.into_iter()
            .map(|id| {
                self.ui_message_row(&id, Some(room_id))?
                    .context("Canonical mirror message disappeared during read")
            })
            .collect()
    }

    fn ui_message_row(
        &self,
        message_id: &str,
        room_filter: Option<&str>,
    ) -> Result<Option<UiMessage>> {
        let row: Option<UiMessageRow> = self
            .conn
            .query_row(
                "SELECT room_id,revision,parent_id,sender_id,created_at,updated_at,status,body_ct,body_nonce
                 FROM messages WHERE message_id=?1
                 ORDER BY revision DESC LIMIT 1",
                [message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
            )
            .optional()?;
        let Some((
            room_id,
            revision,
            parent_id,
            sender_id,
            created_at,
            updated_at,
            status,
            body_ct,
            body_nonce,
        )) = row
        else {
            return Ok(None);
        };
        if room_filter.is_some_and(|expected| expected != room_id) {
            return Ok(None);
        }
        let markdown = match (body_ct, body_nonce) {
            (Some(ct), Some(nonce)) if status == "active" => Some(
                String::from_utf8(self.crypto.open(
                    &ct,
                    &nonce,
                    &message_aad("body", message_id, revision),
                )?)
                .context("Invalid encrypted message body")?,
            ),
            (None, None) => None,
            _ if status == "deleted" => None,
            _ => bail!("Mirror body ciphertext/nonce mismatch"),
        };
        Ok(Some(UiMessage {
            id: message_id.into(),
            room_id,
            revision,
            parent_id,
            sender_id,
            created_at,
            updated_at,
            status,
            markdown,
        }))
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

    /// Record a sanitized sync phase failure for status/retry; no remote response content.
    pub fn record_sync_failure(&mut self, room_id: &str, phase: &str, kind: &str) -> Result<()> {
        if !matches!(phase, "initial" | "catchup" | "backfill" | "reconcile") {
            bail!("Unknown sync failure phase");
        }
        if !matches!(
            kind,
            "auth"
                | "rate_limited"
                | "server"
                | "not_found"
                | "timeout"
                | "pagination"
                | "timestamp"
                | "other"
        ) {
            bail!("Unknown sync failure kind");
        }
        if self.conn.execute(
            "UPDATE room_sync SET last_result=?2,last_catchup_at=?3 WHERE room_id=?1",
            params![
                room_id,
                format!("{phase}_{kind}_error"),
                Utc::now().to_rfc3339()
            ],
        )? != 1
        {
            bail!("Cannot record failure for unknown room");
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

    /// Read one unresolved catch-up gap for an explicit, user-approved
    /// recovery operation. The normal sync never expands its age limit.
    pub fn recovery_gap(&self, room_id: &str) -> Result<Option<RecoveryGap>> {
        let result: Option<String> = self
            .conn
            .query_row(
                "SELECT last_result FROM room_sync WHERE room_id=?1",
                [room_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let Some(result) = result else {
            return Ok(None);
        };
        let Some((from, to)) = parse_gap(&result) else {
            return Ok(None);
        };
        Ok(Some(RecoveryGap {
            room_id: room_id.into(),
            from,
            to,
        }))
    }

    /// Mark a particular persisted gap recovered only after the recovery scan
    /// reached a known pre-gap message. This is auditable and cannot clear a
    /// changed/newer gap by accident.
    pub fn clear_recovery_gap(&mut self, gap: &RecoveryGap) -> Result<()> {
        let expected = format!("gap:{}:{}", gap.from, gap.to);
        if self.conn.execute(
            "UPDATE room_sync SET last_result='ok',last_catchup_at=?2
             WHERE room_id=?1 AND last_result=?3",
            params![gap.room_id, Utc::now().to_rfc3339(), expected],
        )? != 1
        {
            bail!("Recovery gap changed or is no longer pending");
        }
        self.conn.execute(
            "INSERT INTO audit(ts,scope,action,ref,detail_redacted)
             VALUES (?1,'system','gap_recovered',?2,'read_only_extended_history')",
            params![Utc::now().to_rfc3339(), gap.room_id],
        )?;
        Ok(())
    }

    /// Store one user-confirmed UI pairing. The caller provides only a hash of
    /// its 256-bit secret; the daemon never receives or persists the secret.
    pub fn pair_ui_client(&mut self, secret_hash: &str, executable: &str) -> Result<()> {
        if !(43..=128).contains(&secret_hash.len())
            || !secret_hash
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            || !executable.starts_with('/')
            || executable.chars().any(char::is_control)
        {
            bail!("Invalid UI pairing data");
        }
        self.conn.execute(
            "INSERT INTO ui_clients(secret_hash,exe_path,paired_at,last_seen)
             VALUES (?1,?2,?3,?3)
             ON CONFLICT(secret_hash) DO UPDATE SET exe_path=excluded.exe_path,last_seen=excluded.last_seen",
            params![secret_hash, executable, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Check a UI secret hash after an explicit user-confirmed pairing.
    pub fn ui_client_paired(&mut self, secret_hash: &str) -> Result<bool> {
        let found = self
            .conn
            .query_row(
                "SELECT 1 FROM ui_clients WHERE secret_hash=?1",
                [secret_hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if found {
            self.conn.execute(
                "UPDATE ui_clients SET last_seen=?2 WHERE secret_hash=?1",
                params![secret_hash, Utc::now().to_rfc3339()],
            )?;
        }
        Ok(found)
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

fn parse_gap(value: &str) -> Option<(String, String)> {
    let value = value.strip_prefix("gap:")?;
    for (index, _) in value.char_indices().skip(1) {
        if value.as_bytes().get(index - 1) != Some(&b':') {
            continue;
        }
        let (from, to) = value.split_at(index - 1);
        let to = &to[1..];
        if parse_timestamp(from).is_ok() && parse_timestamp(to).is_ok() {
            return Some((from.into(), to.into()));
        }
    }
    None
}

fn parse_timestamp(value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(value).context("Invalid Webex message timestamp")
}

pub(crate) fn message_aad(column: &str, id: &str, revision: i64) -> Vec<u8> {
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
    fn ui_views_decrypt_only_current_rows_and_paginate_messages() {
        let mut mirror = Mirror::in_memory([14_u8; 32]).unwrap();
        let room = Room {
            id: "room-1".into(),
            title: Some("Private room title".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: Some("team-1".into()),
            last_activity: "2026-10-08T12:03:00Z".into(),
            creator_id: "person-1".into(),
            created: "2026-10-08T12:00:00Z".into(),
        };
        mirror.upsert_room(&room, true).unwrap();
        mirror
            .upsert_person(&Person {
                id: "person-1".into(),
                display_name: "Private Person".into(),
                emails: vec!["private@example.test".into()],
                ..Person::default()
            })
            .unwrap();
        for (id, created) in [
            ("message-1", "2026-10-08T12:01:00Z"),
            ("message-2", "2026-10-08T12:02:00Z"),
            ("message-3", "2026-10-08T12:03:00Z"),
        ] {
            mirror
                .upsert_message(&Message {
                    id: Some(id.into()),
                    room_id: Some("room-1".into()),
                    person_id: Some("person-1".into()),
                    text: Some(format!("body {id}")),
                    created: Some(created.into()),
                    ..Message::default()
                })
                .unwrap();
        }

        assert_eq!(
            mirror.ui_rooms().unwrap()[0].title.as_deref(),
            Some("Private room title")
        );
        assert_eq!(
            mirror.ui_person("person-1").unwrap().unwrap().emails,
            Some(vec!["private@example.test".into()])
        );
        let newest = mirror.ui_room_messages("room-1", None, 2).unwrap();
        assert_eq!(
            newest
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            ["message-3", "message-2"]
        );
        assert_eq!(newest[0].markdown.as_deref(), Some("body message-3"));
        let older = mirror
            .ui_room_messages("room-1", Some("message-2"), 2)
            .unwrap();
        assert_eq!(
            older
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            ["message-1"]
        );
        assert!(mirror
            .ui_room_messages("room-1", Some("missing"), 2)
            .is_err());
    }

    #[test]
    fn sync_failure_diagnostic_decrypts_title_only_for_explicit_request() {
        let mut mirror = Mirror::in_memory([11_u8; 32]).unwrap();
        let room = Room {
            id: "room-1".into(),
            title: Some("Private failing room".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: None,
            last_activity: "2026-10-08T12:00:00Z".into(),
            creator_id: "person-1".into(),
            created: "2026-10-08T12:00:00Z".into(),
        };
        mirror.upsert_room(&room, true).unwrap();
        mirror
            .record_sync_failure(&room.id, "initial", "timeout")
            .unwrap();
        assert_eq!(
            mirror.sync_failures().unwrap(),
            vec![SyncFailure {
                room_id: "room-1".into(),
                title: Some("Private failing room".into()),
                is_member: true,
                result: "initial_timeout_error".into(),
            }]
        );
    }

    #[test]
    fn unobserved_rooms_leave_active_progress_but_keep_history() {
        let mut mirror = Mirror::in_memory([21_u8; 32]).unwrap();
        let room = Room {
            id: "room-1".into(),
            title: Some("Former room".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: None,
            last_activity: "2026-10-08T12:00:00Z".into(),
            creator_id: "person-1".into(),
            created: "2026-10-08T12:00:00Z".into(),
        };
        mirror.upsert_room(&room, true).unwrap();
        mirror
            .record_sync_failure(&room.id, "initial", "timeout")
            .unwrap();
        assert_eq!(
            mirror
                .mark_unobserved_rooms_left(&std::collections::HashSet::new())
                .unwrap(),
            1
        );
        assert_eq!(mirror.is_member(&room.id).unwrap(), Some(false));
        assert_eq!(
            mirror.stats().unwrap(),
            MirrorStats {
                rooms: 0,
                revisions: 0,
                initial_done: 0,
                initial_pending: 0,
                gaps: 0,
                failures: 0,
            }
        );
        assert_eq!(
            mirror.sync_failures().unwrap(),
            vec![SyncFailure {
                room_id: room.id,
                title: Some("Former room".into()),
                is_member: false,
                result: "initial_timeout_error".into(),
            }]
        );
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
