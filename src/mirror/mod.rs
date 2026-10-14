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
use webex::{Message, Person, Room, Team};
use zeroize::Zeroizing;

const KEY_CHECK: &[u8] = b"webex-bridge-mirror-v1";
const ACCOUNT_IDENTITY_SLOT: i64 = 1;
const ACCOUNT_IDENTITY_AAD_ID: &str = "current";

type UpsertPrevious = (
    i64,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
);
type StoredBody = (i64, String, Option<Vec<u8>>, Option<Vec<u8>>);
type UiRoomRow = (
    Option<Vec<u8>>,
    String,
    Option<String>,
    Option<String>,
    bool,
    Option<bool>,
);
type UiPersonRow = (Option<Vec<u8>>, Option<Vec<u8>>);
type UiTeamRow = Option<Vec<u8>>;
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
    Option<Vec<u8>>,
    Option<String>,
);
type DeletePrevious = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[derive(serde::Deserialize, Serialize)]
struct StoredAttachmentMeta {
    count: u32,
}

/// Attachment count of decrypted files metadata in either the current
/// count-only form or the legacy URL-list form.
fn legacy_attachment_count(bytes: &[u8]) -> Option<usize> {
    serde_json::from_slice::<StoredAttachmentMeta>(bytes)
        .ok()
        .and_then(|meta| usize::try_from(meta.count).ok())
        .or_else(|| {
            serde_json::from_slice::<Vec<serde_json::Value>>(bytes)
                .ok()
                .map(|legacy| legacy.len())
        })
}

/// Result of a canonical message upsert.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Upsert {
    /// First stored revision of a message (new, or re-hydrated after retention).
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
    /// `None` means this room predates authoritative lock-state mirroring.
    pub is_locked: Option<bool>,
}

/// Team metadata released only to an authorized UI session.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiTeam {
    pub id: String,
    pub name: Option<String>,
}

/// A pending background sweep of one room's older messages.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RoomSweep {
    /// Room being swept.
    pub room_id: String,
    /// Creation time of the oldest message already checked.
    pub cursor_created_at: String,
    /// ID of the oldest message already checked (tie-breaker).
    pub cursor_message_id: String,
    /// Request generation; progress applies only to the same generation.
    pub generation: String,
}

/// One paired UI executable. The secret hash is deliberately omitted.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiPairing {
    /// Kernel-resolved executable path confirmed by the user at pairing.
    pub executable: String,
    /// RFC 3339 pairing time.
    pub paired_at: String,
    /// RFC 3339 time of the last session creation or renewal.
    pub last_seen: Option<String>,
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
    /// Compatibility projection; use `body` for authoritative provenance.
    pub markdown: Option<String>,
    pub body: Option<UiBody>,
    pub attachment_count: u32,
}

/// A body retained for UI rendering/copy/edit with authoritative or legacy provenance.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiBody {
    pub kind: String,
    pub content: String,
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
    /// Metadata-only agent notifications awaiting publication by the daemon.
    pub(crate) agent_events: crate::routing::PendingAgentEvents,
}

/// Internal mirror-key seam. The production implementation uses Keychain;
/// a future fully guarded development bootstrap supplies its fixed in-memory
/// key instead. There is no fallback between providers.
pub(crate) trait MirrorKeyProvider: Send + Sync {
    fn mirror_key(&self, existing_db: bool) -> Result<[u8; 32]>;
}

struct KeychainMirrorKeyProvider;

impl MirrorKeyProvider for KeychainMirrorKeyProvider {
    fn mirror_key(&self, existing_db: bool) -> Result<[u8; 32]> {
        load_or_create_key(existing_db)
    }
}

impl Mirror {
    /// Open/create a 0600 WAL database using a 256-bit key in the user's Keychain.
    /// An existing DB without its key or verification sentinel is never re-keyed silently.
    pub fn open(paths: &Paths) -> Result<Self> {
        Self::open_with_key_provider(paths, &KeychainMirrorKeyProvider)
    }

    /// Open a mirror with an explicitly selected key provider. This internal
    /// seam is for a future development bootstrap that has already validated
    /// and canonicalized its isolated root; it never consults Keychain itself.
    pub(crate) fn open_with_key_provider(
        paths: &Paths,
        provider: &dyn MirrorKeyProvider,
    ) -> Result<Self> {
        paths.ensure_dirs()?;
        let existed = match fs::symlink_metadata(&paths.mirror) {
            Ok(_) => {
                check_mode(&paths.mirror, 0o600)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let key = provider.mirror_key(existed)?;
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
        Ok(Self {
            conn,
            crypto,
            agent_events: crate::routing::PendingAgentEvents::default(),
        })
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
            "INSERT INTO rooms(room_id,title_ct,type,team_id,last_activity,is_member,is_locked,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(room_id) DO UPDATE SET
             title_ct=excluded.title_ct,type=excluded.type,team_id=excluded.team_id,
             last_activity=excluded.last_activity,is_member=excluded.is_member,
             is_locked=excluded.is_locked,updated_at=excluded.updated_at",
            params![room.id, title_ct, room.room_type, room.team_id, room.last_activity,
                is_member, room.is_locked, Utc::now().to_rfc3339()],
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

    /// Return room IDs whose membership was marked departed after a complete
    /// REST listing. Callers may publish metadata-only invalidations only after
    /// this transaction has committed.
    pub fn mark_unobserved_rooms_left_ids(
        &mut self,
        observed_room_ids: &std::collections::HashSet<String>,
    ) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare("SELECT room_id FROM rooms WHERE is_member=1")?;
        let current_members = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let mut left = Vec::new();
        for room_id in current_members {
            if !observed_room_ids.contains(&room_id)
                && self.conn.execute(
                    "UPDATE rooms SET is_member=0,updated_at=?2 WHERE room_id=?1",
                    params![room_id, Utc::now().to_rfc3339()],
                )? == 1
            {
                left.push(room_id);
            }
        }
        Ok(left)
    }

    /// Mark rooms absent from a complete REST room listing as no longer joined.
    /// Call only after every pagination page was fetched successfully.
    pub fn mark_unobserved_rooms_left(
        &mut self,
        observed_room_ids: &std::collections::HashSet<String>,
    ) -> Result<usize> {
        Ok(self
            .mark_unobserved_rooms_left_ids(observed_room_ids)?
            .len())
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
            "SELECT room_id,title_ct,type,team_id,last_activity,is_member,is_locked FROM rooms
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
                row.get::<_, Option<bool>>(6)?,
            ))
        })?;
        rows.map(|row| {
            let (id, title_ct, room_type, team_id, last_activity, is_member, is_locked) = row?;
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
                is_locked,
            })
        })
        .collect::<Result<Vec<_>>>()
    }

    /// Get one room's metadata for an authorized UI session.
    pub fn ui_room(&self, room_id: &str) -> Result<Option<UiRoom>> {
        let row: Option<UiRoomRow> = self
            .conn
            .query_row(
                "SELECT title_ct,type,team_id,last_activity,is_member,is_locked FROM rooms WHERE room_id=?1",
                [room_id],
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
        row.map(
            |(title_ct, room_type, team_id, last_activity, is_member, is_locked)| {
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
                    is_locked,
                })
            },
        )
        .transpose()
    }

    /// Upsert encrypted team name for UI display only.
    pub fn upsert_team(&mut self, team: &Team) -> Result<()> {
        if team.id.is_empty() {
            bail!("REST team has no ID");
        }
        let name_ct = team
            .name
            .as_ref()
            .map(|name| {
                self.crypto
                    .seal_prefixed(name.as_bytes(), &aad("teams", "name", &team.id))
            })
            .transpose()?;
        self.conn.execute(
            "INSERT INTO teams(team_id,name_ct,updated_at) VALUES (?1,?2,?3)
             ON CONFLICT(team_id) DO UPDATE SET name_ct=excluded.name_ct,updated_at=excluded.updated_at",
            params![team.id, name_ct, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Read one team's decrypted identity and name for an authorized UI session.
    pub fn ui_team(&self, team_id: &str) -> Result<Option<UiTeam>> {
        let row: Option<UiTeamRow> = self
            .conn
            .query_row(
                "SELECT name_ct FROM teams WHERE team_id=?1",
                [team_id],
                |row| row.get(0),
            )
            .optional()?;
        row.map(|name_ct| {
            let name = name_ct
                .map(|blob| {
                    self.crypto
                        .open_prefixed(&blob, &aad("teams", "name", team_id))
                        .and_then(|bytes| {
                            String::from_utf8(bytes).context("Invalid encrypted team name")
                        })
                })
                .transpose()?;
            Ok(UiTeam {
                id: team_id.into(),
                name,
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
        self.clear_ui_not_found("person", &person.id)?;
        Ok(())
    }

    /// Persist the authenticated daemon account only after an authoritative
    /// current-user lookup. The account ID is encrypted separately from the
    /// cached person record so a first-run mirror cannot guess an identity.
    pub fn cache_account_identity(&mut self, person: &Person) -> Result<()> {
        self.upsert_person(person)?;
        let person_id_ct = self.crypto.seal_prefixed(
            person.id.as_bytes(),
            &aad("account_identity", "person_id", ACCOUNT_IDENTITY_AAD_ID),
        )?;
        self.conn.execute(
            "INSERT INTO account_identity(slot,person_id_ct) VALUES (?1,?2)
             ON CONFLICT(slot) DO UPDATE SET person_id_ct=excluded.person_id_ct",
            params![ACCOUNT_IDENTITY_SLOT, person_id_ct],
        )?;
        Ok(())
    }

    /// Remember the daemon's own Mercury device (encrypted; its URLs are
    /// device identifiers), so the next connect can try it before listing.
    pub fn remember_mercury_device(&mut self, device: &webex::DeviceData) -> Result<()> {
        let device_ct = self.crypto.seal_prefixed(
            &serde_json::to_vec(device)?,
            &aad("mercury_device", "device", "current"),
        )?;
        self.conn.execute(
            "INSERT INTO mercury_device(slot,device_ct) VALUES (1,?1)
             ON CONFLICT(slot) DO UPDATE SET device_ct=excluded.device_ct",
            [device_ct],
        )?;
        Ok(())
    }

    /// The remembered Mercury device, if any. An unreadable entry is treated
    /// as absent (the device list is the fallback).
    pub fn mercury_device(&self) -> Result<Option<webex::DeviceData>> {
        let device_ct: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT device_ct FROM mercury_device WHERE slot=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(device_ct.and_then(|blob| {
            let json = self
                .crypto
                .open_prefixed(&blob, &aad("mercury_device", "device", "current"))
                .ok()?;
            serde_json::from_slice(&json).ok()
        }))
    }

    /// Read the cached daemon account for an authorized UI session. A missing
    /// identity is normal before the first successful authoritative `/me`.
    pub fn ui_account_identity(&self) -> Result<Option<UiPerson>> {
        let Some(person_id) = self.account_person_id()? else {
            return Ok(None);
        };
        self.ui_person(&person_id)
    }

    /// Decrypt only the cached daemon account person ID, if `/me` has run.
    pub(crate) fn account_person_id(&self) -> Result<Option<String>> {
        let person_id_ct: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT person_id_ct FROM account_identity WHERE slot=?1",
                [ACCOUNT_IDENTITY_SLOT],
                |row| row.get(0),
            )
            .optional()?;
        person_id_ct
            .map(|person_id_ct| {
                String::from_utf8(self.crypto.open_prefixed(
                    &person_id_ct,
                    &aad("account_identity", "person_id", ACCOUNT_IDENTITY_AAD_ID),
                )?)
                .context("Invalid encrypted account person ID")
            })
            .transpose()
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
        let (body, body_kind) = if let Some(markdown) = message.markdown.as_ref() {
            (Some(markdown.as_str()), Some("markdown"))
        } else if let Some(text) = message.text.as_ref() {
            (Some(text.as_str()), Some("plain_text"))
        } else {
            (None, None)
        };
        // Never retain or project attachment URLs. New rows store only a count;
        // legacy rows may still contain encrypted URLs until their revision is
        // superseded or deleted.
        let files = message
            .files
            .as_ref()
            .map(|files| {
                let count = u32::try_from(files.len()).context("Attachment count overflow")?;
                Ok::<_, anyhow::Error>(serde_json::to_vec(&StoredAttachmentMeta { count })?)
            })
            .transpose()?;
        let previous: Option<UpsertPrevious> = self
            .conn
            .query_row(
                "SELECT revision,status,updated_at,body_ct,body_nonce,files_meta_ct,body_kind
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
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        if let Some((revision, status, updated, old_ct, old_nonce, old_files, old_body_kind)) =
            &previous
        {
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
                let old_files_ct = old_files.clone();
                let old_files = old_files
                    .as_ref()
                    .map(|blob| {
                        self.crypto
                            .open_prefixed(blob, &message_aad("files", id, *revision))
                    })
                    .transpose()?;
                if old_body.as_deref() == body.map(str::as_bytes) {
                    // Rows written before body_kind existed (NULL) or with
                    // legacy URL-list attachment metadata are not edits when
                    // the authoritative REST body and attachment count match:
                    // a new revision here would re-queue old agent deliveries.
                    // Backfill them in place instead, at the same revision.
                    let kind_legacy = old_body_kind.is_none() && body_kind.is_some();
                    let kind_matches = kind_legacy || old_body_kind.as_deref() == body_kind;
                    let files_exact = old_files == files;
                    let files_legacy = !files_exact
                        && match (old_files.as_deref(), files.as_ref()) {
                            (Some(old), Some(_)) => {
                                legacy_attachment_count(old) == message.files.as_ref().map(Vec::len)
                            }
                            _ => false,
                        };
                    if kind_matches && (files_exact || files_legacy) {
                        if kind_legacy || files_legacy {
                            let files_ct = if files_legacy {
                                files
                                    .as_ref()
                                    .map(|data| {
                                        self.crypto.seal_prefixed(
                                            data,
                                            &message_aad("files", id, *revision),
                                        )
                                    })
                                    .transpose()?
                            } else {
                                old_files_ct.clone()
                            };
                            self.conn.execute(
                                "UPDATE messages SET body_kind=?3,files_meta_ct=?4
                                 WHERE message_id=?1 AND revision=?2",
                                params![id, revision, body_kind, files_ct],
                            )?;
                        }
                        // A sender that was missing at first ingest is
                        // backfilled in place (never replaced): the same
                        // revision can then be routed.
                        if let Some(sender) = message.person_id.as_deref() {
                            self.conn.execute(
                                "UPDATE messages SET sender_id=?3
                                 WHERE message_id=?1 AND revision=?2 AND sender_id IS NULL",
                                params![id, revision, sender],
                            )?;
                        }
                        return Ok(Upsert::Unchanged);
                    }
                }
            }
        }
        let created = previous.is_none();
        // A thread parent never changes, but Webex omits parentId when it
        // returns an edited message. Keep the known parent rather than
        // overwriting it with NULL (body_kind is stored as returned).
        let parent_id = match (&message.parent_id, &previous) {
            (Some(parent), _) => Some(parent.clone()),
            (None, Some(_)) => self
                .conn
                .query_row(
                    "SELECT parent_id FROM messages WHERE message_id=?1 AND parent_id IS NOT NULL
                     ORDER BY revision DESC LIMIT 1",
                    [id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?,
            (None, None) => None,
        };
        // The revision counter bump and the row INSERT share one transaction.
        let tx = self.conn.transaction()?;
        let revision = take_revision(&tx, previous.as_ref().map(|(rev, ..)| *rev))?;
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
                                  status,body_ct,body_nonce,files_meta_ct,body_kind)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'active',?8,?9,?10,?11)",
            params![room_id,id,revision,parent_id,message.person_id,created_at,
                message.updated,body_ct,body_nonce,files_ct,body_kind],
        )?;
        tx.execute(
            "DELETE FROM ui_lookup WHERE resource='message' AND resource_id=?1",
            [id],
        )?;
        tx.commit()?;
        Ok(if created {
            Upsert::Created(revision)
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

    /// Record a Webex-confirmed negative UI point lookup. This never records
    /// transport/offline failures, so callers can safely retry those later.
    pub fn cache_ui_not_found(&mut self, resource: &str, resource_id: &str) -> Result<()> {
        if !matches!(resource, "person" | "message") || resource_id.is_empty() {
            bail!("Invalid UI lookup resource");
        }
        self.conn.execute(
            "INSERT INTO ui_lookup(resource,resource_id,state,checked_at) VALUES (?1,?2,'not_found',?3)
             ON CONFLICT(resource,resource_id) DO UPDATE SET state='not_found',checked_at=excluded.checked_at",
            params![resource, resource_id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Whether an earlier online point read confirmed this opaque resource ID
    /// does not exist. Online reads intentionally retry instead of trusting it.
    pub fn ui_not_found(&self, resource: &str, resource_id: &str) -> Result<bool> {
        if !matches!(resource, "person" | "message") || resource_id.is_empty() {
            bail!("Invalid UI lookup resource");
        }
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM ui_lookup WHERE resource=?1 AND resource_id=?2 AND state='not_found'",
                params![resource, resource_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    fn clear_ui_not_found(&mut self, resource: &str, resource_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM ui_lookup WHERE resource=?1 AND resource_id=?2",
            params![resource, resource_id],
        )?;
        Ok(())
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

    /// List one reverse-chronological page of active replies to one canonical
    /// parent. A cursor must itself be an active reply to that same parent;
    /// the caller cannot use a room-history cursor to scan another thread.
    pub fn ui_message_children(
        &self,
        parent_id: &str,
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
                         WHERE message_id=?1 AND parent_id=?2 AND status='active'
                         ORDER BY revision DESC LIMIT 1",
                        params![message_id, parent_id],
                        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?
                    .context("Message cursor is not a reply in this thread")
            })
            .transpose()?;
        let mut statement = if before.is_some() {
            self.conn.prepare(
                "SELECT message_id FROM messages AS m
                 WHERE parent_id=?1 AND status='active'
                   AND revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)
                   AND (created_at < ?2 OR (created_at = ?2 AND message_id < ?3))
                 ORDER BY created_at DESC,message_id DESC LIMIT ?4",
            )?
        } else {
            self.conn.prepare(
                "SELECT message_id FROM messages AS m
                 WHERE parent_id=?1 AND status='active'
                   AND revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)
                 ORDER BY created_at DESC,message_id DESC LIMIT ?2",
            )?
        };
        let ids = if let Some((created_at, id)) = before {
            let created_at = created_at.context("Message cursor has no creation time")?;
            statement
                .query_map(params![parent_id, created_at, id, max], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            statement
                .query_map(params![parent_id, max], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        ids.into_iter()
            .map(|id| {
                self.ui_message_row(&id, None)?
                    .context("Canonical mirror reply disappeared during read")
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
                "SELECT room_id,revision,parent_id,sender_id,created_at,updated_at,status,body_ct,body_nonce,
                        files_meta_ct,body_kind
                 FROM messages WHERE message_id=?1
                 ORDER BY revision DESC LIMIT 1",
                [message_id],
                |row| Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?,
                )),
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
            files_meta_ct,
            body_kind,
        )) = row
        else {
            return Ok(None);
        };
        if room_filter.is_some_and(|expected| expected != room_id) {
            return Ok(None);
        }
        let content = match (body_ct, body_nonce) {
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
        let body = content.as_ref().map(|content| UiBody {
            kind: match body_kind.as_deref() {
                Some("markdown") => "markdown",
                Some("plain_text") => "plainText",
                _ => "legacyUnknown",
            }
            .into(),
            content: content.clone(),
        });
        let attachment_count = if status == "active" {
            files_meta_ct
                .map(|blob| {
                    let bytes = self
                        .crypto
                        .open_prefixed(&blob, &message_aad("files", message_id, revision))?;
                    if let Ok(meta) = serde_json::from_slice::<StoredAttachmentMeta>(&bytes) {
                        Ok(meta.count)
                    } else {
                        let legacy: Vec<serde_json::Value> = serde_json::from_slice(&bytes)
                            .context("Invalid encrypted attachment metadata")?;
                        u32::try_from(legacy.len()).context("Attachment count overflow")
                    }
                })
                .transpose()?
                .unwrap_or(0)
        } else {
            0
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
            markdown: content,
            body,
            attachment_count,
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
        let tx = self.conn.transaction()?;
        let new_revision = take_revision(&tx, Some(revision))?;
        tx.execute(
            "UPDATE messages SET body_ct=NULL, body_nonce=NULL, files_meta_ct=NULL,body_kind=NULL WHERE message_id=?1",
            [message_id],
        )?;
        tx.execute("INSERT INTO messages(room_id,message_id,revision,parent_id,sender_id,created_at,updated_at,status)
                    VALUES (?1,?2,?3,?4,?5,?6,?7,'deleted')",
            params![room_id,message_id,new_revision,parent,sender,created,Utc::now().to_rfc3339()])?;
        let removed = {
            let mut statement = tx.prepare(
                "SELECT route_id,revision FROM deliveries WHERE message_id=?1 AND state<>'deleted'",
            )?;
            let rows = statement
                .query_map([message_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        tx.execute(
            "UPDATE deliveries SET state='deleted' WHERE message_id=?1",
            [message_id],
        )?;
        tx.execute(
            "DELETE FROM ui_lookup WHERE resource='message' AND resource_id=?1",
            [message_id],
        )?;
        tx.commit()?;
        for (route_id, revision) in removed {
            self.agent_events.push(crate::routing::AgentEvent::removed(
                route_id, message_id, revision, "deleted",
            ));
        }
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
        // Retention also removes delivery metadata of pruned messages. The
        // revision counter is never lowered, so a later re-hydrate cannot reuse
        // a pruned revision or collide with a former delivery key.
        tx.execute(
            "DELETE FROM deliveries WHERE NOT EXISTS
               (SELECT 1 FROM messages m WHERE m.message_id=deliveries.message_id)",
            [],
        )?;
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

    /// Test hook: remove one UI pairing by hash, as an out-of-band revocation
    /// (one that does not end live sessions) would. Used only by the client
    /// server tests, which need the `client` feature.
    #[cfg(all(test, feature = "client"))]
    pub(crate) fn unpair_ui_client(&mut self, secret_hash: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM ui_clients WHERE secret_hash=?1", [secret_hash])?;
        Ok(())
    }

    /// Test hook: count audit rows for one scope/action.
    #[cfg(test)]
    pub(crate) fn audit_count_for_tests(&self, scope: &str, action: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE scope=?1 AND action=?2",
            [scope, action],
            |row| row.get(0),
        )?)
    }

    #[cfg(test)]
    pub(crate) fn audit_refs_for_tests(
        &self,
        scope: &str,
        action: &str,
    ) -> Result<Vec<Option<String>>> {
        let mut statement = self
            .conn
            .prepare("SELECT ref FROM audit WHERE scope=?1 AND action=?2 ORDER BY rowid")?;
        let rows = statement.query_map([scope, action], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Record one metadata-only UI-scope audit row (no secrets or content).
    pub fn audit_ui(&mut self, action: &str, reference: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit(ts,scope,action,ref,detail_redacted) VALUES (?1,'ui',?2,?3,NULL)",
            params![Utc::now().to_rfc3339(), action, reference],
        )?;
        Ok(())
    }

    /// Paired UI clients, without their secret hashes.
    pub fn ui_pairings(&self) -> Result<Vec<UiPairing>> {
        let mut statement = self.conn.prepare(
            "SELECT exe_path,paired_at,last_seen FROM ui_clients ORDER BY exe_path,paired_at",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(UiPairing {
                executable: row.get(0)?,
                paired_at: row.get(1)?,
                last_seen: row.get(2)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Remove the pairings of one exact executable path (`None`: every
    /// pairing) and audit the count. Returns the removed secret hashes so the
    /// caller can end their live sessions.
    ///
    /// `caller` is the kernel-resolved executable of the requesting process
    /// (any same-user process may unpair), recorded in the audit row's `ref`.
    pub fn unpair_ui_clients(
        &mut self,
        executable: Option<&str>,
        caller: Option<&str>,
    ) -> Result<Vec<String>> {
        if executable
            .is_some_and(|path| !path.starts_with('/') || path.chars().any(char::is_control))
        {
            bail!("Invalid UI executable path");
        }
        let tx = self.conn.transaction()?;
        let hashes = {
            let mut statement = tx.prepare(
                "DELETE FROM ui_clients WHERE ?1 IS NULL OR exe_path=?1 RETURNING secret_hash",
            )?;
            let rows = statement.query_map([executable], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.execute(
            "INSERT INTO audit(ts,scope,action,ref,detail_redacted) VALUES (?1,'ui','unpair',?3,?2)",
            params![
                Utc::now().to_rfc3339(),
                format!(
                    "{}removed={}",
                    if executable.is_none() { "all;" } else { "" },
                    hashes.len()
                ),
                caller
            ],
        )?;
        tx.commit()?;
        Ok(hashes)
    }

    /// The newest `limit` messages (by creation time) whose latest revision is
    /// active in a room, as `(message_id, created_at)`: the bounded
    /// room-reconcile window.
    pub fn recent_active_messages(
        &self,
        room_id: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>> {
        let mut statement = self.conn.prepare(
            "SELECT m.message_id,m.created_at FROM messages m WHERE m.room_id=?1 AND m.status='active'
             AND m.revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)
             ORDER BY m.created_at DESC, m.message_id DESC LIMIT ?2",
        )?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = statement.query_map(params![room_id, limit], |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Request a paced background sweep of a room's messages older than
    /// `(created_at, message_id)`. With no sweep pending, a new pass starts
    /// there. A request that arrives while a pass is running does not reset it
    /// (a busy room would otherwise never finish): the newest start point is
    /// kept and the room is swept once more after the current pass finishes.
    pub fn request_room_sweep(
        &mut self,
        room_id: &str,
        created_at: &str,
        message_id: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO room_sweep(room_id,cursor_created_at,cursor_message_id,requested_at)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(room_id) DO UPDATE SET rerun_requested=1,
               rerun_created_at=excluded.cursor_created_at,
               rerun_message_id=excluded.cursor_message_id",
            params![
                room_id,
                created_at,
                message_id,
                Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
            ],
        )?;
        Ok(())
    }

    /// The longest-waiting room sweep, if any. A failed step re-queues its
    /// room behind the others (see [`Self::fail_room_sweep`]).
    pub fn next_room_sweep(&self) -> Result<Option<RoomSweep>> {
        Ok(self
            .conn
            .query_row(
                "SELECT room_id,cursor_created_at,cursor_message_id,requested_at FROM room_sweep
                 ORDER BY COALESCE(queued_at,requested_at),room_id LIMIT 1",
                [],
                |row| {
                    Ok(RoomSweep {
                        room_id: row.get(0)?,
                        cursor_created_at: row.get(1)?,
                        cursor_message_id: row.get(2)?,
                        generation: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// The next `limit` active messages strictly older than the sweep cursor,
    /// newest first, as `(message_id, created_at)`. A message without a
    /// creation time sorts as the oldest (`""`), so it is still swept.
    pub fn room_sweep_batch(
        &self,
        sweep: &RoomSweep,
        limit: usize,
    ) -> Result<Vec<(String, String)>> {
        let mut statement = self.conn.prepare(
            "SELECT m.message_id,m.created_at FROM messages m WHERE m.room_id=?1 AND m.status='active'
             AND m.revision=(SELECT MAX(revision) FROM messages WHERE message_id=m.message_id)
             AND (COALESCE(m.created_at,'')<?2
                  OR (COALESCE(m.created_at,'')=?2 AND m.message_id<?3))
             ORDER BY COALESCE(m.created_at,'') DESC, m.message_id DESC LIMIT ?4",
        )?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = statement.query_map(
            params![
                sweep.room_id,
                sweep.cursor_created_at,
                sweep.cursor_message_id,
                limit
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Record progress, or finish the sweep when `next` is `None`. Both apply
    /// only to the same request generation: a re-request made meanwhile wins.
    pub fn advance_room_sweep(
        &mut self,
        sweep: &RoomSweep,
        next: Option<(&str, &str)>,
    ) -> Result<()> {
        match next {
            Some((created_at, message_id)) => self.conn.execute(
                "UPDATE room_sweep SET cursor_created_at=?3,cursor_message_id=?4,attempts=0
                 WHERE room_id=?1 AND requested_at=?2",
                params![sweep.room_id, sweep.generation, created_at, message_id],
            )?,
            None => self.finish_room_sweep(sweep)?,
        };
        Ok(())
    }

    /// End this generation's pass: restart once from the newest requested
    /// start point if a request arrived meanwhile, else remove the sweep.
    fn finish_room_sweep(&mut self, sweep: &RoomSweep) -> Result<usize> {
        let restarted = self.conn.execute(
            "UPDATE room_sweep SET cursor_created_at=rerun_created_at,
               cursor_message_id=rerun_message_id,requested_at=?3,attempts=0,queued_at=NULL,
               rerun_requested=0,rerun_created_at=NULL,rerun_message_id=NULL
             WHERE room_id=?1 AND requested_at=?2 AND rerun_requested=1",
            params![
                sweep.room_id,
                sweep.generation,
                Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
            ],
        )?;
        if restarted > 0 {
            return Ok(restarted);
        }
        Ok(self.conn.execute(
            "DELETE FROM room_sweep WHERE room_id=?1 AND requested_at=?2",
            params![sweep.room_id, sweep.generation],
        )?)
    }

    /// Record a failed sweep step of this generation: the room moves behind
    /// every other pending sweep, and after `max_attempts` consecutive
    /// failures its sweep is dropped (a later reconcile can request it again).
    /// Returns whether it was dropped. A stale generation changes nothing.
    pub fn fail_room_sweep(&mut self, sweep: &RoomSweep, max_attempts: u32) -> Result<bool> {
        self.conn.execute(
            "UPDATE room_sweep SET attempts=attempts+1,queued_at=?3
             WHERE room_id=?1 AND requested_at=?2",
            params![
                sweep.room_id,
                sweep.generation,
                Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
            ],
        )?;
        let exhausted: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM room_sweep WHERE room_id=?1 AND requested_at=?2
               AND attempts>=?3)",
            params![sweep.room_id, sweep.generation, max_attempts],
            |row| row.get(0),
        )?;
        if exhausted {
            // Like a finished pass: a request made meanwhile still runs once.
            self.finish_room_sweep(sweep)?;
        }
        Ok(exhausted)
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

/// Largest revision handed out: JSON clients (pi) parse numbers as IEEE-754
/// doubles, so every revision must stay an exactly representable integer.
const MAX_REVISION: i64 = (1 << 53) - 1;

/// Allocate the next message revision from the mirror-wide counter.
///
/// Revisions are opaque: strictly increasing per message and never reused
/// within a mirror, but neither contiguous nor an edit count. This keeps them
/// monotonic when retention prunes every revision of a message and a later
/// hydrate stores it again. An existing mirror without a counter continues
/// above its current maximum. Callers bump within their INSERT transaction.
fn take_revision(conn: &Connection, previous: Option<i64>) -> Result<i64> {
    let stored: Option<i64> = conn
        .query_row(
            "SELECT value FROM mirror_meta WHERE key='revision_seq'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let next = match stored {
        Some(next) => next,
        None => {
            // First allocation in this mirror: continue above every revision
            // ever recorded, including delivery keys of already-pruned
            // messages, then drop those orphaned deliveries.
            let next: i64 = conn.query_row(
                "SELECT COALESCE(MAX(revision)+1, 0) FROM (
                   SELECT MAX(revision) AS revision FROM messages
                   UNION ALL SELECT MAX(revision) FROM deliveries)",
                [],
                |row| row.get(0),
            )?;
            conn.execute(
                "DELETE FROM deliveries WHERE NOT EXISTS
                   (SELECT 1 FROM messages m WHERE m.message_id=deliveries.message_id)",
                [],
            )?;
            next
        }
    };
    let floor = previous.map_or(Ok(0), |revision| {
        revision.checked_add(1).context("Message revision overflow")
    })?;
    let revision = next.max(floor);
    if !(0..=MAX_REVISION).contains(&revision) {
        bail!("Message revision space exhausted");
    }
    conn.execute(
        "INSERT INTO mirror_meta(key,value) VALUES ('revision_seq',?1)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [revision + 1],
    )?;
    Ok(revision)
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
    fn room_sweep_rerequests_coalesce_into_one_rerun_and_ignore_stale_progress() {
        let mut mirror = Mirror::in_memory([39_u8; 32]).unwrap();
        for (id, created) in [
            ("a", "2026-10-08T12:00:01Z"),
            ("b", "2026-10-08T12:00:02Z"),
            ("c", "2026-10-08T12:00:02Z"),
            ("d", "2026-10-08T12:00:03Z"),
        ] {
            let mut message = message(id, "body", None);
            message.created = Some(created.into());
            mirror.upsert_message(&message).unwrap();
        }
        assert_eq!(mirror.next_room_sweep().unwrap(), None);
        mirror
            .request_room_sweep("room-1", "2026-10-08T12:00:03Z", "d")
            .unwrap();
        let sweep = mirror.next_room_sweep().unwrap().unwrap();
        // Older than the cursor, newest first, with a stable tie-breaker.
        let batch = mirror.room_sweep_batch(&sweep, 10).unwrap();
        assert_eq!(
            batch.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            ["c", "b", "a"]
        );
        mirror
            .advance_room_sweep(&sweep, Some(("2026-10-08T12:00:02Z", "b")))
            .unwrap();
        let resumed = mirror.next_room_sweep().unwrap().unwrap();
        assert_eq!(
            mirror.room_sweep_batch(&resumed, 10).unwrap(),
            vec![("a".to_string(), "2026-10-08T12:00:01Z".to_string())]
        );
        // Re-requests mid-sweep do not reset the running pass (a busy room
        // would never finish); they coalesce into one rerun from the newest
        // start point once the pass finishes.
        std::thread::sleep(std::time::Duration::from_millis(2));
        mirror
            .request_room_sweep("room-1", "2026-10-08T12:00:02Z", "c")
            .unwrap();
        mirror
            .request_room_sweep("room-1", "2026-10-08T12:00:03Z", "d")
            .unwrap();
        assert_eq!(mirror.next_room_sweep().unwrap().unwrap(), resumed);
        mirror
            .advance_room_sweep(&resumed, Some(("2026-10-08T12:00:01Z", "a")))
            .unwrap();
        assert_eq!(
            mirror.next_room_sweep().unwrap().unwrap().cursor_message_id,
            "a"
        );
        mirror.advance_room_sweep(&resumed, None).unwrap();
        let restarted = mirror.next_room_sweep().unwrap().unwrap();
        assert_ne!(restarted.generation, resumed.generation);
        assert_eq!(restarted.cursor_message_id, "d");
        // Progress and a finish from the old generation are ignored.
        mirror
            .advance_room_sweep(&resumed, Some(("2026-10-08T12:00:01Z", "a")))
            .unwrap();
        mirror.advance_room_sweep(&resumed, None).unwrap();
        assert_eq!(mirror.next_room_sweep().unwrap().unwrap(), restarted);
        // The rerun happens once.
        mirror.advance_room_sweep(&restarted, None).unwrap();
        assert_eq!(mirror.next_room_sweep().unwrap(), None);
    }

    #[test]
    fn the_mercury_device_is_remembered_encrypted() {
        let mut mirror = Mirror::in_memory([42_u8; 32]).unwrap();
        assert_eq!(mirror.mercury_device().unwrap(), None);
        let device = webex::DeviceData {
            name: Some("host-webex-bridge".into()),
            ws_url: Some("wss://mercury.example.invalid/v1/apps/wx2/registrations/x".into()),
            url: Some("https://wdm.example.invalid/devices/x".into()),
            ..webex::DeviceData::default()
        };
        mirror.remember_mercury_device(&device).unwrap();
        assert_eq!(mirror.mercury_device().unwrap(), Some(device.clone()));
        // Stored only as ciphertext.
        let blob: Vec<u8> = mirror
            .conn
            .query_row("SELECT device_ct FROM mercury_device", [], |row| row.get(0))
            .unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("mercury.example.invalid"));
        let mut newer = device;
        newer.ws_url = Some("wss://mercury.example.invalid/other".into());
        mirror.remember_mercury_device(&newer).unwrap();
        assert_eq!(mirror.mercury_device().unwrap(), Some(newer));
    }

    #[test]
    fn messages_without_a_creation_time_are_swept_last() {
        let mut mirror = Mirror::in_memory([41_u8; 32]).unwrap();
        let mut timed = message("timed", "body", None);
        timed.created = Some("2026-10-08T12:00:01Z".into());
        mirror.upsert_message(&timed).unwrap();
        for id in ["untimed-a", "untimed-b"] {
            mirror
                .conn
                .execute(
                    "INSERT INTO messages(room_id,message_id,revision,status,body_ct,body_nonce)
                     VALUES ('room-1',?1,1,'active',X'01',X'02')",
                    [id],
                )
                .unwrap();
        }
        mirror
            .request_room_sweep("room-1", "2026-10-08T12:00:09Z", "newest")
            .unwrap();
        let sweep = mirror.next_room_sweep().unwrap().unwrap();
        let ids =
            |batch: Vec<(String, String)>| batch.into_iter().map(|(id, _)| id).collect::<Vec<_>>();
        assert_eq!(
            ids(mirror.room_sweep_batch(&sweep, 2).unwrap()),
            ["timed", "untimed-b"]
        );
        // The cursor of an untimed row is ("", id) and the pass continues.
        mirror
            .advance_room_sweep(&sweep, Some(("", "untimed-b")))
            .unwrap();
        let resumed = mirror.next_room_sweep().unwrap().unwrap();
        assert_eq!(
            ids(mirror.room_sweep_batch(&resumed, 10).unwrap()),
            ["untimed-a"]
        );
    }

    #[test]
    fn a_failing_room_sweep_rotates_behind_others_and_is_dropped_after_its_bound() {
        let mut mirror = Mirror::in_memory([40_u8; 32]).unwrap();
        mirror
            .request_room_sweep("room-a", "2026-10-08T12:00:03Z", "d")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        mirror
            .request_room_sweep("room-b", "2026-10-08T12:00:03Z", "d")
            .unwrap();
        let first = mirror.next_room_sweep().unwrap().unwrap();
        assert_eq!(first.room_id, "room-a");
        // A failure rotates room-a behind room-b.
        assert!(!mirror.fail_room_sweep(&first, 3).unwrap());
        assert_eq!(mirror.next_room_sweep().unwrap().unwrap().room_id, "room-b");
        // Progress resets the count; consecutive failures drop it at the bound.
        mirror
            .advance_room_sweep(&first, Some(("2026-10-08T12:00:02Z", "c")))
            .unwrap();
        assert!(!mirror.fail_room_sweep(&first, 3).unwrap());
        assert!(!mirror.fail_room_sweep(&first, 3).unwrap());
        assert!(mirror.fail_room_sweep(&first, 3).unwrap());
        assert_eq!(mirror.next_room_sweep().unwrap().unwrap().room_id, "room-b");
        let b = mirror.next_room_sweep().unwrap().unwrap();
        mirror.advance_room_sweep(&b, None).unwrap();
        assert_eq!(mirror.next_room_sweep().unwrap(), None);
        // A re-request starts over with a clean count.
        mirror
            .request_room_sweep("room-a", "2026-10-08T12:00:03Z", "d")
            .unwrap();
        let again = mirror.next_room_sweep().unwrap().unwrap();
        assert!(!mirror.fail_room_sweep(&again, 2).unwrap());
        // A failure from a stale generation changes nothing.
        assert!(!mirror.fail_room_sweep(&first, 1).unwrap());
        assert_eq!(mirror.next_room_sweep().unwrap().unwrap(), again);
    }

    #[test]
    fn an_edit_without_parent_id_keeps_the_known_thread_parent() {
        let mut mirror = Mirror::in_memory([35_u8; 32]).unwrap();
        let mut reply = message("reply", "original", None);
        reply.parent_id = Some("root".into());
        reply.markdown = Some("**original**".into());
        assert_eq!(mirror.upsert_message(&reply).unwrap(), Upsert::Created(0));
        // Webex returns the edited message without parentId or markdown.
        let mut edited = message("reply", "original edited", Some("2026-10-08T12:05:00Z"));
        edited.parent_id = None;
        assert_eq!(mirror.upsert_message(&edited).unwrap(), Upsert::Edited(1));
        let stored = mirror.ui_message("reply").unwrap().unwrap();
        assert_eq!(stored.parent_id.as_deref(), Some("root"));
        assert_eq!(stored.body.unwrap().kind, "plainText", "kind as returned");
        // A message that never had a parent stays top-level.
        assert_eq!(
            mirror
                .upsert_message(&message("top", "top-level", None))
                .unwrap(),
            Upsert::Created(2)
        );
        assert_eq!(
            mirror
                .upsert_message(&message(
                    "top",
                    "top-level edited",
                    Some("2026-10-08T12:06:00Z")
                ))
                .unwrap(),
            Upsert::Edited(3)
        );
        assert_eq!(mirror.ui_message("top").unwrap().unwrap().parent_id, None);
    }

    #[test]
    fn legacy_rows_are_backfilled_not_rerevisioned_by_an_identical_hydrate() {
        let mut mirror = Mirror::in_memory([31_u8; 32]).unwrap();
        let mut plain = message("legacy", "unchanged body", None);
        plain.files = Some(vec!["https://files.example.test/a".into()]);
        assert_eq!(mirror.upsert_message(&plain).unwrap(), Upsert::Created(0));
        // Simulate a row written before body_kind existed, with legacy
        // URL-list attachment metadata.
        let legacy_files = mirror
            .crypto
            .seal_prefixed(
                br#"["https://files.example.test/legacy-secret.pdf"]"#,
                &message_aad("files", "legacy", 0),
            )
            .unwrap();
        mirror
            .conn
            .execute(
                "UPDATE messages SET body_kind=NULL,files_meta_ct=?1 WHERE message_id='legacy'",
                [legacy_files],
            )
            .unwrap();

        // The identical authoritative payload (as a delete reconcile or
        // catch-up re-reads it) is not an edit.
        assert_eq!(mirror.upsert_message(&plain).unwrap(), Upsert::Unchanged);
        let (revisions, kind, files): (i64, Option<String>, Vec<u8>) = mirror
            .conn
            .query_row(
                "SELECT COUNT(*),MAX(body_kind),MAX(files_meta_ct) FROM messages WHERE message_id='legacy'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(revisions, 1, "no new revision");
        assert_eq!(kind.as_deref(), Some("plain_text"), "kind backfilled");
        assert!(!files
            .windows(b"legacy-secret".len())
            .any(|window| window == b"legacy-secret"));
        assert_eq!(
            mirror
                .ui_message("legacy")
                .unwrap()
                .unwrap()
                .attachment_count,
            1
        );
        // Backfilled rows now compare exactly.
        assert_eq!(mirror.upsert_message(&plain).unwrap(), Upsert::Unchanged);

        // A different attachment count or body is still a real edit.
        let mut more_files = plain.clone();
        more_files.files = Some(vec!["a".into(), "b".into()]);
        assert_eq!(
            mirror.upsert_message(&more_files).unwrap(),
            Upsert::Edited(1)
        );
        mirror
            .conn
            .execute(
                "UPDATE messages SET body_kind=NULL WHERE message_id='legacy'",
                [],
            )
            .unwrap();
        let mut edited = more_files.clone();
        edited.text = Some("a real edit".into());
        assert_eq!(mirror.upsert_message(&edited).unwrap(), Upsert::Edited(2));
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
    fn cached_account_identity_is_encrypted_and_never_guessed() {
        let mut mirror = Mirror::in_memory([13_u8; 32]).unwrap();
        assert!(mirror.ui_account_identity().unwrap().is_none());
        let person = Person {
            id: "account-person".into(),
            display_name: "Account Owner".into(),
            emails: vec!["owner@example.test".into()],
            ..Person::default()
        };
        mirror.cache_account_identity(&person).unwrap();
        assert_eq!(
            mirror.ui_account_identity().unwrap(),
            Some(UiPerson {
                id: "account-person".into(),
                display_name: Some("Account Owner".into()),
                emails: Some(vec!["owner@example.test".into()]),
            })
        );
        let encrypted: Vec<u8> = mirror
            .conn
            .query_row(
                "SELECT person_id_ct FROM account_identity WHERE slot=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!encrypted
            .windows(b"account-person".len())
            .any(|window| window == b"account-person"));
    }

    #[test]
    fn cached_account_identity_survives_mirror_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bridge.db");
        let key = [15_u8; 32];
        let mut mirror = Mirror::initialize(Connection::open(&path).unwrap(), key, true).unwrap();
        mirror
            .cache_account_identity(&Person {
                id: "account-person".into(),
                display_name: "Account Owner".into(),
                emails: vec!["owner@example.test".into()],
                ..Person::default()
            })
            .unwrap();
        drop(mirror);
        let mirror = Mirror::initialize(Connection::open(path).unwrap(), key, false).unwrap();
        assert_eq!(
            mirror.ui_account_identity().unwrap().unwrap().id,
            "account-person"
        );
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
    fn ui_message_projects_body_kind_and_attachment_count_without_urls() {
        let mut mirror = Mirror::in_memory([19_u8; 32]).unwrap();
        let mut plain = message("plain", "plain body", None);
        plain.files = Some(vec![
            "https://files.example.test/private-report.pdf?token=secret".into(),
        ]);
        mirror.upsert_message(&plain).unwrap();
        let projected = mirror.ui_message("plain").unwrap().unwrap();
        assert_eq!(
            projected.body,
            Some(UiBody {
                kind: "plainText".into(),
                content: "plain body".into(),
            })
        );
        assert_eq!(projected.attachment_count, 1);
        let stored: Vec<u8> = mirror
            .conn
            .query_row(
                "SELECT files_meta_ct FROM messages WHERE message_id='plain'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stored
            .windows(b"private-report.pdf".len())
            .any(|window| window == b"private-report.pdf"));

        let mut markdown = message("markdown", "plain fallback", None);
        markdown.markdown = Some("**rich**".into());
        mirror.upsert_message(&markdown).unwrap();
        assert_eq!(
            mirror
                .ui_message("markdown")
                .unwrap()
                .unwrap()
                .body
                .unwrap()
                .kind,
            "markdown"
        );

        // Existing rows have ciphertext but no body_kind. Never relabel their
        // content as plain text or Markdown without an authoritative hydrate.
        mirror
            .conn
            .execute(
                "UPDATE messages SET body_kind=NULL WHERE message_id='plain'",
                [],
            )
            .unwrap();
        assert_eq!(
            mirror
                .ui_message("plain")
                .unwrap()
                .unwrap()
                .body
                .unwrap()
                .kind,
            "legacyUnknown"
        );
        assert!(mirror.mark_deleted("room-1", "plain").unwrap());
        let deleted = mirror.ui_message("plain").unwrap().unwrap();
        assert!(deleted.body.is_none());
        assert_eq!(deleted.attachment_count, 0);
    }

    #[test]
    fn confirmed_not_found_cache_clears_on_hydrate_but_tombstones_stay_final() {
        let mut mirror = Mirror::in_memory([18_u8; 32]).unwrap();
        mirror.cache_ui_not_found("person", "person-1").unwrap();
        mirror.cache_ui_not_found("message", "message-1").unwrap();
        assert!(mirror.ui_not_found("person", "person-1").unwrap());
        assert!(mirror.ui_not_found("message", "message-1").unwrap());
        mirror
            .upsert_person(&Person {
                id: "person-1".into(),
                display_name: "Hydrated person".into(),
                emails: Vec::new(),
                ..Person::default()
            })
            .unwrap();
        mirror
            .upsert_message(&message("message-1", "body", None))
            .unwrap();
        assert!(!mirror.ui_not_found("person", "person-1").unwrap());
        assert!(!mirror.ui_not_found("message", "message-1").unwrap());
        assert!(mirror.mark_deleted("room-1", "message-1").unwrap());
        assert_eq!(
            mirror
                .upsert_message(&message("message-1", "stale body", None))
                .unwrap(),
            Upsert::IgnoredDeleted
        );
        assert_eq!(
            mirror.ui_message("message-1").unwrap().unwrap().status,
            "deleted"
        );
    }

    #[test]
    fn ui_thread_children_are_parent_scoped_and_cursor_validated() {
        let mut mirror = Mirror::in_memory([17_u8; 32]).unwrap();
        mirror
            .upsert_message(&message("parent", "root", None))
            .unwrap();
        for (id, created) in [
            ("reply-1", "2026-10-08T12:01:00Z"),
            ("reply-2", "2026-10-08T12:02:00Z"),
            ("other", "2026-10-08T12:03:00Z"),
        ] {
            let mut reply = message(id, id, None);
            reply.created = Some(created.into());
            reply.parent_id = (id != "other").then(|| "parent".into());
            mirror.upsert_message(&reply).unwrap();
        }
        let replies = mirror.ui_message_children("parent", None, 1).unwrap();
        assert_eq!(replies[0].id, "reply-2");
        assert_eq!(
            mirror
                .ui_message_children("parent", Some("reply-2"), 10)
                .unwrap()
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            ["reply-1"]
        );
        assert!(mirror
            .ui_message_children("parent", Some("other"), 10)
            .is_err());
    }

    #[test]
    fn ui_team_name_is_encrypted_and_room_lock_state_stays_nullable() {
        let mut mirror = Mirror::in_memory([16_u8; 32]).unwrap();
        let room = Room {
            id: "room-1".into(),
            title: Some("Private room title".into()),
            room_type: "group".into(),
            is_locked: true,
            team_id: Some("team-1".into()),
            last_activity: "2026-10-08T12:00:00Z".into(),
            creator_id: "person-1".into(),
            created: "2026-10-08T12:00:00Z".into(),
        };
        mirror.upsert_room(&room, true).unwrap();
        assert_eq!(
            mirror.ui_room("room-1").unwrap().unwrap().is_locked,
            Some(true)
        );

        // A row written before schema v4 carries no authoritative lock state.
        mirror
            .conn
            .execute("UPDATE rooms SET is_locked=NULL WHERE room_id='room-1'", [])
            .unwrap();
        assert_eq!(mirror.ui_room("room-1").unwrap().unwrap().is_locked, None);

        mirror
            .upsert_team(&Team {
                id: "team-1".into(),
                name: Some("Private team name".into()),
                created: "2026-10-08T12:00:00Z".into(),
                description: Some("Private team description".into()),
            })
            .unwrap();
        assert_eq!(
            mirror.ui_team("team-1").unwrap(),
            Some(UiTeam {
                id: "team-1".into(),
                name: Some("Private team name".into()),
            })
        );
        let encrypted: Vec<u8> = mirror
            .conn
            .query_row(
                "SELECT name_ct FROM teams WHERE team_id='team-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!encrypted
            .windows(b"Private team name".len())
            .any(|window| window == b"Private team name"));
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
    fn revisions_stay_monotonic_across_retention_prune_and_rehydrate() {
        let mut mirror = Mirror::in_memory([13_u8; 32]).unwrap();
        let Upsert::Created(first) = mirror.upsert_message(&message("old", "v1", None)).unwrap()
        else {
            panic!("created")
        };
        let mut edit = message("old", "v2", None);
        edit.updated = Some("2026-10-08T12:05:00Z".into());
        let Upsert::Edited(edited) = mirror.upsert_message(&edit).unwrap() else {
            panic!("edited")
        };
        assert!(edited > first);
        assert_eq!(mirror.prune_before("2026-10-08T12:00:01Z").unwrap(), 2);
        // Lazy hydrate stores the pruned message again: still a creation, but
        // above every revision it ever had, never reusing a pruned one.
        let Upsert::Created(rehydrated) = mirror.upsert_message(&edit).unwrap() else {
            panic!("re-created")
        };
        assert!(rehydrated > edited);
        let mut again = message("old", "v3", None);
        again.updated = Some("2026-10-08T12:09:00Z".into());
        let Upsert::Edited(later) = mirror.upsert_message(&again).unwrap() else {
            panic!("edited again")
        };
        assert!(later > rehydrated);
        assert!(mirror.mark_deleted("room-1", "old").unwrap());
        let tombstone = mirror.ui_message("old").unwrap().unwrap();
        assert_eq!(tombstone.status, "deleted");
        assert!(tombstone.revision > later);
    }

    #[test]
    fn existing_mirror_without_a_counter_continues_above_its_maximum() {
        let mut mirror = Mirror::in_memory([14_u8; 32]).unwrap();
        mirror.upsert_message(&message("a", "v0", None)).unwrap();
        for (minute, body) in [(1, "v1"), (2, "v2")] {
            let mut edit = message("a", body, None);
            edit.updated = Some(format!("2026-10-08T12:0{minute}:00Z"));
            mirror.upsert_message(&edit).unwrap();
        }
        // A pre-counter mirror: per-message revisions 0..=2 and no sequence row.
        mirror
            .conn
            .execute("DELETE FROM mirror_meta WHERE key='revision_seq'", [])
            .unwrap();
        let max: i64 = mirror
            .conn
            .query_row("SELECT MAX(revision) FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(max, 2);
        assert_eq!(
            mirror.upsert_message(&message("b", "new", None)).unwrap(),
            Upsert::Created(3)
        );
        let mut edit = message("a", "v3", None);
        edit.updated = Some("2026-10-08T12:03:00Z".into());
        assert_eq!(mirror.upsert_message(&edit).unwrap(), Upsert::Edited(4));
    }

    #[test]
    fn counter_initialisation_covers_orphan_delivery_revisions_and_drops_them() {
        let mut mirror = Mirror::in_memory([16_u8; 32]).unwrap();
        mirror
            .sync_routes(&[crate::config::Route {
                id: "r".into(),
                room_id: "room-1".into(),
                agent_name: "sam/coder".into(),
                allowed_senders: Vec::new(),
                receive: crate::config::Receive::Addressed,
                workspace: "/workspace".into(),
            }])
            .unwrap();
        mirror.upsert_message(&message("a", "v0", None)).unwrap();
        // Pre-counter mirror with an orphan delivery of a pruned message (rev 7).
        mirror
            .conn
            .execute(
                "INSERT INTO deliveries(route_id,message_id,revision,state,decided_at)
                 VALUES ('r','pruned',7,'rejected',NULL)",
                [],
            )
            .unwrap();
        mirror
            .conn
            .execute("DELETE FROM mirror_meta WHERE key='revision_seq'", [])
            .unwrap();
        assert_eq!(
            mirror.upsert_message(&message("b", "new", None)).unwrap(),
            Upsert::Created(8)
        );
        let orphans: i64 = mirror
            .conn
            .query_row(
                "SELECT count(*) FROM deliveries WHERE message_id='pruned'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0);
    }

    #[test]
    fn revisions_stay_json_safe_integers() {
        let mut mirror = Mirror::in_memory([15_u8; 32]).unwrap();
        mirror
            .conn
            .execute(
                "INSERT INTO mirror_meta(key,value) VALUES ('revision_seq',?1)",
                [MAX_REVISION],
            )
            .unwrap();
        assert_eq!(
            mirror.upsert_message(&message("a", "last", None)).unwrap(),
            Upsert::Created(MAX_REVISION)
        );
        assert!(mirror.upsert_message(&message("b", "over", None)).is_err());
        assert!(!mirror.contains_message("b").unwrap());
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
