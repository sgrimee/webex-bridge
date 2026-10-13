//! Versioned SQLite schema. Personal free text is stored only in `*_ct` blobs.

pub(crate) const SCHEMA_V1: &str = r#"
CREATE TABLE mirror_meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE rooms (
    room_id TEXT PRIMARY KEY,
    title_ct BLOB,
    type TEXT NOT NULL,
    team_id TEXT,
    last_activity TEXT,
    is_member INTEGER NOT NULL CHECK (is_member IN (0,1)),
    updated_at TEXT NOT NULL
);
CREATE TABLE people (
    person_id TEXT PRIMARY KEY,
    display_name_ct BLOB,
    emails_ct BLOB,
    updated_at TEXT NOT NULL
);
CREATE TABLE messages (
    room_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    parent_id TEXT,
    sender_id TEXT,
    created_at TEXT,
    updated_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('active','deleted')),
    body_ct BLOB,
    body_nonce BLOB,
    files_meta_ct BLOB,
    PRIMARY KEY(message_id, revision),
    FOREIGN KEY(room_id) REFERENCES rooms(room_id)
);
CREATE INDEX messages_room_time ON messages(room_id, created_at DESC, message_id);
CREATE TABLE room_sync (
    room_id TEXT PRIMARY KEY,
    boundary_created_at TEXT,
    boundary_message_id TEXT,
    oldest_stored_at TEXT,
    initial_done INTEGER NOT NULL DEFAULT 0 CHECK (initial_done IN (0,1)),
    last_catchup_at TEXT,
    last_result TEXT,
    FOREIGN KEY(room_id) REFERENCES rooms(room_id)
);
CREATE TABLE routes (
    route_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    config_hash TEXT NOT NULL
);
CREATE TABLE deliveries (
    route_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','accepted','rejected','superseded','deleted')),
    decided_at TEXT,
    PRIMARY KEY(route_id, message_id, revision),
    FOREIGN KEY(route_id) REFERENCES routes(route_id)
);
CREATE TABLE outbox (
    draft_id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    parent_id TEXT,
    body_ct BLOB NOT NULL,
    body_nonce BLOB NOT NULL,
    sha256 TEXT NOT NULL,
    approval_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL,
    webex_message_id TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE ui_clients (
    secret_hash TEXT PRIMARY KEY,
    exe_path TEXT NOT NULL,
    paired_at TEXT NOT NULL,
    last_seen TEXT
);
CREATE TABLE audit (
    ts TEXT NOT NULL,
    scope TEXT NOT NULL,
    action TEXT NOT NULL,
    ref TEXT,
    detail_redacted TEXT
);
PRAGMA user_version=1;
"#;

pub(crate) const SCHEMA_V2: &str = "PRAGMA user_version=2;";

// The account person ID is encrypted even though other resource IDs are indexed
// plaintext. It identifies the local account and is needed only to locate the
// already-encrypted person record for an authorized UI session.
pub(crate) const SCHEMA_V3: &str = r#"
CREATE TABLE account_identity (
    slot INTEGER PRIMARY KEY CHECK (slot=1),
    person_id_ct BLOB NOT NULL
);
PRAGMA user_version=3;
"#;

// Team names are UI free text. Lock state is nullable: rows written before
// v4 have no authoritative lock observation and must not become `false`.
pub(crate) const SCHEMA_V4: &str = r#"
CREATE TABLE IF NOT EXISTS teams (
    team_id TEXT PRIMARY KEY,
    name_ct BLOB,
    updated_at TEXT NOT NULL
);
PRAGMA user_version=4;
"#;

// Confirmed negative UI lookups contain only opaque resource IDs. They are
// consulted offline, but an online point read always retries Webex so a stale
// negative result cannot permanently suppress an explicit user retry.
pub(crate) const SCHEMA_V5: &str = r#"
CREATE TABLE ui_lookup (
    resource TEXT NOT NULL CHECK (resource IN ('person','message')),
    resource_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state='not_found'),
    checked_at TEXT NOT NULL,
    PRIMARY KEY(resource, resource_id)
);
PRAGMA user_version=5;
"#;

// `NULL` is deliberate for rows written before B6: their encrypted body is
// retained but its original text-vs-Markdown provenance is unknowable.
pub(crate) const SCHEMA_V6: &str = "PRAGMA user_version=6;";

// One row per room whose older history still needs a paced, background
// delete/edit sweep. The cursor (created_at, message_id) is the oldest message
// already checked; `requested_at` is the request generation, so a re-request
// that arrives mid-sweep restarts the pass instead of being lost.
pub(crate) const SCHEMA_V7: &str = r#"
CREATE TABLE IF NOT EXISTS room_sweep (
    room_id TEXT PRIMARY KEY,
    cursor_created_at TEXT NOT NULL,
    cursor_message_id TEXT NOT NULL,
    requested_at TEXT NOT NULL
);
PRAGMA user_version=7;
"#;

// Sweep fairness: `attempts` counts consecutive failed steps of one request
// generation (a failing room is dropped after a bound, and a re-request or
// progress resets it); `queued_at` rotates a failed room behind the others.
// The columns are added by `migrate_v8`; this only bumps the version.
pub(crate) const SCHEMA_V8: &str = "PRAGMA user_version=8;";

// Sweep coalescing: a request that arrives during a pass sets
// `rerun_requested` and keeps the newest start point in `rerun_*`; the pass
// finishes and then restarts once from there. Columns added by `migrate_v9`.
pub(crate) const SCHEMA_V9: &str = "PRAGMA user_version=9;";
