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
