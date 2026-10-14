//! Atomic SQLite schema migrations.

use super::schema::{
    SCHEMA_V1, SCHEMA_V10, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7,
    SCHEMA_V8, SCHEMA_V9,
};
use anyhow::{bail, Result};
use rusqlite::Connection;

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    Ok(columns
        .collect::<rusqlite::Result<Vec<_>>>()?
        .iter()
        .any(|name| name == column))
}

fn migrate_v2(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    // Development databases created before migration v2 may already have the
    // column but report user_version=1. Treat that shape as idempotent.
    if !has_column(&tx, "room_sync", "observed_last_activity")? {
        tx.execute_batch("ALTER TABLE room_sync ADD COLUMN observed_last_activity TEXT;")?;
    }
    tx.execute_batch(SCHEMA_V2)?;
    tx.commit()?;
    Ok(())
}

fn migrate_v3(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(SCHEMA_V3)?;
    tx.commit()?;
    Ok(())
}

fn migrate_v4(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    if !has_column(&tx, "rooms", "is_locked")? {
        tx.execute_batch(
            "ALTER TABLE rooms ADD COLUMN is_locked INTEGER CHECK (is_locked IN (0,1));",
        )?;
    }
    tx.execute_batch(SCHEMA_V4)?;
    tx.commit()?;
    Ok(())
}

fn migrate_v5(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(SCHEMA_V5)?;
    tx.commit()?;
    Ok(())
}

fn migrate_v6(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    if !has_column(&tx, "messages", "body_kind")? {
        tx.execute_batch(
            "ALTER TABLE messages ADD COLUMN body_kind TEXT CHECK (body_kind IN ('plain_text','markdown'));",
        )?;
    }
    tx.execute_batch(SCHEMA_V6)?;
    tx.commit()?;
    Ok(())
}

fn migrate_v7(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(SCHEMA_V7)?;
    tx.commit()?;
    Ok(())
}

fn migrate_v8(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    if !has_column(&tx, "room_sweep", "attempts")? {
        tx.execute_batch(
            "ALTER TABLE room_sweep ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE room_sweep ADD COLUMN queued_at TEXT;",
        )?;
    }
    tx.execute_batch(SCHEMA_V8)?;
    tx.commit()?;
    Ok(())
}

fn migrate_v10(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(SCHEMA_V10)?;
    tx.commit()?;
    Ok(())
}

fn migrate_v9(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    if !has_column(&tx, "room_sweep", "rerun_requested")? {
        tx.execute_batch(
            "ALTER TABLE room_sweep ADD COLUMN rerun_requested INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE room_sweep ADD COLUMN rerun_created_at TEXT;
             ALTER TABLE room_sweep ADD COLUMN rerun_message_id TEXT;",
        )?;
    }
    tx.execute_batch(SCHEMA_V9)?;
    tx.commit()?;
    Ok(())
}

/// One migration that brings the schema to the paired version.
type Step = fn(&mut Connection) -> Result<()>;

/// Newest schema version this code writes.
pub const LATEST_VERSION: i32 = 10;

/// Apply migrations or reject a database written by newer code.
pub fn migrate(conn: &mut Connection) -> Result<()> {
    let version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if !(0..=LATEST_VERSION).contains(&version) {
        bail!("Mirror database schema version {version} is unsupported");
    }
    if version == 0 {
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA_V1)?;
        tx.commit()?;
    }
    let steps: [(i32, Step); 9] = [
        (2, migrate_v2),
        (3, migrate_v3),
        (4, migrate_v4),
        (5, migrate_v5),
        (6, migrate_v6),
        (7, migrate_v7),
        (8, migrate_v8),
        (9, migrate_v9),
        (10, migrate_v10),
    ];
    for (target, step) in steps {
        if version < target {
            step(conn)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migrates_once_and_rejects_future_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        assert!(has_column(&conn, "room_sync", "observed_last_activity").unwrap());
        assert!(has_column(&conn, "account_identity", "person_id_ct").unwrap());
        assert!(has_column(&conn, "rooms", "is_locked").unwrap());
        assert!(has_column(&conn, "teams", "name_ct").unwrap());
        assert!(has_column(&conn, "ui_lookup", "checked_at").unwrap());
        assert!(has_column(&conn, "messages", "body_kind").unwrap());
        assert!(has_column(&conn, "room_sweep", "cursor_message_id").unwrap());
        assert!(has_column(&conn, "room_sweep", "attempts").unwrap());
        assert!(has_column(&conn, "room_sweep", "queued_at").unwrap());
        assert!(has_column(&conn, "room_sweep", "rerun_requested").unwrap());
        // The routing audit lookup is served by the (scope, action, ref) index.
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT 1 FROM audit WHERE scope='agent'
                 AND action='route_filtered' AND ref='r:m:1'",
                [],
                |row| row.get(3),
            )
            .unwrap();
        assert!(plan.contains("audit_scope_action_ref"), "{plan}");
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i32>(0))
                .unwrap(),
            LATEST_VERSION
        );
        conn.execute_batch("PRAGMA user_version=99").unwrap();
        assert!(migrate(&mut conn).is_err());
    }

    #[test]
    fn v2_adds_the_encrypted_account_identity_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch("ALTER TABLE room_sync ADD COLUMN observed_last_activity TEXT;")
            .unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.execute_batch(
            "INSERT INTO rooms(room_id,title_ct,type,team_id,last_activity,is_member,updated_at)
             VALUES ('old-room',NULL,'group',NULL,NULL,1,'2026-10-08T12:00:00Z');",
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        assert!(has_column(&conn, "account_identity", "person_id_ct").unwrap());
        assert!(has_column(&conn, "rooms", "is_locked").unwrap());
        assert!(has_column(&conn, "teams", "name_ct").unwrap());
        assert!(has_column(&conn, "messages", "body_kind").unwrap());
        assert_eq!(
            conn.query_row(
                "SELECT is_locked FROM rooms WHERE room_id='old-room'",
                [],
                |row| row.get::<_, Option<bool>>(0),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i32>(0))
                .unwrap(),
            LATEST_VERSION
        );
    }

    #[test]
    fn v4_adds_confirmed_ui_lookup_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch("ALTER TABLE room_sync ADD COLUMN observed_last_activity TEXT;")
            .unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.execute_batch(SCHEMA_V3).unwrap();
        conn.execute_batch("ALTER TABLE rooms ADD COLUMN is_locked INTEGER;")
            .unwrap();
        conn.execute_batch(SCHEMA_V4).unwrap();
        conn.execute_batch(
            "INSERT INTO rooms(room_id,type,is_member,updated_at)
             VALUES ('legacy-room','group',1,'2026-10-08T12:00:00Z');
             INSERT INTO messages(room_id,message_id,revision,status,body_ct,body_nonce)
             VALUES ('legacy-room','legacy-message',0,'active',X'01',X'02');",
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        assert!(has_column(&conn, "ui_lookup", "checked_at").unwrap());
        assert!(has_column(&conn, "messages", "body_kind").unwrap());
        assert_eq!(
            conn.query_row(
                "SELECT body_kind FROM messages WHERE message_id='legacy-message'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i32>(0))
                .unwrap(),
            LATEST_VERSION
        );
    }

    #[test]
    fn accepts_pre_release_v1_shape_with_new_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch("ALTER TABLE room_sync ADD COLUMN observed_last_activity TEXT;")
            .unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i32>(0))
                .unwrap(),
            LATEST_VERSION
        );
    }
}
