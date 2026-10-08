//! Atomic SQLite schema migrations.

use super::schema::{SCHEMA_V1, SCHEMA_V2};
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

/// Apply migrations or reject a database written by newer code.
pub fn migrate(conn: &mut Connection) -> Result<()> {
    let version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match version {
        0 => {
            let tx = conn.transaction()?;
            tx.execute_batch(SCHEMA_V1)?;
            tx.commit()?;
            migrate_v2(conn)
        }
        1 => migrate_v2(conn),
        2 => Ok(()),
        _ => bail!("Mirror database schema version {version} is unsupported"),
    }
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
        conn.execute_batch("PRAGMA user_version=99").unwrap();
        assert!(migrate(&mut conn).is_err());
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
            2
        );
    }
}
