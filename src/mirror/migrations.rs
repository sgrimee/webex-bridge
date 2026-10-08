//! Atomic SQLite schema migrations.

use super::schema::SCHEMA_V1;
use anyhow::{bail, Result};
use rusqlite::Connection;

/// Apply the initial migration or reject a database written by newer code.
pub fn migrate(conn: &mut Connection) -> Result<()> {
    let version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match version {
        0 => {
            let tx = conn.transaction()?;
            tx.execute_batch(SCHEMA_V1)?;
            tx.commit()?;
            Ok(())
        }
        1 => Ok(()),
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
        conn.execute_batch("PRAGMA user_version=99").unwrap();
        assert!(migrate(&mut conn).is_err());
    }
}
