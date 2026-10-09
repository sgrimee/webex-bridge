//! Redacted, lifecycle-only daemon diagnostics.
//!
//! These helpers deliberately accept only caller-authored messages. Do not pass
//! errors, HTTP bodies, events, IDs, tokens, secrets, or decrypted mirror data:
//! `bridged.log` is useful for operations but must remain content-free.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable metadata-only debug events for this process.
pub fn enable_debug() {
    DEBUG_ENABLED.store(true, Ordering::Relaxed);
}

/// Whether verbose daemon diagnostics are enabled.
#[must_use]
pub fn debug_enabled() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
        || std::env::var_os("WEBEX_BRIDGE_LOG")
            .is_some_and(|value| value.eq_ignore_ascii_case("debug"))
}

/// Emit a normal lifecycle event to stderr (the daemon log destination).
pub fn info(event: impl std::fmt::Display) {
    emit("INFO", event);
}

/// Emit a warning lifecycle event without exposing the underlying error.
pub fn warn(event: impl std::fmt::Display) {
    emit("WARN", event);
}

/// Emit a verbose lifecycle event only when explicitly requested.
pub fn debug(event: impl std::fmt::Display) {
    if debug_enabled() {
        emit("DEBUG", event);
    }
}

fn emit(level: &str, event: impl std::fmt::Display) {
    // RFC 3339 is intentionally unnecessary here: an epoch-milliseconds value
    // is timezone-independent, sorts lexicographically, and needs no fallible
    // formatting dependency in the daemon's failure paths.
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    eprintln!("ts_ms={timestamp_ms} level={level} component=webex-bridge event={event}");
}
