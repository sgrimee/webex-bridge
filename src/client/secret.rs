//! Best-effort wiping of client-held credentials without extra dependencies.
//!
//! The client-only build deliberately has no `zeroize` dependency, so this
//! module overwrites owned buffers with volatile writes before they are freed.
//! It covers the copies this crate owns: the UI session request body, the
//! session response body, the `Authorization` header buffer and the bearer
//! token shared by every `UiClient` clone. Hyper's own internal write and read
//! buffers are outside its control.

use std::{
    fmt,
    sync::{
        atomic::{compiler_fence, Ordering},
        Arc,
    },
};

/// Overwrite `bytes` with zeros in a way the optimiser cannot elide.
pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, exclusive reference to an initialised u8.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// An owned byte buffer that is wiped when dropped. Usable as a
/// `Bytes::from_owner` owner, so hyper releases it through this `Drop`.
pub(crate) struct Wiped(Vec<u8>);

impl Wiped {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// A bearer token held once and shared by every `UiClient` clone; the bytes
/// are wiped when the last clone is dropped. Never printed.
#[derive(Clone)]
pub(crate) struct SecretToken(Arc<Wiped>);

impl SecretToken {
    pub(crate) fn new(token: String) -> Self {
        Self(Arc::new(Wiped::new(token.into_bytes())))
    }

    pub(crate) fn as_str(&self) -> &str {
        // Constructed only from a `String`, so the bytes are valid UTF-8.
        std::str::from_utf8(self.0.as_ref().as_ref()).unwrap_or_default()
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroes_every_byte() {
        let mut bytes = b"secret-token".to_vec();
        wipe(&mut bytes);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn token_is_shared_by_clones_and_never_debug_printed() {
        let token = SecretToken::new("a-bearer-token".into());
        let clone = token.clone();
        assert_eq!(clone.as_str(), "a-bearer-token");
        assert!(std::ptr::eq(
            token.as_str().as_ptr(),
            clone.as_str().as_ptr()
        ));
        assert!(!format!("{token:?}").contains("bearer"));
    }
}
