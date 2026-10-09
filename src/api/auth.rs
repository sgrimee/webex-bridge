//! Authentication and connection identity for the local Unix-socket API.

use anyhow::{bail, Result};

/// Identity captured once from an accepted Unix-domain socket.
///
/// It is deliberately request-local rather than a client-supplied header: local
/// callers cannot impersonate a different process by constructing HTTP fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    /// Operating-system user ID reported by the kernel.
    pub uid: u32,
    /// Peer process ID when the platform exposes it.
    pub pid: Option<u32>,
}

/// Return the effective UID of this per-user daemon.
pub fn daemon_uid() -> u32 {
    // `geteuid` has no preconditions and does not retain any borrowed data.
    unsafe { libc::geteuid() }
}

/// Refuse a socket connection before parsing its HTTP request when it belongs
/// to another local user.
pub fn authorize_peer(peer: PeerIdentity, owner_uid: u32) -> Result<()> {
    if peer.uid != owner_uid {
        bail!("Unix socket peer belongs to another user")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_daemon_user_is_authorized() {
        assert!(authorize_peer(
            PeerIdentity {
                uid: 501,
                pid: Some(1)
            },
            501
        )
        .is_ok());
        assert!(authorize_peer(
            PeerIdentity {
                uid: 502,
                pid: Some(2)
            },
            501
        )
        .is_err());
    }
}
