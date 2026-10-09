//! Authentication and connection identity for the local Unix-socket API.

use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

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

/// Privilege granted to a local API session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// Full mirror access for the paired terminal UI.
    Ui,
    /// Route-scoped inbox and draft access for an agent host.
    Agent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Session {
    scope: Scope,
    peer: PeerIdentity,
    expires_at: Instant,
    agent_session_id: Option<String>,
    claimed_routes: Vec<String>,
}

#[derive(Default)]
struct SessionState {
    sessions: HashMap<String, Session>,
    route_claims: HashMap<String, String>,
}

/// Why a bearer session cannot authorize a local request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// No token was supplied or it has been revoked.
    Missing,
    /// The in-memory lease elapsed.
    Expired,
    /// The token belongs to the other API scope.
    Scope,
    /// A same-UID but different process attempted to replay the token.
    Peer,
    /// An agent session ID does not belong to the supplied token.
    SessionId,
}

/// A matching route is already leased to a live agent session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    /// Another unexpired agent session owns one of the requested routes.
    AlreadyClaimed,
}

/// In-memory, process-bound local API sessions.
///
/// Tokens deliberately do not survive a daemon restart. A captured token is
/// also useless from a different local process when peer PIDs are available.
#[derive(Clone, Default)]
pub struct Sessions {
    inner: Arc<Mutex<SessionState>>,
}

impl Sessions {
    fn token() -> String {
        let mut bytes = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn prune(state: &mut SessionState) {
        let expired = state
            .sessions
            .iter()
            .filter_map(|(token, session)| {
                (session.expires_at <= Instant::now()).then_some(token.clone())
            })
            .collect::<Vec<_>>();
        for token in expired {
            Self::revoke_locked(state, &token);
        }
    }

    fn revoke_locked(state: &mut SessionState, token: &str) {
        if let Some(session) = state.sessions.remove(token) {
            for route_id in session.claimed_routes {
                if state
                    .route_claims
                    .get(&route_id)
                    .is_some_and(|claim| claim == token)
                {
                    state.route_claims.remove(&route_id);
                }
            }
        }
    }

    /// Issue a cryptographically random bearer token for one local peer.
    #[must_use]
    pub fn issue(&self, scope: Scope, peer: PeerIdentity, ttl: Duration) -> String {
        let token = Self::token();
        let expires_at = Instant::now().checked_add(ttl).unwrap_or_else(Instant::now);
        let mut state = self.inner.lock().expect("session mutex poisoned");
        Self::prune(&mut state);
        state.sessions.insert(
            token.clone(),
            Session {
                scope,
                peer,
                expires_at,
                agent_session_id: None,
                claimed_routes: Vec::new(),
            },
        );
        token
    }

    /// Atomically issue an agent token and lease its configured routes.
    pub fn issue_agent(
        &self,
        peer: PeerIdentity,
        agent_session_id: String,
        route_ids: Vec<String>,
        ttl: Duration,
    ) -> std::result::Result<String, ClaimError> {
        let mut state = self.inner.lock().expect("session mutex poisoned");
        Self::prune(&mut state);
        if route_ids
            .iter()
            .any(|route| state.route_claims.contains_key(route))
        {
            return Err(ClaimError::AlreadyClaimed);
        }
        let token = Self::token();
        let expires_at = Instant::now().checked_add(ttl).unwrap_or_else(Instant::now);
        for route_id in &route_ids {
            state.route_claims.insert(route_id.clone(), token.clone());
        }
        state.sessions.insert(
            token.clone(),
            Session {
                scope: Scope::Agent,
                peer,
                expires_at,
                agent_session_id: Some(agent_session_id),
                claimed_routes: route_ids,
            },
        );
        Ok(token)
    }

    /// Check scope, lease and the kernel-derived process identity.
    pub fn authorize(
        &self,
        token: Option<&str>,
        required_scope: Scope,
        peer: PeerIdentity,
    ) -> std::result::Result<(), SessionError> {
        let token = token.ok_or(SessionError::Missing)?;
        let mut state = self.inner.lock().expect("session mutex poisoned");
        let Some(session) = state.sessions.get(token).cloned() else {
            return Err(SessionError::Missing);
        };
        if session.expires_at <= Instant::now() {
            Self::revoke_locked(&mut state, token);
            return Err(SessionError::Expired);
        }
        if session.scope != required_scope {
            return Err(SessionError::Scope);
        }
        if session.peer.uid != peer.uid
            || session
                .peer
                .pid
                .zip(peer.pid)
                .is_some_and(|(issued, presented)| issued != presented)
        {
            return Err(SessionError::Peer);
        }
        Ok(())
    }

    /// Return the expiry for one verified session. SSE uses this to close an
    /// idle UI subscription at lease expiry rather than relying on a later bus
    /// event or keepalive write to trigger revalidation.
    pub fn expires_at(
        &self,
        token: &str,
        required_scope: Scope,
        peer: PeerIdentity,
    ) -> std::result::Result<Instant, SessionError> {
        self.authorize(Some(token), required_scope, peer)?;
        let state = self.inner.lock().expect("session mutex poisoned");
        state
            .sessions
            .get(token)
            .map(|session| session.expires_at)
            .ok_or(SessionError::Missing)
    }

    /// Return the routes that this verified agent token currently owns.
    ///
    /// The caller supplies the kernel-derived peer identity on every request,
    /// so a same-UID process cannot use a copied token when its PID is known.
    pub fn agent_routes(
        &self,
        token: &str,
        peer: PeerIdentity,
    ) -> std::result::Result<Vec<String>, SessionError> {
        self.authorize(Some(token), Scope::Agent, peer)?;
        let state = self.inner.lock().expect("session mutex poisoned");
        state
            .sessions
            .get(token)
            .map(|session| session.claimed_routes.clone())
            .ok_or(SessionError::Missing)
    }

    /// Renew an owned agent lease and preserve its route claim.
    pub fn renew_agent(
        &self,
        token: &str,
        agent_session_id: &str,
        peer: PeerIdentity,
        ttl: Duration,
    ) -> std::result::Result<(), SessionError> {
        self.authorize(Some(token), Scope::Agent, peer)?;
        let mut state = self.inner.lock().expect("session mutex poisoned");
        let session = state.sessions.get_mut(token).ok_or(SessionError::Missing)?;
        if session.agent_session_id.as_deref() != Some(agent_session_id) {
            return Err(SessionError::SessionId);
        }
        session.expires_at = Instant::now().checked_add(ttl).unwrap_or_else(Instant::now);
        Ok(())
    }

    /// Remove one session, for explicit logout or a released lease.
    pub fn revoke(&self, token: &str) {
        let mut state = self.inner.lock().expect("session mutex poisoned");
        Self::revoke_locked(&mut state, token);
    }

    /// Release one owned agent lease.
    pub fn release_agent(
        &self,
        token: &str,
        agent_session_id: &str,
        peer: PeerIdentity,
    ) -> std::result::Result<(), SessionError> {
        self.authorize(Some(token), Scope::Agent, peer)?;
        let state = self.inner.lock().expect("session mutex poisoned");
        let owns = state
            .sessions
            .get(token)
            .is_some_and(|session| session.agent_session_id.as_deref() == Some(agent_session_id));
        drop(state);
        if !owns {
            return Err(SessionError::SessionId);
        }
        self.revoke(token);
        Ok(())
    }
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

    #[test]
    fn sessions_are_scoped_expiring_and_process_bound() {
        let sessions = Sessions::default();
        let peer = PeerIdentity {
            uid: 501,
            pid: Some(10),
        };
        let token = sessions.issue(Scope::Agent, peer, Duration::from_secs(60));
        assert!(sessions.authorize(Some(&token), Scope::Agent, peer).is_ok());
        assert_eq!(
            sessions.authorize(Some(&token), Scope::Ui, peer),
            Err(SessionError::Scope)
        );
        assert_eq!(
            sessions.authorize(
                Some(&token),
                Scope::Agent,
                PeerIdentity {
                    uid: 501,
                    pid: Some(11),
                }
            ),
            Err(SessionError::Peer)
        );
        sessions.revoke(&token);
        assert_eq!(
            sessions.authorize(Some(&token), Scope::Agent, peer),
            Err(SessionError::Missing)
        );
    }

    #[test]
    fn expired_sessions_are_rejected() {
        let sessions = Sessions::default();
        let peer = PeerIdentity {
            uid: 501,
            pid: Some(10),
        };
        let token = sessions.issue(Scope::Ui, peer, Duration::ZERO);
        assert_eq!(
            sessions.authorize(Some(&token), Scope::Ui, peer),
            Err(SessionError::Expired)
        );
    }

    #[test]
    fn agent_route_claim_is_exclusive_and_released() {
        let sessions = Sessions::default();
        let peer = PeerIdentity {
            uid: 501,
            pid: Some(10),
        };
        let token = sessions
            .issue_agent(
                peer,
                "host-session".into(),
                vec!["agents-social".into()],
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(
            sessions.issue_agent(
                peer,
                "other-session".into(),
                vec!["agents-social".into()],
                Duration::from_secs(60),
            ),
            Err(ClaimError::AlreadyClaimed)
        );
        assert!(sessions
            .renew_agent(&token, "host-session", peer, Duration::from_secs(60))
            .is_ok());
        assert!(sessions.release_agent(&token, "host-session", peer).is_ok());
        assert!(sessions
            .issue_agent(
                peer,
                "other-session".into(),
                vec!["agents-social".into()],
                Duration::from_secs(60),
            )
            .is_ok());
    }
}
