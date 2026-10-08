//! Mercury connection owner. Refresh rebuilds client and stream; failures back off.

use crate::{auth, paths::Paths};
use anyhow::{bail, Context, Result};
use rand::Rng;
use std::{future::Future, time::Duration};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{sleep, timeout};
use webex::{error::Error as WebexError, Event, Webex};

/// Public connection states used by the daemon's eventual status endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// Starting or deliberately rebuilding after token refresh.
    Connecting,
    /// Receiving events.
    Connected,
    /// Backing off after a transient error.
    Disconnected,
    /// Authentication was rejected; manual login is required.
    AuthRequired,
}

/// Separate device from the TUI while both run on the same host.
#[must_use]
pub fn device_name() -> String {
    format!(
        "{}-webex-bridge",
        gethostname::gethostname().to_string_lossy()
    )
}

fn authentication_error(error: &WebexError) -> bool {
    match error {
        WebexError::Status(code) | WebexError::StatusText(code, _) => {
            matches!(code.as_u16(), 401 | 403)
        }
        WebexError::Reqwest(error) => error
            .status()
            .is_some_and(|code| matches!(code.as_u16(), 401 | 403)),
        WebexError::Tungstenite(error, _) => {
            matches!(error.as_ref(), tokio_tungstenite::tungstenite::Error::Http(response)
                if matches!(response.status().as_u16(), 401 | 403))
        }
        _ => false,
    }
}

fn next_backoff(previous: Duration) -> Duration {
    (previous * 2).min(Duration::from_secs(300))
}

fn jitter(base: Duration) -> Duration {
    Duration::from_millis(
        (base.as_millis() as u64 * rand::thread_rng().gen_range(800..=1200)) / 1000,
    )
}

/// Connect and pass incoming events to the sync engine. No event body is logged.
/// The callback must validate/hydrate events; errors are safe status codes, not payloads.
/// A 401/403 stops permanently until explicit login (no reconnect loop).
pub async fn run<H, F>(paths: &Paths, mut on_event: H) -> Result<()>
where
    H: FnMut(Event, Webex) -> F,
    F: Future<Output = Result<(), WebexError>>,
{
    let mut term = signal(SignalKind::terminate())?;
    let mut backoff = Duration::from_secs(1);
    loop {
        let tokens = match auth::fresh_token(paths).await {
            Ok(tokens) => tokens,
            Err(error) if error.is::<reqwest::Error>() => {
                eprintln!("Webex bridge: token refresh unavailable; retrying after backoff");
                tokio::select! {
                    _ = term.recv() => return Ok(()),
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                    _ = sleep(jitter(backoff)) => {}
                }
                backoff = next_backoff(backoff);
                continue;
            }
            Err(error) => return Err(error).context("auth_required or token refresh failed"),
        };
        let name = device_name();
        let initialized = tokio::select! {
            _ = term.recv() => return Ok(()),
            _ = tokio::signal::ctrl_c() => return Ok(()),
            result = timeout(Duration::from_secs(30), Webex::new_with_device_name(&name, &tokens.access_token)) => result,
        };
        let Ok(client) = initialized else {
            eprintln!("Webex bridge: initialization timed out; retrying after backoff");
            tokio::select! {
                _ = term.recv() => return Ok(()),
                _ = tokio::signal::ctrl_c() => return Ok(()),
                _ = sleep(jitter(backoff)) => {}
            }
            backoff = next_backoff(backoff);
            continue;
        };
        let stream = tokio::select! {
            _ = term.recv() => return Ok(()),
            _ = tokio::signal::ctrl_c() => return Ok(()),
            result = timeout(Duration::from_secs(30), client.event_stream()) => result,
        };
        match stream {
            Ok(Ok(mut stream)) => {
                backoff = Duration::from_secs(1);
                println!("Webex bridge: connected");
                loop {
                    let wait_for_refresh =
                        Duration::from_secs(tokens.refresh_at().saturating_sub(now()?));
                    tokio::select! {
                        _ = term.recv() => return Ok(()),
                        _ = tokio::signal::ctrl_c() => return Ok(()),
                        _ = sleep(wait_for_refresh) => break,
                        event = stream.next() => match event {
                            Ok(event) => {
                                if let Err(error) = on_event(event, client.clone()).await {
                                    if authentication_error(&error) {
                                        bail!("auth_required: Webex rejected event hydration; run webex-bridge login");
                                    }
                                    // Never log a response body or event data via a Display impl.
                                    eprintln!("Webex event hydration failed; catch-up is required");
                                }
                            }
                            Err(error) if authentication_error(&error) => {
                                bail!("auth_required: Webex rejected Mercury stream; run webex-bridge login");
                            }
                            Err(_) => break,
                        }
                    }
                }
                // Rebuild the immutable token-bearing Webex client and stream.
                if now()? >= tokens.refresh_at() {
                    continue;
                }
            }
            Ok(Err(error)) if authentication_error(&error) => {
                bail!("auth_required: Webex rejected Mercury connection; run webex-bridge login");
            }
            Ok(Err(_)) | Err(_) => {}
        }
        eprintln!("Webex bridge: disconnected; retrying after backoff");
        tokio::select! {
            _ = term.recv() => return Ok(()),
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = sleep(jitter(backoff)) => {}
        }
        backoff = next_backoff(backoff);
    }
}

fn now() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_is_bounded() {
        let mut duration = Duration::from_secs(1);
        for _ in 0..20 {
            duration = next_backoff(duration);
        }
        assert_eq!(duration, Duration::from_secs(300));
        assert!(device_name().ends_with("-webex-bridge"));
    }
    #[test]
    fn rejects_auth_http_codes() {
        assert!(authentication_error(&WebexError::Status(
            reqwest::StatusCode::UNAUTHORIZED
        )));
        assert!(authentication_error(&WebexError::Status(
            reqwest::StatusCode::FORBIDDEN
        )));
        assert!(!authentication_error(&WebexError::Status(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        )));
    }
}
