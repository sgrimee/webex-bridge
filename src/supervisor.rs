//! Mercury connection owner. Refresh rebuilds client and stream; failures back off.

use crate::{auth, config::Config, paths::Paths};
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

fn authentication_status(error: &WebexError) -> Option<u16> {
    let code = match error {
        WebexError::Status(code) | WebexError::StatusText(code, _) => Some(code.as_u16()),
        WebexError::Reqwest(error) => error.status().map(|code| code.as_u16()),
        WebexError::Tungstenite(error, _) => match error.as_ref() {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                Some(response.status().as_u16())
            }
            _ => None,
        },
        _ => None,
    };
    code.filter(|code| matches!(code, 401 | 403))
}

/// Read-only WDM device-list status check, without printing response content or token.
/// This isolates device-scope failures from WebSocket authentication failures.
pub async fn device_list_status(paths: &Paths) -> Result<u16> {
    let tokens = auth::fresh_token(paths).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client
        .get("https://wdm-a.wbx2.com/wdm/api/v1/devices")
        .bearer_auth(tokens.access_token)
        .send()
        .await?;
    Ok(response.status().as_u16())
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
pub async fn run<H, F>(paths: &Paths, on_event: H) -> Result<()>
where
    H: FnMut(Event, Webex) -> F,
    F: Future<Output = Result<(), WebexError>>,
{
    run_with_refresh_after(paths, None, on_event).await
}

/// Same supervisor with a one-time forced refresh, only for the configured dev room.
/// Never expose this override from an agent API or the production daemon.
pub async fn run_with_refresh_after<H, F>(
    paths: &Paths,
    forced_refresh_after: Option<Duration>,
    mut on_event: H,
) -> Result<()>
where
    H: FnMut(Event, Webex) -> F,
    F: Future<Output = Result<(), WebexError>>,
{
    if forced_refresh_after.is_some() && Config::load(paths)?.dev.is_none() {
        bail!("Forced refresh is allowed only with the development write allowlist");
    }
    let mut force_once = forced_refresh_after;
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
                let mut forced = false;
                let force_deadline = force_once.map(|delay| tokio::time::Instant::now() + delay);
                loop {
                    let wait_for_refresh =
                        Duration::from_secs(tokens.refresh_at().saturating_sub(now()?));
                    tokio::select! {
                        _ = async {
                            if let Some(deadline) = force_deadline {
                                tokio::time::sleep_until(deadline).await;
                            } else {
                                std::future::pending::<()>().await;
                            }
                        } => {
                            force_once = None;
                            forced = true;
                            break;
                        },
                        _ = term.recv() => return Ok(()),
                        _ = tokio::signal::ctrl_c() => return Ok(()),
                        _ = sleep(wait_for_refresh) => break,
                        event = stream.next() => match event {
                            Ok(event) => {
                                if let Err(error) = on_event(event, client.clone()).await {
                                    if let Some(status) = authentication_status(&error) {
                                        bail!("auth_required: event hydration returned HTTP {status}; no scope change made");
                                    }
                                    // Never log a response body or event data via a Display impl.
                                    eprintln!("Webex event hydration failed; catch-up is required");
                                }
                            }
                            Err(error) if authentication_status(&error).is_some() => {
                                let status = authentication_status(&error).unwrap_or_default();
                                bail!("auth_required: Mercury stream returned HTTP {status}; no scope change made");
                            }
                            Err(_) => break,
                        }
                    }
                }
                // Rebuild the immutable token-bearing Webex client and stream.
                if forced {
                    println!("Webex bridge: token refresh starting");
                    auth::refresh_now(paths).await?;
                    println!("Webex bridge: token refreshed; rebuilding stream");
                    continue;
                }
                if now()? >= tokens.refresh_at() {
                    continue;
                }
            }
            Ok(Err(error)) if authentication_status(&error).is_some() => {
                let status = authentication_status(&error).unwrap_or_default();
                bail!("auth_required: Mercury connection returned HTTP {status}; no scope change made");
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
        assert_eq!(
            authentication_status(&WebexError::Status(reqwest::StatusCode::UNAUTHORIZED)),
            Some(401)
        );
        assert_eq!(
            authentication_status(&WebexError::Status(reqwest::StatusCode::FORBIDDEN)),
            Some(403)
        );
        assert_eq!(
            authentication_status(&WebexError::Status(reqwest::StatusCode::TOO_MANY_REQUESTS)),
            None
        );
    }
}
