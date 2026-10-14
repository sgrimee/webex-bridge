//! Mercury connection owner. Refresh rebuilds client and stream; failures back off.

use crate::{
    auth, config::Config, diagnostics, mirror::SharedMirror, paths::Paths, sync::history::WebexRest,
};
use anyhow::{bail, Context, Result};
use rand::Rng;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::watch,
};
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
        WebexError::Authentication => Some(401),
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

fn stream_error_kind(error: &WebexError) -> &'static str {
    match error {
        WebexError::Closed(_) => "closed",
        WebexError::Tungstenite(_, _) => "websocket_transport",
        WebexError::Io(_) => "io",
        WebexError::Json(_) => "event_json",
        WebexError::UTF8(_) => "event_utf8",
        WebexError::Other(_) => "other",
        _ => "api",
    }
}

/// Time allowed for one Mercury event-stream setup (device listing, connect
/// and authorization). Listing the account's WDM devices has been seen to take
/// longer than 30 s, so a fixed budget failed the same way forever; each
/// consecutive setup timeout widens the next budget, up to the last step, and
/// a successful connection resets it.
const STREAM_SETUP_BUDGETS: [Duration; 4] = [
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(240),
];

#[derive(Debug, Default)]
struct StreamSetupBudget {
    consecutive_timeouts: usize,
}

impl StreamSetupBudget {
    fn current(&self) -> Duration {
        STREAM_SETUP_BUDGETS[self
            .consecutive_timeouts
            .min(STREAM_SETUP_BUDGETS.len() - 1)]
    }

    /// Record a setup timeout; returns the budget for the next attempt.
    fn timed_out(&mut self) -> Duration {
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
        self.current()
    }

    fn connected(&mut self) {
        self.consecutive_timeouts = 0;
    }
}

/// Keep the device a successful connect used; persist it only when it
/// changed. A persistence failure is metadata-logged and otherwise ignored:
/// the next start just lists devices again.
async fn remember_device(
    memory: Option<&SharedMirror>,
    known: &mut Option<webex::DeviceData>,
    device: webex::DeviceData,
) {
    if known.as_ref() == Some(&device) {
        return;
    }
    if let Some(mirror) = memory {
        let remembered = device.clone();
        if mirror
            .with(move |db| db.remember_mercury_device(&remembered))
            .await
            .is_err()
        {
            diagnostics::warn("supervisor.device_memory_unavailable");
        }
    }
    *known = Some(device);
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
    on_event: H,
) -> Result<()>
where
    H: FnMut(Event, Webex) -> F,
    F: Future<Output = Result<(), WebexError>>,
{
    run_with_refresh_after_and_gap(paths, forced_refresh_after, None, on_event).await
}

/// Development-only refresh/rebuild with an intentional listener gap.
///
/// The gap lets a human post during a known outage so catch-up continuity can
/// be verified. Both controls remain unavailable outside a configured dev room.
pub async fn run_with_refresh_after_and_gap<H, F>(
    paths: &Paths,
    forced_refresh_after: Option<Duration>,
    forced_refresh_gap: Option<Duration>,
    mut on_event: H,
) -> Result<()>
where
    H: FnMut(Event, Webex) -> F,
    F: Future<Output = Result<(), WebexError>>,
{
    run_inner(
        paths,
        forced_refresh_after,
        forced_refresh_gap,
        move |event, client, _rest| on_event(event, client),
        None,
        None,
    )
    .await
}

/// Daemon-only supervisor: latest connected REST client is published after
/// Mercury is listening, allowing catch-up to run concurrently with live events.
pub async fn run_daemon<H, F>(
    paths: &Paths,
    on_event: H,
    connected: watch::Sender<Option<Arc<WebexRest>>>,
) -> Result<()>
where
    H: FnMut(Event, Webex, Arc<WebexRest>) -> F,
    F: Future<Output = Result<(), WebexError>>,
{
    run_daemon_with_refresh_after_and_gap(paths, None, None, on_event, connected, None).await
}

/// Daemon variant used only by explicit development continuity validation.
/// The caller must restrict synchronization to an allowlisted dev room.
pub async fn run_daemon_with_refresh_after_and_gap<H, F>(
    paths: &Paths,
    forced_refresh_after: Option<Duration>,
    forced_refresh_gap: Option<Duration>,
    on_event: H,
    connected: watch::Sender<Option<Arc<WebexRest>>>,
    device_memory: Option<SharedMirror>,
) -> Result<()>
where
    H: FnMut(Event, Webex, Arc<WebexRest>) -> F,
    F: Future<Output = Result<(), WebexError>>,
{
    run_inner(
        paths,
        forced_refresh_after,
        forced_refresh_gap,
        on_event,
        Some(connected),
        device_memory,
    )
    .await
}

async fn run_inner<H, F>(
    paths: &Paths,
    forced_refresh_after: Option<Duration>,
    forced_refresh_gap: Option<Duration>,
    mut on_event: H,
    connected: Option<watch::Sender<Option<Arc<WebexRest>>>>,
    device_memory: Option<SharedMirror>,
) -> Result<()>
where
    H: FnMut(Event, Webex, Arc<WebexRest>) -> F,
    F: Future<Output = Result<(), WebexError>>,
{
    if (forced_refresh_after.is_some() || forced_refresh_gap.is_some())
        && Config::load(paths)?.dev.is_none()
    {
        bail!("Forced refresh is allowed only with the development write allowlist");
    }
    if forced_refresh_gap.is_some() && forced_refresh_after.is_none() {
        bail!("A forced refresh gap requires a forced refresh delay");
    }
    let mut force_once = forced_refresh_after;
    let mut term = signal(SignalKind::terminate())?;
    let mut backoff = Duration::from_secs(1);
    let mut setup_budget = StreamSetupBudget::default();
    // The device the last successful connect used: reconnecting to it skips
    // the multi-megabyte device list. Persisted (encrypted) by the daemon.
    let mut known_device = match &device_memory {
        Some(mirror) => mirror.with(|db| db.mercury_device()).await.ok().flatten(),
        None => None,
    };
    loop {
        diagnostics::debug(format!(
            "supervisor.connecting retry_backoff_secs={}",
            backoff.as_secs()
        ));
        let tokens = match auth::fresh_token(paths).await {
            Ok(tokens) => tokens,
            Err(error) if error.is::<reqwest::Error>() => {
                diagnostics::warn("supervisor.token_refresh_unavailable; retrying_after_backoff");
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
        diagnostics::debug(format!(
            "supervisor.token_ready refresh_in_secs={}",
            tokens.refresh_at().saturating_sub(now()?)
        ));
        let name = device_name();
        let initialized = tokio::select! {
            _ = term.recv() => return Ok(()),
            _ = tokio::signal::ctrl_c() => return Ok(()),
            result = timeout(Duration::from_secs(30), Webex::new_with_device_name(&name, &tokens.access_token)) => result,
        };
        let Ok(client) = initialized else {
            diagnostics::warn("supervisor.initialization_timed_out; retrying_after_backoff");
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
            result = timeout(
                setup_budget.current(),
                client.event_stream_preferring(known_device.as_ref()),
            ) => result,
        };
        match stream {
            Ok(Ok((mut stream, device))) => {
                backoff = Duration::from_secs(1);
                setup_budget.connected();
                remember_device(device_memory.as_ref(), &mut known_device, device).await;
                let rest = Arc::new(WebexRest::new(tokens.access_token.clone())?);
                if let Some(sender) = &connected {
                    sender
                        .send(Some(Arc::clone(&rest)))
                        .map_err(|_| anyhow::anyhow!("Daemon sync receiver closed"))?;
                }
                diagnostics::info("supervisor.connected");
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
                                if let Err(error) = on_event(event, client.clone(), Arc::clone(&rest)).await {
                                    if let Some(status) = authentication_status(&error) {
                                        bail!("auth_required: event hydration returned HTTP {status}; no scope change made");
                                    }
                                    // Never log a response body or event data via a Display impl.
                                    // One malformed or concurrently deleted event must not drop
                                    // the healthy Mercury stream; catch-up heals its state.
                                    diagnostics::warn("supervisor.event_hydration_failed; catchup_required");
                                }
                            }
                            Err(error) if authentication_status(&error).is_some() => {
                                let status = authentication_status(&error).unwrap_or_default();
                                bail!("auth_required: Mercury stream returned HTTP {status}; no scope change made");
                            }
                            Err(error) => {
                                diagnostics::warn(format!(
                                    "supervisor.stream_ended category={}",
                                    stream_error_kind(&error)
                                ));
                                break;
                            }
                        }
                    }
                }
                // Rebuild the immutable token-bearing Webex client and stream.
                if forced {
                    diagnostics::info("supervisor.token_refresh_starting");
                    // Publish the disconnect before dropping the listener. The
                    // daemon's sync task uses this transition to cancel any old
                    // pass and runs catch-up with the newly authenticated REST
                    // client after reconnect.
                    if let Some(sender) = &connected {
                        let _ = sender.send(None);
                    }
                    // The intentional development-only gap begins only after the
                    // Mercury listener is dropped, so a message sent now must be
                    // recovered by the rebuilt stream/catch-up path.
                    drop(stream);
                    drop(client);
                    drop(rest);
                    if let Some(gap) = forced_refresh_gap {
                        diagnostics::info(format!(
                            "supervisor.refresh_gap_started duration_secs={}",
                            gap.as_secs()
                        ));
                        tokio::select! {
                            _ = term.recv() => return Ok(()),
                            _ = tokio::signal::ctrl_c() => return Ok(()),
                            _ = sleep(gap) => {}
                        }
                    }
                    auth::refresh_now(paths).await?;
                    diagnostics::info("supervisor.token_refreshed; rebuilding_stream");
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
            Ok(Err(_)) => {}
            Err(_) => {
                let elapsed = setup_budget.current().as_secs();
                let next = setup_budget.timed_out().as_secs();
                diagnostics::warn(format!(
                    "supervisor.stream_setup_timed_out budget_secs={elapsed} next_budget_secs={next}"
                ));
            }
        }
        if let Some(sender) = &connected {
            let _ = sender.send(None);
        }
        diagnostics::warn(format!(
            "supervisor.disconnected; retrying_after_backoff_secs={}",
            backoff.as_secs()
        ));
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
    #[tokio::test]
    async fn the_connected_device_is_remembered_only_when_it_changes() {
        use crate::mirror::{Mirror, SharedMirror};
        let mirror = SharedMirror::new(Mirror::in_memory([43_u8; 32]).unwrap());
        let device = |ws: &str| webex::DeviceData {
            name: Some("host-webex-bridge".into()),
            ws_url: Some(ws.into()),
            ..webex::DeviceData::default()
        };
        let mut known = None;
        super::remember_device(Some(&mirror), &mut known, device("wss://a")).await;
        assert_eq!(known, Some(device("wss://a")));
        assert_eq!(
            mirror.with(|db| db.mercury_device()).await.unwrap(),
            Some(device("wss://a"))
        );
        super::remember_device(Some(&mirror), &mut known, device("wss://b")).await;
        assert_eq!(
            mirror.with(|db| db.mercury_device()).await.unwrap(),
            Some(device("wss://b"))
        );
        // Without a store (CLI runs) it is kept in memory only.
        let mut transient = None;
        super::remember_device(None, &mut transient, device("wss://c")).await;
        assert_eq!(transient, Some(device("wss://c")));
    }

    #[test]
    fn repeated_stream_setup_timeouts_widen_the_budget_until_a_connection() {
        use super::{StreamSetupBudget, STREAM_SETUP_BUDGETS};
        use std::time::Duration;
        let mut budget = StreamSetupBudget::default();
        assert_eq!(budget.current(), Duration::from_secs(30));
        assert_eq!(budget.timed_out(), Duration::from_secs(60));
        assert_eq!(budget.timed_out(), Duration::from_secs(120));
        assert_eq!(budget.timed_out(), Duration::from_secs(240));
        // Capped at the last step.
        for _ in 0..10 {
            assert_eq!(budget.timed_out(), *STREAM_SETUP_BUDGETS.last().unwrap());
        }
        budget.connected();
        assert_eq!(budget.current(), Duration::from_secs(30));
    }

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
