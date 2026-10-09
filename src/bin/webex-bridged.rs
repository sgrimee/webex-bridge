//! Per-user bridge daemon: Mercury live sync, encrypted local mirror and local status API.
//! Scoped UI/agent sessions and message sends remain disabled until later Step 3 work.

use anyhow::{Context, Result};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;
use webex_bridge::{
    api::{self, ApiState, ConnectionStatus},
    config::Config,
    diagnostics,
    mirror::{Mirror, SharedMirror},
    paths::Paths,
    supervisor,
    sync::{self, history::WebexRest, live},
};

#[tokio::main]
async fn main() -> Result<()> {
    let DevArgs {
        dev_room,
        debug,
        refresh_after,
        refresh_gap,
    } = parse_args()?;
    if debug {
        diagnostics::enable_debug();
    }
    diagnostics::info("daemon.starting");
    let paths = Paths::discover()?;
    let config = Config::load(&paths)?;
    diagnostics::debug(format!(
        "daemon.config_loaded routes={} dev_mode={} dev_room_requested={}",
        config.routes.len(),
        config.dev.is_some(),
        dev_room.is_some()
    ));
    if let Some(room) = dev_room.as_deref() {
        config.check_write_room(room)?;
    }
    if (refresh_after.is_some() || refresh_gap.is_some()) && dev_room.is_none() {
        anyhow::bail!("Forced refresh diagnostics require --dev-room ROOM_ID");
    }
    if refresh_gap.is_some() && refresh_after.is_none() {
        anyhow::bail!("--dev-refresh-gap-secs requires --dev-refresh-after-secs");
    }
    let background_config = Arc::new(config);
    let mirror = SharedMirror::new(Mirror::open(&paths)?);
    mirror
        .with(|db| db.sync_routes(&background_config.routes))
        .await?;
    diagnostics::info("daemon.mirror_opened");
    let (connected_tx, connected_rx) = watch::channel::<Option<Arc<WebexRest>>>(None);
    let (api_connection_tx, api_connection_rx) = watch::channel(ConnectionStatus::Disconnected);
    let api_server = api::start(
        &paths,
        ApiState::with_config_and_rest(
            mirror.clone(),
            api_connection_rx,
            Arc::clone(&background_config),
            connected_rx.clone(),
        ),
    )
    .await?;
    diagnostics::info("daemon.api_listening");
    let connection_task = tokio::spawn(watch_connection(connected_rx.clone(), api_connection_tx));
    let background_mirror = mirror.clone();
    let live_dev_room = dev_room.clone();
    let sync_task = tokio::spawn(run_sync(
        connected_rx,
        background_mirror,
        Arc::clone(&background_config),
        dev_room,
    ));
    diagnostics::debug("daemon.sync_task_started");
    let live_mirror = mirror.clone();
    let live_config = Arc::clone(&background_config);
    let result = supervisor::run_daemon_with_refresh_after_and_gap(
        &paths,
        refresh_after,
        refresh_gap,
        move |event, _mercury, rest| {
            let mirror = live_mirror.clone();
            let dev_room = live_dev_room.clone();
            let config = Arc::clone(&live_config);
            async move {
                let verb: String = event
                    .data
                    .activity
                    .as_ref()
                    .map(|activity| activity.verb.as_str())
                    .unwrap_or(event.data.event_type.as_str())
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .take(32)
                    .collect();
                match live::ingest_event(&mirror, &rest, &event, dev_room.as_deref()).await {
                    Ok(result) => {
                        // Queue from the encrypted mirror only after a
                        // successful hydration/upsert. Routing never reads a
                        // Mercury payload directly.
                        let _queued = mirror
                            .with(|db| db.queue_deliveries(&config))
                            .await
                            .map_err(|_| {
                                webex::error::Error::Other("Agent routing failed".into())
                            })?;
                        let outcome = match result {
                            live::LiveResult::Message(_) => "message",
                            live::LiveResult::Reconciled(_) => "reconciled",
                            live::LiveResult::RoomUpdated => "room_updated",
                            live::LiveResult::RoomLeft => "room_left",
                            live::LiveResult::Ignored => "ignored",
                        };
                        diagnostics::debug(format!(
                            "sync.live_event verb={verb} outcome={outcome}"
                        ));
                        Ok(())
                    }
                    // Preserve only the security category; keep raw event/REST
                    // response details out of stdout and logs.
                    Err(error) if error.to_string().contains("auth_required") => {
                        Err(webex::error::Error::Authentication)
                    }
                    Err(_) => Err(webex::error::Error::Other("Live mirror sync failed".into())),
                }
            }
        },
        connected_tx,
    )
    .await;
    sync_task.abort();
    let _ = sync_task.await;
    connection_task.abort();
    let _ = connection_task.await;
    api_server.shutdown().await?;
    if result.is_ok() {
        diagnostics::info("daemon.stopped");
    }
    result
}

struct DevArgs {
    dev_room: Option<String>,
    debug: bool,
    refresh_after: Option<Duration>,
    refresh_gap: Option<Duration>,
}

fn parse_args() -> Result<DevArgs> {
    let mut dev_room = None;
    let mut debug = false;
    let mut refresh_after = None;
    let mut refresh_gap = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--debug" => debug = true,
            "--dev-room" => {
                let room = args
                    .next()
                    .context("Usage: webex-bridged [--debug] [--dev-room ROOM_ID] [--dev-refresh-after-secs 1..120 [--dev-refresh-gap-secs 1..120]]")?;
                if dev_room.replace(room).is_some() {
                    anyhow::bail!("--dev-room may be specified only once");
                }
            }
            "--dev-refresh-after-secs" => {
                let seconds = args
                    .next()
                    .context("--dev-refresh-after-secs requires a duration")?
                    .parse::<u64>()
                    .context("--dev-refresh-after-secs must be an integer")?;
                if !(1..=120).contains(&seconds) || refresh_after.replace(Duration::from_secs(seconds)).is_some() {
                    anyhow::bail!("--dev-refresh-after-secs must be specified once with 1..120");
                }
            }
            "--dev-refresh-gap-secs" => {
                let seconds = args
                    .next()
                    .context("--dev-refresh-gap-secs requires a duration")?
                    .parse::<u64>()
                    .context("--dev-refresh-gap-secs must be an integer")?;
                if !(1..=120).contains(&seconds) || refresh_gap.replace(Duration::from_secs(seconds)).is_some() {
                    anyhow::bail!("--dev-refresh-gap-secs must be specified once with 1..120");
                }
            }
            _ => anyhow::bail!("Usage: webex-bridged [--debug] [--dev-room ROOM_ID] [--dev-refresh-after-secs 1..120 [--dev-refresh-gap-secs 1..120]]"),
        }
    }
    Ok(DevArgs {
        dev_room,
        debug,
        refresh_after,
        refresh_gap,
    })
}

fn sync_error_kind(error: &anyhow::Error) -> &'static str {
    let detail = error.to_string();
    if detail.contains("auth_required") {
        "auth"
    } else if detail.contains("HTTP 429") {
        "rate_limited"
    } else if detail.contains("HTTP 5") {
        "server"
    } else if detail.contains("pagination") {
        "pagination"
    } else if detail.contains("timestamp") {
        "timestamp"
    } else {
        "other"
    }
}

/// Convert the daemon's connection publication into safe API metadata. The
/// local HTTP server never receives a Webex client or token.
async fn watch_connection(
    mut connected: watch::Receiver<Option<Arc<WebexRest>>>,
    status: watch::Sender<ConnectionStatus>,
) {
    loop {
        let next = if connected.borrow().is_some() {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        };
        let _ = status.send(next);
        if connected.changed().await.is_err() {
            return;
        }
    }
}

async fn run_sync(
    mut connected: watch::Receiver<Option<Arc<WebexRest>>>,
    mirror: SharedMirror,
    config: Arc<Config>,
    dev_room: Option<String>,
) -> Result<()> {
    loop {
        diagnostics::debug("sync.waiting_for_connection");
        while connected.borrow().is_none() {
            connected
                .changed()
                .await
                .context("Mercury supervisor stopped")?;
        }
        let rest = connected
            .borrow_and_update()
            .clone()
            .context("Missing Webex REST client")?;
        let started = Instant::now();
        diagnostics::debug("sync.started");
        tokio::select! {
            changed = connected.changed() => {
                changed.context("Mercury supervisor stopped")?;
            }
            result = sync::synchronize_once(&mirror, &rest, &config, dev_room.as_deref()) => {
                match result {
                    Ok(summary) => {
                        let queued = mirror
                            .with(|db| db.queue_deliveries(&config))
                            .await
                            .context("Agent routing failed after synchronization")?;
                        diagnostics::info(format!(
                            "sync.completed elapsed_ms={} rooms={} initial={} created={} edited={} deleted={} gaps={} backfilled={} failed={} agent_deliveries={}",
                            started.elapsed().as_millis(), summary.rooms, summary.initial_rooms,
                            summary.created, summary.edited, summary.deleted, summary.gaps,
                            summary.backfilled_rooms, summary.failed_rooms, queued
                        ));
                    },
                    // Never expose response bodies, tokens, room titles or message IDs in daemon logs.
                    Err(error) => diagnostics::warn(format!(
                        "sync.failed elapsed_ms={} category={}; reconnect_or_catchup_will_retry",
                        started.elapsed().as_millis(), sync_error_kind(&error)
                    )),
                }
                // No steady-state polling. Wait until a reconnect publishes a new REST client.
                connected.changed().await.context("Mercury supervisor stopped")?;
            }
        }
    }
}
