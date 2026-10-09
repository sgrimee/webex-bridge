//! Per-user bridge daemon: Mercury live sync plus encrypted local mirror.
//! Local HTTP API and message sends are deliberately not enabled in Step 2.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::watch;
use webex_bridge::{
    config::Config,
    mirror::{Mirror, SharedMirror},
    paths::Paths,
    supervisor,
    sync::{self, history::WebexRest, live},
};

#[tokio::main]
async fn main() -> Result<()> {
    let dev_room = match std::env::args().collect::<Vec<_>>().as_slice() {
        [_] => None,
        [_, flag, room] if flag == "--dev-room" => Some(room.clone()),
        _ => anyhow::bail!("Usage: webex-bridged [--dev-room ROOM_ID]"),
    };
    let paths = Paths::discover()?;
    let config = Config::load(&paths)?;
    if let Some(room) = dev_room.as_deref() {
        config.check_write_room(room)?;
    }
    let mirror = SharedMirror::new(Mirror::open(&paths)?);
    let (connected_tx, connected_rx) = watch::channel::<Option<Arc<WebexRest>>>(None);
    let background_mirror = mirror.clone();
    let live_dev_room = dev_room.clone();
    let background_config = Arc::new(config);
    let sync_task = tokio::spawn(run_sync(
        connected_rx,
        background_mirror,
        Arc::clone(&background_config),
        dev_room,
    ));
    let live_mirror = mirror.clone();
    let result = supervisor::run_daemon(
        &paths,
        move |event, _mercury, rest| {
            let mirror = live_mirror.clone();
            let dev_room = live_dev_room.clone();
            async move {
                match live::ingest_event(&mirror, &rest, &event, dev_room.as_deref()).await {
                    Ok(_) => Ok(()),
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
    result
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

async fn run_sync(
    mut connected: watch::Receiver<Option<Arc<WebexRest>>>,
    mirror: SharedMirror,
    config: Arc<Config>,
    dev_room: Option<String>,
) -> Result<()> {
    loop {
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
        tokio::select! {
            changed = connected.changed() => {
                changed.context("Mercury supervisor stopped")?;
            }
            result = sync::synchronize_once(&mirror, &rest, &config, dev_room.as_deref()) => {
                match result {
                    Ok(summary) => eprintln!(
                        "Webex mirror sync: rooms={} initial={} created={} edited={} deleted={} gaps={} backfilled={} failed={}",
                        summary.rooms, summary.initial_rooms, summary.created, summary.edited,
                        summary.deleted, summary.gaps, summary.backfilled_rooms, summary.failed_rooms
                    ),
                    // Never expose response bodies, tokens, room titles or message IDs in daemon logs.
                    Err(error) => eprintln!(
                        "Webex mirror sync failed ({}); reconnect/catch-up will retry",
                        sync_error_kind(&error)
                    ),
                }
                // No steady-state polling. Wait until a reconnect publishes a new REST client.
                connected.changed().await.context("Mercury supervisor stopped")?;
            }
        }
    }
}
