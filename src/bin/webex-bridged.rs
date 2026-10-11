//! Per-user bridge daemon: Mercury live sync, encrypted local mirror and scoped local API.

use anyhow::{bail, Context, Result};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;
use webex_bridge::{
    api::{self, events::EventBus, ApiState, ConnectionStatus},
    config::{Config, DevSecretSource},
    diagnostics,
    mirror::{Mirror, SharedMirror},
    paths::Paths,
    routing::Delivery,
    supervisor,
    sync::{self, history::WebexRest, live},
};

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = parse_args()?;
    // Loading an existing config is the sole production-path operation before
    // this gate. It creates no directory and never opens Keychain, the mirror,
    // socket, or a network connection.
    let paths = Paths::discover()?;
    let config = Config::load_existing(&paths)?;
    preflight_environment_secret_source(
        &config,
        &arguments,
        &paths.data,
        BootstrapFacts::current(),
    )?;
    let DevArgs {
        dev_room,
        debug,
        refresh_after,
        refresh_gap,
        ..
    } = arguments;
    if debug {
        diagnostics::enable_debug();
    }
    diagnostics::info("daemon.starting");
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
    let api_state = ApiState::with_config_and_rest(
        mirror.clone(),
        api_connection_rx,
        Arc::clone(&background_config),
        connected_rx.clone(),
    );
    let events = api_state.events();
    let api_server = api::start(&paths, api_state).await?;
    diagnostics::info("daemon.api_listening");
    let connection_task = tokio::spawn(watch_connection(
        connected_rx.clone(),
        api_connection_tx,
        events.clone(),
    ));
    let background_mirror = mirror.clone();
    let live_dev_room = dev_room.clone();
    let sync_task = tokio::spawn(run_sync(
        connected_rx,
        background_mirror,
        Arc::clone(&background_config),
        dev_room,
        events.clone(),
    ));
    diagnostics::debug("daemon.sync_task_started");
    let live_mirror = mirror.clone();
    let live_config = Arc::clone(&background_config);
    let live_events = events.clone();
    let result = supervisor::run_daemon_with_refresh_after_and_gap(
        &paths,
        refresh_after,
        refresh_gap,
        move |event, _mercury, rest| {
            let mirror = live_mirror.clone();
            let dev_room = live_dev_room.clone();
            let config = Arc::clone(&live_config);
            let events = live_events.clone();
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
                        let queued = mirror
                            .with(|db| db.queue_new_deliveries(&config))
                            .await
                            .map_err(|_| {
                                webex::error::Error::Other("Agent routing failed".into())
                            })?;
                        publish_deliveries(&events, &queued);
                        for invalidation in live::ui_invalidations(&result) {
                            events.publish_ui(invalidation.name, invalidation.data);
                        }
                        let outcome = match &result {
                            live::LiveResult::Message(_) => "message",
                            live::LiveResult::Reconciled { .. } => "reconciled",
                            live::LiveResult::RoomUpdated { .. } => "room_updated",
                            live::LiveResult::RoomLeft { .. } => "room_left",
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
    dev_env_secrets: bool,
    dev_data_dir: Option<PathBuf>,
    debug: bool,
    refresh_after: Option<Duration>,
    refresh_gap: Option<Duration>,
}

#[derive(Clone, Copy)]
struct BootstrapFacts {
    foreground_tty: bool,
    service_invocation: bool,
    unprivileged_same_uid: bool,
    biometric_feature_enabled: bool,
}

impl BootstrapFacts {
    fn current() -> Self {
        // Environment-secret mode remains unavailable until every provider is
        // isolated, but collect only non-secret invocation facts so its guard
        // can never be bypassed if that mode is enabled later.
        Self {
            foreground_tty: std::io::IsTerminal::is_terminal(&std::io::stdin())
                && std::io::IsTerminal::is_terminal(&std::io::stdout()),
            // A non-interactive invocation is treated as service-managed. This
            // deliberately fails closed rather than trying to infer launchd.
            service_invocation: !(std::io::IsTerminal::is_terminal(&std::io::stdin())
                && std::io::IsTerminal::is_terminal(&std::io::stdout())),
            unprivileged_same_uid: unsafe {
                libc::getuid() == libc::geteuid() && libc::geteuid() != 0
            },
            biometric_feature_enabled: cfg!(feature = "biometric-keychain"),
        }
    }
}

/// Refuse the development backend until it has an isolated auth/token/mirror
/// implementation. This gate runs before production directories, Keychain,
/// mirror, service, socket, or network code. It intentionally never captures
/// environment values in an incomplete build.
fn preflight_environment_secret_source(
    config: &Config,
    arguments: &DevArgs,
    production_root: &std::path::Path,
    facts: BootstrapFacts,
) -> Result<()> {
    let secret_source = config
        .dev
        .as_ref()
        .map_or(DevSecretSource::Keychain, |dev| dev.secret_source);
    if secret_source != DevSecretSource::EnvironmentDev {
        if arguments.dev_env_secrets || arguments.dev_data_dir.is_some() {
            bail!("development environment bootstrap flags require [dev].secret_source = 'environment_dev'");
        }
        return Ok(());
    }

    #[cfg(feature = "dev-env-secrets")]
    {
        use webex_bridge::dev_env_secrets::{validate_configured_foreground, ForegroundOptions};

        let options = ForegroundOptions {
            enabled: arguments.dev_env_secrets,
            development_root: arguments.dev_data_dir.clone(),
            development_room: arguments.dev_room.clone(),
        };
        // Validate feature + config + CLI, foreground/service/UID, canonical
        // roots, and room/route isolation before considering any secret input.
        let _roots = validate_configured_foreground(
            config,
            &options,
            production_root,
            facts.foreground_tty,
            facts.service_invocation,
            facts.unprivileged_same_uid,
            facts.biometric_feature_enabled,
        )?;
        bail!("[dev].secret_source = 'environment_dev' is not available: refusing to fall back to production Keychain, mirror, or paths until isolated auth and mirror providers are installed");
    }

    #[cfg(not(feature = "dev-env-secrets"))]
    {
        let _ = (arguments, production_root, facts);
        bail!("[dev].secret_source = 'environment_dev' requires a dev-env-secrets build; refusing production fallback");
    }
}

fn parse_args() -> Result<DevArgs> {
    let mut dev_room = None;
    let mut dev_env_secrets = false;
    let mut dev_data_dir = None;
    let mut debug = false;
    let mut refresh_after = None;
    let mut refresh_gap = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--debug" => debug = true,
            "--dev-env-secrets" if !dev_env_secrets => dev_env_secrets = true,
            "--dev-data-dir" if dev_data_dir.is_none() => {
                let path = args
                    .next()
                    .context("--dev-data-dir requires an absolute directory")?;
                let path = PathBuf::from(path);
                if !path.is_absolute() {
                    bail!("--dev-data-dir requires an absolute directory");
                }
                dev_data_dir = Some(path);
            }
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
        dev_env_secrets,
        dev_data_dir,
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
    events: EventBus,
) {
    loop {
        let next = if connected.borrow().is_some() {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        };
        let _ = status.send(next);
        events.publish_both(
            "connection.status",
            serde_json::json!({ "connection": next.as_str() }),
        );
        if connected.changed().await.is_err() {
            return;
        }
    }
}

fn publish_deliveries(events: &EventBus, deliveries: &[Delivery]) {
    for delivery in deliveries {
        events.publish_agent_route(
            &delivery.route_id,
            "inbox.new",
            serde_json::json!({
                "deliveryId": delivery.id,
                "revision": delivery.revision,
            }),
        );
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod bootstrap_tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use webex_bridge::{
        config::{DevConfig, Route},
        paths::Paths,
    };

    fn environment_config() -> Config {
        Config {
            dev: Some(DevConfig {
                write_allowlist: vec!["test-room".into()],
                secret_source: DevSecretSource::EnvironmentDev,
            }),
            routes: vec![Route {
                id: "test-route".into(),
                room_id: "test-room".into(),
                agent_name: "test-agent".into(),
                allowed_senders: Vec::new(),
                receive: Default::default(),
                workspace: "/tmp".into(),
            }],
            ..Config::default()
        }
    }

    fn arguments(development_root: PathBuf) -> DevArgs {
        DevArgs {
            dev_room: Some("test-room".into()),
            dev_env_secrets: true,
            dev_data_dir: Some(development_root),
            debug: false,
            refresh_after: None,
            refresh_gap: None,
        }
    }

    fn guarded_facts() -> BootstrapFacts {
        BootstrapFacts {
            foreground_tty: true,
            service_invocation: false,
            unprivileged_same_uid: true,
            biometric_feature_enabled: false,
        }
    }

    #[test]
    fn environment_source_never_initializes_production_runtime_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let production = temporary.path().join("production");
        let development = temporary.path().join("development");
        fs::create_dir(&production).unwrap();
        fs::create_dir(&development).unwrap();
        let paths = Paths::under(production.clone());
        let serialized = toml::to_string_pretty(&environment_config()).unwrap();
        fs::write(&paths.config, serialized).unwrap();
        fs::set_permissions(&paths.config, fs::Permissions::from_mode(0o600)).unwrap();

        // `load_existing` is intentionally non-creating. This is the same
        // config read the daemon makes before it decides which backend applies.
        let loaded = Config::load_existing(&paths).unwrap();
        assert!(preflight_environment_secret_source(
            &loaded,
            &arguments(development),
            &production,
            guarded_facts(),
        )
        .is_err());
        assert!(!paths.run.exists());
        assert!(!paths.mirror.exists());
        assert!(!paths.socket.exists());
    }

    #[test]
    fn environment_source_requires_bootstrap_flags_before_any_fallback() {
        let temporary = tempfile::tempdir().unwrap();
        let production = temporary.path().join("production");
        fs::create_dir(&production).unwrap();
        let arguments = DevArgs {
            dev_room: None,
            dev_env_secrets: false,
            dev_data_dir: None,
            debug: false,
            refresh_after: None,
            refresh_gap: None,
        };
        assert!(preflight_environment_secret_source(
            &environment_config(),
            &arguments,
            &production,
            guarded_facts(),
        )
        .is_err());
    }

    #[test]
    fn production_source_refuses_development_bootstrap_flags() {
        let temporary = tempfile::tempdir().unwrap();
        let production = temporary.path().join("production");
        let development = temporary.path().join("development");
        fs::create_dir(&production).unwrap();
        fs::create_dir(&development).unwrap();
        let mut config = Config::default();
        config.dev.as_mut().unwrap().secret_source = DevSecretSource::Keychain;
        assert!(preflight_environment_secret_source(
            &config,
            &arguments(development),
            &production,
            guarded_facts(),
        )
        .is_err());
    }
}

async fn run_sync(
    mut connected: watch::Receiver<Option<Arc<WebexRest>>>,
    mirror: SharedMirror,
    config: Arc<Config>,
    dev_room: Option<String>,
    events: EventBus,
) -> Result<()> {
    // A failed REST sync must recover without waiting for an unrelated Mercury
    // reconnect. This is failure recovery, not steady-state polling: a clean
    // pass still waits only for a connection change before the next sync.
    let mut retry_backoff = Duration::from_secs(1);
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
                            .with(|db| db.queue_new_deliveries(&config))
                            .await
                            .context("Agent routing failed after synchronization")?;
                        publish_deliveries(&events, &queued);
                        for room_id in &summary.departed_rooms {
                            events.publish_ui(
                                "membership.changed",
                                serde_json::json!({ "roomId": room_id, "isMember": false }),
                            );
                        }
                        for room_id in &summary.changed_rooms {
                            events.publish_ui(
                                "room.resync",
                                serde_json::json!({ "roomId": room_id, "reason": "sync" }),
                            );
                        }
                        events.publish_ui(
                            "sync.progress",
                            serde_json::json!({
                                "rooms": summary.rooms,
                                "initial": summary.initial_rooms,
                                "gaps": summary.gaps,
                                "failed": summary.failed_rooms,
                            }),
                        );
                        diagnostics::info(format!(
                            "sync.completed elapsed_ms={} rooms={} initial={} created={} edited={} deleted={} gaps={} backfilled={} failed={} agent_deliveries={}",
                            started.elapsed().as_millis(), summary.rooms, summary.initial_rooms,
                            summary.created, summary.edited, summary.deleted, summary.gaps,
                            summary.backfilled_rooms, summary.failed_rooms, queued.len()
                        ));
                    },
                    // Never expose response bodies, tokens, room titles or message IDs in daemon logs.
                    Err(error) => {
                        diagnostics::warn(format!(
                            "sync.failed elapsed_ms={} category={} retry_after_secs={}",
                            started.elapsed().as_millis(),
                            sync_error_kind(&error),
                            retry_backoff.as_secs(),
                        ));
                        tokio::select! {
                            changed = connected.changed() => {
                                changed.context("Mercury supervisor stopped")?;
                            }
                            _ = tokio::time::sleep(retry_backoff) => {
                                retry_backoff = (retry_backoff * 2).min(Duration::from_secs(300));
                            }
                        }
                        continue;
                    }
                }
                retry_backoff = Duration::from_secs(1);
                // No steady-state polling. After a clean pass, wait until a
                // reconnect publishes a new REST client.
                connected.changed().await.context("Mercury supervisor stopped")?;
            }
        }
    }
}
