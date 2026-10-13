//! Read-only transport probe and safe, explicit integration authentication.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use webex_bridge::{
    auth,
    config::Config,
    hydrate,
    mirror::{Mirror, SharedMirror},
    paths::Paths,
    rooms, service, supervisor,
    sync::{history::WebexRest, recovery},
};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = Paths::discover()?;
    match args.as_slice() {
        [command] if command == "login" => {
            auth::login(&paths).await?;
            println!("Webex bridge authentication complete; tokens are in Keychain.");
        }
        [command, action, flag, id]
            if command == "messages" && action == "inspect" && flag == "--id" =>
        {
            let tokens = auth::fresh_token(&paths).await?;
            hydrate::inspect_message(&tokens.access_token, id).await?;
        }
        [command, action] if command == "devices" && action == "status" => {
            println!("WDM device-list HTTP {}", supervisor::device_list_status(&paths).await?);
        }
        [command] if command == "me" => {
            let tokens = auth::fresh_token(&paths).await?;
            println!("{}", rooms::own_person_id(&tokens.access_token).await?);
        }
        [command] if command == "install-service" => {
            service::install(&build_dir()?, &paths)?;
            println!("webex-bridged service installed and started");
        }
        [command] if command == "uninstall-service" => {
            service::uninstall(&paths)?;
            println!("webex-bridged service removed");
        }
        [command] if command == "status" => {
            let state = match auth::load()? {
                Some(tokens) if tokens.expires_at > now()? => match (tokens.scope_mode, tokens.scopes_verified) {
                    (webex_bridge::config::OAuthScope::Granular, true) => "authenticated; ten granular scopes confirmed by token response",
                    (webex_bridge::config::OAuthScope::SparkAll, true) => "authenticated; spark:all confirmed by token response",
                    (_, false) => "authenticated; granted scopes not reported by token response",
                },
                Some(_) => "access token expired",
                None => "login required",
            };
            println!("Webex bridge: {state}");
            if paths.mirror.exists() {
                match Mirror::open(&paths).and_then(|mirror| mirror.stats()) {
                    Ok(stats) => println!(
                        "Mirror: rooms={} revisions={} initialDone={} initialPending={} gaps={} retryableFailures={}",
                        stats.rooms, stats.revisions, stats.initial_done, stats.initial_pending, stats.gaps, stats.failures
                    ),
                    // A locked Keychain means encrypted content remains unavailable;
                    // report health without creating a plaintext fallback.
                    Err(_) => println!("Mirror: unavailable (Keychain locked or unavailable)"),
                }
            } else {
                println!("Mirror: not initialized");
            }
        }
        [command, action, room_flag, room_id, email_flag, email]
            if command == "membership"
                && action == "invite"
                && room_flag == "--room"
                && email_flag == "--email" =>
        {
            invite_member(&paths, room_id, email).await?;
        }
        [command, action, room_flag, room_id, email_flag, email]
            if command == "membership"
                && action == "cycle"
                && room_flag == "--room"
                && email_flag == "--email" =>
        {
            cycle_member(&paths, room_id, email).await?;
        }
        [command, action, flag, room_id]
            if command == "sync" && action == "recover-gap" && flag == "--room" =>
        {
            if paths.socket.exists() {
                bail!("Stop webex-bridged before read-only gap recovery; the mirror has one writer");
            }
            let config = Config::load(&paths)?;
            let token = auth::fresh_token(&paths).await?;
            let mirror = SharedMirror::new(Mirror::open(&paths)?);
            let rest = WebexRest::new(token.access_token)?;
            let result = recovery::recover_gap(
                &mirror,
                &rest,
                room_id,
                config.webex.initial_page_size,
            )
            .await?;
            println!(
                "{}",
                serde_json::json!({
                    "roomId": result.room_id,
                    "from": result.from,
                    "to": result.to,
                    "visited": result.visited,
                    "created": result.created,
                    "edited": result.edited,
                    "boundaryReached": result.boundary_reached,
                })
            );
        }
        [command, action] if command == "sync" && action == "failures" => {
            let mirror = Mirror::open(&paths)?;
            for failure in mirror.sync_failures()? {
                // JSON encoding escapes terminal-control characters in a user-supplied
                // title. This explicit CLI request is the only diagnostic path that
                // decrypts a room title; daemon logs remain metadata-only.
                println!(
                    "{}",
                    serde_json::json!({
                        "roomId": failure.room_id,
                        "title": failure.title,
                        "isMember": failure.is_member,
                        "result": failure.result,
                    })
                );
            }
        }
        [command, action, url_flag, link, title_flag, title, agent_flag, agent, workspace_flag, workspace]
            if command == "routes"
                && action == "init"
                && url_flag == "--url"
                && title_flag == "--title"
                && agent_flag == "--agent"
                && workspace_flag == "--workspace" =>
        {
            let tokens = auth::fresh_token(&paths).await?;
            let room = rooms::verify_space(&tokens.access_token, link, title).await?;
            let sender = rooms::own_person_id(&tokens.access_token).await?;
            Config::write_initial(&paths, &room.id, &sender, agent, workspace.as_ref())?;
            println!("Created restricted config at {}", paths.config.display());
        }
        [command, action, flag, link, title_flag, title]
            if command == "rooms"
                && action == "verify"
                && flag == "--url"
                && title_flag == "--title" =>
        {
            let tokens = auth::fresh_token(&paths).await?;
            let room = rooms::verify_space(&tokens.access_token, link, title).await?;
            println!("{}", room.id);
        }
        [command, action, flag, title]
            if command == "rooms" && action == "find" && flag == "--title" =>
        {
            let tokens = auth::fresh_token(&paths).await?;
            let matches = rooms::find_by_title(&tokens.access_token, title).await?;
            if matches.len() == 1 {
                println!("{}", matches[0].id);
            } else {
                eprintln!("Expected exactly one matching room; found {}", matches.len());
                for room in matches {
                    eprintln!(
                        "id={} type={} lastActivity={}",
                        room.id,
                        room.room_type.as_deref().unwrap_or("unknown"),
                        room.last_activity.as_deref().unwrap_or("unknown")
                    );
                }
                bail!("Choose the intended test-space room ID before updating config.toml");
            }
        }
        [command] if command == "probe" => {
            supervisor::run(&paths, |event, client| async move {
                hydrate::probe_event(event, client, None).await
            })
            .await?;
        }
        [command, room_flag, room_id, refresh_flag, seconds, gap_flag, gap_seconds]
            if command == "probe"
                && room_flag == "--room"
                && refresh_flag == "--refresh-after-secs"
                && gap_flag == "--refresh-gap-secs" =>
        {
            Config::load(&paths)?.check_write_room(room_id)?;
            let seconds = parse_probe_seconds(seconds, "refresh delay")?;
            let gap_seconds = parse_probe_seconds(gap_seconds, "refresh gap")?;
            let room_id = room_id.clone();
            supervisor::run_with_refresh_after_and_gap(
                &paths,
                Some(Duration::from_secs(seconds)),
                Some(Duration::from_secs(gap_seconds)),
                move |event, client| {
                    let filter = room_id.clone();
                    async move { hydrate::probe_event(event, client, Some(&filter)).await }
                },
            )
            .await?;
        }
        [command, room_flag, room_id, refresh_flag, seconds]
            if command == "probe"
                && room_flag == "--room"
                && refresh_flag == "--refresh-after-secs" =>
        {
            Config::load(&paths)?.check_write_room(room_id)?;
            let seconds = parse_probe_seconds(seconds, "refresh delay")?;
            let room_id = room_id.clone();
            supervisor::run_with_refresh_after(&paths, Some(Duration::from_secs(seconds)), move |event, client| {
                let filter = room_id.clone();
                async move { hydrate::probe_event(event, client, Some(&filter)).await }
            }).await?;
        }
        [command, flag, room_id] if command == "probe" && flag == "--room" => {
            let room_id = room_id.clone();
            supervisor::run(&paths, move |event, client| {
                let filter = room_id.clone();
                async move { hydrate::probe_event(event, client, Some(&filter)).await }
            })
            .await?;
        }
        _ => bail!("Usage: webex-bridge login | me | status | install-service | uninstall-service | sync failures | sync recover-gap --room ROOM_ID | devices status | messages inspect --id ID | rooms find --title TITLE | rooms verify --url SPACE_URL --title TITLE | routes init --url SPACE_URL --title TITLE --agent NAME --workspace PATH | membership (invite|cycle) --room ROOM_ID --email PERSON_EMAIL | probe [--room ROOM_ID [--refresh-after-secs 1..120 [--refresh-gap-secs 1..120]]]"),
    }
    Ok(())
}

/// Minimal metadata returned by Webex after a membership is created or found.
/// It deliberately omits display name and email from diagnostic output.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipResult {
    id: String,
    room_id: String,
    person_id: String,
}

#[derive(Deserialize)]
struct MembershipList {
    #[serde(default)]
    items: Vec<MembershipResult>,
}

fn validate_member_test(
    paths: &webex_bridge::paths::Paths,
    room_id: &str,
    email: &str,
) -> Result<()> {
    webex_bridge::config::Config::load(paths)?.check_write_room(room_id)?;
    if !email.contains('@') || email.chars().any(char::is_whitespace) {
        bail!("Expected one non-whitespace participant email address");
    }
    Ok(())
}

fn membership_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Cannot create Webex membership diagnostic client")
}

async fn create_membership(
    client: &reqwest::Client,
    token: &str,
    room_id: &str,
    email: &str,
) -> Result<MembershipResult> {
    let response = client
        .post("https://webexapis.com/v1/memberships")
        .bearer_auth(token)
        .json(&serde_json::json!({ "roomId": room_id, "personEmail": email }))
        .send()
        .await?;
    if !response.status().is_success() {
        bail!(
            "Webex membership invite failed (HTTP {})",
            response.status()
        );
    }
    let membership: MembershipResult = response
        .json()
        .await
        .context("Webex returned an invalid membership response")?;
    if membership.room_id != room_id || membership.id.is_empty() || membership.person_id.is_empty()
    {
        bail!("Webex returned a membership outside the requested test room");
    }
    Ok(membership)
}

/// Invite an explicitly selected test participant to the configured development room.
/// This is a narrowly scoped Step 1 diagnostic, not an agent/UI API write path.
async fn invite_member(
    paths: &webex_bridge::paths::Paths,
    room_id: &str,
    email: &str,
) -> Result<()> {
    validate_member_test(paths, room_id, email)?;
    let token = auth::fresh_token(paths).await?;
    let membership =
        create_membership(&membership_client()?, &token.access_token, room_id, email).await?;
    println!(
        "{}",
        serde_json::json!({
            "action": "membership_invited",
            "roomId": membership.room_id,
            "personId": membership.person_id,
        })
    );
    Ok(())
}

/// Temporarily remove and immediately restore the explicitly selected participant.
/// The final state remains membership in the allowlisted development room.
async fn cycle_member(
    paths: &webex_bridge::paths::Paths,
    room_id: &str,
    email: &str,
) -> Result<()> {
    validate_member_test(paths, room_id, email)?;
    let token = auth::fresh_token(paths).await?;
    let client = membership_client()?;
    let mut url = reqwest::Url::parse("https://webexapis.com/v1/memberships")?;
    url.query_pairs_mut()
        .append_pair("roomId", room_id)
        .append_pair("personEmail", email);
    let response = client
        .get(url)
        .bearer_auth(&token.access_token)
        .send()
        .await?;
    if !response.status().is_success() {
        bail!(
            "Webex membership lookup failed (HTTP {})",
            response.status()
        );
    }
    let mut memberships: Vec<_> = response
        .json::<MembershipList>()
        .await
        .context("Webex returned an invalid membership list")?
        .items
        .into_iter()
        .filter(|membership| membership.room_id == room_id)
        .collect();
    if memberships.len() != 1 {
        bail!("Expected exactly one existing membership in the configured test room");
    }
    let prior = memberships.pop().expect("verified exactly one membership");
    let mut delete_url = reqwest::Url::parse("https://webexapis.com/v1/memberships/")?;
    delete_url
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("Invalid Webex membership URL"))?
        .push(&prior.id);
    let response = client
        .delete(delete_url)
        .bearer_auth(&token.access_token)
        .send()
        .await?;
    if !response.status().is_success() {
        bail!(
            "Webex membership removal failed (HTTP {})",
            response.status()
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let restored = create_membership(&client, &token.access_token, room_id, email).await?;
    println!(
        "{}",
        serde_json::json!({
            "action": "membership_cycled",
            "roomId": restored.room_id,
            "personId": restored.person_id,
        })
    );
    Ok(())
}

/// Directory holding the signed `webex-bridge`/`webex-bridged` pair to
/// install: the directory of this CLI executable.
fn build_dir() -> Result<PathBuf> {
    let cli = std::env::current_exe().context("Cannot locate webex-bridge executable")?;
    cli.canonicalize()
        .context("Cannot canonicalize webex-bridge path")?
        .parent()
        .map(Path::to_path_buf)
        .context("webex-bridge executable has no parent directory")
}

fn parse_probe_seconds(value: &str, label: &str) -> Result<u64> {
    let seconds = value
        .parse::<u64>()
        .with_context(|| format!("Expected {label} in seconds"))?;
    if !(1..=120).contains(&seconds) {
        bail!("Forced {label} must be between 1 and 120 seconds");
    }
    Ok(seconds)
}

fn now() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
