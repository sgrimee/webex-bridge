//! Read-only transport probe and safe, explicit integration authentication.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use webex_bridge::{auth, config::Config, hydrate, paths::Paths, rooms, supervisor};

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
            println!("Webex bridge: {state} (daemon not implemented yet)");
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
        [command, room_flag, room_id, refresh_flag, seconds]
            if command == "probe"
                && room_flag == "--room"
                && refresh_flag == "--refresh-after-secs" =>
        {
            Config::load(&paths)?.check_write_room(room_id)?;
            let seconds = seconds.parse::<u64>().context("Expected refresh delay in seconds")?;
            if !(1..=120).contains(&seconds) {
                bail!("Forced refresh delay must be between 1 and 120 seconds");
            }
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
        _ => bail!("Usage: webex-bridge login | me | status | devices status | messages inspect --id ID | rooms find --title TITLE | rooms verify --url SPACE_URL --title TITLE --agent NAME --workspace PATH | probe [--room ROOM_ID [--refresh-after-secs 1..120]]"),
    }
    Ok(())
}

fn now() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
