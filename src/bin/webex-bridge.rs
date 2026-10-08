//! Read-only transport probe and safe, explicit integration authentication.

use anyhow::{bail, Result};
use webex_bridge::{auth, hydrate, paths::Paths, rooms, supervisor};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = Paths::discover()?;
    match args.as_slice() {
        [command] if command == "login" => {
            auth::login(&paths).await?;
            println!("Webex bridge authentication complete; tokens are in Keychain.");
        }
        [command] if command == "status" => {
            let state = match auth::load()? {
                Some(tokens) if tokens.expires_at > now()? => "authenticated",
                Some(_) => "access token expired",
                None => "login required",
            };
            println!("Webex bridge: {state} (daemon not implemented yet)");
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
        [command, flag, room_id] if command == "probe" && flag == "--room" => {
            let room_id = room_id.clone();
            supervisor::run(&paths, move |event, client| {
                let filter = room_id.clone();
                async move { hydrate::probe_event(event, client, Some(&filter)).await }
            })
            .await?;
        }
        _ => bail!("Usage: webex-bridge login | status | rooms find --title TITLE | probe [--room ROOM_ID]"),
    }
    Ok(())
}

fn now() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
