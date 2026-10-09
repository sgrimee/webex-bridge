//! Per-user service installation. macOS uses a private LaunchAgent; other
//! platforms deliberately fail closed until the planned systemd unit exists.

use anyhow::{bail, Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const LABEL: &str = "com.sgrimee.webex-bridged";

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn plist(daemon: &Path, log: &Path) -> Result<String> {
    let daemon = daemon.to_str().context("Daemon path is not valid UTF-8")?;
    let log = log.to_str().context("Log path is not valid UTF-8")?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>{}</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ProcessType</key><string>Background</string>
<key>StdOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#,
        xml_escape(daemon),
        xml_escape(log),
        xml_escape(log),
    ))
}

#[cfg(target_os = "macos")]
fn agent_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("No home directory available")?
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

#[cfg(target_os = "macos")]
fn log_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("No home directory available")?
        .join("Library/Logs/webex-bridge/bridged.log"))
}

#[cfg(target_os = "macos")]
fn launchctl(arguments: &[String]) -> Result<()> {
    let output = Command::new("/bin/launchctl")
        .args(arguments)
        .output()
        .context("Cannot invoke launchctl")?;
    if !output.status.success() {
        bail!(
            "launchctl {} failed",
            arguments.first().map_or("command", String::as_str)
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn gui_domain() -> String {
    // The per-user daemon is never installed into a system domain.
    format!("gui/{}", unsafe { libc::geteuid() })
}

#[cfg(target_os = "macos")]
fn verify_signed_daemon(daemon: &Path) -> Result<()> {
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=2"])
        .arg(daemon)
        .output()
        .context("Cannot inspect webex-bridged code signature")?;
    let details = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success()
        || !details.contains("Identifier=com.sgrimee.webex-bridged")
        || !details.contains("Authority=")
        || details.contains("Authority=adhoc")
    {
        bail!("Refusing to install an unsigned or ad-hoc signed webex-bridged; run ./scripts/sign-bridged-dev first");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_agent(path: &Path, contents: &str) -> Result<()> {
    let parent = path.parent().context("LaunchAgent path has no parent")?;
    fs::create_dir_all(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("LaunchAgent path is not a regular file");
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("Cannot securely write LaunchAgent plist")?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Install and start the current user's daemon. The selected binary must
/// already exist; installation never builds, downloads or executes a shell.
pub fn install(daemon: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let metadata = fs::metadata(daemon).context("webex-bridged binary is unavailable")?;
        if !metadata.is_file() {
            bail!("webex-bridged path is not a regular file");
        }
        verify_signed_daemon(daemon)?;
        let agent = agent_path()?;
        let log = log_path()?;
        fs::create_dir_all(log.parent().context("Log path has no parent")?)?;
        write_agent(&agent, &plist(daemon, &log)?)?;
        let domain = gui_domain();
        // A missing prior job is normal. Ignore only that best-effort removal;
        // bootstrap and kickstart failures remain visible to the user.
        let _ = launchctl(&[
            "bootout".into(),
            domain.clone(),
            agent.display().to_string(),
        ]);
        launchctl(&[
            "bootstrap".into(),
            domain.clone(),
            agent.display().to_string(),
        ])?;
        launchctl(&["kickstart".into(), "-k".into(), format!("{domain}/{LABEL}")])?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = daemon;
        bail!("install-service is currently supported only on macOS")
    }
}

/// Stop and remove only the known per-user LaunchAgent plist.
pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let agent = agent_path()?;
        let domain = gui_domain();
        let _ = launchctl(&["bootout".into(), domain, agent.display().to_string()]);
        match fs::symlink_metadata(&agent) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(agent).context("Cannot remove LaunchAgent plist")?;
            }
            Ok(_) => bail!("Refusing to remove unexpected LaunchAgent path"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    bail!("uninstall-service is currently supported only on macOS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_escapes_paths_without_a_shell() {
        let rendered = plist(Path::new("/tmp/a<&\"'"), Path::new("/tmp/log&x")).unwrap();
        assert!(rendered.contains("/tmp/a&lt;&amp;&quot;&apos;"));
        assert!(rendered.contains("/tmp/log&amp;x"));
        assert!(!rendered.contains("/bin/sh"));
    }
}
