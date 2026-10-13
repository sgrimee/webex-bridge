//! Native, fail-closed confirmation dialogs for privileged local pairing.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Resolve the executable of a kernel-reported peer PID. A client cannot
/// supply this path in HTTP, avoiding a display-name spoof in the dialog.
pub fn executable_for_pid(pid: u32) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CStr;
        let mut bytes = vec![0_i8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // proc_pidpath copies a NUL-terminated path into caller-owned memory.
        let length = unsafe {
            libc::proc_pidpath(
                pid as i32,
                bytes.as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() as u32,
            )
        };
        if length <= 0 {
            anyhow::bail!("Cannot resolve local client executable");
        }
        let path = unsafe { CStr::from_ptr(bytes.as_ptr()) }
            .to_str()
            .context("Client executable path is not UTF-8")?;
        Ok(PathBuf::from(path))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .context("Cannot resolve local client executable")
    }
}

/// Seconds the pairing dialog stays up before it gives up (a denial).
pub const PAIRING_DIALOG_SECS: u32 = 60;

/// The AppleScript for one pairing confirmation. `giving up after` is the
/// only bound that applies to `display dialog` run inside osascript itself;
/// `with timeout` affects only Apple events sent to other applications.
fn pairing_script(executable: &Path) -> String {
    let executable = executable.display().to_string();
    // AppleScript uses backslash and double quote escaping. Newlines cannot
    // originate from a canonical executable path but are escaped anyway.
    let escaped = executable
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!(
        "set choice to button returned of (display dialog \"Allow {escaped} full access to your Webex mirror?\" buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" cancel button \"Deny\" with icon caution giving up after {PAIRING_DIALOG_SECS})\nreturn choice"
    )
}

/// Test-only scripted answer, so API tests never open a real dialog.
#[cfg(test)]
pub(crate) static TEST_ANSWER: std::sync::Mutex<Option<PairingAnswer>> =
    std::sync::Mutex::new(None);

/// The user's answer to one pairing dialog. Only `Allowed` approves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingAnswer {
    /// The user clicked "Allow".
    Allowed,
    /// "Deny" (the cancel button), no graphical session, or any other result.
    Denied,
    /// Nobody answered within [`PAIRING_DIALOG_SECS`].
    GaveUp,
}

/// Only an explicit "Allow" approves; a give-up returns an empty button; a
/// cancel button, missing GUI and any other output deny.
fn classify(success: bool, stdout: &[u8]) -> PairingAnswer {
    match (success, stdout) {
        (true, b"Allow\n") => PairingAnswer::Allowed,
        (true, b"\n") => PairingAnswer::GaveUp,
        _ => PairingAnswer::Denied,
    }
}

/// Run `program -e script` and classify its result. The child is killed when
/// this future is dropped, so a cancelled pairing request (for example a
/// client that gave up) removes its dialog instead of leaving it on screen
/// to collect a click that nobody receives.
async fn confirm_with(program: &Path, script: String) -> Result<PairingAnswer> {
    let output = tokio::process::Command::new(program)
        .arg("-e")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .context("Cannot display macOS pairing dialog")?;
    Ok(classify(output.status.success(), &output.stdout))
}

/// Ask the logged-in macOS user whether this exact executable may receive full
/// mirror access. A missing GUI, deny, give-up after
/// [`PAIRING_DIALOG_SECS`], or a platform without a native dialog is a denial.
pub async fn confirm_ui_pairing(executable: &Path) -> Result<PairingAnswer> {
    #[cfg(test)]
    if let Some(answer) = *TEST_ANSWER.lock().expect("test dialog mutex") {
        return Ok(answer);
    }
    #[cfg(target_os = "macos")]
    {
        confirm_with(Path::new("/usr/bin/osascript"), pairing_script(executable)).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (executable, confirm_with, pairing_script(executable));
        Ok(PairingAnswer::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_dialog(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("fake-osascript");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn the_script_gives_up_instead_of_using_an_ineffective_timeout() {
        let script = pairing_script(Path::new("/Applications/Tui \"x\".app/tui"));
        assert!(script.contains("giving up after 60"));
        assert!(!script.contains("with timeout"));
        assert!(script.contains("default button \"Deny\""));
        assert!(
            script.contains("Tui \\\"x\\\".app"),
            "quotes escaped: {script}"
        );
    }

    #[test]
    fn only_an_explicit_allow_approves() {
        assert_eq!(classify(true, b"Allow\n"), PairingAnswer::Allowed);
        assert_eq!(classify(true, b"\n"), PairingAnswer::GaveUp);
        for (success, stdout) in [
            (true, &b"Deny\n"[..]),
            (false, b""),
            (false, b"Allow\n"),
            (false, b"\n"),
            (true, b"Allow"),
            (true, b"Allow\nAllow\n"),
        ] {
            assert_eq!(
                classify(success, stdout),
                PairingAnswer::Denied,
                "{success} {stdout:?}"
            );
        }
    }

    #[tokio::test]
    async fn runner_results_are_classified() {
        let dir = tempfile::tempdir().unwrap();
        for (body, answer) in [
            ("echo Allow", PairingAnswer::Allowed),
            ("echo", PairingAnswer::GaveUp),
            ("exit 1", PairingAnswer::Denied),
        ] {
            let dialog = fake_dialog(dir.path(), body);
            assert_eq!(
                confirm_with(&dialog, "ignored".into()).await.unwrap(),
                answer
            );
        }
        assert!(confirm_with(&dir.path().join("missing"), "x".into())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_dropped_request_kills_its_dialog() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("answered");
        let dialog = fake_dialog(
            dir.path(),
            &format!("sleep 1\ntouch '{}'\necho Allow", marker.display()),
        );
        let pending = tokio::spawn(async move { confirm_with(&dialog, "x".into()).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        pending.abort();
        let _ = pending.await;
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(!marker.exists(), "the dialog process outlived its request");
    }
}
