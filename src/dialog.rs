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

/// Ask the logged-in macOS user whether this exact executable may receive full
/// mirror access. A missing GUI, cancel, timeout, or platform without a native
/// dialog is a denial.
pub async fn confirm_ui_pairing(executable: &Path) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let executable = executable.display().to_string();
        // AppleScript uses backslash and double quote escaping. Newlines cannot
        // originate from a canonical executable path but are escaped anyway.
        let escaped = executable
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        let script = format!(
            "with timeout of 60 seconds\nset choice to button returned of (display dialog \"Allow {escaped} full access to your Webex mirror?\" buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" cancel button \"Deny\" with icon caution)\nreturn choice\nend timeout"
        );
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("/usr/bin/osascript")
                .args(["-e", &script])
                .output()
        })
        .await
        .context("Pairing dialog task failed")?
        .context("Cannot display macOS pairing dialog")?;
        Ok(output.status.success() && output.stdout == b"Allow\n")
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = executable;
        Ok(false)
    }
}
