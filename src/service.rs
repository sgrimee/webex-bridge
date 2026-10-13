//! Per-user service installation. macOS uses a private LaunchAgent; other
//! platforms deliberately fail closed until the planned systemd unit exists.
//!
//! The LaunchAgent never runs a binary inside a build tree. `install` copies
//! the persistently signed `webex-bridged` and `webex-bridge` into the private
//! 0700 `bin/` directory of the application data root, verifies the signature
//! of each copy, and only then points the plist at the copied daemon. Later
//! `cargo build`/`cargo test` runs can therefore never replace (and ad-hoc
//! re-sign) the running service binary.

// The plist, signature and copy helpers are platform-neutral and unit tested
// everywhere, but only the macOS install path calls them.
#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

use crate::paths::{check_mode, Paths};
use anyhow::{bail, Context, Result};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const LABEL: &str = "com.sgrimee.webex-bridged";

/// Executables copied into the private install directory, with the code
/// signing identifier each one must carry.
pub const INSTALLED_BINARIES: [(&str, &str); 2] = [
    ("webex-bridged", "com.sgrimee.webex-bridged"),
    ("webex-bridge", "com.sgrimee.webex-bridge"),
];

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

/// Whether `codesign -d --verbose=2` output shows a persistent (non-ad-hoc)
/// signature with exactly the expected identifier.
fn persistent_signature(details: &str, identifier: &str) -> bool {
    let expected = format!("Identifier={identifier}");
    details.lines().any(|line| line.trim() == expected)
        && details
            .lines()
            .any(|line| line.trim_start().starts_with("Authority="))
        && !details.contains("Signature=adhoc")
        && !details.contains("Authority=adhoc")
}

/// Verify a binary's persistent code signature with the system `codesign`:
/// the signature must be intact (`--verify --strict`) and carry `identifier`.
#[cfg(target_os = "macos")]
fn verify_signature(binary: &Path, identifier: &str) -> Result<()> {
    let verified = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(binary)
        .output()
        .context("Cannot verify a webex-bridge code signature")?;
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=2"])
        .arg(binary)
        .output()
        .context("Cannot inspect a webex-bridge code signature")?;
    let details = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !verified.status.success()
        || !output.status.success()
        || !persistent_signature(&details, identifier)
    {
        bail!(
            "Refusing to install an unsigned or ad-hoc signed {identifier}; run ./scripts/sign-bridged-dev first"
        );
    }
    Ok(())
}

/// Create (0700) or validate the private install directory.
fn ensure_bin_dir(bin: &Path) -> Result<()> {
    if !bin.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(bin)
            .with_context(|| format!("Cannot create {}", bin.display()))?;
    }
    check_mode(bin, 0o700)
}

/// Copy the signed executables from `source_dir` into `bin`, verifying the
/// signature of every copy before it replaces an installed binary.
///
/// Each copy is written to a private temporary file and atomically renamed
/// into place, so a running daemon keeps executing its existing file and an
/// unverifiable copy never replaces an installed one. Returns the installed
/// daemon path.
fn install_binaries(
    source_dir: &Path,
    bin: &Path,
    verify: &dyn Fn(&Path, &str) -> Result<()>,
) -> Result<PathBuf> {
    ensure_bin_dir(bin)?;
    for (name, identifier) in INSTALLED_BINARIES {
        let source = source_dir.join(name);
        let metadata = fs::metadata(&source)
            .with_context(|| format!("{name} binary is unavailable next to webex-bridge"))?;
        if !metadata.is_file() {
            bail!("{name} path is not a regular file");
        }
        // Refuse early on the source too; the copy is verified again below.
        verify(&source, identifier)?;
        let staged = bin.join(format!(".{name}.new"));
        match fs::remove_file(&staged) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        {
            let mut input = File::open(&source)
                .with_context(|| format!("Cannot read {name} for installation"))?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&staged)
                .with_context(|| format!("Cannot stage {name} for installation"))?;
            io::copy(&mut input, &mut output)?;
            output.sync_all()?;
        }
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))?;
        if let Err(error) = verify(&staged, identifier) {
            let _ = fs::remove_file(&staged);
            return Err(error);
        }
        let installed = bin.join(name);
        if let Ok(metadata) = fs::symlink_metadata(&installed) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                let _ = fs::remove_file(&staged);
                bail!("Installed {name} path is not a regular file");
            }
        }
        fs::rename(&staged, &installed)
            .with_context(|| format!("Cannot install {name} into the private bin directory"))?;
    }
    Ok(bin.join(INSTALLED_BINARIES[0].0))
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

/// Install and start the current user's daemon from the signed executables in
/// `source_dir` (normally the directory of the running `webex-bridge`). The
/// executables are copied into `paths.bin` first; the LaunchAgent runs only
/// that verified copy. Installation never builds, downloads or runs a shell.
pub fn install(source_dir: &Path, paths: &Paths) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        paths.ensure_dirs()?;
        let daemon = install_binaries(source_dir, &paths.bin, &verify_signature)?;
        let agent = agent_path()?;
        let log = log_path()?;
        fs::create_dir_all(log.parent().context("Log path has no parent")?)?;
        write_agent(&agent, &plist(&daemon, &log)?)?;
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
        let _ = (source_dir, paths);
        bail!("install-service is currently supported only on macOS")
    }
}

/// Stop and remove only the known per-user LaunchAgent plist and the known
/// installed executables.
pub fn uninstall(paths: &Paths) -> Result<()> {
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
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        for (name, _) in INSTALLED_BINARIES {
            let installed = paths.bin.join(name);
            match fs::symlink_metadata(&installed) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    fs::remove_file(&installed)
                        .with_context(|| format!("Cannot remove installed {name}"))?;
                }
                Ok(_) => bail!("Refusing to remove unexpected installed {name} path"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = paths;
        bail!("uninstall-service is currently supported only on macOS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn plist_escapes_paths_without_a_shell() {
        let rendered = plist(Path::new("/tmp/a<&\"'"), Path::new("/tmp/log&x")).unwrap();
        assert!(rendered.contains("/tmp/a&lt;&amp;&quot;&apos;"));
        assert!(rendered.contains("/tmp/log&amp;x"));
        assert!(!rendered.contains("/bin/sh"));
    }

    #[test]
    fn persistent_signatures_are_distinguished_from_ad_hoc_ones() {
        let signed = "Executable=/x\nIdentifier=com.sgrimee.webex-bridged\nFormat=Mach-O\nAuthority=Webex Bridge Development\nSignature size=1\n";
        assert!(persistent_signature(signed, "com.sgrimee.webex-bridged"));
        assert!(!persistent_signature(signed, "com.sgrimee.webex-bridge"));
        let adhoc = "Executable=/x\nIdentifier=webex_bridged-127cdcbca4d2e7e9\nSignature=adhoc\n";
        assert!(!persistent_signature(adhoc, "com.sgrimee.webex-bridged"));
        let relabelled = "Identifier=com.sgrimee.webex-bridged\nSignature=adhoc\n";
        assert!(!persistent_signature(
            relabelled,
            "com.sgrimee.webex-bridged"
        ));
    }

    fn fake_build(dir: &Path, contents: &str) {
        fs::create_dir_all(dir).unwrap();
        for (name, _) in INSTALLED_BINARIES {
            fs::write(dir.join(name), format!("{contents}:{name}")).unwrap();
        }
    }

    #[test]
    fn installs_verified_copies_into_a_private_bin_and_points_the_plist_there() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        paths.ensure_dirs().unwrap();
        let build = temp.path().join("target/debug");
        fake_build(&build, "signed");
        let verified = RefCell::new(Vec::new());
        let daemon = install_binaries(&build, &paths.bin, &|binary, identifier| {
            verified
                .borrow_mut()
                .push((binary.to_path_buf(), identifier.to_owned()));
            Ok(())
        })
        .unwrap();
        assert_eq!(daemon, paths.bin.join("webex-bridged"));
        check_mode(&paths.bin, 0o700).unwrap();
        for (name, identifier) in INSTALLED_BINARIES {
            let installed = paths.bin.join(name);
            assert_eq!(
                fs::read_to_string(&installed).unwrap(),
                format!("signed:{name}")
            );
            assert_eq!(
                fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
                0o700
            );
            // Both the source and the staged copy were verified.
            let checks: Vec<_> = verified
                .borrow()
                .iter()
                .filter(|(_, id)| id == identifier)
                .map(|(path, _)| path.clone())
                .collect();
            assert_eq!(checks.len(), 2, "{name}");
            assert!(checks[0].starts_with(&build));
            assert!(checks[1].starts_with(&paths.bin));
        }
        // The LaunchAgent runs the private copy, never the build tree.
        let rendered = plist(&daemon, Path::new("/tmp/bridged.log")).unwrap();
        assert!(rendered.contains(&format!(
            "<string>{}</string>",
            paths.bin.join("webex-bridged").display()
        )));
        assert!(!rendered.contains("target/debug"));
        // A later rebuild of the source tree cannot touch the installed file.
        fake_build(&build, "rebuilt-adhoc");
        assert_eq!(
            fs::read_to_string(paths.bin.join("webex-bridged")).unwrap(),
            "signed:webex-bridged"
        );
    }

    #[test]
    fn an_unverifiable_copy_never_replaces_the_installed_binary() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        paths.ensure_dirs().unwrap();
        let build = temp.path().join("build");
        fake_build(&build, "signed");
        install_binaries(&build, &paths.bin, &|_, _| Ok(())).unwrap();
        fake_build(&build, "adhoc");
        // The source check passes, but the staged copy fails verification.
        let error = install_binaries(&build, &paths.bin, &|binary, _| {
            if binary.starts_with(&paths.bin) {
                bail!("Refusing to install an unsigned or ad-hoc signed copy")
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("ad-hoc"));
        assert_eq!(
            fs::read_to_string(paths.bin.join("webex-bridged")).unwrap(),
            "signed:webex-bridged"
        );
        assert!(!paths.bin.join(".webex-bridged.new").exists());
        // An ad-hoc source is refused before any copy is staged.
        let error =
            install_binaries(&build, &paths.bin, &|_, _| bail!("ad-hoc source")).unwrap_err();
        assert!(error.to_string().contains("ad-hoc source"));
    }

    #[test]
    fn a_loose_install_directory_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        paths.ensure_dirs().unwrap();
        fs::create_dir(&paths.bin).unwrap();
        fs::set_permissions(&paths.bin, fs::Permissions::from_mode(0o755)).unwrap();
        let build = temp.path().join("build");
        fake_build(&build, "signed");
        assert!(install_binaries(&build, &paths.bin, &|_, _| Ok(())).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_real_codesign_check_refuses_an_ad_hoc_cargo_build() {
        // Cargo signs every test executable ad hoc, exactly like a stray
        // `cargo build` of webex-bridged: it must never be installable.
        let exe = std::env::current_exe().unwrap();
        let error = verify_signature(&exe, "com.sgrimee.webex-bridged").unwrap_err();
        assert!(error.to_string().contains("ad-hoc"));
    }
}
