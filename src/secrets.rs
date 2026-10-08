//! Keychain wrapper. Token values and OAuth credentials never touch config or logs.
//!
//! Unsigned CLI/daemon builds use the macOS login Keychain (Keychain ACL and
//! account-password access). A future properly signed app can explicitly build
//! with `biometric-keychain` to require Touch ID or an OS password fallback;
//! that data-protection backend requires Keychain access-group entitlements.
//! The two modes never silently fall back to each other.

use anyhow::{Context, Result};
use keyring::{Entry, Error as KeyringError};

const LEGACY_OAUTH_SERVICE: &str = "webex-bridge.oauth";
const MIRROR_KEY_SERVICE: &str = "webex-bridge.mirror-key";

#[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
const BIOMETRIC_OAUTH_SERVICE: &str = "webex-bridge.oauth.biometric";

fn legacy_entry(account: &str) -> Result<Entry> {
    Entry::new(LEGACY_OAUTH_SERVICE, account).context("Keychain entry unavailable")
}

fn legacy_get(account: &str) -> Result<Option<String>> {
    match legacy_entry(account)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(error) => Err(error).context("Keychain read failed"),
    }
}

#[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
fn legacy_delete(account: &str) -> Result<()> {
    match legacy_entry(account)?.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
        Err(error) => Err(error).context("Could not remove the migrated legacy Keychain item"),
    }
}

#[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
mod macos {
    use anyhow::{Context, Result};
    use security_framework::passwords::{
        generic_password, set_generic_password_options, AccessControlOptions, PasswordOptions,
    };

    use super::BIOMETRIC_OAUTH_SERVICE;

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    fn options(account: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(BIOMETRIC_OAUTH_SERVICE, account);
        // Access-control policies, including Touch ID, require the macOS
        // data-protection Keychain rather than the older Keychain Services API.
        options.use_protected_keychain();
        options
    }

    /// Read an item whose access policy causes macOS to show its Touch ID UI.
    pub(super) fn get(account: &str) -> Result<Option<String>> {
        match generic_password(options(account)) {
            Ok(value) => String::from_utf8(value)
                .map(Some)
                .context("Keychain item contains non-UTF-8 data"),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(error).context("Keychain read failed"),
        }
    }

    /// Create or update an item protected by Touch ID or the OS password fallback.
    pub(super) fn set(account: &str, value: &str) -> Result<()> {
        let mut options = options(account);
        options.set_access_control_options(AccessControlOptions::USER_PRESENCE);
        set_generic_password_options(value.as_bytes(), options).context("Keychain write failed")
    }
}

/// Look up a secret; return `None` only for a missing item, not for a Keychain error.
pub fn get(account: &str) -> Result<Option<String>> {
    #[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
    {
        match macos::get(account)? {
            Some(value) => Ok(Some(value)),
            None => {
                // An existing installation may still have an item made by the
                // legacy Keychain Services backend. Read it once, recreate it
                // under the Touch ID policy, then remove the old copy.
                if let Some(value) = legacy_get(account)? {
                    macos::set(account, &value)?;
                    legacy_delete(account)?;
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }
        }
    }

    #[cfg(not(all(target_os = "macos", feature = "biometric-keychain")))]
    legacy_get(account)
}

/// Store a secret in the user's Keychain, never in a file.
pub fn set(account: &str, value: &str) -> Result<()> {
    #[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
    {
        macos::set(account, value)?;
        // `set` also handles a fresh OAuth login, which might replace a legacy
        // token without first reading it.
        legacy_delete(account)
    }

    #[cfg(not(all(target_os = "macos", feature = "biometric-keychain")))]
    legacy_entry(account)?
        .set_password(value)
        .context("Keychain write failed")
}

/// Load the 256-bit mirror key from the login Keychain (not a file or config).
/// The daemon needs it during unattended sync, including after token refresh.
pub fn get_mirror_key() -> Result<Option<String>> {
    let entry =
        Entry::new(MIRROR_KEY_SERVICE, "key").context("Mirror Keychain entry unavailable")?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(error) => Err(error).context("Mirror Keychain read failed"),
    }
}

/// Store a newly generated mirror key in the login Keychain.
pub fn set_mirror_key(value: &str) -> Result<()> {
    Entry::new(MIRROR_KEY_SERVICE, "key")
        .context("Mirror Keychain entry unavailable")?
        .set_password(value)
        .context("Mirror Keychain write failed")
}

/// Credentials for the dedicated webex-bridge integration.
pub struct ClientCredentials {
    /// Webex integration client ID.
    pub id: String,
    /// Webex integration client secret.
    pub secret: String,
}

/// Load integration credentials without prompting (safe for the headless daemon).
pub fn credentials_cached() -> Result<ClientCredentials> {
    Ok(ClientCredentials {
        id: get("client_id")?
            .context("Webex integration client ID missing; run webex-bridge login")?,
        secret: get("client_secret")?
            .context("Webex integration client secret missing; run webex-bridge login")?,
    })
}

/// Load integration credentials, prompting only during an interactive login.
pub fn credentials() -> Result<ClientCredentials> {
    let id = match get("client_id")? {
        Some(id) => id,
        None => {
            let id = rpassword::prompt_password("Webex bridge client ID: ")?;
            set("client_id", &id)?;
            id
        }
    };
    let secret = match get("client_secret")? {
        Some(secret) => secret,
        None => {
            let secret = rpassword::prompt_password("Webex bridge client secret: ")?;
            set("client_secret", &secret)?;
            secret
        }
    };
    Ok(ClientCredentials { id, secret })
}
