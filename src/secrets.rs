//! macOS Keychain wrapper. Token values and OAuth credentials never touch config or logs.

use anyhow::{Context, Result};
use keyring::{Entry, Error};

const OAUTH_SERVICE: &str = "webex-bridge.oauth";

fn entry(account: &str) -> Result<Entry> {
    Entry::new(OAUTH_SERVICE, account).context("Keychain entry unavailable")
}

/// Look up a secret; return `None` only for a missing item, not for a Keychain error.
pub fn get(account: &str) -> Result<Option<String>> {
    match entry(account)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(Error::NoEntry) => Ok(None),
        Err(error) => Err(error).context("Keychain read failed"),
    }
}

/// Store a secret in the user's Keychain, never in a file.
pub fn set(account: &str, value: &str) -> Result<()> {
    entry(account)?
        .set_password(value)
        .context("Keychain write failed")
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
