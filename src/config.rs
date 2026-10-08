//! Strict, secret-free daemon configuration. Unknown keys are errors, not ignored.

use crate::paths::{check_mode, Paths};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

/// Configuration for a single user's Webex bridge.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Webex sync settings.
    #[serde(default)]
    pub webex: WebexConfig,
    /// Message, approval and routing limits.
    #[serde(default)]
    pub limits: Limits,
    /// Development write boundary; remove only after Step 6 sign-off.
    pub dev: Option<DevConfig>,
    /// Explicit agent routes; none are enabled by default.
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// Mercury device and initial/catch-up sync settings.
#[derive(Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebexConfig {
    /// Auto means `<hostname>-webex-bridge`.
    pub device_name: String,
    /// Oldest time a room can be backfilled.
    pub catchup_max_age: String,
    /// Number of newest messages read first.
    pub initial_page_size: u32,
    /// Optional explicit retention setting.
    pub retention_max_age: Option<String>,
}

impl Default for WebexConfig {
    fn default() -> Self {
        Self {
            device_name: "auto".into(),
            catchup_max_age: "180d".into(),
            initial_page_size: 50,
            retention_max_age: None,
        }
    }
}

/// Daemon-enforced resource ceilings.
#[derive(Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum inbound message size accepted for an agent.
    pub agent_inbound_max_bytes: usize,
    /// Maximum pending deliveries per route.
    pub route_queue_cap: usize,
    /// Inbound messages per sender and minute.
    pub sender_rate_per_min: u32,
    /// Maximum consecutive agent replies in a thread.
    pub thread_agent_hop_limit: u32,
    /// Maximum outbound sends per minute.
    pub outbound_rate_per_min: u32,
    /// Summarize catch-up beyond this many notifications.
    pub catchup_notify_threshold: u32,
    /// Lifetime of a draft approval.
    pub approval_ttl: String,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            agent_inbound_max_bytes: 7168,
            route_queue_cap: 500,
            sender_rate_per_min: 20,
            thread_agent_hop_limit: 6,
            outbound_rate_per_min: 10,
            catchup_notify_threshold: 50,
            approval_ttl: "10m".into(),
        }
    }
}

/// Restrict all API writes to listed Webex room IDs during development.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevConfig {
    /// Allowed destination IDs for writes. Empty is deny-all.
    pub write_allowlist: Vec<String>,
}

/// Agent delivery mode.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Receive {
    /// Only leading `<agentName>:` addresses count.
    #[default]
    Addressed,
    /// All messages from allowed senders in the room.
    All,
}

/// Route definition; sender IDs, not display names or email addresses.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Stable route name.
    pub id: String,
    /// Webex room ID.
    pub room_id: String,
    /// Agent address in this room.
    pub agent_name: String,
    /// Webex person IDs allowed to send to the agent.
    pub allowed_senders: Vec<String>,
    /// Address matching policy.
    #[serde(default)]
    pub receive: Receive,
    /// Local workspace permitted to claim this route.
    pub workspace: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            webex: WebexConfig::default(),
            limits: Limits::default(),
            dev: Some(DevConfig {
                write_allowlist: Vec::new(),
            }),
            routes: Vec::new(),
        }
    }
}

impl Config {
    /// Read a 0600 config; refuse to run without one or with unknown settings.
    pub fn load(paths: &Paths) -> Result<Self> {
        paths.ensure_dirs()?;
        check_mode(&paths.config, 0o600)?;
        let data = fs::read_to_string(&paths.config)?;
        toml::from_str(&data).context("Invalid webex-bridge config.toml")
    }

    /// Check a write operation's destination against the development allowlist.
    pub fn check_write_room(&self, room_id: &str) -> Result<()> {
        match &self.dev {
            Some(dev) if dev.write_allowlist.iter().any(|id| id == room_id) => Ok(()),
            Some(_) => bail!("Write blocked by [dev] write_allowlist"),
            None => Ok(()), // Only remove [dev] after Step 6 sign-off.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_config_and_allowlist() {
        let config: Config = toml::from_str("[dev]\nwrite_allowlist = ['social']\n").unwrap();
        assert!(config.check_write_room("elsewhere").is_err());
        assert!(config.check_write_room("social").is_ok());
        assert!(toml::from_str::<Config>("[webex]\nspark_all = true\n").is_err());
        assert!(toml::from_str::<Config>("[[routes]]\nid = 'r'\nroom_id = 'a'\nagent_name = 'b'\nallowed_senders = []\nworkspace = 'x'\nreceive = 'any'\n").is_err());
    }
}
