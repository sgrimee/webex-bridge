//! Strict, secret-free daemon configuration. Unknown keys are errors, not ignored.

use crate::paths::{check_mode, Paths};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use webex::{GlobalId, GlobalIdType};

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
    /// Explicit OAuth scope policy: granular by default, broad only after user approval.
    pub oauth_scope: OAuthScope,
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
            oauth_scope: OAuthScope::Granular,
            device_name: "auto".into(),
            catchup_max_age: "180d".into(),
            initial_page_size: 50,
            retention_max_age: None,
        }
    }
}

/// Explicit user choice of OAuth scope set; never auto-upgrade on HTTP 403.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthScope {
    /// Ten granular scopes in the initial feasibility test.
    #[default]
    Granular,
    /// Broad `spark:all` only, as explicitly approved by this user.
    SparkAll,
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
    /// Secret backend selection. Keychain is the production/default path; the
    /// environment mode is rejected unless the feature and foreground guards
    /// independently opt into it.
    #[serde(default)]
    pub secret_source: DevSecretSource,
}

/// Secret-free development backend selector. It contains no credential values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevSecretSource {
    /// Default production behavior; never inspect environment variables.
    #[default]
    Keychain,
    /// Feature-gated foreground development source only.
    EnvironmentDev,
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
                secret_source: DevSecretSource::Keychain,
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

    /// Create the initial configuration only after independently verifying a test room.
    /// Never overwrite an existing configuration or write with permissive file modes.
    pub fn write_initial(
        paths: &Paths,
        room_id: &str,
        own_person_id: &str,
        agent_name: &str,
        workspace: &Path,
    ) -> Result<()> {
        paths.ensure_dirs()?;
        let _ = GlobalId::new(GlobalIdType::Room, room_id.to_owned())?;
        let _ = GlobalId::new(GlobalIdType::Person, own_person_id.to_owned())?;
        if agent_name.is_empty()
            || agent_name.contains(':')
            || agent_name.chars().any(char::is_whitespace)
        {
            bail!("Agent name must be a non-empty address without colons or whitespace");
        }
        let workspace = workspace.canonicalize().context("Workspace must exist")?;
        if !workspace.is_dir() {
            bail!("Workspace must be a directory");
        }
        let config = Self {
            dev: Some(DevConfig {
                write_allowlist: vec![room_id.to_owned()],
                secret_source: DevSecretSource::Keychain,
            }),
            routes: vec![Route {
                id: "agents-social".into(),
                room_id: room_id.to_owned(),
                agent_name: agent_name.to_owned(),
                allowed_senders: vec![own_person_id.to_owned()],
                receive: Receive::Addressed,
                workspace: workspace.to_string_lossy().into_owned(),
            }],
            ..Self::default()
        };
        let data = toml::to_string_pretty(&config)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&paths.config)
            .context("Config already exists or cannot be securely created")?;
        file.write_all(data.as_bytes())?;
        file.sync_all()?;
        check_mode(&paths.config, 0o600)?;
        Ok(())
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
        assert_eq!(
            toml::from_str::<Config>("[webex]\noauth_scope = 'spark_all'\n")
                .unwrap()
                .webex
                .oauth_scope,
            OAuthScope::SparkAll
        );
        assert_eq!(
            toml::from_str::<Config>(
                "[dev]\nwrite_allowlist = ['social']\nsecret_source = 'environment_dev'\n"
            )
            .unwrap()
            .dev
            .unwrap()
            .secret_source,
            DevSecretSource::EnvironmentDev
        );
        assert!(toml::from_str::<Config>("[[routes]]\nid = 'r'\nroom_id = 'a'\nagent_name = 'b'\nallowed_senders = []\nworkspace = 'x'\nreceive = 'any'\n").is_err());
    }

    #[test]
    fn initial_config_is_restrictive_and_not_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::under(temp.path().join("bridge"));
        let room = "Y2lzY29zcGFyazovL3VzL1JPT00vMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDBhMDAx";
        let person =
            "Y2lzY29zcGFyazovL3VzL1BFT1BMRS8wMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMGIwMDE";
        Config::write_initial(&paths, room, person, "sam/coder", temp.path()).unwrap();
        assert!(Config::write_initial(&paths, room, person, "sam/coder", temp.path()).is_err());
        let loaded = Config::load(&paths).unwrap();
        assert_eq!(loaded.routes[0].agent_name, "sam/coder");
        assert_eq!(loaded.routes[0].allowed_senders, vec![person]);
        assert!(loaded.check_write_room("other-room").is_err());
        assert!(loaded.check_write_room(room).is_ok());
    }
}
