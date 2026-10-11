//! Feature-gated, foreground-only development environment-secret bootstrap.
//!
//! This module deliberately accepts an injected environment map. It never calls
//! `std::env::var`, opens Keychain, starts a daemon, mutates a database, or
//! changes process environment. The future synchronous binary bootstrap owns
//! those operations and must call these guards before Tokio creates threads.

use crate::{
    auth::{AuthProvider, TokenSet},
    config::{Config, DevSecretSource, OAuthScope},
    mirror::MirrorKeyProvider,
    secrets::ClientCredentials,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;

/// The only environment variables accepted by this development interface.
pub const ALLOWED_VARIABLES: [&str; 4] = [
    "WEBEX_BRIDGE_DEV_CLIENT_ID",
    "WEBEX_BRIDGE_DEV_CLIENT_SECRET",
    "WEBEX_BRIDGE_DEV_TOKEN_SET_JSON",
    "WEBEX_BRIDGE_DEV_MIRROR_KEY_B64",
];
const PREFIX: &str = "WEBEX_BRIDGE_DEV_";
const MAX_CREDENTIAL_BYTES: usize = 4 * 1024;
const MAX_TOKEN_JSON_BYTES: usize = 32 * 1024;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_ACCESS_LIFETIME: u64 = 30 * 24 * 60 * 60;
const MAX_REFRESH_LIFETIME: u64 = 365 * 24 * 60 * 60;

/// Secret-free invocation facts captured before any secret environment access.
#[derive(Clone, Debug)]
pub struct GuardRequest<'a> {
    /// The required explicit daemon CLI flag was supplied.
    pub cli_opt_in: bool,
    /// The selected secret source from validated development configuration.
    pub secret_source: DevSecretSource,
    /// The isolated development root requested by the foreground command.
    pub development_root: &'a Path,
    /// The regular production application-data root.
    pub production_root: &'a Path,
    /// The approved development room requested by the foreground command.
    pub development_room: Option<&'a str>,
    /// Existing development write allowlist from validated configuration.
    pub write_allowlist: &'a [&'a str],
    /// Existing configured route room IDs from validated configuration.
    pub route_rooms: &'a [&'a str],
    /// Process has a controlling terminal and is in the foreground.
    pub foreground_tty: bool,
    /// Invocation was identified as service/manager launched.
    pub service_invocation: bool,
    /// Real/effective UID are equal and the process is not privileged.
    pub unprivileged_same_uid: bool,
    /// Whether the incompatible biometric backend was compiled too.
    pub biometric_feature_enabled: bool,
}

/// Parsed, secret-free foreground development flags. This is intentionally
/// separate from the production daemon parser until synchronous bootstrap is
/// wired before Tokio runtime creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForegroundOptions {
    pub enabled: bool,
    pub development_root: Option<PathBuf>,
    pub development_room: Option<String>,
}

/// Parse only the three development bootstrap flags from an injected argument
/// sequence. Unknown arguments are refused without echoing their value.
pub fn parse_foreground_options<I, S>(arguments: I) -> Result<ForegroundOptions>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut options = ForegroundOptions {
        enabled: false,
        development_root: None,
        development_room: None,
    };
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_ref() {
            "--dev-env-secrets" if !options.enabled => options.enabled = true,
            "--dev-data-dir" if options.development_root.is_none() => {
                let value = arguments
                    .next()
                    .context("development data directory is required")?;
                options.development_root = Some(PathBuf::from(value.as_ref()));
            }
            "--dev-room" if options.development_room.is_none() => {
                let value = arguments.next().context("development room is required")?;
                let value = value.as_ref();
                if value.is_empty() || value.chars().any(char::is_control) {
                    bail!("development room is invalid");
                }
                options.development_room = Some(value.into());
            }
            _ => bail!("invalid development bootstrap arguments"),
        }
    }
    Ok(options)
}

/// Validate the CLI/config half of development bootstrap with no secret map,
/// Keychain, socket, mirror, or network access.
pub fn validate_configured_foreground(
    config: &Config,
    options: &ForegroundOptions,
    production_root: &Path,
    foreground_tty: bool,
    service_invocation: bool,
    unprivileged_same_uid: bool,
    biometric_feature_enabled: bool,
) -> Result<IsolatedRoots> {
    let dev = config
        .dev
        .as_ref()
        .context("development environment secrets require a [dev] configuration")?;
    let root = options
        .development_root
        .as_deref()
        .context("development environment secrets require --dev-data-dir")?;
    let room = options.development_room.as_deref();
    let allowlist = dev
        .write_allowlist
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let routes = config
        .routes
        .iter()
        .map(|route| route.room_id.as_str())
        .collect::<Vec<_>>();
    validate_guards(&GuardRequest {
        cli_opt_in: options.enabled,
        secret_source: dev.secret_source,
        development_root: root,
        production_root,
        development_room: room,
        write_allowlist: &allowlist,
        route_rooms: &routes,
        foreground_tty,
        service_invocation,
        unprivileged_same_uid,
        biometric_feature_enabled,
    })
}

/// A captured, non-`Debug` development secret bundle. No method exposes a
/// printable aggregate; future auth/mirror integration consumes these values
/// directly and replaces rotated tokens only in memory.
pub struct DevelopmentSecrets {
    client_id: Zeroizing<String>,
    client_secret: Zeroizing<String>,
    token_set: Zeroizing<String>,
    mirror_key: Zeroizing<[u8; 32]>,
}

/// In-memory providers created only from a previously validated development
/// secret bundle. They are intentionally not wired into daemon startup yet.
#[allow(dead_code)] // Kept inert until the synchronous bootstrap is fully wired.
pub(crate) struct DevelopmentProviders {
    pub(crate) auth: DevelopmentAuthProvider,
    pub(crate) mirror_key: DevelopmentMirrorKeyProvider,
}

/// Credential/token provider that has no Keychain or filesystem fallback.
#[allow(dead_code)] // Constructed only by the intentionally inert provider factory.
pub(crate) struct DevelopmentAuthProvider {
    client_id: Zeroizing<String>,
    client_secret: Zeroizing<String>,
    token_set: Mutex<Zeroizing<String>>,
}

impl AuthProvider for DevelopmentAuthProvider {
    fn credentials(&self) -> Result<ClientCredentials> {
        Ok(ClientCredentials {
            id: self.client_id.to_string(),
            secret: self.client_secret.to_string(),
        })
    }

    fn load_tokens(&self) -> Result<Option<TokenSet>> {
        let token_set = self
            .token_set
            .lock()
            .map_err(|_| anyhow::anyhow!("development token store is unavailable"))?;
        serde_json::from_str(token_set.as_str())
            .map(Some)
            .context("development token store is malformed")
    }

    fn save_tokens(&self, tokens: &TokenSet) -> Result<()> {
        let serialized = Zeroizing::new(serde_json::to_string(tokens)?);
        let mut token_set = self
            .token_set
            .lock()
            .map_err(|_| anyhow::anyhow!("development token store is unavailable"))?;
        *token_set = serialized;
        Ok(())
    }
}

/// Fixed mirror-key provider for one isolated development process. It never
/// creates, reads, or updates a Keychain value.
#[allow(dead_code)] // Constructed only by the intentionally inert provider factory.
pub(crate) struct DevelopmentMirrorKeyProvider {
    key: Zeroizing<[u8; 32]>,
}

impl MirrorKeyProvider for DevelopmentMirrorKeyProvider {
    fn mirror_key(&self, _existing_db: bool) -> Result<[u8; 32]> {
        Ok(*self.key)
    }
}

impl DevelopmentSecrets {
    /// Turn this validated secret bundle into in-memory-only providers. A
    /// future synchronous bootstrap must use only these providers with the
    /// canonical development root returned by `validate_guards`.
    #[allow(dead_code)] // Bootstrap wiring is deliberately deferred.
    pub(crate) fn into_providers(self) -> DevelopmentProviders {
        DevelopmentProviders {
            auth: DevelopmentAuthProvider {
                client_id: self.client_id,
                client_secret: self.client_secret,
                token_set: Mutex::new(self.token_set),
            },
            mirror_key: DevelopmentMirrorKeyProvider {
                key: self.mirror_key,
            },
        }
    }

    /// Borrow the integration ID for the immediate OAuth client construction.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Borrow the integration secret for the immediate OAuth client construction.
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    /// Borrow the strictly validated token JSON for one in-memory token store.
    pub fn token_set_json(&self) -> &str {
        &self.token_set
    }

    /// Borrow the fixed 256-bit mirror key for the isolated development mirror.
    pub fn mirror_key(&self) -> &[u8; 32] {
        &self.mirror_key
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenSeed {
    access_token: String,
    refresh_token: String,
    issued_at: u64,
    expires_at: u64,
    refresh_expires_at: u64,
    #[serde(default)]
    scopes_verified: bool,
    scope_mode: OAuthScope,
}

fn valid_secret_text(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

/// Canonical, existing directory roots approved for a future development
/// bootstrap. Callers must use these returned paths rather than the untrusted
/// spellings that came from arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolatedRoots {
    pub development: PathBuf,
    pub production: PathBuf,
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{label} root must be absolute");
    }
    // `canonicalize` resolves every path component before comparison. Requiring
    // an existing directory keeps a later bootstrap from first creating a path
    // through an attacker-controlled symlink.
    let canonical = path
        .canonicalize()
        .with_context(|| format!("{label} root must already exist"))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("Cannot inspect canonical {label} root"))?;
    if !metadata.is_dir() {
        bail!("{label} root must be a directory");
    }
    Ok(canonical)
}

fn path_overlaps(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

/// Check all secret-free opt-in/lifecycle/path guards before an environment map
/// is even inspected. It neither creates directories nor reads Keychain state.
///
/// The returned canonical roots are the only roots a future bootstrap may use.
pub fn validate_guards(request: &GuardRequest<'_>) -> Result<IsolatedRoots> {
    if request.biometric_feature_enabled {
        bail!("development environment secrets cannot be combined with biometric Keychain mode");
    }
    if !request.cli_opt_in || request.secret_source != DevSecretSource::EnvironmentDev {
        bail!(
            "development environment secrets require matching feature, config, and foreground flag"
        );
    }
    if !request.foreground_tty || request.service_invocation || !request.unprivileged_same_uid {
        bail!("development environment secrets require an unprivileged interactive foreground process");
    }
    let development = canonical_directory(request.development_root, "development")?;
    let production = canonical_directory(request.production_root, "production")?;
    if path_overlaps(&development, &production) {
        bail!("development root must be isolated from the production root");
    }
    let room = request
        .development_room
        .filter(|room| !room.is_empty())
        .context("development environment secrets require an approved dev room")?;
    if !request.write_allowlist.contains(&room)
        || request
            .write_allowlist
            .iter()
            .any(|allowed| *allowed != room)
        || request
            .route_rooms
            .iter()
            .any(|configured| *configured != room)
    {
        bail!("development environment secrets require routes and writes limited to the selected dev room");
    }
    Ok(IsolatedRoots {
        development,
        production,
    })
}

/// Refuse reserved development-secret variables unless the caller has already
/// selected and validated the full development mode. This has no side effects.
pub fn reject_reserved_variables_when_disabled<I, S>(names: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    if names.into_iter().any(|name| {
        name.as_ref()
            .to_str()
            .is_some_and(|name| name.starts_with(PREFIX))
    }) {
        bail!("reserved development-secret variables require explicit development mode");
    }
    Ok(())
}

fn required<'a>(environment: &'a BTreeMap<OsString, OsString>, name: &str) -> Result<&'a str> {
    let value = environment
        .get(OsStr::new(name))
        .context("development secret input is incomplete")?
        .to_str()
        .context("development secret input is not Unicode")?;
    if value.is_empty() {
        bail!("development secret input is invalid");
    }
    Ok(value)
}

/// Parse exactly the four allowed variables from an injected map. This parser
/// deliberately has no fallback to Keychain, files, aliases or process env.
pub fn capture_from_map(
    environment: &BTreeMap<OsString, OsString>,
    now: u64,
    scope_mode: OAuthScope,
) -> Result<DevelopmentSecrets> {
    for name in environment.keys() {
        let name = name
            .to_str()
            .context("development secret input name is not Unicode")?;
        if name.starts_with(PREFIX) && !ALLOWED_VARIABLES.contains(&name) {
            bail!("development secret input contains an unknown reserved variable");
        }
    }
    let client_id = required(environment, ALLOWED_VARIABLES[0])?;
    let client_secret = required(environment, ALLOWED_VARIABLES[1])?;
    let token_json = required(environment, ALLOWED_VARIABLES[2])?;
    let mirror_key_b64 = required(environment, ALLOWED_VARIABLES[3])?;
    if !valid_secret_text(client_id, MAX_CREDENTIAL_BYTES)
        || !valid_secret_text(client_secret, MAX_CREDENTIAL_BYTES)
        || token_json.len() > MAX_TOKEN_JSON_BYTES
        || mirror_key_b64.len() != 44
        || !mirror_key_b64.is_ascii()
    {
        bail!("development secret input is invalid");
    }
    let decoded = STANDARD
        .decode(mirror_key_b64)
        .context("development mirror key is invalid")?;
    if decoded.len() != 32 || STANDARD.encode(&decoded) != mirror_key_b64 {
        bail!("development mirror key is invalid");
    }
    let mut mirror_key = [0_u8; 32];
    mirror_key.copy_from_slice(&decoded);

    let seed: TokenSeed =
        serde_json::from_str(token_json).context("development token seed is invalid")?;
    if !valid_secret_text(&seed.access_token, MAX_TOKEN_BYTES)
        || !valid_secret_text(&seed.refresh_token, MAX_TOKEN_BYTES)
        || seed.issued_at == 0
        || seed.issued_at > now.saturating_add(60)
        || seed.expires_at <= seed.issued_at
        || seed.refresh_expires_at <= now.max(seed.issued_at)
        || seed.expires_at.saturating_sub(seed.issued_at) > MAX_ACCESS_LIFETIME
        || seed.refresh_expires_at.saturating_sub(seed.issued_at) > MAX_REFRESH_LIFETIME
        || seed.scope_mode != scope_mode
    {
        bail!("development token seed is invalid");
    }
    // Parsing this field ensures strict schema compatibility, but the future
    // in-memory store must start false until a real OAuth response proves it.
    let _untrusted_scopes_verified = seed.scopes_verified;
    Ok(DevelopmentSecrets {
        client_id: Zeroizing::new(client_id.into()),
        client_secret: Zeroizing::new(client_secret.into()),
        token_set: Zeroizing::new(token_json.into()),
        mirror_key: Zeroizing::new(mirror_key),
    })
}

/// Drop reserved secret names from an injected child environment. The caller
/// decides its remaining explicit allowlist; this helper never launches a child.
pub fn scrub_development_variables(
    environment: &BTreeMap<OsString, OsString>,
) -> BTreeMap<OsString, OsString> {
    environment
        .iter()
        .filter(|(name, _)| !name.to_str().is_some_and(|name| name.starts_with(PREFIX)))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Make a synthetic, complete environment map for feature-gated tests only.
#[cfg(test)]
fn fixture(now: u64) -> BTreeMap<OsString, OsString> {
    let token = serde_json::json!({
        "access_token": "access-token",
        "refresh_token": "refresh-token",
        "issued_at": now,
        "expires_at": now + 3600,
        "refresh_expires_at": now + 86_400,
        "scopes_verified": true,
        "scope_mode": "granular",
    })
    .to_string();
    BTreeMap::from([
        (
            OsString::from(ALLOWED_VARIABLES[0]),
            OsString::from("client-id"),
        ),
        (
            OsString::from(ALLOWED_VARIABLES[1]),
            OsString::from("client-secret"),
        ),
        (OsString::from(ALLOWED_VARIABLES[2]), OsString::from(token)),
        (
            OsString::from(ALLOWED_VARIABLES[3]),
            OsString::from(STANDARD.encode([7_u8; 32])),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn guard<'a>(development_root: &'a Path, production_root: &'a Path) -> GuardRequest<'a> {
        GuardRequest {
            cli_opt_in: true,
            secret_source: DevSecretSource::EnvironmentDev,
            development_root,
            production_root,
            development_room: Some("room-1"),
            write_allowlist: &["room-1"],
            route_rooms: &["room-1"],
            foreground_tty: true,
            service_invocation: false,
            unprivileged_same_uid: true,
            biometric_feature_enabled: false,
        }
    }

    #[test]
    fn guards_require_isolation_and_all_three_opt_ins() {
        let temp = tempfile::tempdir().unwrap();
        let development = temp.path().join("development");
        let production = temp.path().join("production");
        fs::create_dir(&development).unwrap();
        fs::create_dir(&production).unwrap();
        assert!(validate_guards(&guard(&development, &production)).is_ok());
        let mut invalid = guard(&development, &production);
        invalid.cli_opt_in = false;
        assert!(validate_guards(&invalid).is_err());
        let mut overlap = guard(&development, &development);
        overlap.secret_source = DevSecretSource::EnvironmentDev;
        assert!(validate_guards(&overlap).is_err());
        let mut service = guard(&development, &production);
        service.service_invocation = true;
        assert!(validate_guards(&service).is_err());
    }

    #[test]
    fn canonical_roots_reject_symlinked_production_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let production = temp.path().join("production");
        let development_alias = temp.path().join("development-alias");
        fs::create_dir(&production).unwrap();
        std::os::unix::fs::symlink(&production, &development_alias).unwrap();
        assert!(validate_guards(&guard(&development_alias, &production)).is_err());
    }

    #[test]
    fn accepted_roots_are_returned_canonical_for_future_use() {
        let temp = tempfile::tempdir().unwrap();
        let development = temp.path().join("development");
        let development_alias = temp.path().join("development-alias");
        let production = temp.path().join("production");
        fs::create_dir(&development).unwrap();
        fs::create_dir(&production).unwrap();
        std::os::unix::fs::symlink(&development, &development_alias).unwrap();
        let roots = validate_guards(&guard(&development_alias, &production)).unwrap();
        assert_eq!(roots.development, development.canonicalize().unwrap());
        assert_eq!(roots.production, production.canonicalize().unwrap());
    }

    #[test]
    fn foreground_cli_and_config_wiring_stay_secret_free() {
        let temp = tempfile::tempdir().unwrap();
        let development = temp.path().join("development");
        let production = temp.path().join("production");
        fs::create_dir(&development).unwrap();
        fs::create_dir(&production).unwrap();
        let options = parse_foreground_options([
            "--dev-env-secrets",
            "--dev-data-dir",
            development.to_str().unwrap(),
            "--dev-room",
            "room-1",
        ])
        .unwrap();
        let mut config = Config::default();
        let dev = config.dev.as_mut().unwrap();
        dev.write_allowlist = vec!["room-1".into()];
        dev.secret_source = DevSecretSource::EnvironmentDev;
        assert!(validate_configured_foreground(
            &config,
            &options,
            &production,
            true,
            false,
            true,
            false,
        )
        .is_ok());
        assert!(parse_foreground_options(["--dev-env-secrets", "--dev-env-secrets"]).is_err());
        let mut production_config = config;
        production_config.dev.as_mut().unwrap().secret_source = DevSecretSource::Keychain;
        assert!(validate_configured_foreground(
            &production_config,
            &options,
            &production,
            true,
            false,
            true,
            false,
        )
        .is_err());
    }

    #[test]
    fn parser_is_all_or_nothing_and_scrubs_only_reserved_names() {
        let now = 1_700_000_000;
        let environment = fixture(now);
        let secrets = capture_from_map(&environment, now, OAuthScope::Granular).unwrap();
        assert_eq!(secrets.mirror_key().len(), 32);
        assert!(!secrets.client_id().is_empty());
        assert!(!secrets.client_secret().is_empty());
        assert!(!secrets.token_set_json().is_empty());
        let mut missing = environment.clone();
        missing.remove(OsStr::new(ALLOWED_VARIABLES[1]));
        assert!(capture_from_map(&missing, now, OAuthScope::Granular).is_err());
        let mut unknown = environment.clone();
        unknown.insert(
            OsString::from("WEBEX_BRIDGE_DEV_EXTRA"),
            OsString::from("x"),
        );
        assert!(capture_from_map(&unknown, now, OAuthScope::Granular).is_err());
        let mut child = environment.clone();
        child.insert(OsString::from("SAFE_NAME"), OsString::from("safe"));
        let scrubbed = scrub_development_variables(&child);
        assert_eq!(
            scrubbed.get(OsStr::new("SAFE_NAME")),
            Some(&OsString::from("safe"))
        );
        assert!(scrubbed
            .keys()
            .all(|name| !name.to_string_lossy().starts_with(PREFIX)));
    }

    #[test]
    fn in_memory_providers_rotate_synthetic_tokens_without_keychain() {
        let providers =
            capture_from_map(&fixture(1_700_000_000), 1_700_000_000, OAuthScope::Granular)
                .unwrap()
                .into_providers();
        let credentials = providers.auth.credentials().unwrap();
        assert_eq!(credentials.id, "client-id");
        assert_eq!(credentials.secret, "client-secret");
        let before = providers.auth.load_tokens().unwrap().unwrap();
        assert_eq!(before.access_token, "access-token");
        let rotated = TokenSet {
            access_token: "rotated-access-token".into(),
            refresh_token: "rotated-refresh-token".into(),
            issued_at: 1_700_000_001,
            expires_at: 1_700_003_601,
            refresh_expires_at: 1_700_086_401,
            scopes_verified: false,
            scope_mode: OAuthScope::Granular,
        };
        providers.auth.save_tokens(&rotated).unwrap();
        let after = providers.auth.load_tokens().unwrap().unwrap();
        assert_eq!(after.access_token, "rotated-access-token");
        assert_eq!(after.refresh_token, "rotated-refresh-token");
    }

    #[test]
    fn provider_key_opens_only_an_isolated_development_mirror() {
        let temporary = tempfile::tempdir().unwrap();
        let production_root = temporary.path().join("production");
        let development_root = temporary.path().join("development");
        fs::create_dir(&production_root).unwrap();
        fs::create_dir(&development_root).unwrap();
        fs::set_permissions(&development_root, fs::Permissions::from_mode(0o700)).unwrap();
        let providers =
            capture_from_map(&fixture(1_700_000_000), 1_700_000_000, OAuthScope::Granular)
                .unwrap()
                .into_providers();
        let development_paths = crate::paths::Paths::under(development_root.clone());
        let mirror = crate::mirror::Mirror::open_with_key_provider(
            &development_paths,
            &providers.mirror_key,
        )
        .unwrap();
        drop(mirror);
        // Existing isolated mirrors use the same injected key; no regeneration
        // or Keychain lookup is permitted on reopen.
        crate::mirror::Mirror::open_with_key_provider(&development_paths, &providers.mirror_key)
            .unwrap();
        assert!(development_paths.mirror.exists());
        assert!(!production_root.join("bridge.db").exists());
        assert!(!production_root.join("run").exists());
    }

    #[tokio::test]
    async fn fake_providers_share_only_validated_isolated_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let production_root = temporary.path().join("production");
        let development_root = temporary.path().join("development");
        fs::create_dir(&production_root).unwrap();
        fs::create_dir(&development_root).unwrap();
        fs::set_permissions(&development_root, fs::Permissions::from_mode(0o700)).unwrap();

        // This is the bounded fake bootstrap: guards select canonical isolated
        // paths; the injected map constructs in-memory auth/key providers; and
        // no daemon or process-environment access is involved.
        let roots = validate_guards(&guard(&development_root, &production_root)).unwrap();
        let development_paths = crate::paths::Paths::under(roots.development);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let providers = capture_from_map(&fixture(now), now, OAuthScope::Granular)
            .unwrap()
            .into_providers();

        // A new synthetic token is cached, so this invokes the injected auth
        // seam (and its isolated refresh lock) without any OAuth request.
        let tokens = crate::auth::fresh_token_with(&development_paths, &providers.auth)
            .await
            .unwrap();
        assert_eq!(tokens.access_token, "access-token");
        assert!(development_paths.refresh_lock.exists());

        let mirror = crate::mirror::Mirror::open_with_key_provider(
            &development_paths,
            &providers.mirror_key,
        )
        .unwrap();
        assert_eq!(mirror.stats().unwrap().rooms, 0);
        drop(mirror);
        assert!(development_paths.mirror.exists());
        assert!(!production_root.join("run").exists());
        assert!(!production_root.join("bridge.db").exists());
    }

    #[test]
    fn token_seed_rejects_scope_expiry_and_key_errors_without_fallback() {
        let now = 1_700_000_000;
        let environment = fixture(now);
        let mut scope = environment.clone();
        let value = scope.get_mut(OsStr::new(ALLOWED_VARIABLES[2])).unwrap();
        *value = OsString::from(
            serde_json::json!({
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "issued_at": now,
                "expires_at": now + 3600,
                "refresh_expires_at": now + 86_400,
                "scope_mode": "spark_all"
            })
            .to_string(),
        );
        assert!(capture_from_map(&scope, now, OAuthScope::Granular).is_err());
        let mut key = environment.clone();
        key.insert(
            OsString::from(ALLOWED_VARIABLES[3]),
            OsString::from("not-a-key"),
        );
        assert!(capture_from_map(&key, now, OAuthScope::Granular).is_err());
        assert!(reject_reserved_variables_when_disabled(environment.keys()).is_err());
        assert!(reject_reserved_variables_when_disabled([OsString::from("SAFE")]).is_ok());
    }
}
