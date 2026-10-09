//! Browser PKCE login and locked refresh for the dedicated Webex integration.
//! No OAuth code, token, callback query or client secret is logged.

use crate::{
    config::{Config, OAuthScope},
    diagnostics,
    paths::Paths,
    secrets,
};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout_at, Instant};

const AUTHORIZE_URL: &str = "https://webexapis.com/v1/authorize";
const TOKEN_URL: &str = "https://webexapis.com/v1/access_token";
const REDIRECT_URL: &str = "http://localhost:8765/callback";
const GRANULAR_SCOPES: [&str; 10] = [
    "spark:messages_read",
    "spark:messages_write",
    "spark:rooms_read",
    "spark:rooms_write",
    "spark:memberships_read",
    "spark:memberships_write",
    "spark:people_read",
    "spark:teams_read",
    "spark:devices_read",
    "spark:devices_write",
];

/// Credentials and expiration metadata; serialized only into the Keychain.
#[derive(Serialize, Deserialize)]
pub struct TokenSet {
    /// Access token for Webex requests.
    pub access_token: String,
    /// Refresh token for renewal.
    pub refresh_token: String,
    /// Unix seconds when the access token was issued.
    pub issued_at: u64,
    /// Unix seconds when the access token expires.
    pub expires_at: u64,
    /// Unix seconds when the refresh token expires.
    pub refresh_expires_at: u64,
    /// Whether the token response explicitly confirmed the selected scope set.
    #[serde(default)]
    pub scopes_verified: bool,
    /// The scope mode under which this token was obtained, checked against config on use.
    #[serde(default)]
    pub scope_mode: OAuthScope,
}

impl TokenSet {
    /// Time at which the supervisor should rebuild the Webex client (80% of lifetime).
    #[must_use]
    pub fn refresh_at(&self) -> u64 {
        let lifetime = self.expires_at.saturating_sub(self.issued_at);
        self.issued_at
            .saturating_add((lifetime / 5) * 4 + (lifetime % 5) * 4 / 5)
    }
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    refresh_token_expires_in: Option<u64>,
    scope: Option<String>,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_secs())
}

fn requested_scopes(mode: OAuthScope) -> &'static [&'static str] {
    match mode {
        OAuthScope::Granular => &GRANULAR_SCOPES,
        OAuthScope::SparkAll => &["spark:all"],
    }
}

fn selected_scope(paths: &Paths) -> Result<OAuthScope> {
    match std::fs::symlink_metadata(&paths.config) {
        Ok(_) => Ok(Config::load(paths)?.webex.oauth_scope),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(OAuthScope::Granular),
        Err(error) => Err(error.into()),
    }
}

fn token_from_reply(
    reply: TokenReply,
    old: Option<&TokenSet>,
    mode: OAuthScope,
) -> Result<TokenSet> {
    let requested = requested_scopes(mode);
    let scopes_verified = if let Some(scopes) = reply.scope.as_deref() {
        let actual: std::collections::HashSet<_> = scopes.split_whitespace().collect();
        if actual.len() != requested.len() || requested.iter().any(|scope| !actual.contains(scope))
        {
            bail!("Webex did not grant exactly the configured OAuth scopes; stop and ask the user");
        }
        true
    } else {
        old.is_some_and(|tokens| tokens.scopes_verified)
    };
    if reply.access_token.is_empty() || reply.expires_in == 0 {
        bail!("Webex returned an invalid access token lifetime");
    }
    let issued_at = now()?;
    let refresh_token = reply
        .refresh_token
        .filter(|token| !token.is_empty())
        .or_else(|| old.map(|tokens| tokens.refresh_token.clone()))
        .context("Webex did not return a refresh token")?;
    let refresh_expires_at = match reply.refresh_token_expires_in {
        Some(seconds) if seconds > 0 => issued_at.saturating_add(seconds),
        _ => old
            .map(|tokens| tokens.refresh_expires_at)
            .context("Webex did not report a refresh-token expiry; stop and ask the user")?,
    };
    Ok(TokenSet {
        access_token: reply.access_token,
        refresh_token,
        issued_at,
        expires_at: issued_at.saturating_add(reply.expires_in),
        refresh_expires_at,
        scopes_verified,
        scope_mode: mode,
    })
}

/// Retrieve tokens from Keychain without revealing them in status/log output.
pub fn load() -> Result<Option<TokenSet>> {
    secrets::get("tokens")?
        .map(|json| serde_json::from_str(&json).context("Stored Webex tokens are malformed"))
        .transpose()
}

fn save(tokens: &TokenSet) -> Result<()> {
    secrets::set("tokens", &serde_json::to_string(tokens)?)
}

/// Browser login. Binds the callback before opening the browser and validates CSRF/PKCE.
pub async fn login(paths: &Paths) -> Result<()> {
    paths.ensure_dirs()?;
    let scope_mode = selected_scope(paths)?;
    let credentials = secrets::credentials()?;
    let listener = TcpListener::bind("127.0.0.1:8765")
        .await
        .context("Cannot bind the Webex OAuth callback on port 8765")?;
    let client = BasicClient::new(ClientId::new(credentials.id.clone()))
        .set_client_secret(ClientSecret::new(credentials.secret.clone()))
        .set_auth_uri(AuthUrl::new(AUTHORIZE_URL.to_owned())?)
        .set_token_uri(TokenUrl::new(TOKEN_URL.to_owned())?)
        .set_redirect_uri(RedirectUrl::new(REDIRECT_URL.to_owned())?);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(challenge);
    for scope in requested_scopes(scope_mode) {
        request = request.add_scope(Scope::new((*scope).to_owned()));
    }
    let (auth_url, state) = request.url();
    webbrowser::open(auth_url.as_str()).context("Cannot open a browser for Webex login")?;
    let code = wait_for_callback(&listener, state.secret()).await?;

    let reply = exchange(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URL),
        ("client_id", &credentials.id),
        ("client_secret", &credentials.secret),
        ("code_verifier", verifier.secret()),
    ])
    .await?;
    let tokens = token_from_reply(reply, None, scope_mode)?;
    save(&tokens)?;
    if tokens.scopes_verified {
        println!("Webex explicitly confirmed the configured OAuth scope set.");
    } else {
        println!("Webex token response did not report granted scopes; device access must be tested separately.");
    }
    Ok(())
}

async fn exchange(form: &[(&str, &str)]) -> Result<TokenReply> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client.post(TOKEN_URL).form(form).send().await?;
    if !response.status().is_success() {
        if matches!(response.status().as_u16(), 401 | 403) {
            bail!("auth_required: Webex rejected the OAuth credentials; run webex-bridge login");
        }
        bail!("Webex OAuth token request failed (HTTP {}); stop and ask the user before changing scopes", response.status());
    }
    response
        .json::<TokenReply>()
        .await
        .context("Webex returned an invalid OAuth token response")
}

/// Refresh under an inter-process lock; re-read tokens after acquiring it.
/// Never refresh after the refresh expiry or silently broaden scopes.
pub async fn fresh_token(paths: &Paths) -> Result<TokenSet> {
    let lock = paths.open_refresh_lock()?;
    lock.lock_exclusive().context("Cannot lock token refresh")?;
    // The lock is released when its file handle is dropped, including on error.
    let tokens = load()?.context("Login required: run webex-bridge login")?;
    if tokens.scope_mode != selected_scope(paths)? {
        bail!("OAuth scope configuration changed; reauthorize with webex-bridge login before any Webex request");
    }
    let current = now()?;
    if current < tokens.refresh_at() {
        diagnostics::debug("auth.cached_token_accepted");
        return Ok(tokens);
    }
    if current >= tokens.refresh_expires_at {
        bail!("Webex refresh token expired; run webex-bridge login");
    }
    diagnostics::info("auth.token_refresh_required");
    refresh_locked(tokens).await
}

/// Development-only forced refresh for testing client/stream rebuilds.
/// The caller must enforce `[dev]` mode and an allowed test room.
pub async fn refresh_now(paths: &Paths) -> Result<TokenSet> {
    let lock = paths.open_refresh_lock()?;
    lock.lock_exclusive().context("Cannot lock token refresh")?;
    let tokens = load()?.context("Login required: run webex-bridge login")?;
    if tokens.scope_mode != selected_scope(paths)? {
        bail!("OAuth scope configuration changed; reauthorize before refreshing");
    }
    if now()? >= tokens.refresh_expires_at {
        bail!("Webex refresh token expired; run webex-bridge login");
    }
    diagnostics::info("auth.token_refresh_forced");
    refresh_locked(tokens).await
}

async fn refresh_locked(tokens: TokenSet) -> Result<TokenSet> {
    let credentials = secrets::credentials_cached()?;
    let reply = exchange(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &tokens.refresh_token),
        ("client_id", &credentials.id),
        ("client_secret", &credentials.secret),
    ])
    .await?;
    let refreshed = token_from_reply(reply, Some(&tokens), tokens.scope_mode)?;
    save(&refreshed)?;
    diagnostics::info("auth.token_refreshed");
    Ok(refreshed)
}

fn parse_callback_line(line: &str, expected_state: &str) -> Result<Option<String>> {
    let mut parts = line.split_whitespace();
    if parts.next() != Some("GET") {
        bail!("Unexpected OAuth callback method");
    }
    let target = parts.next().context("OAuth callback has no path")?;
    let url = oauth2::url::Url::parse(&format!("http://localhost:8765{target}"))?;
    if url.path() != "/callback" || url.origin().ascii_serialization() != "http://localhost:8765" {
        bail!("Unexpected OAuth callback path");
    }
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned());
    if state.as_deref() != Some(expected_state) {
        bail!("OAuth callback CSRF state did not match");
    }
    if url.query_pairs().any(|(key, _)| key == "error") {
        bail!("Webex OAuth authorization was denied; stop and ask the user");
    }
    Ok(url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned()))
}

async fn read_request_line<R: AsyncRead + Unpin>(stream: &mut R) -> Result<String> {
    let mut line = Vec::with_capacity(256);
    loop {
        let mut byte = [0_u8];
        if stream.read(&mut byte).await? == 0 {
            bail!("Incomplete OAuth callback request");
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= 4096 || byte[0] == 0 {
            bail!("Invalid OAuth callback request");
        }
        line.push(byte[0]);
    }
    Ok(String::from_utf8(line)?.trim_end_matches('\r').to_owned())
}

async fn wait_for_callback(listener: &TcpListener, expected_state: &str) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let (mut socket, _) = timeout_at(deadline, listener.accept())
            .await
            .context("Timed out waiting for Webex OAuth authorization")??;
        // A slow or malformed local request cannot abort or indefinitely block login.
        let read_deadline = std::cmp::min(deadline, Instant::now() + Duration::from_secs(5));
        let parsed = match timeout_at(read_deadline, read_request_line(&mut socket)).await {
            Ok(Ok(line)) => parse_callback_line(&line, expected_state),
            _ => Err(anyhow::anyhow!("Invalid OAuth callback request")),
        };
        let (status, body) = if matches!(parsed, Ok(Some(_))) {
            (
                "200 OK",
                "Authorization received. You can close this window.",
            )
        } else {
            ("400 Bad Request", "Invalid authorization callback.")
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        match parsed {
            Ok(Some(code)) => return Ok(code),
            Err(error) if error.to_string().contains("authorization was denied") => {
                return Err(error)
            }
            _ => {} // Ignore unrelated browser requests without revealing their contents.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_state_and_exact_callback_path() {
        assert_eq!(
            parse_callback_line("GET /callback?state=expected&code=abc HTTP/1.1", "expected")
                .unwrap(),
            Some("abc".to_string())
        );
        assert!(
            parse_callback_line("GET /callback?state=wrong&code=abc HTTP/1.1", "expected").is_err()
        );
        assert!(
            parse_callback_line("GET /other?state=expected&code=abc HTTP/1.1", "expected").is_err()
        );
        assert!(parse_callback_line(
            "GET /callback?state=expected&error=invalid_scope HTTP/1.1",
            "expected"
        )
        .is_err());
    }

    #[tokio::test]
    async fn callback_reader_handles_fragmented_requests() {
        let (mut sender, mut receiver) = tokio::io::duplex(128);
        let task = tokio::spawn(async move { read_request_line(&mut receiver).await.unwrap() });
        sender.write_all(b"GET /callback?state=a").await.unwrap();
        sender.write_all(b"&code=b HTTP/1.1\r\n").await.unwrap();
        assert_eq!(task.await.unwrap(), "GET /callback?state=a&code=b HTTP/1.1");
    }

    #[test]
    fn refuses_scope_escalation() {
        let reply = TokenReply {
            access_token: "not-a-real-token".into(),
            refresh_token: Some("not-a-real-refresh".into()),
            expires_in: 3600,
            refresh_token_expires_in: Some(7200),
            scope: Some("spark:all".into()),
        };
        assert!(token_from_reply(reply, None, OAuthScope::Granular).is_err());
    }

    #[test]
    fn broad_mode_requires_exact_single_scope() {
        let reply = TokenReply {
            access_token: "not-a-real-token".into(),
            refresh_token: Some("not-a-real-refresh".into()),
            expires_in: 3600,
            refresh_token_expires_in: Some(7200),
            scope: Some("spark:all".into()),
        };
        let tokens = token_from_reply(reply, None, OAuthScope::SparkAll).unwrap();
        assert!(tokens.scopes_verified);
        assert_eq!(tokens.scope_mode, OAuthScope::SparkAll);
    }

    #[test]
    fn rejects_extra_scopes() {
        let reply = TokenReply {
            access_token: "not-a-real-token".into(),
            refresh_token: Some("not-a-real-refresh".into()),
            expires_in: 3600,
            refresh_token_expires_in: Some(7200),
            scope: Some(format!("{} spark:kms", GRANULAR_SCOPES.join(" "))),
        };
        assert!(token_from_reply(reply, None, OAuthScope::Granular).is_err());
    }

    #[test]
    fn requires_both_expiries() {
        let reply = TokenReply {
            access_token: "not-a-real-token".into(),
            refresh_token: Some("not-a-real-refresh".into()),
            expires_in: 3600,
            refresh_token_expires_in: None,
            scope: None,
        };
        assert!(token_from_reply(reply, None, OAuthScope::Granular).is_err());
    }
}
