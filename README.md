# webex-bridge

Local Webex connection owner, encrypted mirror and scoped API for UI and agent clients.

**Status:** Step 2 encrypted mirror and sync is in progress. The
`webex-bridge` CLI has Keychain-backed PKCE login, read-only room/identity
lookup, a metadata-only Mercury probe, explicit development-only forced
refresh, and mirror progress status. `webex-bridged` owns the Mercury
connection and maintains the encrypted SQLite mirror; `--dev-room` restricts
validation to an allowlisted room, while normal mode mirrors all rooms. The
scoped local API and message sends remain unimplemented, so do not run the
daemon as a service yet.

The dedicated `webex-bridge` integration is separate from the TUI integration.
OAuth defaults to ten granular scopes. The user explicitly approved
`[webex] oauth_scope = "spark_all"` for this installation after Webex WDM
rejected the confirmed granular token with HTTP 403. There is no automatic
scope upgrade: changing the config rejects cached tokens until a fresh
`webex-bridge login`. Secrets are in the macOS login Keychain; an unsigned CLI
cannot use the optional `biometric-keychain` feature (requires a properly
signed/entitled app). Never put tokens or client secrets in `config.toml`.

Local testing:

```sh
cargo run --bin webex-bridge -- login
cargo run --bin webex-bridge -- status
# Explicit local diagnostic: emits roomId, title, isMember and result as JSON.
# It decrypts the room title for stdout only; daemon logs remain metadata-only.
cargo run --bin webex-bridge -- sync failures
cargo run --bin webex-bridge -- probe --room <approved-room-id>
# With [dev] write_allowlist configured, one-time refresh test:
cargo run --bin webex-bridge -- probe --room <approved-room-id> --refresh-after-secs 20
```

Probe output contains only IDs, timestamps, lengths and sanitized event types,
not message bodies. `webex-bridged --dev-room <allowlisted ID>` is a restricted
Step 2 validation mode; without it, the daemon follows D7 and mirrors all
rooms. Optional `[webex] retention_max_age = "365d"` prunes old encrypted
message revisions; leaving it unset keeps all history. All write paths must
enforce `[dev] write_allowlist` in later steps. See [the local implementation plan](../docs/webex-agent-channel-plan.md)
and [`docs/events.md`](docs/events.md) for observations.

## Daemon diagnostics and macOS development Keychain access

`bridged.log` is deliberately metadata-only: it never includes Webex payloads,
room/message IDs, tokens, secrets, or decrypted mirror data. The daemon now
emits timestamped lifecycle events at normal level (startup, mirror open,
connect/reconnect, refresh, and sync counts/duration). For additional safe
progress events, run it with `--debug` or set `WEBEX_BRIDGE_LOG=debug`:

```sh
./target/debug/webex-bridged --debug
# or, after the initial setup below:
WEBEX_BRIDGE_LOG=debug ./scripts/run-bridged-dev
```

Do **not** disable the Keychain or cache Webex secrets in a file for development.
A normal daemon startup reads two distinct Keychain items: the OAuth state and
the encrypted-mirror key. On a newly trusted executable macOS may therefore
ask once per item. Choosing **Always Allow** should prevent prompts on later
starts *only while the executable keeps the same code requirement*.

Cargo gives each rebuilt `target/debug/webex-bridged` an ad-hoc signature, whose
code hash changes after each build; macOS therefore treats it as a new caller
and requests access again. Use the development launcher after creating an
Apple Development or local Code Signing certificate in Keychain Access/Xcode:

```sh
./scripts/run-bridged-dev --debug
```

It builds the daemon and re-signs it with a persistent identity and stable
identifier before starting it. On its first run, choose **Always Allow** for
each Keychain item; subsequent rebuilds/restarts should not prompt. If several
signing identities are present, select one explicitly:

```sh
WEBEX_BRIDGE_CODESIGN_IDENTITY='Apple Development: Your Name (TEAMID)' \
  ./scripts/run-bridged-dev --debug
```

The launcher intentionally refuses to fall back to an ad-hoc signature: that
would reintroduce the repeated prompts. A password-file/plaintext development
mode is not provided.

During development this crate depends on the sibling `../webex-rust` checkout.
No PRs or remote dependency changes are required for local work.
