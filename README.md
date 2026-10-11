# webex-bridge

Local Webex connection owner, encrypted mirror and scoped API for UI and agent clients.

**Status:** Step 2 encrypted mirror and sync is in progress. The
`webex-bridge` CLI has Keychain-backed PKCE login, read-only room/identity
lookup, a metadata-only Mercury probe, explicit development-only forced
refresh, and mirror progress status. `webex-bridged` owns the Mercury
connection and maintains the encrypted SQLite mirror; `--dev-room` restricts
validation to an allowlisted room, while normal mode mirrors all rooms. The
daemon exposes a same-user, 0600 HTTP-over-UDS API at `run/bridge.sock`.
`GET /v1/status` is metadata-only; a paired `ui` session can read the encrypted
mirror, lazily hydrate one older message page, and directly send, edit, delete
or leave an allowlisted group room. Agent hosts can create an exclusive,
process-bound 60-second route lease and use the scoped inbox API: listing is
metadata-only (plus optional decrypted `senderName`/`roomTitle` display names),
and remote text enters model context only through an explicit local accept.
`GET /v1/agent/inbox/{id}/preview` returns the identical sanitized text of a
still-pending claimed delivery for local human display in the agent host UI,
without changing its state; anything else is an indistinguishable `404`.
Agent sends are encrypted, route-bound drafts; a one-time approval binds the
exact text and destination, then makes one non-retrying Webex request. SSE
revalidates the process-bound token for each metadata-only event and filters
agent events by claimed route. UI pairing uses a native macOS confirmation
showing the kernel-resolved executable path, then creates an in-memory UI
session. The macOS LaunchAgent installer is implemented; use the signed Mise
tasks below for local service management. Typed Rust UI clients remain in progress. Attachment content is never downloaded
by the bridge; the UI may offer a user-controlled external-open flow.

The dedicated `webex-bridge` integration is separate from the TUI integration.
OAuth defaults to ten granular scopes. The user explicitly approved
`[webex] oauth_scope = "spark_all"` for this installation after Webex WDM
rejected the confirmed granular token with HTTP 403. There is no automatic
scope upgrade: changing the config rejects cached tokens until a fresh
`webex-bridge login`. Secrets are in the macOS login Keychain; an unsigned CLI
cannot use the optional `biometric-keychain` feature (requires a properly
signed/entitled app). Never put tokens or client secrets in `config.toml`.

Local testing:

`mise.toml` provides the preferred, signing-safe shortcuts:

```sh
mise run check             # fmt check + tests + clippy
mise run build             # build and sign both local executables
mise run service:start     # signed build + install/start LaunchAgent
mise run service:restart   # signed build + replace/restart LaunchAgent
mise run service:status
mise run service:stop
```

```sh
cargo run --bin webex-bridge -- login
cargo run --bin webex-bridge -- status
# Always build and persistently sign the daemon before starting/installing it:
# an ad-hoc Cargo signature causes repeated Keychain/password prompts.
./scripts/sign-bridged-dev
# Installs/removes the per-user macOS LaunchAgent (persistent service).
# The installer rejects unsigned or ad-hoc-signed daemon binaries.
cargo run --bin webex-bridge -- install-service
cargo run --bin webex-bridge -- uninstall-service
# Explicit local diagnostic: emits roomId, title, isMember and result as JSON.
# It decrypts the room title for stdout only; daemon logs remain metadata-only.
cargo run --bin webex-bridge -- sync failures
cargo run --bin webex-bridge -- probe --room <approved-room-id>
# With [dev] write_allowlist configured, one-time refresh test:
cargo run --bin webex-bridge -- probe --room <approved-room-id> --refresh-after-secs 20
# For refresh-gap continuity, drop the listener for an explicit 1–120 s window.
cargo run --bin webex-bridge -- probe --room <approved-room-id> --refresh-after-secs 10 --refresh-gap-secs 60
# Explicit Step 1 membership diagnostics; the room must be allowlisted.
cargo run --bin webex-bridge -- membership invite --room <approved-room-id> --email <consented-participant-email>
# Temporarily removes and restores that existing participant; final state remains a member.
cargo run --bin webex-bridge -- membership cycle --room <approved-room-id> --email <consented-participant-email>
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
