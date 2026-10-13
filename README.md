# webex-bridge

Local Webex connection owner, encrypted mirror and scoped API for UI and agent clients.

**Status:** Steps 1–2 (transport, encrypted mirror and sync) are complete and
live-validated; Step 3 (daemon API and service) is functionally complete on
`step-3-api-service` and awaiting its final live validation (see the
[plan](../docs/webex-agent-channel-plan.md)). No Webex writes happen without an
explicit local action.

- **Daemon and mirror.** `webex-bridged` owns the single Mercury connection and
  keeps an encrypted SQLite mirror of all rooms (`--dev-room` restricts it to
  one allowlisted room). Message revisions are opaque and strictly increasing
  per message; optional `retention_max_age` prunes old history.
- **Local API.** Same-user, 0600 HTTP-over-UDS at `run/bridge.sock` with
  kernel peer checks and process-bound, in-memory bearer tokens.
  `GET /v1/status` is unauthenticated and metadata-only.
- **UI scope.** Pairing needs a native macOS confirmation showing the
  kernel-resolved executable path. A paired UI reads the mirror (with bounded
  lazy hydration and thread reads), receives metadata-only SSE with continuity
  markers, and can send, edit, delete or leave allowlisted group rooms.
  UI leases last 10 minutes; `POST /v1/ui/sessions/renew` extends the same
  token by 10 minutes for the issuing process only, while its pairing still
  exists, up to 12 hours after issuance (SSE follows the extended lease).
  `webex-bridge ui pairings` and `webex-bridge ui unpair (PATH|--all)` list
  and remove pairings through the daemon (Keychain-free) and end the removed
  pairings' live sessions at once. Unpair needs no confirmation dialog: it only
  removes access, re-pairing requires the native dialog, and webex-pi's
  tool-call guard blocks agents from referencing the bridge or its socket.
  `webex_bridge::client` is the typed, client-only UDS client used by the TUI;
  `webex_bridge::dto` exports the write bounds it shares with the daemon.
- **Agent scope.** Hosts claim exclusive 60-second leases for configured
  `(agentName, workspace)` routes (the claim also carries the daemon account's
  opaque `selfPersonId` once known). Routing filters by sender, address, size,
  rate, queue and retention. The inbox list is metadata-only plus best-effort
  `senderName`/`roomTitle`; `preview` shows the identical sanitized text to the
  human without changing state; only `accept` releases text into model
  context. Released text is stripped of terminal controls and invisible or
  smuggling characters. Route-scoped SSE carries `inbox.new`,
  `inbox.revised`, `inbox.deleted`, `outbox.status` and `connection.status`.
- **Agent sends.** Encrypted, route-bound drafts; a one-time approval binds the
  exact text and destination, then one non-retrying Webex request. The
  bridge's own sends never route back as inbound, and a `delivery-unknown`
  send is reconciled to `sent` when its echo is mirrored.
- **Service.** A per-user macOS LaunchAgent runs a verified signed copy under
  `~/Library/Application Support/webex-bridge/bin/` (see below); daemon logs
  are metadata-only. Attachment content is never downloaded by the bridge.

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
mise run service:start     # signed build, copy into private bin/, install/start LaunchAgent
mise run service:restart   # signed build, re-copy into private bin/, restart LaunchAgent
mise run service:status    # installed CLI (reads Keychain auth state)
mise run service:health    # socket-only daemon status, no Keychain access
mise run service:stop      # remove LaunchAgent and installed binaries
```

The LaunchAgent never runs a binary from the build tree. `install-service`
copies the persistently signed `webex-bridged` and `webex-bridge` into the
private 0700 directory `~/Library/Application Support/webex-bridge/bin/`,
re-verifies the signature of each copy (`codesign --verify --strict`, expected
identifier, no ad-hoc signature) and atomically replaces the installed files;
the plist points at that copy. Later `cargo build`/`cargo test` runs therefore
cannot replace or ad-hoc re-sign the running daemon. The build scripts and
Mise tasks honour `CARGO_TARGET_DIR`.

Upgrading from an install made before this change (whose plist still points
at `target/debug/webex-bridged`): build outside the checkout so the running
binary is not overwritten in place, then reinstall once:

```sh
CARGO_TARGET_DIR=$HOME/tmp/wb-target mise run service:restart
```

```sh
cargo run --bin webex-bridge -- login
cargo run --bin webex-bridge -- status
# Always build and persistently sign the daemon before starting/installing it:
# an ad-hoc Cargo signature causes repeated Keychain/password prompts.
./scripts/sign-bridged-dev
# Installs/removes the per-user macOS LaunchAgent (persistent service) from the
# signed build (`cargo run` would rebuild ad hoc and is refused by the
# installer, which rejects unsigned or ad-hoc-signed source binaries and copies).
"${CARGO_TARGET_DIR:-target}/debug/webex-bridge" install-service
"$HOME/Library/Application Support/webex-bridge/bin/webex-bridge" uninstall-service
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
message revisions (and their agent delivery metadata); leaving it unset keeps
all history. Message `revision` values come from one mirror-wide counter: they
are opaque, strictly increasing per message and never reused, even when a pruned
message is later re-hydrated, but they are not contiguous and not an edit count. All write paths must
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
