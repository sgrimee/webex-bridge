# webex-bridge

Local Webex connection owner, encrypted mirror and scoped API for UI and agent clients.

macOS only for now (LaunchAgent, Keychain, native pairing dialog). No Webex
write happens without an explicit local action.

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

## Setup

Requirements: macOS, Rust 1.88 (`rust-toolchain.toml`) and a persistent code
signing identity in your login Keychain (an Apple Development certificate or a
self-signed "Code Signing" certificate created in Keychain Access); [mise](https://mise.jdx.dev) is optional.

1. **Create your own Webex integration** at
   <https://developer.webex.com/my-apps>, with the redirect URI
   `http://localhost:8765/callback` and these scopes: `spark:messages_read`,
   `spark:messages_write`, `spark:rooms_read`, `spark:rooms_write`,
   `spark:memberships_read`, `spark:memberships_write`, `spark:people_read`,
   `spark:teams_read`, `spark:devices_read`, `spark:devices_write`. Keep its
   client ID and secret for step 3. Use a dedicated integration for the
   bridge, not one shared with another client.
2. **Build, sign and install the service** (copies the signed binaries into
   `~/Library/Application Support/webex-bridge/bin/` and starts the
   LaunchAgent):

   ```sh
   mise run service:start
   # without mise: ./scripts/sign-bridged-dev, then
   #   "${CARGO_TARGET_DIR:-target}/debug/webex-bridge" install-service
   ```
3. **Log in with the installed CLI:**

   ```sh
   CLI="$HOME/Library/Application Support/webex-bridge/bin/webex-bridge"
   "$CLI" login     # prompts once for the client ID and secret, then OAuth
   "$CLI" health    # socket-only daemon status, no Keychain access
   "$CLI" status    # authentication and mirror progress
   ```

   `login` opens the browser for the OAuth consent and stores the client
   credentials and tokens in the macOS login Keychain. Always use the
   installed, signed CLI: a `cargo run` build is ad-hoc signed, so the
   Keychain would prompt on every rebuild.

Clients (the terminal UI, the pi agent channel) then pair with the daemon
through a native confirmation dialog.

OAuth defaults to the ten granular scopes above. If Webex WDM rejects that
token with HTTP 403 (it did for the author's account), the only alternative is
an explicit opt-in: set `[webex] oauth_scope = "spark_all"` in
`~/Library/Application Support/webex-bridge/config.toml`, add `spark:all` to the
integration and run `login` again. There is no automatic scope upgrade: a
changed scope rejects cached tokens until a fresh `login`. Secrets live only in
the macOS login Keychain; never put tokens or client secrets in `config.toml`.
An unsigned CLI cannot use the optional `biometric-keychain` feature (it needs
a properly signed and entitled app).

**Keychain prompts.** The daemon reads two Keychain items (OAuth state and the
mirror key). With a self-signed development identity, macOS asks again for
each item after a rebuild; choose **Always Allow** each time. This is accepted
for development; an ad-hoc (`cargo run`) signature is refused instead, because
its prompts would never stop.

## Development

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

```sh
CLI="$HOME/Library/Application Support/webex-bridge/bin/webex-bridge"
"$CLI" login
"$CLI" status
# Always build and persistently sign the daemon before starting/installing it:
# an ad-hoc Cargo signature causes repeated Keychain/password prompts.
./scripts/sign-bridged-dev
# Installs/removes the per-user macOS LaunchAgent (persistent service) from the
# signed build (`cargo run` would rebuild ad hoc and is refused by the
# installer, which rejects unsigned or ad-hoc-signed source binaries and copies).
"${CARGO_TARGET_DIR:-target}/debug/webex-bridge" install-service
"$CLI" uninstall-service
# Explicit local diagnostic: emits roomId, title, isMember and result as JSON.
# It decrypts the room title for stdout only; daemon logs remain metadata-only.
"$CLI" sync failures
# Webex device diagnostics (no IDs or names printed): counts, ages, list size/time.
"$CLI" devices summary
# Dry run listing this host's stale bridge/webex-tui devices; deletes nothing.
# Deleting requires the exact count and fingerprint the dry run printed.
"$CLI" devices prune
"$CLI" probe --room <approved-room-id>
# With [dev] write_allowlist configured, one-time refresh test:
"$CLI" probe --room <approved-room-id> --refresh-after-secs 20
# For refresh-gap continuity, drop the listener for an explicit 1–120 s window.
"$CLI" probe --room <approved-room-id> --refresh-after-secs 10 --refresh-gap-secs 60
# Membership diagnostics; the room must be allowlisted.
"$CLI" membership invite --room <approved-room-id> --email <consented-participant-email>
# Temporarily removes and restores that existing participant; final state remains a member.
"$CLI" membership cycle --room <approved-room-id> --email <consented-participant-email>
```

Probe output contains only IDs, timestamps, lengths and sanitized event types,
not message bodies. `webex-bridged --dev-room <allowlisted ID>` is a restricted
validation mode; without it, the daemon mirrors all rooms. Optional
`[webex] retention_max_age = "365d"` prunes old encrypted
message revisions (and their agent delivery metadata); leaving it unset keeps
all history. Message `revision` values come from one mirror-wide counter: they
are opaque, strictly increasing per message and never reused, even when a pruned
message is later re-hydrated, but they are not contiguous and not an edit count.
See [`docs/events.md`](docs/events.md) for observed Mercury event shapes.

## Daemon diagnostics and macOS development Keychain access

`bridged.log` is deliberately metadata-only: it never includes Webex payloads,
room/message IDs, tokens, secrets, or decrypted mirror data. The daemon
emits timestamped lifecycle events at normal level (startup, mirror open,
connect/reconnect, refresh, and sync counts/duration). For additional safe
progress events, run it with `--debug` or set `WEBEX_BRIDGE_LOG=debug`. Debug
mode also logs each agent-visible bus event (`agent.event_published`, with the
receiver count) and each agent SSE frame (`agent.sse_emitted`), by event name
and route name only:

```sh
./target/debug/webex-bridged --debug
# or, with the signing setup below:
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
identifier before starting it. Choose **Always Allow** for each Keychain item
when asked; with a self-signed identity this repeats after each rebuild (see
Setup). If several
signing identities are present, select one explicitly:

```sh
WEBEX_BRIDGE_CODESIGN_IDENTITY='Apple Development: Your Name (TEAMID)' \
  ./scripts/run-bridged-dev --debug
```

The launcher intentionally refuses to fall back to an ad-hoc signature: that
would reintroduce the repeated prompts. A password-file/plaintext development
mode is not provided.

## Dependencies

The `webex` crate comes from the
[sgrimee/webex-rust](https://github.com/sgrimee/webex-rust) fork. Published
branches pin it as a git dependency; for local work on both crates, point it at
a sibling `../webex-rust` checkout (a path dependency or a `[patch]` entry).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
