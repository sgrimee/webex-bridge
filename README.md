# webex-bridge

Local Webex connection owner, encrypted mirror and scoped API for UI and agent clients.

**Status:** Step 1 transport feasibility in progress. The `webex-bridge` CLI has
Keychain-backed PKCE login, read-only room/identity lookup, a metadata-only
Mercury probe, and explicit development-only forced refresh. The daemon,
encrypted mirror, scoped local API and message sends are **not implemented**;
`webex-bridged` deliberately refuses to start. Do not run it as a service yet.

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

During development this crate depends on the sibling `../webex-rust` checkout.
No PRs or remote dependency changes are required for local work.
