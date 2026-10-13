# Agent-scope wire contract fixtures

Each `*.json` file here is a real request/response or SSE exchange from the
daemon. The test `api::contract_tests` produces them with the real handlers,
serializers and SSE stream over the Unix socket, using **synthetic IDs and text
only**. It fails if the daemon's output drifts from these committed files.
Consumers such as webex-pi should load these files in their own tests rather
than hand-writing the bridge's shapes.

- `kind: "http"`: `request.route` (a path template), the optional
  `request.body`, `response.status` and the optional `response.body`.
- `kind: "sse"`: `frames`, every agent SSE frame (`event`, `data`) that one
  daemon change produced, in wire order.
- Random or clock-derived values are fixed placeholders: `"<token>"` (bearer
  and approval tokens), `"<draft-id>"` and `"<timestamp>"` (`expiresAt`,
  `decidedAt`). Everything else is byte-for-byte what the daemon sent, as JSON.

Regenerate after an intended API change, then review the diff:

```sh
WEBEX_BRIDGE_UPDATE_CONTRACT=1 cargo test --features client contract
```
