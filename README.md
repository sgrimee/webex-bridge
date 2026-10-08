# webex-bridge

Local Webex connection owner, encrypted mirror and scoped API for UI and agent clients.

**Status:** Step 0 skeleton only. The binaries intentionally refuse to run until the
transport, authentication and security layers in
[the implementation plan](../docs/webex-agent-channel-plan.md) are built.
No Webex connection, local API, or message send is implemented yet.

During development this crate depends on the sibling `../webex-rust` checkout.
Before publishing, push changes to webex-rust and switch the dependency to git.
