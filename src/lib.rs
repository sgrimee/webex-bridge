//! Webex bridge: connection owner, local mirror and scoped clients.
//! Step 0 defines module boundaries; implementations follow the approved plan.

/// Wire-safe UI DTOs shared by the client and daemon API boundary.
pub mod dto;
/// Per-user protected runtime and socket paths.
pub mod paths;
/// UI-neutral message thread grouping.
pub mod threads;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod api;
#[cfg(feature = "server")]
pub mod auth;
#[cfg(feature = "server")]
pub mod config;
/// Feature-gated, injected-environment development-secret bootstrap guards.
/// This module never reads this process environment by itself.
#[cfg(feature = "dev-env-secrets")]
pub mod dev_env_secrets;
#[cfg(feature = "server")]
pub mod devices;
#[cfg(feature = "server")]
pub mod diagnostics;
#[cfg(feature = "server")]
pub mod dialog;
/// Keychain-free daemon health check over the protected socket.
#[cfg(feature = "server")]
pub mod health;
#[cfg(feature = "server")]
pub mod hydrate;
#[cfg(feature = "server")]
pub mod mirror;
#[cfg(feature = "server")]
pub mod outbox;
#[cfg(feature = "server")]
pub mod rooms;
#[cfg(feature = "server")]
pub mod routing;
#[cfg(feature = "server")]
pub mod secrets;
#[cfg(feature = "server")]
pub mod service;
#[cfg(feature = "server")]
pub mod supervisor;
#[cfg(feature = "server")]
pub mod sync;
/// Keychain-free UI pairing listing and removal over the protected socket.
#[cfg(feature = "server")]
pub mod ui_pairing;
