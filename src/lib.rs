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
#[cfg(feature = "server")]
pub mod diagnostics;
#[cfg(feature = "server")]
pub mod dialog;
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
