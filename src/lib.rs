//! Webex bridge: connection owner, local mirror and scoped clients.
//! Step 0 defines module boundaries; implementations follow the approved plan.

pub mod auth;
pub mod config;
pub mod hydrate;
pub mod paths;
pub mod secrets;
pub mod supervisor;
pub mod threads;

#[cfg(feature = "server")]
pub mod api;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod dialog;
#[cfg(feature = "server")]
pub mod mirror;
#[cfg(feature = "server")]
pub mod outbox;
#[cfg(feature = "server")]
pub mod routing;
#[cfg(feature = "server")]
pub mod sync;
