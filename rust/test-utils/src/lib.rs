//! Small helpers shared by the integration-test binaries.
//!
//! The helpers deliberately use only the Tokio runtime features already used
//! by the rest of the workspace; no extra async stack is required.

pub mod args;
pub mod http;
pub mod socks5;
