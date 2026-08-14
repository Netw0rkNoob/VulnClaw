//! Reusable native TUI library for VulnClaw.
//!
//! The binary target is intentionally thin. State transitions, protocol
//! handling, rendering, persistence, and backend transport live in this
//! library so they can be exercised through integration tests.

pub mod app;
pub mod events;
pub mod exec;
pub mod prompts;
pub mod protocol;
pub mod sessions;
pub mod skills;
pub mod theme;
pub mod ui;
pub mod views;

pub use app::App;
pub use protocol::AppEvent;
