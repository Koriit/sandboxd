//! Library surface for `sandbox-cli`.
//!
//! Houses the CLI's reusable building blocks — backend resolution
//! (`backend`), capabilities cache (`backends_cache`), XDG config-path
//! resolution (`cli_xdg`), and the client-local preset system
//! (`presets`) — so binary-level integration tests can exercise them
//! in-process without re-spawning the compiled binary.
//!
//! The CLI entry point itself still lives in `src/main.rs`, which
//! imports these modules via `sandbox_cli::*`.

pub mod backend;
pub mod backends_cache;
pub mod cfg_migrations;
pub mod cli_xdg;
pub mod doctor;
pub mod presets;
pub mod proxy;
pub mod ssh_commands;
pub mod ssh_config;
pub mod update;
