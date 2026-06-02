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

/// Canonical socket path of a system-service install — the path the systemd
/// unit pins via `--socket` (`/run/sandbox/sandboxd.sock`).
///
/// The operator CLI probes this FIRST when neither `--socket` nor
/// `SANDBOX_SOCKET` is set, so a deployed host's CLI reaches the system daemon
/// out of the box (the daemon listens here, but the CLI's XDG/HOME default
/// would otherwise never look here). Shared between `main`'s
/// `default_socket_path` and `doctor::resolve_socket_path_strict` so the CLI
/// and its self-diagnosis probe the same location.
pub const SYSTEM_SOCKET_PATH: &str = "/run/sandbox/sandboxd.sock";
