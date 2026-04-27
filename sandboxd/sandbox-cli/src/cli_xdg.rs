//! XDG config-path resolution shared by the CLI's user-config
//! consumers.
//!
//! Spec § "CLI & UX → Config file" mandates "one resolver, not two":
//! `~/.config/sandboxd/presets/` (preset catalog) and
//! `~/.config/sandboxd/config.json` (CLI defaults) must agree on how
//! they discover `~/.config/sandboxd/`. This module is that one
//! resolver.
//!
//! Precedence is the same as the rest of the project's XDG plumbing:
//!
//! 1. an explicit override (used by tests to redirect away from a
//!    developer's real `~/.config`);
//! 2. `$XDG_CONFIG_HOME` if set and non-empty;
//! 3. `$HOME/.config`.
//!
//! Returning `None` from the last fallback (no `$HOME` either) is the
//! "nothing to load" signal — callers treat it as an empty config, not
//! as an error.

use std::path::{Path, PathBuf};

/// Resolve the per-user `sandboxd` config base directory (i.e.
/// `~/.config/sandboxd/`).
///
/// Returns `None` when neither `$XDG_CONFIG_HOME` nor `$HOME` is set
/// (or both are empty). Callers append the per-feature subpath: e.g.
/// `presets/` for the preset catalog or `config.json` for the CLI
/// defaults file.
///
/// `xdg_override` lets tests redirect away from the developer's real
/// `~/.config`. When set, it short-circuits both env checks and is
/// returned as-is.
pub fn resolve_sandboxd_config_dir(xdg_override: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = xdg_override {
        return Some(path.to_path_buf());
    }

    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("sandboxd"));
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home).join(".config").join("sandboxd"));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Save and restore the relevant env vars so tests can mutate them
    /// without polluting one another. `cargo nextest run` already
    /// process-isolates each test, but a guard keeps the intent
    /// explicit and the behaviour unchanged if the runner ever swaps to
    /// thread-isolation.
    struct EnvGuard {
        xdg: Option<String>,
        home: Option<String>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self {
                xdg: std::env::var("XDG_CONFIG_HOME").ok(),
                home: std::env::var("HOME").ok(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: tests mutate process-global env; the guard
            // restores the prior state on drop. Restoring explicitly
            // (vs. leaving the env mutated) keeps unrelated tests in
            // the same binary unaffected on thread-isolated runners.
            unsafe {
                match self.xdg.take() {
                    Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                    None => std::env::remove_var("XDG_CONFIG_HOME"),
                }
                match self.home.take() {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    #[test]
    fn override_short_circuits_env() {
        let _guard = EnvGuard::new();
        // SAFETY: process-global env mutation; restored by EnvGuard on
        // drop.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", "/should/be/ignored");
            std::env::set_var("HOME", "/should/also/be/ignored");
        }

        let override_path = PathBuf::from("/explicit/override");
        let resolved = resolve_sandboxd_config_dir(Some(&override_path));
        assert_eq!(resolved.as_deref(), Some(override_path.as_path()));
    }

    #[test]
    fn xdg_config_home_wins_over_home() {
        let _guard = EnvGuard::new();
        // SAFETY: process-global env mutation; restored by EnvGuard on
        // drop.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", "/xdg/home");
            std::env::set_var("HOME", "/usr/somebody");
        }
        let resolved = resolve_sandboxd_config_dir(None).expect("resolved");
        assert_eq!(resolved, PathBuf::from("/xdg/home").join("sandboxd"));
    }

    #[test]
    fn empty_xdg_falls_back_to_home() {
        let _guard = EnvGuard::new();
        // SAFETY: process-global env mutation; restored by EnvGuard on
        // drop.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", "");
            std::env::set_var("HOME", "/usr/somebody");
        }
        let resolved = resolve_sandboxd_config_dir(None).expect("resolved");
        assert_eq!(
            resolved,
            PathBuf::from("/usr/somebody")
                .join(".config")
                .join("sandboxd")
        );
    }

    #[test]
    fn no_env_returns_none() {
        let _guard = EnvGuard::new();
        // SAFETY: process-global env mutation; restored by EnvGuard on
        // drop.
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("HOME");
        }
        assert!(resolve_sandboxd_config_dir(None).is_none());
    }
}
