//! macOS daemon startup integration tests.
//!
//! These are black-box tests that spawn the `sandboxd` binary and assert
//! startup behaviour. They require macOS; on Linux the tests compile but
//! are skipped at runtime (no-op gate at the top of each test).
//!
//! ## Self-contained seams
//!
//! The `spawn_and_wait` helper redirects every production path the macOS
//! startup binds or creates before the IP-forwarding check, so the test
//! runs as the current user without root or `_sandbox` membership:
//!
//! | Production path | Override | Notes |
//! |---|---|---|
//! | `/var/run/sandbox/broker.sock` | `SANDBOX_BROKER_SOCKET` → tempdir | User-facing env var, always active (no feature flag needed) |
//! | `{base_dir}/sessions.db` | `--base-dir` → tempdir | SQLite in tempdir |
//! | `{socket_dir}/sandboxd.sock` | `--socket` → tempdir | API socket in tempdir |
//! | `/etc/sandboxd/users.conf` | `SANDBOX_USERS_CONF` → tempdir | Well-established test seam |
//! | `/etc/sandboxd/bridge.conf` | absent is OK (returns `Ok(())`) | No override needed |
//!
//! The startup sequence between broker bind and IP-forwarding check
//! (`LimaManagerRegistry::new` + some pure in-memory construction) has no
//! additional production filesystem access. `guest_agent_path()` is called
//! *after* the macOS startup block, so the early-exit tests never reach it.
//!
//! ## Build requirements
//!
//! Must be built with:
//! ```
//! --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override
//! ```
//! These transitively enable `sandbox-core/test-env-override`, which activates
//! the `target/debug/` sibling fallback in `guest_agent_path()`. Without this,
//! tests that continue past the broker bind (e.g. anything that reaches step 3+)
//! would fail because `/usr/local/libexec/sandboxd/sandbox-guest` does not exist
//! in a dev environment. For the early-exit tests (forwarding ON, socket_vmnet
//! absent) this is not strictly required since the daemon exits before reaching
//! `guest_agent_path()`, but the canonical invocation always passes these features.
//!
//! ## What is tested here
//!
//! ### `integration_macos_daemon_startup_refuses_when_ip_forwarding_on`
//! Verifies the daemon refuses to start when host IP forwarding is enabled.
//! Gates on the current host state — skips automatically when forwarding is
//! off. Enable forwarding first (`sudo sysctl -w net.inet.ip.forwarding=1`),
//! then re-run. See the test body for the exact command.
//!
//! ### `integration_macos_daemon_startup_refuses_when_socket_vmnet_absent`
//! Verifies the daemon fails fast when socket_vmnet is absent from the staged
//! path. Skips when socket_vmnet is installed (cannot remove root-owned files
//! to simulate absence).
//!
//! ## Invocation
//!
//! ```
//! cd sandboxd && cargo nextest run --profile integration \
//!   --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override \
//!   -E 'test(integration_macos_daemon_startup)'
//! ```
//!
//! ## Live cross-user 6b test
//! The full cross-user 6b live test (real agent, real VM) is deferred to M21.
//! The agent-gated gate is unit-tested in `broker.rs` without a live agent.

#[cfg(not(target_os = "macos"))]
#[test]
fn integration_macos_daemon_startup_skipped_on_non_macos() {
    // This test file is macOS-specific. On Linux the tests are no-ops.
    // The compiler includes them on all platforms; they just return early.
}

// The actual test bodies are macOS-only.
#[cfg(target_os = "macos")]
mod macos_startup_tests {
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    fn sandboxd_bin() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
    }

    /// Resolve the current process's uid to a username via nix.
    ///
    /// Used in the users.conf fixture so `allow_users` contains a real username
    /// the daemon's allocation-pool lookup can resolve to the current uid.
    fn current_username() -> String {
        let uid = nix::unistd::Uid::current();
        nix::unistd::User::from_uid(uid)
            .expect("getpwuid_r succeeded")
            .expect("uid maps to a passwd entry")
            .name
    }

    /// Spawn the daemon with a self-contained environment and wait for it to exit.
    ///
    /// Returns `(stderr_text, exit_code)`. The daemon is expected to exit
    /// within `timeout_secs` seconds (these are failure-path tests that
    /// should exit quickly without doing any I/O-heavy work).
    ///
    /// ## Seams applied
    ///
    /// - `SANDBOX_BROKER_SOCKET` → tempdir socket (redirects `/var/run/sandbox/broker.sock`)
    /// - `SANDBOX_USERS_CONF` → tempdir fixture (redirects `/etc/sandboxd/users.conf`)
    /// - `--base-dir` → tempdir (redirects `/var/lib/sandboxd/<uid>/`)
    /// - `--socket` → tempdir (redirects the API socket)
    /// - `XDG_DATA_HOME` / `XDG_RUNTIME_DIR` → tempdir (suppresses any XDG-default fallbacks)
    ///
    /// With these overrides, the broker bind succeeds as the current user,
    /// and the startup reaches the macOS prerequisite checks (step 2) where
    /// IP-forwarding and socket_vmnet are asserted.
    fn spawn_and_wait(extra_env: &[(&str, String)], timeout_secs: u64) -> (String, i32) {
        let tmp = TempDir::new().expect("tempdir");
        let users_conf_path = tmp.path().join("users.conf");
        let socket_path = tmp.path().join("sandboxd.sock");
        let base_dir = tmp.path().join("state");
        // The broker socket is redirected to the tempdir. `SANDBOX_BROKER_SOCKET`
        // is a user-facing env var honoured by broker_socket_path() without any
        // feature-flag requirement, so this works in all builds.
        let broker_socket_path = tmp.path().join("broker.sock");

        // Write a minimal valid users.conf. The daemon requires this on macOS
        // too (the container backend and NetworkManager use the /28 pool CIDR
        // from users.conf). Key requirements:
        // - `_schema_version`: must use the underscore-prefixed name (serde
        //   rename); `schema_version` is an unknown field and causes a
        //   deny_unknown_fields parse failure.
        // - Value must be 1 (the only currently supported version).
        // - `allow_users` takes usernames, not uid numbers; resolve via getpwuid.
        let username = current_username();
        let users_conf = format!(
            r#"{{"_schema_version":1,"subnets":[{{"cidr":"10.209.0.0/24","allow_users":["{username}"]}}]}}"#
        );
        {
            let mut f = std::fs::File::create(&users_conf_path).expect("create users.conf");
            f.write_all(users_conf.as_bytes())
                .expect("write users.conf");
        }

        let mut cmd = Command::new(sandboxd_bin());
        cmd.arg("--base-dir")
            .arg(&base_dir)
            .arg("--socket")
            .arg(&socket_path)
            .env("XDG_DATA_HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", tmp.path())
            .env("SANDBOX_USERS_CONF", &users_conf_path)
            // Redirect the broker socket so the daemon can bind it as the current
            // user. Production default is /var/run/sandbox/broker.sock which is
            // owned 0750 _sandbox:_sandbox and not writable by a non-_sandbox uid.
            .env("SANDBOX_BROKER_SOCKET", &broker_socket_path)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        for (k, v) in extra_env {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn sandboxd");

        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let exit_code = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code().unwrap_or(-1),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!(
                            "sandboxd did not exit within {timeout_secs}s. \
                             tmp dir: {:?}",
                            tmp.path()
                        );
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("try_wait failed: {e}"),
            }
        };

        let mut stderr_output = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut stderr_output);
        }
        (stderr_output, exit_code)
    }

    /// Test that the daemon refuses to start when host IP forwarding is on.
    ///
    /// The daemon's macOS startup block asserts `net.inet.ip.forwarding == 0`
    /// as step 2f — the first check inside the macOS-specific startup sequence.
    /// If forwarding is on, the daemon refuses immediately with a hard error.
    ///
    /// ## Startup sequence: what fires before the forwarding check
    ///
    /// The ordering is:
    ///
    /// 1. `users.conf` parse + allocation pool (fixture provided in tempdir)
    /// 2. `SessionStore::new` (SQLite in tempdir)
    /// 3. macOS broker bind (redirected to tempdir via `SANDBOX_BROKER_SOCKET`)
    /// 4. `LimaManagerRegistry::new` (pure in-memory)
    /// 5. **[macOS startup block]** → **IP-forwarding check** (step 2f)
    ///    → hard refuse with "host IP forwarding ... must be 0" error
    ///
    /// With all seams set, steps 1-4 succeed as the current user, and the
    /// forwarding check fires as expected.
    ///
    /// ## How to run live
    ///
    /// ```sh
    /// # Enable forwarding (requires root):
    /// sudo sysctl -w net.inet.ip.forwarding=1
    ///
    /// # Run the test (from the workspace root):
    /// cd sandboxd && cargo nextest run --profile integration \
    ///   --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override \
    ///   -E 'test(integration_macos_daemon_startup_refuses_when_ip_forwarding_on)'
    ///
    /// # Restore (required — always restore after the test):
    /// sudo sysctl -w net.inet.ip.forwarding=0
    /// ```
    ///
    /// The test auto-skips when forwarding is already off, so it is safe to
    /// include in the integration suite without the sudo flip.
    #[test]
    fn integration_macos_daemon_startup_refuses_when_ip_forwarding_on() {
        // Check current forwarding state. Skip if forwarding is off (normal state).
        let out = std::process::Command::new("sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
            .expect("sysctl must be available on macOS");
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();

        if v != "1" {
            println!(
                "SKIP: net.inet.ip.forwarding={v} (off). \
                 To run this live test: sudo sysctl -w net.inet.ip.forwarding=1, \
                 run the test, then sudo sysctl -w net.inet.ip.forwarding=0."
            );
            return;
        }

        // Host IP forwarding is ON. The daemon must refuse to start.
        let (stderr, code) = spawn_and_wait(&[], 10);

        assert_ne!(
            code, 0,
            "daemon must exit non-zero when host IP forwarding is on; stderr: {stderr}"
        );
        assert!(
            stderr.contains("forwarding") || stderr.contains("net.inet.ip.forwarding"),
            "error message must mention forwarding; got: {stderr}"
        );
    }

    /// Test that the daemon refuses to start when socket_vmnet is absent.
    ///
    /// On a dev machine where `/Library/sandboxd/socket_vmnet` is NOT installed,
    /// the daemon must fail fast with an actionable error. The socket_vmnet check
    /// is step 2a of the macOS startup sequence, immediately after the
    /// IP-forwarding check (step 2f).
    ///
    /// Skips when socket_vmnet IS installed (cannot remove a root-owned file to
    /// simulate absence in a self-contained test).
    #[test]
    fn integration_macos_daemon_startup_refuses_when_socket_vmnet_absent() {
        let staged_path = "/Library/sandboxd/socket_vmnet";
        if std::path::Path::new(staged_path).exists() {
            // socket_vmnet is installed. Can't test the absent case without removing
            // a root-owned file. Skip on fully-installed hosts.
            println!("SKIP: {staged_path} exists; can only test absence on uninstalled hosts");
            return;
        }

        let (stderr, code) = spawn_and_wait(&[], 10);

        assert_ne!(
            code, 0,
            "daemon must exit non-zero when socket_vmnet is absent; stderr: {stderr}"
        );
        assert!(
            stderr.contains("socket_vmnet") || stderr.contains("Library/sandboxd"),
            "error message must mention socket_vmnet or the staged path; got: {stderr}"
        );
    }
}

// Re-export the skipped test for non-macOS builds so nextest sees at least one
// test in this file (avoids "no tests found" warnings).
#[cfg(not(target_os = "macos"))]
#[test]
fn integration_macos_daemon_startup_platform_gate() {
    // On non-macOS platforms all macOS-specific startup tests are no-ops.
    // This test exists only to satisfy nextest's "at least one test" check.
}
