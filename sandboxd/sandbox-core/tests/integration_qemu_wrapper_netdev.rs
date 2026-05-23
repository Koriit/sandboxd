//! Integration test: the QEMU wrapper script emits a `-netdev bridge,…`
//! argv that contains **no** `helper=` parameter.
//!
//! The wrapper script's bridge-networking branch was simplified in the
//! daemon-productionization revision: QEMU now resolves
//! `qemu-bridge-helper` via its compile-time `libexecdir` default, and
//! the rootless-Docker code path that previously substituted an
//! nsenter wrapper is gone. Hermetic regression tests inside
//! `sandbox-core::lima` pin the script source; this integration test
//! pins the *runtime behavior*: that the wrapper, when actually
//! executed with a representative `SANDBOX_DOCKER_BRIDGE` value,
//! produces an argv with the bare `br=` segment and nothing else.
//!
//! Mechanism:
//!   1. Stage the wrapper script via [`LimaManager::ensure_qemu_wrapper`]
//!      into a tempdir's `libexec/`.
//!   2. Override `PATH` so the wrapper resolves `qemu-system-x86_64` to
//!      a stub that simply prints its argv.
//!   3. Set `SANDBOX_DOCKER_BRIDGE` to a representative bridge name.
//!   4. Exec the wrapper with `-machine help` arg — the wrapper's
//!      help-passthrough short-circuits to `exec REAL_QEMU "$@"`, so
//!      our stub sees the original args; that path doesn't exercise
//!      the bridge branch. To exercise the bridge branch we pass
//!      neutral non-help args (`-version-not-really`, etc.) — but
//!      the wrapper's help-arg matcher is anchored to the literal
//!      tokens (`help`, `--version`, `--help`, `-help`); a custom
//!      arg flows through the `EXTRA_ARGS` build path and the
//!      stub captures the full composed argv.
//!
//! Spec reference: daemon-productionization § 11.6 —
//! `integration_qemu_wrapper_no_helper_param_in_netdev`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use sandbox_core::lima::{DEFAULT_BASE_VM_NAME, LimaManager};

/// Build the wrapper, stage a fake `qemu-system-x86_64` next to it,
/// exec the wrapper with a benign non-help argument, and return the
/// captured argv that the stub printed.
///
/// Returns `None` when `limactl` is not on PATH (typical on ubuntu-latest
/// CI runners that have Docker but not Lima). The caller skips gracefully
/// via `eprintln!` + `return` rather than panicking, consistent with the
/// soft-skip pattern used in `integration_guest_refresh_lima_backend`.
fn capture_wrapper_argv(bridge_name: &str) -> Option<String> {
    let dir = tempfile::TempDir::new().expect("tempdir");

    // The LimaManager constructor probes PATH for `limactl`. On CI
    // runners that have Docker but not Lima (e.g. ubuntu-latest), this
    // returns Err — the caller skips rather than panics.
    let mgr = match LimaManager::new(dir.path().to_path_buf(), DEFAULT_BASE_VM_NAME.to_string()) {
        Ok(m) => m,
        Err(_) => return None,
    };
    let wrapper_path: PathBuf = mgr
        .ensure_qemu_wrapper_for_test()
        .expect("write wrapper script");

    // Stage a stub `qemu-system-x86_64` inside a fresh PATH dir. The
    // stub just `echo`s its argv so the test can inspect the
    // composed command line the wrapper would have execed.
    //
    // The wrapper deliberately skips its own SCRIPT_DIR when searching
    // PATH (to avoid recursive self-invocation), so the stub must NOT
    // live in the same directory as the wrapper itself.
    let stub_dir = dir.path().join("stub-bin");
    std::fs::create_dir(&stub_dir).expect("create stub bin dir");
    let stub_path = stub_dir.join("qemu-system-x86_64");
    std::fs::write(&stub_path, "#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 0\n").expect("write stub");
    std::fs::set_permissions(&stub_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod stub");

    // PATH ordering: stub_dir FIRST so the wrapper's
    // `for dir in $PATH` loop picks our stub over any real QEMU on the
    // CI host. The wrapper's loop excludes SCRIPT_DIR (its own
    // location); since the wrapper is under `libexec/` and the stub
    // is under `stub-bin/`, the exclusion does not affect the stub.
    let path = format!(
        "{}:{}",
        stub_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new(&wrapper_path)
        .env("PATH", &path)
        .env("SANDBOX_DOCKER_BRIDGE", bridge_name)
        .env("SANDBOX_VM_MAC", "52:54:00:12:34:56")
        // Cgroup-limit env vars are intentionally absent so the
        // wrapper takes the direct-exec branch (not the
        // systemd-run-wrapped branch); the bridge argv composition is
        // identical on both branches but the direct path is the
        // simplest to capture.
        .arg("-machine-not-help")
        .output()
        .expect("run wrapper script");

    if !output.status.success() {
        panic!(
            "wrapper exited non-zero (status={:?}); stdout=\n{}\nstderr=\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Some(String::from_utf8(output.stdout).expect("argv must be utf-8"))
}

#[test]
fn integration_qemu_wrapper_no_helper_param_in_netdev() {
    let bridge_name = "sandbox-test-br";
    let Some(argv) = capture_wrapper_argv(bridge_name) else {
        eprintln!(
            "integration_qemu_wrapper_no_helper_param_in_netdev: limactl not on PATH — skipping. \
             Lima is not installed on this CI runner (ubuntu-latest has Docker but not Lima). \
             The wrapper script test requires LimaManager to stage the wrapper; run locally \
             or on a Lima-equipped runner to exercise this assertion."
        );
        return;
    };

    // Sanity: the bridge branch fired. The wrapper composes the
    // `-netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE` token
    // into EXTRA_ARGS only when the env var is set; if the branch
    // were skipped the assertion below would mis-attribute the
    // failure mode.
    assert!(
        argv.contains("-netdev"),
        "wrapper must include a `-netdev` arg when SANDBOX_DOCKER_BRIDGE is set; argv=\n{argv}"
    );
    assert!(
        argv.contains("bridge,id=net_sandbox"),
        "wrapper must emit a bridge netdev with id=net_sandbox; argv=\n{argv}"
    );
    assert!(
        argv.contains(&format!("br={bridge_name}")),
        "wrapper must emit `br=<SANDBOX_DOCKER_BRIDGE>`; argv=\n{argv}"
    );

    // The load-bearing assertion: no `helper=` segment anywhere.
    // QEMU resolves the helper via its compile-time libexecdir.
    assert!(
        !argv.contains("helper="),
        "wrapper must NOT emit any `helper=` parameter — QEMU resolves the helper itself; argv=\n{argv}"
    );
    // Anchored stricter: not even a `,helper` suffix on the netdev token.
    assert!(
        !argv.contains(",helper"),
        "wrapper must NOT emit a `,helper` continuation in the netdev arg; argv=\n{argv}"
    );
}
