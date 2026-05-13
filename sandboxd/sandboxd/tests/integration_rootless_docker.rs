//! Rootless-Docker enforcement at the daemon (integration tests).
//!
//! Pins four contracts:
//!
//! 1. `integration_rootless_docker_session_create_refused` — the daemon
//!    returns HTTP 400 with the spec-shaped rejection body when the
//!    rootless-Docker probe reports `name=rootless` and the operator
//!    did not pass `--force-rootless-docker`. No container artifacts
//!    are allocated (the probe runs before `setup_session_networking`,
//!    `ensure_image`, and the runtime's `create()`).
//! 2. `integration_rootless_docker_force_flag_overrides` — under the
//!    same stubbed environment, `sandbox create --lite
//!    --force-rootless-docker` succeeds; `sandbox inspect` carries
//!    `rootless: { detected: true, forced: true }`; the session reaches
//!    `Running` and is cleanly removed afterwards.
//! 3. `integration_rootless_docker_force_flag_rejected_on_lima` —
//!    `sandbox create --backend lima --force-rootless-docker` is a
//!    pre-flight CLI rejection (exit 2) rendered by the byte-pinned
//!    helper in `sandbox-cli`'s `backend.rs`. No daemon contact.
//! 4. `integration_default_hardened_docker_proceeds` — under a stub
//!    that reports default-hardened, `sandbox create --lite` succeeds
//!    without the override; `sandbox inspect` carries `rootless:
//!    { detected: false, forced: false }`; the session reaches
//!    `Running` and is cleanly removed.
//!
//! # Harness shape
//!
//! Tests #1, #2, #4 spawn a real `sandboxd` binary (resolved via
//! `CARGO_BIN_EXE_sandboxd`) under a `DockerPathStub`-mutated `PATH`
//! environment. The stub intercepts only `docker info --format
//! '{{.SecurityOptions}}'` and forwards every other docker call to the
//! real binary via `SANDBOX_REAL_PATH`, so the daemon's session-create
//! flow (image ensure, network create, container create+start, gateway
//! container) reaches the host's actual Docker daemon. The probe's
//! daemon-lifetime cache is implicitly reset between tests because each
//! test spawns a fresh daemon process.
//!
//! Test #3 spawns only the `sandbox` CLI — the rejection runs before
//! any daemon contact (see `dispatch_create_preflight` in
//! `sandbox-cli/src/main.rs:3907`) so no `sandboxd` is needed.
//!
//! # Why spawn the binary instead of an in-process router
//!
//! The daemon's `AppState` requires a `LimaManager` (depends on
//! `limactl`), `NetworkManager`, `GatewayManager`, an event bus, and
//! several live tasks at construction time. Building a usable in-
//! process `axum::Router` for these tests would mean replicating
//! `main()`'s startup choreography in the test fixture. Spawning the
//! freshly-built `sandboxd` binary is the same approach
//! `integration_users_conf_startup.rs` and `tests/e2e/conftest.py`
//! already use; it stays one source of truth on startup wiring and
//! exercises the exact ordering operators experience.
//!
//! # Why CLI-driven (not raw HTTP)
//!
//! `sandboxd` exposes its API over a unix socket and the CLI binary
//! (`sandbox`) already encapsulates the request/response shape, exit
//! codes, and JSON parsing the operator sees. Driving the tests
//! through `sandbox create` / `sandbox inspect` / `sandbox rm` keeps
//! the assertions on the same surface used by the e2e suite and the
//! delivery doc's claim cluster — and avoids pulling `hyper` into
//! `sandboxd`'s dev-dependencies just for these tests. The CLI's exit
//! code 1 is the daemon-relayed-error path (used by test #1); exit 0
//! is the success path (#2, #4).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_core::test_support::docker_path_stub::{DockerInfoBehavior, DockerPathStub};
use serde_json::Value;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------------------

/// Path to the `sandboxd` binary produced by `cargo build`. Cargo sets
/// `CARGO_BIN_EXE_<name>` for the integration test crate of the
/// containing package.
fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

/// Canonical install path of the test-cap'd route helper, populated by
/// `make install-route-helper-test-cap`. Tests #2 and #4 (`force_flag_overrides`
/// and `default_hardened_docker_proceeds`) point the daemon here via
/// `SANDBOX_ROUTE_HELPER_PATH` so the helper's `users.conf` authorization
/// flow reads the SAME tempfile config the daemon uses — otherwise the
/// helper denies the route install with "gateway ip <test-subnet> not in
/// any subnet". The production-feature helper at
/// `/usr/local/libexec/sandboxd/sandbox-route-helper` ignores
/// `SANDBOX_USERS_CONF` (privilege boundary: a cap'd helper must not be
/// redirectable to an attacker-controlled config file via a process-
/// environment variable); the test-cap'd helper here is built with the
/// `test-env-override` feature and therefore consults `SANDBOX_USERS_CONF`,
/// which keeps the daemon's allocator pool and the helper's auth check on
/// the same tempfile config without weakening the production privilege
/// boundary. Tests #1 and #5 (`session_create_refused` and
/// `probe_failure_surfaces_as_gateway_error`) reject before
/// `setup_session_networking` runs and never invoke the route helper, so
/// they leave the env var unset. See
/// `sandbox-route-helper/tests/integration_route_helper.rs` for the same
/// path constant on the helper side.
const TEST_ROUTE_HELPER_PATH: &str = "/usr/local/libexec/sandboxd-test/sandbox-route-helper";

/// Path to the `sandbox` CLI binary. The CLI lives in a sibling
/// package (`sandbox-cli`) so `CARGO_BIN_EXE_sandbox` is **not**
/// available for this test crate. Cargo always emits both binaries
/// into the same directory (`target/<profile>/`), so the CLI is the
/// `sandbox` sibling of `CARGO_BIN_EXE_sandboxd`.
///
/// Verified at fixture setup: a missing CLI binary is a workspace-
/// build problem, not a test failure to swallow.
fn sandbox_cli_bin() -> PathBuf {
    let sibling = sandboxd_bin()
        .parent()
        .expect("sandboxd binary must have a parent directory")
        .join("sandbox");
    assert!(
        sibling.exists(),
        "sandbox CLI not found at {} — run `cargo build --workspace --bins` before \
         `cargo nextest run --profile integration`",
        sibling.display(),
    );
    sibling
}

// ---------------------------------------------------------------------------
// users.conf fixture — the daemon refuses to start without one
// ---------------------------------------------------------------------------

/// Materialise a `users.conf` whose single subnet's `allow_users`
/// resolves to the test process's own uid. The daemon's startup
/// validator requires this to come up.
///
/// Returns the file path; the caller passes it to the daemon via
/// `SANDBOX_USERS_CONF`. The caller owns the surrounding tempdir.
fn write_users_conf(dir: &Path) -> PathBuf {
    // `whoami`-equivalent without pulling a new dep — `getlogin_r` is
    // unreliable inside CI containers; `User::from_uid` (already a
    // dep via the daemon's `nix` crate) is the same route the daemon
    // uses to map uid → name.
    let uid = nix::unistd::Uid::current();
    let user = nix::unistd::User::from_uid(uid)
        .expect("getpwuid_r succeeded")
        .expect("uid maps to a passwd entry")
        .name;
    // Match the dev-host `/etc/sandboxd/users.conf` shape so the
    // /28 allocator has a /24 worth of headroom for any session
    // that actually runs in #2/#4. Subnet picked outside the
    // production 10.209.0.0/24 to avoid colliding with a real
    // daemon if one happens to be running on the same host.
    let path = dir.join("users.conf");
    let body = format!(r#"{{"_schema_version":1,"subnets":[{{"cidr":"10.219.0.0/24","allow_users":["{user}"]}}]}}"#,);
    let mut f = std::fs::File::create(&path).expect("create users.conf");
    f.write_all(body.as_bytes()).expect("write users.conf");
    f.flush().expect("flush users.conf");
    path
}

// ---------------------------------------------------------------------------
// Daemon fixture
// ---------------------------------------------------------------------------

/// Live `sandboxd` child process plus the tempdir holding its socket,
/// state directory, log files, and `users.conf`.
///
/// On `Drop`: SIGTERM → wait → kill. The tempdir cleans up the
/// socket and state on the way out. Log files (`sandboxd.stdout.log`,
/// `sandboxd.stderr.log`) survive inside the tempdir for the test
/// body's lifetime; on a panicking test the tempdir is leaked and the
/// log path printed by the panic message lets an operator inspect it.
struct Daemon {
    socket: PathBuf,
    proc: Option<Child>,
    _tempdir: TempDir,
}

impl Daemon {
    /// Spawn the daemon with the given environment-extending closure
    /// applied to the `Command`. The closure is the place to install
    /// extra env vars (e.g. the `PATH` mutation forwarded from a
    /// `DockerPathStub`).
    fn spawn(extend_env: impl FnOnce(&mut Command)) -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let socket = tmp.path().join("sandboxd.sock");
        let base_dir = tmp.path().join("state");
        let users_conf = write_users_conf(tmp.path());

        std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

        let stdout_log = tmp.path().join("sandboxd.stdout.log");
        let stderr_log = tmp.path().join("sandboxd.stderr.log");
        let stdout_fh = std::fs::File::create(&stdout_log).expect("create stdout log");
        let stderr_fh = std::fs::File::create(&stderr_log).expect("create stderr log");

        let mut cmd = Command::new(sandboxd_bin());
        cmd.arg("--socket")
            .arg(&socket)
            .arg("--base-dir")
            .arg(&base_dir)
            // Pin XDG paths inside the tempdir so the daemon does not
            // touch the operator's real `~/.local/share/sandboxd/`.
            .env("XDG_DATA_HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", tmp.path())
            .env("SANDBOX_USERS_CONF", &users_conf)
            // Keep the log volume modest — `info` is enough to debug a
            // stuck startup, `debug` would flood the file with per-poll
            // chatter.
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(stdout_fh))
            .stderr(Stdio::from(stderr_fh));
        extend_env(&mut cmd);
        let proc = cmd.spawn().expect("spawn sandboxd");

        let daemon = Self {
            socket,
            proc: Some(proc),
            _tempdir: tmp,
        };

        // Wait for the unix socket to appear. 30s is generous on a
        // dev box (~500ms typical) but absorbs CI variance.
        daemon.wait_for_socket(Duration::from_secs(30));
        daemon
    }

    fn wait_for_socket(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if self.socket.exists() {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "sandboxd socket did not appear at {} within {:?}; check {}/sandboxd.stderr.log",
                    self.socket.display(),
                    timeout,
                    self._tempdir.path().display(),
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn socket_str(&self) -> String {
        self.socket.to_string_lossy().into_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut proc) = self.proc.take() {
            // SIGTERM first; if the daemon ignores it, escalate. We
            // cannot use `nix::sys::signal::kill` here without adding
            // it as a separate dep — `Child::kill` sends SIGKILL,
            // which is fine for cleanup.
            let _ = proc.kill();
            let _ = proc.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// CLI invocation
// ---------------------------------------------------------------------------

/// Output of a `sandbox` CLI invocation.
struct CliOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

impl CliOutput {
    fn assert_success(&self, ctx: &str) {
        assert!(
            self.status.success(),
            "{ctx}: sandbox CLI failed with code {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.status.code(),
            self.stdout,
            self.stderr,
        );
    }
}

/// Run `sandbox <args>` against the daemon's socket. Captures both
/// streams; default 60s timeout is plenty for create/inspect/rm
/// against a healthy daemon (the heavy session-create takes ~30s on
/// this host's hardware).
fn run_cli(daemon: &Daemon, args: &[&str], timeout: Duration) -> CliOutput {
    let mut cmd = Command::new(sandbox_cli_bin());
    cmd.arg("--socket")
        .arg(daemon.socket_str())
        .arg("--yes") // skip any "are you sure?" prompts
        .args(args)
        // Avoid the operator's CLI config bleeding in (default
        // backend, presets, etc.).
        .env("XDG_CONFIG_HOME", "/nonexistent/xdg-rootless-wave3")
        .env_remove("SANDBOX_DEFAULT_BACKEND")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn sandbox CLI");

    // Lift stdout/stderr off the child's pipes ourselves so we can
    // bound the wait. Reading via threads avoids the classic
    // pipe-buffer-deadlock that `wait_with_output` is also susceptible
    // to under stderr volume.
    let mut stdout_pipe = child.stdout.take().expect("stdout pipe");
    let mut stderr_pipe = child.stderr.take().expect("stderr pipe");
    let stdout_handle = thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout_pipe.read_to_string(&mut buf);
        buf
    });
    let stderr_handle = thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle.join().unwrap_or_default();
                let stderr = stderr_handle.join().unwrap_or_default();
                return CliOutput {
                    status,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let stdout = stdout_handle.join().unwrap_or_default();
                    let stderr = stderr_handle.join().unwrap_or_default();
                    panic!(
                        "sandbox CLI did not exit within {timeout:?}\nargs: {args:?}\n\
                         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                    );
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("try_wait on sandbox CLI failed: {e}"),
        }
    }
}

/// Spawn the CLI WITHOUT a daemon — used by the Lima-misuse test
/// (rejection happens before the daemon is contacted).
fn run_cli_standalone(args: &[&str], timeout: Duration) -> CliOutput {
    let mut cmd = Command::new(sandbox_cli_bin());
    cmd.arg("--yes")
        .args(args)
        .env("XDG_CONFIG_HOME", "/nonexistent/xdg-rootless-wave3")
        .env_remove("SANDBOX_DEFAULT_BACKEND")
        // The rejection runs before any /backends or /sessions call,
        // so the socket value is irrelevant. Pin to a definitely-
        // missing path so a regression that *does* contact the
        // daemon surfaces as a connection error rather than a
        // reach-into-the-real-daemon side effect.
        .env("SANDBOX_SOCKET", "/nonexistent/socket-rootless-wave3.sock")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("spawn sandbox CLI");
    let output = child
        .wait_with_output()
        .expect("collect sandbox CLI output");
    let _ = timeout; // not actually used — CLI rejection is synchronous
    CliOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// Session-cleanup guard
// ---------------------------------------------------------------------------

/// Force-`sandbox rm -y <name>` on drop so a panicking assertion
/// cannot orphan a real container session. Cheap on the
/// already-removed path (the CLI's "rm" is idempotent in the
/// `not found` case).
struct SessionCleanupGuard<'a> {
    daemon: &'a Daemon,
    name: String,
    armed: bool,
}

impl<'a> SessionCleanupGuard<'a> {
    fn new(daemon: &'a Daemon, name: impl Into<String>) -> Self {
        Self {
            daemon,
            name: name.into(),
            armed: true,
        }
    }

    /// Disarm the guard once an explicit `rm` has succeeded so the
    /// `Drop` path doesn't double-remove (which is harmless but
    /// surfaces noise in the daemon log).
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl<'a> Drop for SessionCleanupGuard<'a> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Best-effort. A failed `rm` here is still useful signal
        // (the session may have leaked) so propagate to stderr.
        let out = run_cli(
            self.daemon,
            &["rm", "-y", &self.name],
            Duration::from_secs(120),
        );
        if !out.status.success() {
            eprintln!(
                "SessionCleanupGuard: `sandbox rm -y {}` failed (rc={:?})\n\
                 stdout: {}\nstderr: {}",
                self.name,
                out.status.code(),
                out.stdout,
                out.stderr,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test 1 — rootless host without `--force-rootless-docker`: HTTP 400
/// surfaces through the CLI as exit 1 with the spec-shaped message;
/// no docker artifacts (sandbox-{id} container, sandbox-net-{id}
/// network, sandbox-home-{id} volume) are created.
///
/// The probe must run *before* any docker artifact allocation — Wave
/// 2 confirmed this ordering by placing the gate immediately after
/// the spec validation pass and before the per-session network
/// allocation. This test pins that ordering by snapshotting the
/// docker artifact namespace before the create call and asserting it
/// is unchanged afterwards.
#[test]
fn integration_rootless_docker_session_create_refused() {
    let _stub = DockerPathStub::new(DockerInfoBehavior::ReportRootless);
    let daemon = Daemon::spawn(|_cmd| {
        // The `_stub` is alive in this scope so `PATH` /
        // `SANDBOX_REAL_PATH` are already mutated; `Command::spawn`
        // inherits the parent's env block, so the daemon child sees
        // the stubbed PATH automatically. No per-cmd env override
        // needed.
    });

    // Snapshot the docker artifact namespace so we can prove no new
    // sandbox-* artifacts appear after the rejected create.
    let artifacts_before = list_sandbox_artifacts();

    let out = run_cli(
        &daemon,
        &["create", "--lite", "--name", "rootless-refused"],
        Duration::from_secs(60),
    );

    assert!(
        !out.status.success(),
        "sandbox create --lite must fail on rootless host without --force-rootless-docker;\n\
         exit code: {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        out.stdout,
        out.stderr,
    );

    // The CLI relays the daemon's error body into stderr verbatim
    // (with an `error: ` prefix). The three greppable substrings
    // pinned in `SandboxError::RootlessDockerRefused`'s Display impl
    // must all survive.
    let combined = format!("{}\n{}", out.stdout, out.stderr);
    for token in &[
        "rootless docker",
        "--force-rootless-docker",
        "§ Non-goals line 1195",
    ] {
        assert!(
            combined.contains(token),
            "expected token {token:?} in CLI output; got:\n--- stdout ---\n{}\n\
             --- stderr ---\n{}",
            out.stdout,
            out.stderr,
        );
    }

    // No artifacts allocated. The probe gate runs before the
    // per-session network create, image ensure, container create.
    let artifacts_after = list_sandbox_artifacts();
    let leaked: Vec<&String> = artifacts_after.difference(&artifacts_before).collect();
    assert!(
        leaked.is_empty(),
        "rootless rejection must not allocate any sandbox-* docker artifacts; leaked: {leaked:?}",
    );
}

/// Test 2 — rootless host with `--force-rootless-docker`: the daemon
/// proceeds, the session reaches `Running`, and `sandbox inspect`
/// surfaces `rootless: { detected: true, forced: true }`.
///
/// This is the heaviest of the four — it spans the full lite
/// container lifecycle (image ensure cache hit, gateway container
/// create, lite container create+start, route-helper invocation,
/// guest-agent readiness) against the host's real Docker daemon.
/// Cleanup is defensive via `SessionCleanupGuard` so a panicking
/// assertion cannot leak a Docker container + named volume.
#[test]
fn integration_rootless_docker_force_flag_overrides() {
    let _stub = DockerPathStub::new(DockerInfoBehavior::ReportRootless);
    // Test runs a real lite session that invokes the route helper, so
    // point the daemon at the test-cap'd helper; see the doc comment on
    // `TEST_ROUTE_HELPER_PATH` for the privilege-boundary rationale.
    let daemon = Daemon::spawn(|cmd| {
        cmd.env("SANDBOX_ROUTE_HELPER_PATH", TEST_ROUTE_HELPER_PATH);
    });

    let session_name = "rootless-forced";
    let cleanup = SessionCleanupGuard::new(&daemon, session_name);

    // Reaching `Running` end-to-end (image+gateway+container+guest)
    // is bounded at ~5min on a healthy box. The CLI itself blocks
    // until the daemon publishes `running`, so a single
    // create-with-timeout is enough — no separate poll loop.
    let out = run_cli(
        &daemon,
        &[
            "create",
            "--lite",
            "--force-rootless-docker",
            "--name",
            session_name,
        ],
        Duration::from_secs(300),
    );
    out.assert_success("sandbox create --lite --force-rootless-docker");

    // `sandbox create`'s post-success summary stays terse (id, name,
    // state, resources) — the rootless-Docker block lives in
    // `sandbox describe` / `sandbox inspect` per `render_rootless_block`'s
    // call site (`sandbox-cli/src/main.rs:1457`). Authoritative
    // assertion goes through `inspect` below.

    // Authoritative check: GET the session via `sandbox inspect`
    // (JSON shape) and assert the rootless DTO carries the right pair.
    let inspected = inspect_session(&daemon, session_name);
    let rootless = inspected
        .get("rootless")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!(
                "session DTO must carry the `rootless` object on a container session;\n\
                 raw: {inspected}"
            )
        });
    assert_eq!(
        rootless.get("detected"),
        Some(&Value::Bool(true)),
        "stub reports rootless ⇒ detected must be true; raw: {rootless:?}",
    );
    assert_eq!(
        rootless.get("forced"),
        Some(&Value::Bool(true)),
        "operator passed --force-rootless-docker AND probe detected ⇒ forced must be true; \
         raw: {rootless:?}",
    );

    // State must have reached `running`. The CLI returns once the
    // daemon publishes that state, so a steady-state inspect after
    // `create` is the cheapest correctness witness.
    let state = inspected
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("<missing>");
    assert_eq!(
        state, "running",
        "session must be Running after create returned; raw: {inspected}",
    );

    // Explicit cleanup so the guard's drop path is a no-op (avoids
    // a redundant `not found` log line in the daemon).
    let rm = run_cli(
        &daemon,
        &["rm", "-y", session_name],
        Duration::from_secs(120),
    );
    rm.assert_success("sandbox rm -y after forced create");
    cleanup.disarm();
}

/// Test 3 — Lima resolution + `--force-rootless-docker` is a CLI-side
/// pre-flight rejection. No daemon contact, exit 2, byte-pinned
/// rejection text from `sandbox-cli/src/backend.rs`'s
/// `render_force_rootless_docker_lima_rejection`.
///
/// Hermetic: no daemon, no PATH stub. The rejection lives in the
/// resolver branch BEFORE `dispatch_create_preflight` calls the
/// `BackendsCache` (so even a misconfigured `SANDBOX_SOCKET` does not
/// affect the test).
#[test]
fn integration_rootless_docker_force_flag_rejected_on_lima() {
    let out = run_cli_standalone(
        &[
            "create",
            "--backend",
            "lima",
            "--force-rootless-docker",
            "--name",
            "lima-misuse-rejection",
        ],
        Duration::from_secs(15),
    );

    assert_eq!(
        out.status.code(),
        Some(2),
        "Lima + --force-rootless-docker must exit 2 (CLI rejection);\n\
         stdout: {}\nstderr: {}",
        out.stdout,
        out.stderr,
    );

    // Byte-pinned to the renderer in `sandbox-cli/src/backend.rs`.
    // A unit test in that module pins the full string literal; this
    // test pins that the wired-up CLI actually emits the renderer's
    // output on stderr (no swallowing, no rewording).
    for line in &[
        "error: `--force-rootless-docker` is only meaningful for the container backend",
        "help: rootless-Docker detection (spec § Non-goals 1195) is a container-backend gate",
        "help: drop `--force-rootless-docker`, or pass `--backend container` / `--lite` if you intended a container session",
    ] {
        assert!(
            out.stderr.contains(line),
            "stderr must contain {line:?};\nstderr was:\n{}",
            out.stderr,
        );
    }
}

/// Test 4 — default-hardened host: the daemon proceeds without the
/// override; `sandbox inspect` shows `rootless: { detected: false,
/// forced: false }`. The session reaches `Running` and is cleanly
/// removed.
///
/// This is the unchanged-baseline-behavior test — confirms the gate
/// is a strict refusal, not a default-on. The host we run on is
/// itself rootless, but the stub reports default-hardened, so the
/// daemon's gate logic relies entirely on the probe outcome (not on
/// any host-state inference).
#[test]
fn integration_default_hardened_docker_proceeds() {
    let _stub = DockerPathStub::new(DockerInfoBehavior::ReportDefault);
    // Test runs a real lite session that invokes the route helper, so
    // point the daemon at the test-cap'd helper; see the doc comment on
    // `TEST_ROUTE_HELPER_PATH` for the privilege-boundary rationale.
    let daemon = Daemon::spawn(|cmd| {
        cmd.env("SANDBOX_ROUTE_HELPER_PATH", TEST_ROUTE_HELPER_PATH);
    });

    let session_name = "default-hardened";
    let cleanup = SessionCleanupGuard::new(&daemon, session_name);

    let out = run_cli(
        &daemon,
        &["create", "--lite", "--name", session_name],
        Duration::from_secs(300),
    );
    out.assert_success("sandbox create --lite (default-hardened stub)");

    let inspected = inspect_session(&daemon, session_name);
    let rootless = inspected
        .get("rootless")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!(
                "session DTO must carry the `rootless` object on every container session \
                 (default-hardened ⇒ {{detected:false, forced:false}}, not field-absent); \
                 raw: {inspected}"
            )
        });
    assert_eq!(
        rootless.get("detected"),
        Some(&Value::Bool(false)),
        "default-hardened stub ⇒ detected must be false; raw: {rootless:?}",
    );
    assert_eq!(
        rootless.get("forced"),
        Some(&Value::Bool(false)),
        "no --force-rootless-docker AND probe says default-hardened ⇒ forced must be false; \
         raw: {rootless:?}",
    );

    let state = inspected
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("<missing>");
    assert_eq!(
        state, "running",
        "session must be Running after create; raw: {inspected}",
    );

    let rm = run_cli(
        &daemon,
        &["rm", "-y", session_name],
        Duration::from_secs(120),
    );
    rm.assert_success("sandbox rm -y after default-hardened create");
    cleanup.disarm();
}

/// Test 5 — probe failure surfaces as a daemon-side gateway error.
///
/// When the docker-info PATH stub is configured to `Fail`, the
/// rootless-Docker probe at session-create time bubbles up its
/// underlying error rather than silently defaulting to "rootless" or
/// "default-hardened". The daemon must surface this as a typed
/// `SandboxError::Gateway` (HTTP 500), not absorb it into a permissive
/// classification.
///
/// This pins three distinct contracts:
///
/// 1. The probe's failure path is wired through to the
///    session-create gate (not a no-op).
/// 2. The daemon maps probe failures to HTTP 500 (Gateway, not 400 —
///    the request is fine; the host is broken).
/// 3. The CLI surfaces enough of the underlying error for an
///    operator to diagnose ("rootless-docker probe stub: configured
///    to fail" is the stub's stderr; we look for the
///    machine-readable "gateway error" prefix the daemon's
///    `SandboxError::Gateway` produces via Display).
///
/// As with test #1, no docker artifacts (sandbox-* containers,
/// networks, volumes) must be created — the probe gate runs before
/// any allocation.
#[test]
fn integration_rootless_docker_probe_failure_surfaces_as_gateway_error() {
    let _stub = DockerPathStub::new(DockerInfoBehavior::Fail);
    let daemon = Daemon::spawn(|_cmd| {});

    // Snapshot the docker artifact namespace so we can prove no new
    // sandbox-* artifacts appear after the rejected create.
    let artifacts_before = list_sandbox_artifacts();

    let out = run_cli(
        &daemon,
        &["create", "--lite", "--name", "probe-fail"],
        Duration::from_secs(60),
    );

    assert!(
        !out.status.success(),
        "sandbox create --lite must fail when the rootless probe itself errors out;\n\
         exit code: {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        out.stdout,
        out.stderr,
    );

    // The daemon must surface the probe failure as `Gateway`, not
    // silently treat it as default-hardened (which would proceed) or
    // as rootless-refused (which would be the `RootlessDockerRefused`
    // path with a different message). The CLI relays the daemon's
    // Display string verbatim; "gateway error" is the prefix from
    // `SandboxError::Gateway`'s `#[error("gateway error: {0}")]`.
    let combined = format!("{}\n{}", out.stdout, out.stderr);
    assert!(
        combined.contains("gateway error") || combined.contains("rootless-docker probe"),
        "expected probe-failure relay token in CLI output;\n--- stdout ---\n{}\n\
         --- stderr ---\n{}",
        out.stdout,
        out.stderr,
    );

    // Critically: the rejection MUST NOT mention `--force-rootless-docker`.
    // That hint belongs to the `RootlessDockerRefused` path (test #1) and
    // would mislead an operator whose host's docker-info command is broken
    // — passing the flag would not fix anything.
    assert!(
        !combined.contains("--force-rootless-docker"),
        "probe-failure error must not point at --force-rootless-docker (that's the \
         rootless-refused path's hint, distinct from a probe failure);\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        out.stdout,
        out.stderr,
    );

    // No artifacts allocated. Mirrors test #1's contract — the probe
    // gate runs before per-session network/image/container allocation
    // regardless of which probe outcome (rootless / default / fail)
    // is returned.
    let artifacts_after = list_sandbox_artifacts();
    let leaked: Vec<&String> = artifacts_after.difference(&artifacts_before).collect();
    assert!(
        leaked.is_empty(),
        "probe-failure rejection must not allocate any sandbox-* docker artifacts; leaked: {leaked:?}",
    );
}

// ---------------------------------------------------------------------------
// Helpers used by tests #2 and #4
// ---------------------------------------------------------------------------

/// Run `sandbox inspect <name>` and parse the resulting JSON array's
/// first element. The CLI emits a JSON array (one entry per id arg),
/// so a single-id invocation has one element.
fn inspect_session(daemon: &Daemon, name: &str) -> Value {
    let out = run_cli(daemon, &["inspect", name], Duration::from_secs(30));
    out.assert_success(&format!("sandbox inspect {name}"));
    let parsed: Value = serde_json::from_str(out.stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "sandbox inspect must emit valid JSON ({e});\nstdout: {}",
            out.stdout,
        )
    });
    let arr = parsed
        .as_array()
        .unwrap_or_else(|| panic!("sandbox inspect must emit a JSON array; got: {parsed}"));
    assert_eq!(
        arr.len(),
        1,
        "single-id inspect must return a one-element array; got {arr:?}",
    );
    arr[0].clone()
}

// ---------------------------------------------------------------------------
// Docker-side artifact snapshot — used by test #1 to prove no orphans
// ---------------------------------------------------------------------------

/// Snapshot of every host-side `sandbox-*` docker artifact
/// (containers, networks, volumes). Used by test #1 to confirm a
/// rejected create allocates none of them.
///
/// Names like `sandbox-{id}` (lite container), `sandbox-net-{id}`
/// (per-session network), `sandbox-home-{id}` (per-session volume),
/// and the gateway equivalents are all created by the daemon under
/// the same `sandbox-*` prefix family — listing them all together
/// gives a single before/after diff.
fn list_sandbox_artifacts() -> HashSet<String> {
    let mut set = HashSet::new();
    push_docker_names(&mut set, &["ps", "-a", "--format", "{{.Names}}"]);
    push_docker_names(&mut set, &["network", "ls", "--format", "{{.Name}}"]);
    push_docker_names(&mut set, &["volume", "ls", "--format", "{{.Name}}"]);
    set
}

fn push_docker_names(set: &mut HashSet<String>, args: &[&str]) {
    let out = Command::new("docker")
        .args(args)
        .output()
        .expect("docker invocation");
    if !out.status.success() {
        // A docker hiccup here is surprising on a host running the
        // rest of the suite; surface it loudly so the assertion that
        // depends on this snapshot is not silently corrupted.
        panic!(
            "docker {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("sandbox-") || trimmed.starts_with("sandbox_") {
            set.insert(trimmed.to_string());
        }
    }
}
