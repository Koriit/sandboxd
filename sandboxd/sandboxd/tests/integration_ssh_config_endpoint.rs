//! Integration coverage for `GET /sessions/{id}/ssh-config` on both
//! backends.
//!
//! The cross-user CLI access spec § Phase 2 step 3 calls for
//! `integration_*` coverage of the endpoint per backend: a real
//! session row, an HTTP GET through the daemon's unix socket, and a
//! decoded `SshConfigDto` whose `config` text is parseable by `ssh
//! -G` and whose `private_key` bytes are accepted by `ssh-keygen -y
//! -f` (i.e. they round-trip through OpenSSH's key parser). Without
//! this, the only existing coverage is hermetic — the daemon's
//! happy-path branch is never exercised against a real HTTP pipeline,
//! the `SSH_NOT_AVAILABLE` 404 branch only fires in unit tests, and a
//! refactor that breaks the DTO shape would land in CI silently.
//!
//! Both tests follow the same template the
//! `integration_owner_peercred.rs` suite established: spawn the
//! daemon binary against a tempdir base-dir, seed an `ssh_keypair`-
//! carrying session row directly via `SessionStore` (the same
//! internal API the daemon uses), issue a real HTTP/1.1 `GET` over
//! the unix socket, decode the response, and validate it byte-for-
//! byte against OpenSSH's parsers.
//!
//! ## Per-backend differences
//!
//! * **Container backend** — `set_ssh_keypair` writes the persisted
//!   keypair; the handler reads it back directly.
//! * **Lima backend** — the handler reads
//!   `$HOME/.lima/_config/user`. We seed that file as a freshly-
//!   generated OpenSSH ed25519 key and point the daemon's `HOME` at
//!   the tempdir for the duration of the test.
//!
//! The third test exercises the `SSH_NOT_AVAILABLE` typed-error
//! 404 path on container sessions whose row has `ssh_keypair_json
//! IS NULL` (V006-shape rows under V007 schema — the forward-compat
//! window the spec explicitly accommodates).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::backend::BackendKind;
use sandbox_core::{SessionConfig, SessionStore, SshKeypair};
use tempfile::TempDir;
use tokio::net::UnixStream;

fn lima_helper_bin() -> PathBuf {
    // The test-env-override–capable helper is installed at this path by
    // `make setup-dev-env` alongside the production helper.  It is the
    // same binary the Lima proxy integration test uses.
    PathBuf::from("/usr/local/libexec/sandboxd-test/sandbox-lima-helper")
}

// ---------------------------------------------------------------------------
// Binary resolution & users.conf fixture (shape mirrors
// integration_owner_peercred.rs — see that file for rationale).
// ---------------------------------------------------------------------------

fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

fn current_username() -> String {
    let uid = nix::unistd::Uid::current();
    nix::unistd::User::from_uid(uid)
        .expect("getpwuid_r succeeded")
        .expect("uid maps to a passwd entry")
        .name
}

fn write_users_conf(dir: &Path, user: &str) -> PathBuf {
    let path = dir.join("users.conf");
    let body = format!(
        r#"{{"_schema_version":1,"subnets":[{{"cidr":"10.220.0.0/24","allow_users":["{user}"]}}]}}"#
    );
    let mut f = std::fs::File::create(&path).expect("create users.conf");
    f.write_all(body.as_bytes()).expect("write users.conf");
    f.flush().expect("flush users.conf");
    path
}

// ---------------------------------------------------------------------------
// Daemon fixture
// ---------------------------------------------------------------------------

struct Daemon {
    socket: PathBuf,
    proc: Option<Child>,
    tmp: TempDir,
}

impl Daemon {
    /// Spawn the daemon against the given pre-seeded base directory.
    /// `extra_env` lets the Lima test pin `HOME` to the tempdir so
    /// the handler's `~/.lima/_config/user` read lands inside the
    /// test's sandbox.
    fn spawn_with_env(tmp: TempDir, base_dir: PathBuf, extra_env: &[(&str, &Path)]) -> Self {
        let user = current_username();
        let socket = tmp.path().join("sandboxd.sock");
        let users_conf = write_users_conf(tmp.path(), &user);
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
            .env("XDG_DATA_HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", tmp.path())
            .env("SANDBOX_USERS_CONF", &users_conf)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(stdout_fh))
            .stderr(Stdio::from(stderr_fh));
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let proc = cmd.spawn().expect("spawn sandboxd");
        let daemon = Self {
            socket,
            proc: Some(proc),
            tmp,
        };
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
                    self.tmp.path().display(),
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut proc) = self.proc.take() {
            let _ = proc.kill();
            let _ = proc.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP-over-unix client
// ---------------------------------------------------------------------------

async fn http_get(
    socket_path: &Path,
    path: &str,
    timeout: Duration,
) -> (hyper::StatusCode, Vec<u8>) {
    let socket_str = socket_path.to_string_lossy().into_owned();
    tokio::time::timeout(timeout, async move {
        let stream = UnixStream::connect(&socket_str)
            .await
            .unwrap_or_else(|e| panic!("connect {socket_str}: {e}"));
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("hyper handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(Empty::<hyper::body::Bytes>::new())
            .expect("build GET request");
        let resp = sender.send_request(req).await.expect("send_request");
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        (status, body.to_vec())
    })
    .await
    .unwrap_or_else(|_| panic!("HTTP request timed out after {timeout:?}"))
}

// ---------------------------------------------------------------------------
// OpenSSH-side validators — used by both backend tests
// ---------------------------------------------------------------------------

/// Verify `private_key` bytes are accepted by OpenSSH's key parser
/// by piping them into `ssh-keygen -y -f /dev/stdin`. The command
/// extracts and prints the matching public key on success; we assert
/// it starts with `ssh-ed25519 ` (or `ssh-rsa `/`ssh-ecdsa-...`; Lima
/// may pick any default) and exits zero.
fn assert_private_key_parses_via_ssh_keygen(private_key: &str) {
    // `ssh-keygen -y -f -` is not supported on every OpenSSH build
    // (the `-f` flag wants a regular file). Write to a tempfile with
    // mode 0600 to satisfy strict-mode checks the binary applies.
    let tmp = TempDir::new().expect("tempdir for keyfile");
    let path = tmp.path().join("id_test");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .expect("create keyfile");
        f.write_all(private_key.as_bytes()).expect("write keyfile");
    }
    let out = Command::new("ssh-keygen")
        .args(["-y", "-f"])
        .arg(&path)
        .output()
        .expect("spawn ssh-keygen");
    assert!(
        out.status.success(),
        "ssh-keygen -y -f {path:?} failed (rc={:?}); stdout={:?} stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let pub_text = String::from_utf8_lossy(&out.stdout);
    assert!(
        pub_text.starts_with("ssh-ed25519 ")
            || pub_text.starts_with("ssh-rsa ")
            || pub_text.starts_with("ecdsa-sha2-"),
        "ssh-keygen output does not look like an OpenSSH public key: {pub_text:?}",
    );
    let path_to_keep = path.clone();
    let _ = tmp; // keep alive
    drop(path_to_keep);
}

/// Verify the daemon-emitted SSH config text parses through `ssh -G`.
/// `ssh -G` resolves every `Host` match against the supplied config
/// without opening a network connection — perfect for asserting the
/// config is syntactically valid. We additionally assert the
/// alias-specific resolution exposes the expected daemon-emitted
/// directives (`port 22`, `user sandbox`, `proxycommand sandbox proxy
/// <id>`).
fn assert_config_text_parses_via_ssh_dash_g(config: &str, session_id: &str) {
    let tmp = TempDir::new().expect("tempdir for ssh config");
    let cfg_path = tmp.path().join("config");
    std::fs::write(&cfg_path, config).expect("write ssh config");
    let alias = format!("sandbox-{session_id}");
    let out = Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&cfg_path)
        .arg(&alias)
        .output()
        .expect("spawn ssh -G");
    assert!(
        out.status.success(),
        "`ssh -G -F {cfg_path:?} {alias}` failed (rc={:?}); stdout={:?} stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let resolved = String::from_utf8_lossy(&out.stdout);
    // `ssh -G` emits one `<key> <value>` per resolved directive,
    // lowercase key. We check a few load-bearing keys; full template
    // pinning lives in `sandbox_core::ssh::tests`.
    let directives: std::collections::HashMap<&str, &str> = resolved
        .lines()
        .filter_map(|line| line.split_once(' '))
        .collect();
    assert_eq!(
        directives.get("port"),
        Some(&"22"),
        "ssh -G must resolve `Port 22`; full output:\n{resolved}"
    );
    assert_eq!(
        directives.get("user"),
        Some(&"sandbox"),
        "ssh -G must resolve `User sandbox`; full output:\n{resolved}"
    );
    let expected_proxy = format!("sandbox proxy {session_id}");
    assert_eq!(
        directives.get("proxycommand"),
        Some(&expected_proxy.as_str()),
        "ssh -G must resolve the daemon-emitted ProxyCommand; full output:\n{resolved}"
    );
}

// ---------------------------------------------------------------------------
// Test 1 — container backend round-trip
// ---------------------------------------------------------------------------

/// Seed a container-backed session row carrying a fresh ed25519
/// keypair, then `GET /sessions/<id>/ssh-config` over the unix
/// socket. Assert:
///
/// 1. HTTP 200.
/// 2. The decoded `SshConfigDto.private_key` bytes parse through
///    `ssh-keygen -y -f`.
/// 3. The decoded `SshConfigDto.config` text parses through `ssh -G`
///    with the daemon-emitted `Port 22` / `User sandbox` / `ProxyCommand`
///    directives intact.
///
/// Together these pin the wire-shape contract every CLI ⇄ daemon
/// integration depends on.
#[tokio::test]
async fn integration_get_ssh_config_container_backend() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

    // Seed the row PRE-spawn so the daemon picks it up at open.
    let owner = current_username();
    let session_id_str = {
        let (store, _orphans) = SessionStore::new(base_dir.clone()).expect("open store pre-spawn");
        let session = store
            .create_session_with_backend(
                SessionConfig::default(),
                Some("ssh-config-container".to_string()),
                BackendKind::Container,
                &owner,
                0,
                "",
                None,
                None,
            )
            .expect("create container session row");
        let id = session.id;
        let kp =
            SshKeypair::generate("integration_ssh_config_container").expect("keypair generation");
        store
            .set_ssh_keypair(&id, &owner, &kp)
            .expect("persist ssh_keypair");
        id.to_string()
    };

    let daemon = Daemon::spawn_with_env(tmp, base_dir, &[]);
    let path = format!("/sessions/{session_id_str}/ssh-config");
    let (status, body) = http_get(&daemon.socket, &path, Duration::from_secs(15)).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "GET {path} must return 200 for an owner-matched, keypair-populated container session; \
         body: {}",
        String::from_utf8_lossy(&body),
    );

    let dto: sandbox_core::SshConfigDto = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("decode SshConfigDto from response: {e}; body={body:?}"));
    assert_private_key_parses_via_ssh_keygen(&dto.private_key);
    assert_config_text_parses_via_ssh_dash_g(&dto.config, &session_id_str);
}

// ---------------------------------------------------------------------------
// Test 2 — Lima backend round-trip
// ---------------------------------------------------------------------------

/// Seed a Lima-backed session row (no keypair persisted — the Lima branch
/// reads the key by pivoting through `sandbox-lima-helper read-user-key`
/// to the operator's per-operator LIMA_HOME at
/// `/var/lib/sandboxd/<op_uid>/lima/_config/user`). We stage a fresh
/// ed25519 key at that path under a redirected state root and
/// `GET /sessions/<id>/ssh-config`. Same three assertions as the
/// container test.
///
/// ## How the test-environment pivot works
///
/// The production path requires `cap_setuid+ep` on `sandbox-lima-helper`.
/// In the integration test environment we use the same technique the Lima
/// proxy WebSocket test uses:
///
/// * Point the daemon at `/usr/local/libexec/sandboxd-test/sandbox-lima-helper`
///   (the `test-env-override`–capable build installed by `make setup-dev-env`).
/// * Set `SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER` / `..._GROUP` to the test
///   runner's username/group so the helper's identity check (step 1) accepts
///   the test runner uid as "sandbox".
/// * Set `SANDBOX_LIMA_HELPER_TEST_STATE_ROOT` to a tempdir so both
///   `operator_lima_home` (in `sandbox-core`) and the helper's
///   `read-user-key` path construction resolve the key file inside the
///   tempdir rather than `/var/lib/sandboxd/`.
///
/// The `test-env-override` build of the helper skips the `setresuid` step
/// when the caller uid already equals `op_uid` (test runner running as its
/// own uid). The result is that the key file is read directly as the test
/// user, exercising every daemon-side hop (session-ownership check, DTO
/// shape, LimaManager routing) without a live setcap binary.
#[tokio::test]
async fn integration_get_ssh_config_lima_backend() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

    // Determine current user identity for helper overrides.
    let owner = current_username();
    let owner_uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current();
    let group_name = nix::unistd::Group::from_gid(gid)
        .expect("getgrgid succeeded")
        .expect("gid maps to a group entry")
        .name;

    // Redirect per-operator LIMA_HOME to a tempdir subtree.
    // Both sandbox-core's operator_lima_home() and the helper's
    // read-user-key subcommand consult SANDBOX_LIMA_HELPER_TEST_STATE_ROOT
    // when the test-env-override feature is active.
    //
    // Per-operator path: `<state_root>/<uid>/lima/_config/user`
    let state_root = tmp.path().join("sandboxd-state");
    let per_op_config_dir = state_root.join(owner_uid.to_string()).join("lima/_config");
    std::fs::create_dir_all(&per_op_config_dir).expect("mkdir per-operator _config dir");

    // Stage a fresh ed25519 keypair at the per-operator key path.
    let kp = SshKeypair::generate("integration_ssh_config_lima").expect("keypair generation");
    let user_key_path = per_op_config_dir.join("user");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&user_key_path)
            .expect("create per-operator _config/user");
        f.write_all(kp.private.as_bytes())
            .expect("write per-operator _config/user");
    }

    // Seed the session row with `operator_uid = owner_uid` so the daemon's
    // Lima branch looks up the right per-operator LimaManager.
    let session_id_str = {
        let (store, _orphans) = SessionStore::new(base_dir.clone()).expect("open store pre-spawn");
        let session = store
            .create_session_with_backend(
                SessionConfig::default(),
                Some("ssh-config-lima".to_string()),
                BackendKind::Lima,
                &owner,
                owner_uid,
                "",
                None,
                None,
            )
            .expect("create lima session row");
        session.id.to_string()
    };

    let daemon = Daemon::spawn_with_env(
        tmp,
        base_dir,
        &[
            // Point at the test-env-override–capable helper binary.
            ("SANDBOX_LIMA_HELPER_PATH", lima_helper_bin().as_path()),
            // Accept the test runner uid as the "sandbox" caller so the
            // helper's identity check (step 1) passes without a real
            // uid-999 daemon process.
            ("SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER", Path::new(&owner)),
            (
                "SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP",
                Path::new(&group_name),
            ),
            // Redirect the state root so operator_lima_home() and the
            // helper's read-user-key path both resolve inside the tempdir.
            ("SANDBOX_LIMA_HELPER_TEST_STATE_ROOT", state_root.as_path()),
        ],
    );
    let path = format!("/sessions/{session_id_str}/ssh-config");
    let (status, body) = http_get(&daemon.socket, &path, Duration::from_secs(15)).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "GET {path} must return 200 for a Lima session with a seeded user key; body: {}",
        String::from_utf8_lossy(&body),
    );

    let dto: sandbox_core::SshConfigDto = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("decode SshConfigDto from response: {e}; body={body:?}"));
    // Lima's handler returns the key bytes verbatim. Pin both the
    // shape (OpenSSH-parseable) and the value (matches what we
    // staged on disk).
    assert_private_key_parses_via_ssh_keygen(&dto.private_key);
    assert_eq!(
        dto.private_key, kp.private,
        "Lima handler must return the verbatim contents of \
         the per-operator LIMA_HOME/_config/user key file"
    );
    assert_config_text_parses_via_ssh_dash_g(&dto.config, &session_id_str);
}

// ---------------------------------------------------------------------------
// Test 3 — SSH_NOT_AVAILABLE 404 typed-error branch
// ---------------------------------------------------------------------------

/// Seed a container-backed session row with `ssh_keypair_json IS
/// NULL` (the V006-shape row under V007 schema — the forward-compat
/// case the spec explicitly accommodates). The handler must return
/// `404 Not Found` with an error body that carries the typed
/// `SSH_NOT_AVAILABLE` token the CLI matches on.
#[tokio::test]
async fn integration_get_ssh_config_container_returns_404_when_keypair_absent() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

    let owner = current_username();
    let session_id_str = {
        let (store, _orphans) = SessionStore::new(base_dir.clone()).expect("open store pre-spawn");
        let session = store
            .create_session_with_backend(
                SessionConfig::default(),
                Some("ssh-config-pre-v007".to_string()),
                BackendKind::Container,
                &owner,
                0,
                "",
                None,
                None,
            )
            .expect("create container session row");
        // Intentionally do NOT call set_ssh_keypair — the row's
        // ssh_keypair_json column stays NULL, identical to the
        // V006-shape rows under V007 schema.
        session.id.to_string()
    };

    let daemon = Daemon::spawn_with_env(tmp, base_dir, &[]);
    let path = format!("/sessions/{session_id_str}/ssh-config");
    let (status, body) = http_get(&daemon.socket, &path, Duration::from_secs(15)).await;
    assert_eq!(
        status,
        hyper::StatusCode::NOT_FOUND,
        "container session without a persisted keypair must surface as 404; \
         body: {}",
        String::from_utf8_lossy(&body),
    );
    let body_text = String::from_utf8_lossy(&body);
    let api_err: sandbox_core::ApiError = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("decode ApiError from 404 body: {e}; body={body_text}"));
    // Typed-code field pin — this is what the CLI matches on.
    assert_eq!(
        api_err.code.as_deref(),
        Some("SSH_NOT_AVAILABLE"),
        "404 body must carry the typed `code` field set to SSH_NOT_AVAILABLE; got: {api_err:?}",
    );
    // Backward-compat prefix pin — the legacy substring stays in the
    // `error` string so consumers that predate the typed `code` field
    // still see the same operator-facing token they did before.
    assert!(
        api_err.error.starts_with("SSH_NOT_AVAILABLE:"),
        "legacy SSH_NOT_AVAILABLE prefix must remain in the `error` string \
         for backward-compat with consumers that predate the typed code; got: {api_err:?}",
    );
}
