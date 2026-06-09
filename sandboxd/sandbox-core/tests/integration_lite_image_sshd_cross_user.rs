//! End-to-end integration test for the cross-user SSH proxy
//! substrate.
//!
//! Proves the load-bearing claim that decision (b) on todo #221 (the
//! synthetic `/etc/passwd` overlay) is sufficient to let sshd start
//! and accept the daemon-staged `authorized_keys` when the container
//! runs under a daemon uid that is NOT the in-image `sandbox` user's
//! uid (1000). Without this, the cross-user CLI access design
//! never reaches the operator's `ssh` client — sshd fails on
//! `getpwuid(geteuid())` and the lite-image's launch wrapper falls
//! through to the legacy `docker exec`-based path.
//!
//! Test shape:
//!
//! 1. Build the lite image via the production `ensure_image` path.
//! 2. Generate a fresh ed25519 keypair via [`sandbox_core::SshKeypair`]
//!    — the same code path the daemon's session-create handler uses.
//! 3. Stage the three credential files
//!    (`authorized_keys` + synthetic `passwd` + synthetic `group`)
//!    via [`sandbox_core::backend::stage_ssh_credentials`], using
//!    `daemon_uid = 9876` (well clear of 1000 to make the cross-user
//!    case unambiguous).
//! 4. Launch the lite-image container under the production hardening
//!    profile with `--user 9876:9876` and the three bind-mounts the
//!    daemon emits in its `docker create` argv (see
//!    `build_ssh_mount_args` for the per-file spec).
//! 5. Wait for sshd to bind `127.0.0.1:22` — this is the
//!    `getpwuid`-passes signal, since sshd aborts startup under any
//!    OpenSSH version when its own uid lookup fails.
//! 6. Authenticate against the in-container sshd with the staged
//!    private key via `ssh -o ProxyCommand='docker exec -i <ctr>
//!    socat - TCP:127.0.0.1:22' sandbox@dummy uname -a`. Asserts the
//!    full handshake completes — the cryptographic proof that the
//!    bind-mounted `authorized_keys` is consumed by the sshd inside
//!    the container.
//!
//! The dummy hostname in the `ssh` invocation is a syntactic
//! placeholder; the `ProxyCommand` opens the real bytes pipe via
//! `docker exec ... socat` — the same byte mover the daemon's
//! WebSocket proxy adopts in production. The `docker exec socat`
//! substrate is the right shim to prove the per-session keypair
//! contract independently of the WebSocket plumbing.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_core::SshKeypair;
use sandbox_core::backend::{LITE_IMAGE_REPOSITORY, ensure_image, stage_ssh_credentials};

// Non-1000 daemon uid used throughout the test — picked clear of any
// real system uid range so a host-side collision with `useradd` is
// vanishingly unlikely. Mirrors the production case the cross-user
// CLI access design exists to fix: when the daemon runs as the
// `sandbox` system user (created by `setup-dev-env` with an arbitrary
// system uid), the in-container effective uid is not 1000.
const CROSS_USER_DAEMON_UID: u32 = 9876;
const CROSS_USER_DAEMON_GID: u32 = 9876;

// ---------------------------------------------------------------------------
// sandbox-guest staging — same one-time copy as the build tests, so
// the lite Dockerfile's `COPY` of `sandbox-guest` resolves under
// nextest's `target/<profile>/deps/` exe layout.
// ---------------------------------------------------------------------------

static GUEST_STAGED: Once = Once::new();

fn ensure_sandbox_guest_in_exe_parent() {
    GUEST_STAGED.call_once(|| {
        let exe = std::env::current_exe().expect("current_exe");
        let deps_dir = exe.parent().expect("test exe parent (deps/)");
        let dest = deps_dir.join("sandbox-guest");
        if dest.exists() {
            return;
        }

        let profile_dir = deps_dir
            .parent()
            .expect("deps_dir parent (target/<profile>/)");
        let candidates = [
            profile_dir.join("sandbox-guest"),
            profile_dir
                .parent()
                .map(|p| p.join("sandbox-guest"))
                .unwrap_or_default(),
        ];
        let src = candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "sandbox-guest binary not found in any of: {candidates:?}. \
                     Run `cargo build --workspace` first.",
                )
            });

        std::fs::copy(&src, &dest).unwrap_or_else(|e| {
            panic!(
                "failed to stage sandbox-guest from {} to {}: {e}",
                src.display(),
                dest.display()
            )
        });
    });
}

// ---------------------------------------------------------------------------
// Image / container cleanup helpers.
// ---------------------------------------------------------------------------

fn unique_daemon_version(label: &str) -> String {
    static COUNTER: Mutex<u64> = Mutex::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let n = {
        let mut g = COUNTER.lock().unwrap();
        *g = g.wrapping_add(1);
        *g
    };
    format!("test-cross-user-{label}-{pid}-{nanos}-{n}")
}

struct LiteImageCleanup {
    tag: String,
}

impl Drop for LiteImageCleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rmi", "-f", &self.tag])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct ContainerCleanup {
    name: String,
}

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn unique_container_name(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("sandbox-lite-cross-user-{label}-{pid}-{nanos}")
}

fn docker_exec(container: &str, argv: &[&str]) -> (bool, String, String) {
    let output = Command::new("docker")
        .arg("exec")
        .arg(container)
        .args(argv)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn docker exec {container} {argv:?}: {e}"));
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn wait_for(container: &str, deadline: Duration, mut pred: impl FnMut(&str) -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        let (ok, stdout, _) = docker_exec(container, &["ss", "-tlnH"]);
        if ok && pred(&stdout) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// **Cross-user SSH proxy substrate proof.**
///
/// Stages a per-session keypair + synthetic `/etc/passwd` overlay,
/// launches a container under `--user 9876:9876` (the non-1000
/// cross-user case the design exists to fix), and authenticates an
/// outbound `ssh` against the in-container sshd via `docker exec
/// socat` — the same byte mover the daemon's WebSocket proxy uses.
///
/// If this test passes, every load-bearing part of the keypair-
/// injection substrate is wired:
///
/// 1. `ssh-key`-based keypair generation produces an OpenSSH-format
///    public key that the in-image sshd accepts.
/// 2. `stage_ssh_credentials` writes the three files in the right
///    shape (authorized_keys + synthetic passwd + synthetic group).
/// 3. `build_ssh_mount_args`'s bind-mount destinations
///    (`/run/sandbox/authorized_keys`, `/etc/passwd`, `/etc/group`)
///    line up with the lite-image's sshd config (`AuthorizedKeysFile
///    /run/sandbox/authorized_keys`) and OpenSSH's lookup paths.
/// 4. The synthetic `/etc/passwd` overlay (todo #221 decision (b))
///    resolves `getpwuid(9876)` so sshd starts at all.
///
/// All four together are what the cross-user CLI proxy substrate
/// promises; if the test passes the daemon-side WebSocket proxy and
/// the CLI-side `~/.ssh/sandbox/` module can build on it without
/// rediscovering this contract.
#[test]
fn integration_lite_image_sshd_accepts_staged_key_under_cross_user_uid() {
    ensure_sandbox_guest_in_exe_parent();
    let version = unique_daemon_version("auth");
    let tag = format!("{LITE_IMAGE_REPOSITORY}:{version}");
    let _image_cleanup = LiteImageCleanup { tag: tag.clone() };

    // Step 1: build the lite image via the production code path.
    let docker_home = tempfile::tempdir().expect("per-test docker_home tempdir");
    ensure_image(&version, docker_home.path()).expect("ensure_image must succeed for cross-user proof");

    // Step 2: generate a fresh ed25519 keypair. The session-id slot
    // here is purely cosmetic — the in-container sshd does not look
    // at the OpenSSH comment.
    let kp = SshKeypair::generate("crossuser0001").expect("keypair generation");

    // Step 3: stage the three credential files under a host tempdir
    // the test owns. The container will bind-mount them readonly.
    let stage_dir = tempfile::TempDir::new().expect("tempdir for ssh staging");
    stage_ssh_credentials(
        stage_dir.path(),
        &kp,
        CROSS_USER_DAEMON_UID,
        CROSS_USER_DAEMON_GID,
    )
    .expect("stage_ssh_credentials");

    let authorized_keys_host = stage_dir.path().join("authorized_keys");
    let passwd_host = stage_dir.path().join("passwd");
    let group_host = stage_dir.path().join("group");

    // Step 4: launch the container. Same hardening profile as the
    // production `build_create_argv` plus the cross-user `--user`
    // flag and the three SSH-credential bind-mounts.
    let container_name = unique_container_name("auth");
    let _ctr_cleanup = ContainerCleanup {
        name: container_name.clone(),
    };

    let user_flag = format!("{CROSS_USER_DAEMON_UID}:{CROSS_USER_DAEMON_GID}");
    let ak_mount = format!(
        "type=bind,src={},dst=/run/sandbox/authorized_keys,readonly",
        authorized_keys_host.display()
    );
    let passwd_mount = format!(
        "type=bind,src={},dst=/etc/passwd,readonly",
        passwd_host.display()
    );
    let group_mount = format!(
        "type=bind,src={},dst=/etc/group,readonly",
        group_host.display()
    );
    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &container_name,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m",
            "--tmpfs",
            "/run:rw,nosuid,nodev,size=16m",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            "seccomp=builtin",
            "--cap-drop",
            "ALL",
            "--sysctl",
            "net.ipv4.ip_unprivileged_port_start=22",
            "--user",
            &user_flag,
            "--mount",
            &ak_mount,
            "--mount",
            &passwd_mount,
            "--mount",
            &group_mount,
            &tag,
        ])
        .output()
        .expect("failed to spawn docker run");
    assert!(
        run.status.success(),
        "docker run failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );

    // Step 5: wait for sshd to bind 127.0.0.1:22. With the synthetic
    // `/etc/passwd` overlay in place, OpenSSH's `getpwuid` lookup
    // succeeds and sshd reaches its listen loop. Without the overlay
    // the launch wrapper logs `ssh-keygen failed (probably uid has no
    // /etc/passwd entry)` and falls through to `sandbox-guest`; this
    // wait would then time out.
    let listening = wait_for(&container_name, Duration::from_secs(15), |out| {
        out.lines().any(|line| line.contains("127.0.0.1:22"))
    });
    if !listening {
        // Pull the sandbox-entrypoint stderr from `docker logs` so a
        // failing run names exactly which leg of the chain broke
        // (getpwuid vs. bind vs. authorized_keys readability).
        let logs = Command::new("docker")
            .args(["logs", &container_name])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
            .unwrap_or_default();
        panic!(
            "sshd did not start listening on 127.0.0.1:22 within 15s. \
             entrypoint logs:\n{logs}\nlast `ss -tlnH`:\n{}",
            docker_exec(&container_name, &["ss", "-tlnH"]).1
        );
    }

    // Step 6: authenticate. Spawn an `ssh` process whose
    // `ProxyCommand` is `docker exec -i <ctr> socat - TCP:127.0.0.1:22`
    // — the same byte mover the daemon's WebSocket proxy will adopt
    // — write the staged private key to a host tempfile, and
    // exercise the full SSH handshake against the in-container sshd.
    let key_file = stage_dir.path().join("client_key");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut f = std::fs::File::create(&key_file).expect("create client key");
        f.write_all(kp.private.as_bytes())
            .expect("write client key");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("chmod client key");
    }

    let proxy_cmd = format!("docker exec -i {container_name} socat - TCP:127.0.0.1:22");
    let ssh_output = Command::new("ssh")
        .args([
            // The HostName/Port pair is syntactic; the ProxyCommand
            // shim opens the real bytes pipe — same shape the
            // generated SSH config block uses.
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "ConnectTimeout=10",
            "-o",
            &format!("ProxyCommand={proxy_cmd}"),
            "-i",
            key_file.to_str().expect("utf-8 key path"),
            "sandbox@cross-user-dummy",
            "uname",
            "-a",
        ])
        .output()
        .expect("failed to spawn ssh");
    assert!(
        ssh_output.status.success(),
        "ssh handshake against staged keypair failed (rc={:?}).\n\
         stdout: {}\nstderr: {}",
        ssh_output.status.code(),
        String::from_utf8_lossy(&ssh_output.stdout),
        String::from_utf8_lossy(&ssh_output.stderr),
    );
    let stdout = String::from_utf8_lossy(&ssh_output.stdout);
    assert!(
        stdout.contains("Linux"),
        "expected `Linux` in `uname -a` output through SSH; got: {stdout}",
    );
}
