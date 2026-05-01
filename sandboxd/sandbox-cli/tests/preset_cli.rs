//! CLI surface tests for the M10-S5 preset system.
//!
//! These tests spawn the compiled `sandbox` binary via
//! `CARGO_BIN_EXE_sandbox` and exercise every public preset touch-point:
//!
//! - `sandbox policy preset list | show | expand` — client-local, no
//!   daemon I/O. Covered by [`policy_preset_list_emits_every_builtin`],
//!   [`policy_preset_show_github_repo_documents_repo_param`],
//!   [`policy_preset_expand_github_repo_emits_valid_policy`], and
//!   [`policy_preset_expand_unknown_preset_exits_nonzero`].
//! - `sandbox policy update <sid> --preset 'npm:' --clear` — clap-level
//!   mutual exclusion. Covered by
//!   [`policy_update_preset_plus_clear_is_parse_error`].
//! - `sandbox create --policy ... --preset ... --preset ...` and
//!   `sandbox policy update <sid> --preset ...` — end-to-end body
//!   construction. Covered by
//!   [`create_with_policy_and_two_presets_posts_merged_body`],
//!   [`policy_update_with_preset_posts_merged_body`], and the
//!   integration counterpart
//!   [`create_with_npm_preset_ships_source_presets`].
//!
//! The fake-daemon tests spin an in-process axum HTTP/1.1 server on a
//! tempdir Unix socket, capture exactly one `POST /sessions` (or
//! `POST /sessions/{id}/policy`) request, and assert on its body.
//! This is the same pattern the `events_binary.rs` test uses — no
//! Lima / QEMU work happens in this suite.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{delete, get, post};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Fake-daemon harness
// ---------------------------------------------------------------------------

/// Captured body from the first matching HTTP request the fake daemon
/// sees. `None` until the first request lands.
type CapturedBody = Arc<Mutex<Option<String>>>;

/// Spin a fake axum server on a temp Unix socket that captures the
/// JSON body of the first `POST /sessions` request.
///
/// Returns the tempdir (so the socket survives the test), the socket
/// path as a string, and the shared `CapturedBody` the caller asserts
/// on. The server lives for the duration of the returned `JoinHandle`;
/// drop it to shut the server down.
async fn spawn_fake_daemon_for_create() -> (TempDir, String, CapturedBody) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sandboxd.sock");
    let sock_str = sock_path.to_string_lossy().into_owned();
    let captured: CapturedBody = Arc::new(Mutex::new(None));

    let captured_clone = captured.clone();
    let app = Router::new()
        .route(
            "/sessions",
            post(
                |State(state): State<CapturedBody>, body: String| async move {
                    *state.lock().await = Some(body);
                    // Full `SessionDto` shape — the CLI's
                    // `handle_response` parses the response as
                    // `SessionDto` via serde (see `Command::Create`
                    // branch in `main.rs::handle_response`).
                    (StatusCode::CREATED, Json(fake_session_dto_json()))
                },
            ),
        )
        // M11-S4 Phase 4A: the CLI hits `GET /backends` once per
        // invocation before sending `POST /sessions` (capability-driven
        // client-side validation). Without this route the create
        // would fail in the preflight with HTTP 404 before our
        // `POST /sessions` capture runs. Serve a minimal Lima-only
        // matrix so the preflight succeeds for these preset tests.
        .route("/backends", get(fake_backends_lima_only))
        .with_state(captured_clone);

    spawn_unix_server(&sock_path, app).await;
    (tmp, sock_str, captured)
}

/// Minimal `/backends` body — a single Lima entry with the canonical
/// capability matrix from [`sandbox_core::Capabilities::for_lima`].
///
/// Reused by every fake daemon in this file because Phase 4A's
/// preflight does a single `GET /backends` per CLI invocation; without
/// this route the CLI errors out before the test's request capture
/// runs.
async fn fake_backends_lima_only() -> Json<Value> {
    let infos = vec![sandbox_core::backend::BackendInfo {
        kind: sandbox_core::BackendKind::Lima,
        capabilities: sandbox_core::Capabilities::for_lima(),
    }];
    Json(serde_json::to_value(infos).expect("BackendInfo always serializes"))
}

/// Build a JSON object that matches `sandbox_core::SessionDto` well
/// enough for `handle_response`'s `Command::Create` branch to parse
/// and pretty-print without error.
fn fake_session_dto_json() -> Value {
    // `SessionId::parse` requires exactly 12 lowercase hex characters
    // (see `sandbox_core::session::SessionId::LEN`). Any other shape
    // fails deserialization and the CLI prints `failed to parse
    // response: ...`, turning our "did the daemon receive X?"
    // assertion into a red herring.
    json!({
        "id": "abcdef012345",
        "name": "preset-test",
        "state": "creating",
        "created_at": "2026-04-23T00:00:00Z",
        "updated_at": "2026-04-23T00:00:00Z",
        "config": {
            "cpus": 2,
            "memory_mb": 4096,
            "disk_gb": 20,
            "hardened": true,
        },
    })
}

/// Fake daemon variant for `POST /sessions/{id}/policy`. Accepts any
/// session id and captures the body.
async fn spawn_fake_daemon_for_policy_update() -> (TempDir, String, CapturedBody) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sandboxd.sock");
    let sock_str = sock_path.to_string_lossy().into_owned();
    let captured: CapturedBody = Arc::new(Mutex::new(None));

    let captured_clone = captured.clone();
    let app = Router::new()
        .route(
            "/sessions/{id}/policy",
            post(
                |State(state): State<CapturedBody>, body: String| async move {
                    *state.lock().await = Some(body);
                    (StatusCode::OK, Json(json!({"message": "Policy updated."})))
                },
            )
            .delete(|| async { (StatusCode::OK, Json(json!({"message": "Policy cleared."}))) }),
        )
        .route(
            // Defensive: DELETE on same path for completeness.
            "/dummy",
            delete(|| async { (StatusCode::NOT_FOUND, "") }),
        )
        .with_state(captured_clone);

    spawn_unix_server(&sock_path, app).await;
    (tmp, sock_str, captured)
}

/// Bind an axum router to a Unix listener and spawn the acceptor task.
///
/// `axum::serve` over a `UnixListener` "just works" in axum 0.8 — the
/// same approach `tests/events_binary.rs` uses. The returned task
/// handle is detached (on process exit the temp socket is unlinked and
/// the acceptor drops with the runtime).
async fn spawn_unix_server(sock_path: &std::path::Path, app: Router) {
    let listener = UnixListener::bind(sock_path).expect("bind unix socket");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // Let the spawned accept-loop task register before the client
    // connects. 50ms is plenty — on CI the local-filesystem bind is
    // instant.
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Spawn the compiled `sandbox` binary with a fixed argv, stream its
/// stdout/stderr into strings, and return `(exit_status, stdout,
/// stderr)`.
async fn run_sandbox(
    args: &[&str],
    socket: Option<&str>,
) -> (std::process::ExitStatus, String, String) {
    let binary = env!("CARGO_BIN_EXE_sandbox");
    let mut cmd = Command::new(binary);
    if let Some(sock) = socket {
        cmd.arg("--socket").arg(sock);
    }
    cmd.args(args)
        .env(
            "SANDBOX_SOCKET",
            "/nonexistent/should-be-ignored-when-socket-flag-present",
        )
        // Keep XDG_CONFIG_HOME pointed somewhere empty so user preset
        // files on the developer's machine don't perturb the tests.
        .env(
            "XDG_CONFIG_HOME",
            "/tmp/sandbox-cli-preset-tests-nonexistent",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("subprocess timed out")
        .expect("subprocess spawn/wait");
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Client-local subcommand tests
// ---------------------------------------------------------------------------

/// `sandbox policy preset list` prints one row per built-in (and any
/// user preset), alphabetically by name.
///
/// Verifies every built-in name appears. Doesn't assert the exact
/// format beyond the built-in set — the golden ordering is enforced by
/// a unit test in `presets::mod::tests`.
#[tokio::test]
async fn policy_preset_list_emits_every_builtin() {
    let (status, stdout, stderr) = run_sandbox(&["policy", "preset", "list"], None).await;
    assert!(status.success(), "exit: {status:?}\nstderr: {stderr}");

    // The 10 built-ins shipped in M10-S5 Phase 3, plus the `ubuntu`
    // distro preset added in M12-S4.
    let builtins = [
        "npm",
        "pypi",
        "cargo",
        "goproxy",
        "maven",
        "gradle",
        "dockerhub",
        "github",
        "github-repo",
        "github-pr",
        "ubuntu",
    ];
    for name in builtins {
        assert!(
            stdout.contains(name),
            "`list` stdout missing built-in '{name}'.\nfull output:\n{stdout}"
        );
    }
    // Source column for built-ins must say `built-in` on at least one
    // row. (Every row says it; sampling one proves the column exists.)
    assert!(
        stdout.contains("built-in"),
        "`list` stdout should surface 'built-in' source label.\nfull:\n{stdout}"
    );
}

/// `sandbox policy preset show github-repo` surfaces both the
/// description and the `repo=owner/name` parameter schema.
#[tokio::test]
async fn policy_preset_show_github_repo_documents_repo_param() {
    let (status, stdout, stderr) =
        run_sandbox(&["policy", "preset", "show", "github-repo"], None).await;
    assert!(status.success(), "exit: {status:?}\nstderr: {stderr}");

    assert!(
        stdout.contains("github-repo"),
        "`show` missing preset name. output:\n{stdout}"
    );
    assert!(
        stdout.contains("repo="),
        "`show` missing `repo=` param docs. output:\n{stdout}"
    );
    assert!(
        stdout.contains("owner/name"),
        "`show` missing `owner/name` shape docs. output:\n{stdout}"
    );
}

/// `sandbox policy preset expand 'github-repo:repo=foo/bar'` emits a
/// `{"version":"2.0.0","rules":[...]}` document that round-trips
/// through the `Policy` deserializer.
#[tokio::test]
async fn policy_preset_expand_github_repo_emits_valid_policy() {
    let (status, stdout, stderr) = run_sandbox(
        &["policy", "preset", "expand", "github-repo:repo=foo/bar"],
        None,
    )
    .await;
    assert!(status.success(), "exit: {status:?}\nstderr: {stderr}");

    // D-10: the output is the JSON document shape the daemon accepts
    // via `--policy`. Parse it as JSON and check the version + rules
    // array are present.
    let doc: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expand output is not valid JSON: {e}\noutput:\n{stdout}"));
    assert_eq!(
        doc["version"], "2.0.0",
        "unexpected schema version.\ndoc:\n{doc}"
    );
    assert!(
        doc["rules"].is_array(),
        "expected rules array.\ndoc:\n{doc}"
    );
    let rules = doc["rules"].as_array().unwrap();
    assert!(
        !rules.is_empty(),
        "github-repo:repo=foo/bar should emit at least one rule"
    );
}

/// `sandbox policy preset expand 'does-not-exist:'` exits non-zero
/// with the `UnknownPreset` error text on stderr. Verifies that the
/// CLI surfaces the `PresetError::Display` output verbatim (spec
/// Part 2 "Error shapes").
#[tokio::test]
async fn policy_preset_expand_unknown_preset_exits_nonzero() {
    let (status, stdout, stderr) =
        run_sandbox(&["policy", "preset", "expand", "does-not-exist:"], None).await;
    assert!(
        !status.success(),
        "expected non-zero exit. stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        stderr.contains("unknown preset"),
        "stderr missing `unknown preset` text. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("does-not-exist"),
        "stderr missing preset name. stderr:\n{stderr}"
    );
}

/// `sandbox policy update <sid> --preset 'npm:' --clear` is rejected
/// by clap — `--preset` and `--clear` are mutually exclusive per D-7.
/// Verifies the mutual-exclusion lives at parse time (so the daemon
/// never sees a malformed invocation) rather than at dispatch time.
#[tokio::test]
async fn policy_update_preset_plus_clear_is_parse_error() {
    let (status, _stdout, stderr) = run_sandbox(
        &[
            "policy",
            "update",
            "my-session",
            "--preset",
            "npm:",
            "--clear",
        ],
        None,
    )
    .await;
    assert!(
        !status.success(),
        "expected clap parse error for --preset + --clear"
    );
    // clap's default error mentions "cannot be used with". The exact
    // wording is clap's, not ours — assert on a subset that any
    // reasonable clap version emits.
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("cannot be used with") || lower.contains("conflict"),
        "stderr missing conflict text. stderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// End-to-end body-construction tests (fake daemon)
// ---------------------------------------------------------------------------

/// `sandbox create --policy p.json --preset 'npm:' --preset 'pypi:'`
/// builds a POST body with:
/// - `policy.rules` containing the merged set (policy-file rules first,
///   then the preset rules in invocation order).
/// - `source_presets = ["npm:", "pypi:"]` as a sibling field.
#[tokio::test]
async fn create_with_policy_and_two_presets_posts_merged_body() {
    // Write a minimal policy file with one rule the presets will
    // *not* collide with, so the merge is lossless.
    let tmp = tempfile::tempdir().expect("tempdir");
    let policy_path = tmp.path().join("probe-policy.json");
    let policy_json = r#"{
        "version": "2.0.0",
        "rules": [
            {
                "host": "example.com",
                "port": 443,
                "protocol": "tcp",
                "level": "tls"
            }
        ]
    }"#;
    tokio::fs::File::create(&policy_path)
        .await
        .expect("create policy file")
        .write_all(policy_json.as_bytes())
        .await
        .expect("write policy file");

    let (_dtmp, sock, captured) = spawn_fake_daemon_for_create().await;

    let (status, stdout, stderr) = run_sandbox(
        &[
            "create",
            "--policy",
            policy_path.to_str().unwrap(),
            "--preset",
            "npm:",
            "--preset",
            "pypi:",
            "-y",
        ],
        Some(&sock),
    )
    .await;
    assert!(
        status.success(),
        "exit: {status:?}\nstdout: {stdout}\nstderr: {stderr}"
    );

    let body = captured
        .lock()
        .await
        .clone()
        .expect("fake daemon never saw the create request");
    let parsed: Value = serde_json::from_str(&body).expect("request body is not valid JSON");
    let policy = &parsed["policy"];
    assert_eq!(policy["version"], "2.0.0");
    let rules = policy["rules"]
        .as_array()
        .expect("policy.rules must be an array");
    // 1 file rule + >= 2 preset rules (npm + pypi/files).
    assert!(
        rules.len() >= 3,
        "expected ≥ 3 merged rules, got {}: {:?}",
        rules.len(),
        rules
    );
    // Check a host from each source is present.
    let hosts: Vec<String> = rules
        .iter()
        .filter_map(|r| r["host"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(hosts.contains(&"example.com".to_string()));
    assert!(hosts.contains(&"registry.npmjs.org".to_string()));
    assert!(hosts.contains(&"pypi.org".to_string()));

    let sps = parsed["source_presets"]
        .as_array()
        .expect("source_presets must be an array");
    let sps_strs: Vec<&str> = sps.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(sps_strs, vec!["npm:", "pypi:"]);
}

/// `sandbox policy update <sid> --preset 'cargo:'` builds a POST body
/// via the `UpdatePolicyRequest` DTO shape: top-level Policy fields
/// (`version`, `rules`) flattened plus a sibling `source_presets`
/// array.
#[tokio::test]
async fn policy_update_with_preset_posts_merged_body() {
    let (_dtmp, sock, captured) = spawn_fake_daemon_for_policy_update().await;

    let (status, stdout, stderr) = run_sandbox(
        &["policy", "update", "my-session", "--preset", "cargo:"],
        Some(&sock),
    )
    .await;
    assert!(
        status.success(),
        "exit: {status:?}\nstdout: {stdout}\nstderr: {stderr}"
    );

    let body = captured
        .lock()
        .await
        .clone()
        .expect("fake daemon never saw the policy-update request");
    let parsed: Value = serde_json::from_str(&body).expect("request body is not valid JSON");

    // UpdatePolicyRequest flattens Policy at the top level:
    // {"version": "...", "rules": [...], "source_presets": [...]}.
    assert_eq!(parsed["version"], "2.0.0");
    let rules = parsed["rules"]
        .as_array()
        .expect("top-level rules must be an array");
    let hosts: Vec<String> = rules
        .iter()
        .filter_map(|r| r["host"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        hosts.contains(&"crates.io".to_string()),
        "expected cargo preset to emit crates.io. hosts: {hosts:?}"
    );

    let sps = parsed["source_presets"]
        .as_array()
        .expect("source_presets must be an array");
    let sps_strs: Vec<&str> = sps.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(sps_strs, vec!["cargo:"]);
}

/// `sandbox policy update <sid>` with no `--policy`, no `--preset`,
/// and no `--clear` is rejected by our post-parse validator with a
/// concrete error that names all three options.
///
/// clap's `conflicts_with` covers the "two-of-three" cases but cannot
/// express "at least one of three"; the CLI must surface that
/// ourselves in `build_request`. Regression guard for a subtle bug
/// where we previously required exactly one of `--policy` / `--clear`
/// and silently accepted neither once `--preset` joined the group.
#[tokio::test]
async fn policy_update_with_no_flags_errors_with_three_option_guidance() {
    let (status, _stdout, stderr) = run_sandbox(&["policy", "update", "my-session"], None).await;
    assert!(
        !status.success(),
        "expected non-zero exit when no flags provided"
    );
    // All three option names must appear so the operator can see the
    // full set without looking at `--help`.
    assert!(stderr.contains("--policy"), "stderr:\n{stderr}");
    assert!(stderr.contains("--preset"), "stderr:\n{stderr}");
    assert!(stderr.contains("--clear"), "stderr:\n{stderr}");
}

/// Integration-style test mirroring the cross-check the spec asks for:
/// a create request with only `--preset 'npm:'` produces a daemon-side
/// body that carries `source_presets: ["npm:"]` AND a policy whose
/// rules include the npm registry host.
///
/// This is the "daemon sees the wire shape M10-S5 specifies" test. It
/// complements the unit tests that verify CLI-internal types.
#[tokio::test]
async fn create_with_npm_preset_ships_source_presets() {
    let (_dtmp, sock, captured) = spawn_fake_daemon_for_create().await;

    let (status, stdout, stderr) =
        run_sandbox(&["create", "--preset", "npm:", "-y"], Some(&sock)).await;
    assert!(
        status.success(),
        "exit: {status:?}\nstdout: {stdout}\nstderr: {stderr}"
    );

    let body = captured
        .lock()
        .await
        .clone()
        .expect("fake daemon never saw the create request");
    let parsed: Value = serde_json::from_str(&body).unwrap();

    assert_eq!(parsed["source_presets"], json!(["npm:"]));

    let rules = parsed["policy"]["rules"]
        .as_array()
        .expect("policy.rules array");
    let hosts: Vec<String> = rules
        .iter()
        .filter_map(|r| r["host"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        hosts.contains(&"registry.npmjs.org".to_string()),
        "npm preset should emit registry.npmjs.org. hosts: {hosts:?}"
    );
}
