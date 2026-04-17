//! Integration test: verify `sandboxd --log-file PATH` writes tracing output
//! to the file instead of stderr.
//!
//! Strategy:
//!   1. Spawn the freshly-built `sandboxd` binary with `--log-file`, a
//!      tempdir-scoped `--base-dir`, and a tempdir-scoped `--socket`.
//!   2. Poll the log file until it has content (or timeout).
//!   3. Kill the process, read the file, assert at least one line matches
//!      the default tracing fmt layout (`<ISO-8601 ts>  <LEVEL> ...`).
//!   4. `tempfile::TempDir` handles cleanup on drop.
//!
//! This test does NOT require Lima, Docker, or network access: we only
//! need the daemon to run far enough to emit the `"sandboxd starting"`
//! log line, which happens before any resource initialization.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Path to the `sandboxd` binary produced by `cargo build`.
///
/// Cargo sets `CARGO_BIN_EXE_<name>` for the integration test crate of a
/// binary target.
fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

/// A line produced by the default `tracing_subscriber::fmt` layer looks like:
///
///     2024-11-15T12:34:56.789012Z  INFO sandboxd: sandboxd starting ...
///
/// We don't need a strict regex -- a quick shape check is enough.
fn looks_like_tracing_line(line: &str) -> bool {
    // Starts with a year (4 digits + '-') and contains a known level keyword.
    let starts_with_iso =
        line.chars().take(4).all(|c| c.is_ascii_digit()) && line.chars().nth(4) == Some('-');
    let has_level = line.contains(" INFO ")
        || line.contains(" WARN ")
        || line.contains(" DEBUG ")
        || line.contains(" ERROR ")
        || line.contains(" TRACE ");
    starts_with_iso && has_level
}

#[test]
fn sandboxd_log_file_flag_writes_parseable_lines() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_path = tmp.path().join("sandboxd.log");
    let base_dir = tmp.path().join("state");
    let socket_path = tmp.path().join("sandboxd.sock");

    // Spawn the daemon. It will emit startup logs regardless of whether
    // later initialization (Lima, network) succeeds on this host.
    let mut child = Command::new(sandboxd_bin())
        .arg("--log-file")
        .arg(&log_path)
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--socket")
        .arg(&socket_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sandboxd");

    // Poll until the log file has content, or time out. We don't care
    // whether the daemon is still alive -- even a crash post-startup is
    // fine as long as at least one tracing line was written.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got_content = false;
    while Instant::now() < deadline {
        if let Ok(meta) = std::fs::metadata(&log_path)
            && meta.len() > 0
        {
            got_content = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Kill the daemon before we assert, so the tempdir cleanup succeeds
    // even if assertions fail.
    let _ = child.kill();
    let _ = child.wait();

    // Drain stderr for debugging if the assertion fails.
    let mut stderr_output = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut stderr_output);
    }

    assert!(
        got_content,
        "log file {log_path:?} was never written to within 10s; stderr was: {stderr_output}"
    );

    let contents = std::fs::read_to_string(&log_path).expect("read log file");
    assert!(
        !contents.is_empty(),
        "log file exists but is empty; stderr was: {stderr_output}"
    );

    let has_parseable_line = contents.lines().any(looks_like_tracing_line);
    assert!(
        has_parseable_line,
        "no tracing-formatted line found in log file.\n\
         --- log contents ---\n{contents}\n\
         --- stderr ---\n{stderr_output}",
    );

    // Sanity: stderr must NOT contain tracing output when --log-file is set.
    // (We only check for the exact startup message -- other stderr output
    // from unrelated errors is fine.)
    assert!(
        !stderr_output.contains("sandboxd starting"),
        "stderr should not receive tracing output when --log-file is set; got:\n{stderr_output}"
    );
}
