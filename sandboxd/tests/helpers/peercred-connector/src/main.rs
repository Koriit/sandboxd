//! `peercred-connector` — setuid-root test helper that forwards a
//! request to the sandboxd unix socket under a caller-specified uid.
//!
//! Spec reference: `2026-05-11-api-session-isolation-guest-compat-design`
//! § 9.2 (Multi-uid test harness for `SO_PEERCRED` — Lima VM path).
//!
//! ## Why this exists
//!
//! `SO_PEERCRED` is kernel-set on `connect(2)`; you cannot fake it
//! from userspace. To verify the daemon's per-caller ownership filter
//! end-to-end (alice's `GET /sessions/<id>` against bob's session
//! returns `404`), the test fixture must connect from a uid distinct
//! from the test runner's. That requires either spinning up two real
//! OS users (unworkable on a typical developer host) or a setuid
//! helper that drops to a target uid before opening the socket.
//!
//! This helper is the second option. It is installed setuid-root
//! inside the Lima E2E VM template (`install -o root -m 4755 .../`)
//! by Spec 4 § 6's provisioning step, NEVER on the host CI runner or
//! the developer workstation. It is not a privilege-cap'd production
//! binary; it lives in `sandboxd/tests/helpers/`, not the workspace
//! `[workspace.members]` list, and the release tarball never carries
//! it.
//!
//! ## Interface
//!
//! ```text
//! peercred-connector --uid <target-uid> --request-file <path> [--socket <path>]
//! ```
//!
//! - `--uid <target-uid>` — numeric uid to `setresuid` / `setresgid`
//!   to before the connect. The helper drops both uid and gid so
//!   `SO_PEERCRED` reports the matching values. Mandatory.
//! - `--request-file <path>` — file containing the raw HTTP/1.1
//!   request bytes to send to the daemon socket. The contents are
//!   transmitted verbatim; the helper does not parse or modify
//!   them. Mandatory.
//! - `--socket <path>` — daemon unix socket path. Defaults to
//!   `/run/sandbox/sandboxd.sock` (Spec 3's production location).
//!
//! The helper:
//!
//! 1. Parses argv.
//! 2. Reads the request bytes into a buffer (small — kilobytes).
//! 3. `setresgid(target_gid, target_gid, target_gid)` then
//!    `setresuid(target_uid, target_uid, target_uid)`. The strict
//!    triple-uid set drops saved-uid too, so the helper cannot
//!    regain root after the drop.
//! 4. Verifies the drop took (`geteuid() == target_uid`,
//!    `getegid() == target_gid`, `getuid() == target_uid`) — if
//!    `setres*` silently no-op'd (e.g. the binary was not setuid),
//!    the helper exits with `EXIT_PRIV_DROP_FAILED`.
//! 5. `connect(2)` the daemon socket.
//! 6. Writes the request buffer (one `write_all`).
//! 7. Reads the response until EOF or a 64 KiB cap. Writes the
//!    bytes verbatim to stdout. The cap is a safety bound — real
//!    daemon responses for `GET /sessions[/id]` are under 16 KiB
//!    in practice.
//! 8. Exits `0` on success, non-zero on any error.
//!
//! ## What this helper does NOT do
//!
//! - Parse HTTP. The caller composes the full request line +
//!   headers + body and writes them to `--request-file`. The
//!   helper is a verbatim forwarder so the harness can drive
//!   arbitrary endpoints (H3, H5, H6, H7, H8, H9, H10, H11, H12)
//!   without re-encoding the wire format.
//! - Retry. A failed `connect(2)` is fatal — the test harness can
//!   re-invoke the helper if it wants retries.
//! - Resolve the target uid by name. `--uid` is numeric so the
//!   test does the `getent passwd sandbox | awk -F: '{print $3}'`
//!   lookup in shell (where it can fail-loud if the user is
//!   missing). This keeps the helper's TCB minimal — no
//!   `getpwnam_r` reach into NSS.
//!
//! ## Build / installation (not wired in this commit)
//!
//! This binary is added to the test-helper build target by the
//! future Lima multi-uid test harness work. For now, this commit
//! lands the artifact only so that future harness work has a
//! buildable helper to install. The Cargo.toml above is
//! deliberately a *standalone* crate (not a workspace member) so
//! a workspace-level `cargo build --workspace` does not pull this
//! into the release build's feature graph. To build it:
//!
//! ```sh
//! cd sandboxd/tests/helpers/peercred-connector
//! cargo build --release
//! ```
//!
//! The expected install step inside a Lima VM template (added by
//! the future session):
//!
//! ```sh
//! sudo install -o root -m 4755 \
//!     "${SANDBOXD_TEST_HELPERS}/peercred-connector" \
//!     /usr/local/lib/sandboxd-tests/peercred-connector
//! ```

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Exit codes — kept distinct so harness failures point at the right step.
// ---------------------------------------------------------------------------

/// Argv malformed (missing flag, non-numeric uid, ...). Equivalent
/// shape to the route-helper's argv-parse failure exit.
const EXIT_BAD_ARGV: u8 = 2;
/// `setresuid` / `setresgid` returned success but `geteuid`/`getuid`
/// disagree with `--uid`. The binary is probably not setuid-root.
const EXIT_PRIV_DROP_FAILED: u8 = 3;
/// I/O failure (request-file read, socket connect, write, read).
const EXIT_IO: u8 = 4;
/// Response exceeded the 64 KiB safety cap.
const EXIT_RESPONSE_TOO_LARGE: u8 = 5;

/// Maximum response bytes the helper accepts. Real `GET /sessions`
/// bodies are well under this; the cap is a safety bound against a
/// pathological daemon response or a corrupted stream that never
/// EOFs.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Production default daemon socket path (Spec 3 § 5.2). The Lima
/// VM template's `--socket` override is rarely needed; lite-mode
/// dev hosts may pass `--socket` explicitly.
const DEFAULT_SOCKET_PATH: &str = "/run/sandbox/sandboxd.sock";

#[derive(Debug, Error)]
enum Error {
    #[error("bad argv: {0}")]
    BadArgv(String),
    #[error("privilege drop failed: setres{kind} did not take effect (target={target}, current={current})")]
    PrivDropFailed {
        kind: &'static str,
        target: u32,
        current: u32,
    },
    #[error("setres{kind}({target}) failed: errno={errno}")]
    SetresFailed {
        kind: &'static str,
        target: u32,
        errno: i32,
    },
    #[error("read request-file {path}: {err}")]
    ReadRequest {
        path: PathBuf,
        err: std::io::Error,
    },
    #[error("connect to socket {path}: {err}")]
    Connect {
        path: PathBuf,
        err: std::io::Error,
    },
    #[error("write to socket: {0}")]
    Write(std::io::Error),
    #[error("read response: {0}")]
    Read(std::io::Error),
    #[error("response exceeded {MAX_RESPONSE_BYTES} bytes safety cap")]
    ResponseTooLarge,
}

impl Error {
    fn exit_code(&self) -> u8 {
        match self {
            Error::BadArgv(_) => EXIT_BAD_ARGV,
            Error::PrivDropFailed { .. } | Error::SetresFailed { .. } => EXIT_PRIV_DROP_FAILED,
            Error::ReadRequest { .. }
            | Error::Connect { .. }
            | Error::Write(_)
            | Error::Read(_) => EXIT_IO,
            Error::ResponseTooLarge => EXIT_RESPONSE_TOO_LARGE,
        }
    }
}

#[derive(Debug)]
struct Args {
    target_uid: u32,
    request_file: PathBuf,
    socket: PathBuf,
}

fn parse_argv(argv: &[String]) -> Result<Args, Error> {
    let mut target_uid: Option<u32> = None;
    let mut request_file: Option<PathBuf> = None;
    let mut socket: Option<PathBuf> = None;
    let mut i = 1; // skip argv[0]
    while i < argv.len() {
        match argv[i].as_str() {
            "--uid" => {
                let raw = argv.get(i + 1).ok_or_else(|| {
                    Error::BadArgv("--uid requires a numeric value".into())
                })?;
                target_uid = Some(raw.parse::<u32>().map_err(|e| {
                    Error::BadArgv(format!("--uid value {raw:?} is not a u32: {e}"))
                })?);
                i += 2;
            }
            "--request-file" => {
                let raw = argv
                    .get(i + 1)
                    .ok_or_else(|| Error::BadArgv("--request-file requires a path".into()))?;
                request_file = Some(PathBuf::from(raw));
                i += 2;
            }
            "--socket" => {
                let raw = argv
                    .get(i + 1)
                    .ok_or_else(|| Error::BadArgv("--socket requires a path".into()))?;
                socket = Some(PathBuf::from(raw));
                i += 2;
            }
            other => {
                return Err(Error::BadArgv(format!("unknown flag: {other}")));
            }
        }
    }
    Ok(Args {
        target_uid: target_uid.ok_or_else(|| Error::BadArgv("--uid is required".into()))?,
        request_file: request_file
            .ok_or_else(|| Error::BadArgv("--request-file is required".into()))?,
        socket: socket.unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
    })
}

/// Drop the helper's uid+gid to `target_uid` via `setresuid` /
/// `setresgid`. The triple-uid set is deliberate — without dropping
/// the saved uid, a binary like this could `setuid(0)` later to
/// regain root, which is not what we want for a test helper.
///
/// `target_gid` is set to the same numeric value as `target_uid` so
/// the resulting `SO_PEERCRED` carries matching uid/gid (the daemon
/// only consults the uid today, but matching keeps the values
/// consistent for any future gid-based check).
fn drop_to(target_uid: u32) -> Result<(), Error> {
    // SAFETY: `setresgid` / `setresuid` are well-defined libc calls;
    // we check the return value below and never reuse the helper
    // across uid drops.
    let target_gid = target_uid; // see doc-comment
    let gid_rc = unsafe { libc::setresgid(target_gid, target_gid, target_gid) };
    if gid_rc != 0 {
        return Err(Error::SetresFailed {
            kind: "gid",
            target: target_gid,
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    let uid_rc = unsafe { libc::setresuid(target_uid, target_uid, target_uid) };
    if uid_rc != 0 {
        return Err(Error::SetresFailed {
            kind: "uid",
            target: target_uid,
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }

    // Belt-and-suspenders verification: if the binary is not setuid-
    // root (e.g. the test harness forgot to `install -m 4755`),
    // `setresuid` returns 0 but the uid does not change. Cross-check
    // via `geteuid` / `getuid` so a misconfigured install fails loudly
    // rather than silently connecting as the test runner.
    let actual_euid = nix::unistd::geteuid().as_raw();
    if actual_euid != target_uid {
        return Err(Error::PrivDropFailed {
            kind: "euid",
            target: target_uid,
            current: actual_euid,
        });
    }
    let actual_ruid = nix::unistd::getuid().as_raw();
    if actual_ruid != target_uid {
        return Err(Error::PrivDropFailed {
            kind: "ruid",
            target: target_uid,
            current: actual_ruid,
        });
    }
    let actual_egid = nix::unistd::getegid().as_raw();
    if actual_egid != target_gid {
        return Err(Error::PrivDropFailed {
            kind: "egid",
            target: target_gid,
            current: actual_egid,
        });
    }

    Ok(())
}

/// Forward bytes from `request_path` to `socket_path` and copy the
/// daemon's response to stdout. Caps the response at
/// [`MAX_RESPONSE_BYTES`].
fn forward(request_path: &std::path::Path, socket_path: &std::path::Path) -> Result<(), Error> {
    let request_bytes =
        std::fs::read(request_path).map_err(|err| Error::ReadRequest {
            path: request_path.to_path_buf(),
            err,
        })?;

    let mut stream = UnixStream::connect(socket_path).map_err(|err| Error::Connect {
        path: socket_path.to_path_buf(),
        err,
    })?;

    stream.write_all(&request_bytes).map_err(Error::Write)?;
    // Half-close the write side so the daemon sees EOF if the
    // request body has indefinite length (e.g. no Content-Length
    // header on a GET). For Content-Length-stamped requests this
    // is a no-op; for the test harness's typical short GET it
    // ensures the daemon's HTTP parser sees the request as
    // complete.
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut buf = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let n = stream.read(&mut chunk).map_err(Error::Read)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_RESPONSE_BYTES {
            return Err(Error::ResponseTooLarge);
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&buf).map_err(Error::Write)?;
    stdout.flush().map_err(Error::Write)?;
    Ok(())
}

fn run() -> Result<(), Error> {
    let argv: Vec<String> = std::env::args().collect();
    let args = parse_argv(&argv)?;
    drop_to(args.target_uid)?;
    forward(&args.request_file, &args.socket)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("peercred-connector: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        std::iter::once("peercred-connector".to_string())
            .chain(items.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn parses_minimum_argv() {
        let parsed = parse_argv(&argv(&[
            "--uid",
            "1000",
            "--request-file",
            "/tmp/req",
        ]))
        .expect("parse");
        assert_eq!(parsed.target_uid, 1000);
        assert_eq!(parsed.request_file, PathBuf::from("/tmp/req"));
        assert_eq!(parsed.socket, PathBuf::from(DEFAULT_SOCKET_PATH));
    }

    #[test]
    fn parses_with_socket_override() {
        let parsed = parse_argv(&argv(&[
            "--uid",
            "2000",
            "--request-file",
            "/tmp/req2",
            "--socket",
            "/tmp/sandboxd.sock",
        ]))
        .expect("parse");
        assert_eq!(parsed.target_uid, 2000);
        assert_eq!(parsed.socket, PathBuf::from("/tmp/sandboxd.sock"));
    }

    #[test]
    fn argv_order_independent() {
        // Each flag's value follows it immediately, but the flag
        // *order* may vary — the parser must accept any permutation.
        let parsed = parse_argv(&argv(&[
            "--request-file",
            "/tmp/req",
            "--socket",
            "/tmp/sock",
            "--uid",
            "1000",
        ]))
        .expect("parse");
        assert_eq!(parsed.target_uid, 1000);
        assert_eq!(parsed.request_file, PathBuf::from("/tmp/req"));
        assert_eq!(parsed.socket, PathBuf::from("/tmp/sock"));
    }

    #[test]
    fn missing_uid_is_argv_error() {
        let err = parse_argv(&argv(&["--request-file", "/tmp/req"])).expect_err("must error");
        assert!(matches!(err, Error::BadArgv(_)));
        assert_eq!(err.exit_code(), EXIT_BAD_ARGV);
        let msg = format!("{err}");
        assert!(msg.contains("--uid"), "error must name the missing flag; got: {msg}");
    }

    #[test]
    fn missing_request_file_is_argv_error() {
        let err = parse_argv(&argv(&["--uid", "1000"])).expect_err("must error");
        assert!(matches!(err, Error::BadArgv(_)));
        let msg = format!("{err}");
        assert!(
            msg.contains("--request-file"),
            "error must name the missing flag; got: {msg}"
        );
    }

    #[test]
    fn non_numeric_uid_is_argv_error() {
        let err = parse_argv(&argv(&[
            "--uid",
            "alice",
            "--request-file",
            "/tmp/req",
        ]))
        .expect_err("must error");
        assert!(matches!(err, Error::BadArgv(_)));
        let msg = format!("{err}");
        assert!(
            msg.contains("alice") || msg.contains("u32"),
            "error must name the bad value or the parse target type; got: {msg}"
        );
    }

    #[test]
    fn unknown_flag_is_argv_error() {
        let err = parse_argv(&argv(&[
            "--uid",
            "1000",
            "--request-file",
            "/tmp/req",
            "--foo",
            "bar",
        ]))
        .expect_err("must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("--foo"),
            "error must name the unknown flag; got: {msg}"
        );
    }

    #[test]
    fn exit_codes_are_distinct() {
        // Mechanical: the exit-code table must keep each Error
        // variant on a distinct value so the harness can distinguish
        // failure modes from the exit code alone.
        let codes = [
            EXIT_BAD_ARGV,
            EXIT_PRIV_DROP_FAILED,
            EXIT_IO,
            EXIT_RESPONSE_TOO_LARGE,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "exit codes must be unique");
        // 0 is reserved for success and 1 conventionally denotes
        // "generic failure"; neither should appear here.
        for c in codes {
            assert!(c >= 2, "exit code {c} collides with conventional 0/1");
        }
    }
}
