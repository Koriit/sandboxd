//! `sandbox-docker-argv` — `docker` command-line fragments shared by the two
//! sides of the broker channel.
//!
//! # Why this is its own crate
//!
//! The daemon (`sandbox-core`) decides *what* a `docker` invocation should do;
//! on macOS the per-operator agent (`sandbox-agent`) is what actually runs it,
//! because the Docker socket lives inside the operator's VM and is unreadable
//! by the daemon account. Both sides therefore need the same argv fragments,
//! and they must not drift: a mismatch between the shape the daemon assumes
//! and the shape the agent builds is a silent behaviour difference on the
//! egress-enforcement path.
//!
//! The obvious two homes for shared fragments are both wrong:
//!
//! - **`sandbox-core`** — `sandbox-agent` does not depend on it, deliberately.
//!   The agent is a small, separately-reviewable binary that runs as the
//!   operator; keeping `sandbox-core` (and its dependency tree: sqlite,
//!   refinery, rcgen, ring, …) out of it is what makes that review tractable.
//!   Reversing the arrow — `sandbox-core` → `sandbox-agent` — inverts the same
//!   boundary from the other end.
//! - **The broker protocol library** (`sandbox_agent_protocol`) — that library
//!   is macOS-only, because the broker channel does not exist on Linux. The
//!   `docker` argv builders run **on Linux too** (the lite container backend),
//!   so moving them there either breaks the Linux build or forces the
//!   inversion above.
//!
//! Hence a leaf crate: **zero dependencies, depended on by both**, buildable on
//! every target the workspace supports. The dependency direction is
//! `sandbox-core → sandbox-docker-argv ← sandbox-agent`, with no edge between
//! `sandbox-core` and `sandbox-agent` in either direction.
//!
//! # What belongs here
//!
//! Pure functions from typed values to argv fragments, with no I/O, no process
//! spawning and no policy. Anything that decides *whether* an invocation is
//! allowed belongs on the agent side, next to the rest of its validation.

use std::path::Path;

/// The `docker` executable name, as it appears in argv slot 0.
///
/// Resolution to an absolute path is deliberately *not* done here: the daemon
/// and the agent resolve binaries under different rules (the agent resolves
/// from a fixed candidate list rather than searching `PATH`), and folding that
/// difference into a shared constant would hide it.
pub const DOCKER_BIN: &str = "docker";

/// Render a Unix socket path as a `docker -H` target URL: `unix://<path>`.
///
/// Non-UTF-8 path bytes are rendered lossily, matching the behaviour of every
/// call site this replaced.
pub fn unix_socket_url(socket: &Path) -> String {
    format!("unix://{}", socket.display())
}

/// The `-H unix://<socket>` prefix arguments for a `docker` invocation.
///
/// `None` yields an empty vector: the caller's `docker` talks to whatever
/// socket its own environment resolves, which is the Linux/host-daemon case.
/// `Some(socket)` pins the target authority explicitly, which is the macOS
/// case where the daemon must reach the Docker instance inside a specific VM.
///
/// Returning the flag and its value as two separate arguments (rather than one
/// `-H=unix://…` token) keeps the fragment usable both by argv builders and by
/// `Command::args`, and matches how `docker` documents the flag.
pub fn host_args(socket: Option<&Path>) -> Vec<String> {
    match socket {
        None => Vec::new(),
        Some(socket) => vec!["-H".to_string(), unix_socket_url(socket)],
    }
}

/// The rsync remote-shell (`-e`) transport string for reaching a container.
///
/// This one is a **shell string, not an argv**: rsync re-parses the value of
/// `-e` as a word list, so the fragment is assembled as text and split again
/// downstream. It is the one shape in the `docker` surface that cannot be
/// expressed as a `Vec<String>` handed straight to `exec`, which is exactly why
/// it is built here once instead of being formatted at each call site.
///
/// `-i` forwards stdin so rsync can speak its binary protocol in both
/// directions. There is deliberately no `-t`: a TTY would line-buffer and
/// corrupt the wire format.
///
/// The socket argument follows [`host_args`]: `None` is the host-daemon case.
/// A socket path containing whitespace or shell metacharacters would not
/// survive rsync's re-parse — callers that accept operator-supplied socket
/// paths must validate them; the daemon's socket paths are constructed, not
/// supplied.
pub fn exec_rsh_transport(socket: Option<&Path>) -> String {
    match socket {
        None => format!("{DOCKER_BIN} exec -i"),
        Some(socket) => format!("{DOCKER_BIN} -H {} exec -i", unix_socket_url(socket)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_socket_yields_no_host_arguments() {
        assert!(
            host_args(None).is_empty(),
            "the host-daemon case must add nothing to the argv"
        );
    }

    #[test]
    fn socket_yields_flag_and_url_as_separate_arguments() {
        let args = host_args(Some(Path::new("/var/run/gateway-docker.sock")));
        assert_eq!(
            args,
            vec![
                "-H".to_string(),
                "unix:///var/run/gateway-docker.sock".to_string()
            ]
        );
    }

    #[test]
    fn socket_url_carries_the_unix_scheme() {
        assert_eq!(
            unix_socket_url(Path::new("/tmp/docker.sock")),
            "unix:///tmp/docker.sock"
        );
    }

    #[test]
    fn rsh_transport_without_socket_is_the_host_daemon_form() {
        assert_eq!(exec_rsh_transport(None), "docker exec -i");
    }

    #[test]
    fn rsh_transport_with_socket_pins_the_target_authority() {
        assert_eq!(
            exec_rsh_transport(Some(Path::new("/run/gw.sock"))),
            "docker -H unix:///run/gw.sock exec -i"
        );
    }

    /// The `-e` value is re-parsed by rsync as a word list, so the fragment
    /// must split into the same tokens the argv form produces.
    #[test]
    fn rsh_transport_splits_into_the_same_tokens_as_the_argv_form() {
        let socket = Path::new("/run/gw.sock");
        let transport = exec_rsh_transport(Some(socket));
        let words: Vec<&str> = transport.split(' ').collect();
        let mut expected = vec![DOCKER_BIN.to_string()];
        expected.extend(host_args(Some(socket)));
        expected.extend(["exec".to_string(), "-i".to_string()]);
        assert_eq!(words, expected);
    }
}
