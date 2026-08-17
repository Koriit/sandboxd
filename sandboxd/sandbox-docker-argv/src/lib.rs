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
//!
//! # Why the inputs are enums rather than strings
//!
//! Several builders take a small enum where a string would have been the
//! obvious choice — the `docker inspect` format template, the command run by
//! `docker exec`, the tarball a `docker load` reads. Each of those is a place
//! where a caller-supplied string would be a pass-through in disguise: a Go
//! template can read any field of a container's configuration, an exec argv is
//! arbitrary code inside the container, and a file path is arbitrary read
//! access. Enumerating the values keeps the surface a reviewer can enumerate
//! too, which is the property the whole broker op set rests on.

use std::path::Path;

pub mod container;
pub mod gateway;
pub mod image;
pub mod network;
pub mod stream;
pub mod volume;

/// A refusal from an argv builder.
///
/// Builders are pure and cannot consult docker about what an escape would
/// mean, so the few inputs that cannot be rendered unambiguously are refused
/// with an operator-facing explanation rather than escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerArgvError {
    message: String,
}

impl DockerArgvError {
    /// Construct a refusal carrying an operator-facing explanation.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The operator-facing explanation.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Consume the error, yielding its message.
    pub fn into_message(self) -> String {
        self.message
    }
}

impl std::fmt::Display for DockerArgvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DockerArgvError {}

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
///
/// # What "survives the re-parse" means, and what it does not
///
/// The value is split by rsync's own parser ([`rsh_split`]) and the resulting
/// word list is handed to `execvp` — **no shell is involved at any point**.
/// So the failure mode of a path this parser mangles is a malformed `docker`
/// argv that fails loudly, not command injection: there is nothing for a
/// metacharacter to be a metacharacter *to*. What the property protects is
/// that the invocation rsync builds is the invocation intended, which
/// [`rsh_split`] makes checkable rather than assumed.
///
/// A socket path containing a space or a quote would not reconstruct
/// (`rsh_split`'s tests characterise exactly how each one fails). Every path
/// reaching this function today is constructed — the daemon renders
/// `{lima_home}/sandboxd-gateway/gateway-docker.sock` from numeric uids and
/// the agent derives its own — so none is operator-supplied. A caller that
/// ever accepts one must check it through [`rsh_split`] first.
pub fn exec_rsh_transport(socket: Option<&Path>) -> String {
    match socket {
        None => format!("{DOCKER_BIN} exec -i"),
        Some(socket) => format!("{DOCKER_BIN} -H {} exec -i", unix_socket_url(socket)),
    }
}

/// Split a remote-shell (`-e` / `--rsh`) string into the argv **rsync**
/// builds from it — or refuse, when the two rsync implementations in play
/// would not build the same one.
///
/// This exists because the one fragment in this crate that is a
/// shell-shaped *string* rather than a `Vec<String>` has to be checked
/// against the argv it is meant to become. It is not checked against a model
/// of a shell: rsync re-parses `-e` itself and hands the words straight to
/// `execvp`, so a shell's rules — backslash escapes, `$`, `;`, globbing —
/// are the rules of a parser this string never reaches.
///
/// # Why it refuses rather than picking an answer
///
/// The same transport string is re-parsed by **GNU rsync** on Linux and by
/// **openrsync** on macOS, which is what `/usr/bin/rsync` is there. They do
/// not agree everywhere, and the disagreements were measured on this host
/// (openrsync 2.6.9-compatible, protocol 29) by pointing `-e` at a script
/// that dumps its own argv:
///
/// * **A tab separates words in openrsync and does not in GNU rsync.**
///   `-H unix://a<TAB>b` reaches openrsync's child as two arguments and GNU
///   rsync's as one.
/// * **A doubled quote inside a quoted run differs.** openrsync emits one
///   literal quote and stays inside the run (`'a''b'` → `a'b`); GNU rsync
///   emits one and lets the second close the run, which for that input
///   leaves the rest unterminated and aborts.
/// * **An empty quoted word aborts openrsync** with an assertion failure in
///   `fargs.c`, rather than producing an empty argument.
///
/// So this returns the words only where both implementations produce the
/// same ones, and `Err` otherwise. Anything it accepts is parsed identically
/// by both; anything it refuses has no single correct answer, which for a
/// fragment shared by both platforms is the only useful verdict.
///
/// The rules it does implement, and on which both agree:
///
/// * Words are separated by **spaces**; runs collapse and leading/trailing
///   ones vanish.
/// * Single and double quotes suppress separation and are removed; a quote
///   may open mid-word; a quote of the *other* kind inside a quoted run is
///   an ordinary character.
/// * A backslash is an ordinary character — there is no escape, so it does
///   not protect the space after it.
/// * An unterminated quote is fatal to rsync itself, so it is an `Err` here.
pub fn rsh_split(transport: &str) -> Result<Vec<String>, DockerArgvError> {
    if let Some(c) = transport.chars().find(|c| c.is_whitespace() && *c != ' ') {
        return Err(DockerArgvError::new(format!(
            "remote-shell command contains {c:?}, which openrsync treats as a word \
             separator and GNU rsync treats as an ordinary character — the two would \
             build different command lines from it"
        )));
    }

    let chars: Vec<char> = transport.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] == ' ' {
            i += 1;
            continue;
        }
        let mut word = String::new();
        let mut in_quote: Option<char> = None;
        while i < chars.len() && (chars[i] != ' ' || in_quote.is_some()) {
            let c = chars[i];
            match (c, in_quote) {
                ('\'' | '"', None) => {
                    in_quote = Some(c);
                    i += 1;
                }
                ('\'' | '"', Some(q)) if c == q => {
                    if chars.get(i + 1).copied() == Some(q) {
                        return Err(DockerArgvError::new(format!(
                            "remote-shell command doubles a {q} inside a {q}-quoted run; \
                             openrsync and GNU rsync disagree about what that means"
                        )));
                    }
                    in_quote = None;
                    i += 1;
                }
                _ => {
                    word.push(c);
                    i += 1;
                }
            }
        }
        if in_quote.is_some() {
            let q = in_quote.expect("checked");
            return Err(DockerArgvError::new(format!(
                "remote-shell command has no closing {q} — rsync refuses it outright \
                 (\"Missing terminating `{q}` in specified remote-shell command\")"
            )));
        }
        if word.is_empty() {
            return Err(DockerArgvError::new(
                "remote-shell command contains an empty quoted word; openrsync aborts \
                 on one rather than passing an empty argument"
                    .to_string(),
            ));
        }
        words.push(word);
    }

    Ok(words)
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

    /// The `-e` value is re-parsed by **rsync's** word-splitter, not by a
    /// shell, so the round trip is asserted through [`rsh_split`] — the port
    /// of rsync's own loop — rather than through `str::split(' ')`, which
    /// agrees with it only by accident on inputs this simple.
    #[test]
    fn rsh_transport_reparses_into_the_same_tokens_as_the_argv_form() {
        let socket = Path::new("/run/gw.sock");
        let transport = exec_rsh_transport(Some(socket));
        let mut expected = vec![DOCKER_BIN.to_string()];
        expected.extend(host_args(Some(socket)));
        expected.extend(["exec".to_string(), "-i".to_string()]);
        assert_eq!(
            rsh_split(&transport).expect("the transport must be re-parsable"),
            expected
        );
    }

    /// The host-daemon form round-trips too, and to an argv with no `-H`.
    #[test]
    fn host_daemon_rsh_transport_reparses_without_a_target_flag() {
        let words = rsh_split(&exec_rsh_transport(None)).expect("re-parsable");
        assert_eq!(words, vec![DOCKER_BIN, "exec", "-i"]);
    }

    /// The shapes production actually renders: the daemon builds the socket
    /// path from `{lima_home}/sandboxd-gateway/gateway-docker.sock` with
    /// numeric uids, and the agent derives the same shape from its own
    /// LIMA_HOME. Both must reconstruct exactly, with the URL surviving as
    /// one word.
    #[test]
    fn constructed_socket_paths_reparse_to_a_single_url_word() {
        for path in [
            "/var/lib/sandboxd/501/sandboxd-gateway/gateway-docker.sock",
            "/var/lib/sandboxd/280/502/lima/sandboxd-gateway/gateway-docker.sock",
        ] {
            let socket = Path::new(path);
            let words = rsh_split(&exec_rsh_transport(Some(socket))).expect("re-parsable");
            assert_eq!(
                words,
                vec![
                    DOCKER_BIN.to_string(),
                    "-H".to_string(),
                    format!("unix://{path}"),
                    "exec".to_string(),
                    "-i".to_string(),
                ],
                "the socket URL must survive rsync's re-parse as one word"
            );
        }
    }

    /// Characterises the inputs that would **not** survive, so the doc
    /// comment's "a caller that accepts an operator-supplied path must check
    /// it" is a checkable statement rather than a warning nobody can test.
    /// A space splits the URL in two — rsync would exec `docker` with a
    /// truncated target and a stray argument, which fails loudly and is not
    /// an injection, because rsync `execvp`s this list without a shell.
    #[test]
    fn a_socket_path_with_a_space_does_not_survive_the_reparse() {
        let socket = Path::new("/var/lib/sandbox d/gw.sock");
        let words = rsh_split(&exec_rsh_transport(Some(socket))).expect("re-parsable");
        assert_eq!(
            words,
            vec![
                "docker",
                "-H",
                "unix:///var/lib/sandbox",
                "d/gw.sock",
                "exec",
                "-i"
            ],
            "a space splits the URL into two words — the target authority is lost"
        );
    }

    /// An unterminated quote is fatal to rsync itself: it prints
    /// `Missing trailing-'` and exits rather than running anything.
    #[test]
    fn an_unterminated_quote_is_refused_outright() {
        let err = rsh_split("docker -H 'unix:///gw.sock exec -i")
            .expect_err("an unterminated quote must not parse");
        assert!(
            err.message().contains("no closing '"),
            "the refusal must name the missing quote; got {}",
            err.message()
        );
    }

    /// Runs of spaces collapse and leading/trailing ones vanish — both
    /// implementations agree, measured on openrsync.
    #[test]
    fn rsh_split_collapses_runs_of_spaces() {
        assert_eq!(
            rsh_split("  docker   -H  unix:///gw.sock  exec -i ").expect("re-parsable"),
            vec!["docker", "-H", "unix:///gw.sock", "exec", "-i"]
        );
    }

    /// A tab is where the two implementations part company: openrsync splits
    /// on it, GNU rsync keeps it inside the word. There is no single right
    /// answer, so the split refuses rather than picking one.
    #[test]
    fn rsh_split_refuses_whitespace_the_two_implementations_disagree_about() {
        for transport in ["docker -H unix://a\tb exec", "docker\nexec", "a\rb"] {
            let err =
                rsh_split(transport).expect_err("whitespace other than a space must be refused");
            assert!(
                err.message().contains("word separator"),
                "the refusal must say why; got {}",
                err.message()
            );
        }
    }

    /// Quotes suppress separation and are removed. This is the mechanism a
    /// caller would have to reach for if a path ever did contain a space,
    /// and it is pinned here so the behaviour is known before anyone relies
    /// on it.
    #[test]
    fn rsh_split_removes_quotes_and_keeps_quoted_runs_whole() {
        assert_eq!(
            rsh_split("docker -H 'unix:///var/lib/sandbox d/gw.sock' exec -i")
                .expect("re-parsable"),
            vec![
                "docker",
                "-H",
                "unix:///var/lib/sandbox d/gw.sock",
                "exec",
                "-i"
            ]
        );
        assert_eq!(
            rsh_split(r#"a "b c" d"#).expect("re-parsable"),
            vec!["a", "b c", "d"]
        );
        // A quote of the other kind inside a quoted run is literal.
        assert_eq!(rsh_split(r#"'a"b'"#).expect("re-parsable"), vec![r#"a"b"#]);
    }

    /// rsync has no backslash escape: a backslash is an ordinary character
    /// and does **not** protect the space after it.
    #[test]
    fn rsh_split_has_no_backslash_escape() {
        assert_eq!(
            rsh_split(r"a b\ c").expect("re-parsable"),
            vec!["a", r"b\", "c"]
        );
    }

    /// A doubled quote is the second measured divergence: openrsync yields
    /// `a'b` from `'a''b'` while GNU rsync's loop lets the second quote close
    /// the run and then aborts on the unterminated remainder. Refused rather
    /// than modelled.
    #[test]
    fn rsh_split_refuses_a_doubled_quote() {
        let err = rsh_split("docker -H 'a''b' exec").expect_err("a doubled quote must be refused");
        assert!(
            err.message().contains("disagree"),
            "the refusal must say why; got {}",
            err.message()
        );
    }

    /// An empty quoted word crashes openrsync outright (an assertion failure
    /// in `fargs.c`), so it is refused here rather than passed through as an
    /// empty argument.
    #[test]
    fn rsh_split_refuses_an_empty_quoted_word() {
        let err = rsh_split("docker -H '' exec").expect_err("an empty word must be refused");
        assert!(
            err.message().contains("empty quoted word"),
            "the refusal must say why; got {}",
            err.message()
        );
    }

    /// A quote may open part-way through a word, and the quoted run joins
    /// onto what precedes and follows it — measured on openrsync
    /// (`a'b c'd` → `ab cd`).
    #[test]
    fn rsh_split_allows_a_quote_to_open_mid_word() {
        assert_eq!(
            rsh_split("-H a'b c'd exec").expect("re-parsable"),
            vec!["-H", "ab cd", "exec"]
        );
    }
}
