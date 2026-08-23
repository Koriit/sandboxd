//! VM-level operations: is the VM's Docker up, what NICs does it have, and
//! the nftables baseline that decides what may leave it.
//!
//! # `sudo -n`, everywhere in this crate
//!
//! Every privileged step below runs `sudo -n`. Lima provisions the gateway VM
//! with passwordless sudo, so the flag never changes the outcome of a healthy
//! call — what it changes is the unhealthy one. Without `-n`, a `sudo` that
//! decided it wanted a password would read one **from the command's stdin**,
//! and [`apply_nft_baseline_argv`] puts the nftables ruleset there. A prompt
//! would silently consume the egress policy as a password attempt and then
//! fail, which is the worst available failure for this particular op. `-n`
//! makes sudo refuse rather than read, so stdin reaches `nft` or nothing runs.

use crate::owned;

/// `docker info` inside the VM — the authoritative signal that the VM's own
/// Docker daemon is up, independent of whether Lima's host-side socket
/// forward has been established yet.
///
/// Deliberately bare: no `-H`. The target is the VM's default socket, which
/// is the only Docker daemon in there. The answer is the exit status; the
/// output is diagnostic only.
pub fn docker_ready_argv() -> Vec<String> {
    owned(&["docker", "info"])
}

/// `ip -json link show` inside the VM — the guest's view of its own NICs.
///
/// The slot→NIC map is built host-side from the declared slot set; this
/// output only verifies it. See `discover_nics_from_ip_json`.
pub fn link_show_json_argv() -> Vec<String> {
    owned(&["ip", "-json", "link", "show"])
}

/// `sudo -n nft -f -` inside the VM — apply an nftables ruleset read from
/// stdin.
///
/// # What this ruleset is
///
/// The gateway VM's `eth0` baseline: a default-drop `output` chain bounding
/// the VM's *own host-namespace* egress on `eth0` and nowhere else — it
/// accepts `oifname != "eth0"` outright — and an `input` chain that drops new
/// and invalid inbound on `eth0`. It declares no `forward` chain and does not
/// govern session traffic, which the per-session `sandbox_dnat`/`sandbox_policy`
/// ruleset in each gateway container's netns judges instead. What it bounds is
/// the blast radius of a component that escapes a container netns into the VM.
///
/// A ruleset that arrives corrupted or truncated fails to parse and so fails
/// the caller; one that arrives subtly altered but still valid installs
/// silently, and nothing at runtime re-checks what is installed. That is what
/// the three properties below are for.
///
/// Three properties keep that honest, and all three are why the ruleset
/// travels on **stdin** rather than in the command line:
///
/// 1. **Nothing parses it as a command.** The bytes go down the SSH channel to
///    the child's standard input; the guest's login shell execs `nft` and
///    never reads them. So no quote, newline, backtick or `$(…)` in the policy
///    can become anything but policy text. The shape this replaced
///    interpolated the whole multi-KB document into a `bash -c` heredoc, whose
///    correctness rested on the generator never emitting a line equal to the
///    terminator — an invariant real at the time and checked by nothing, in a
///    document whose whole purpose is to change.
/// 2. **It is applied or it is refused, never half-applied.** `nft -f` is
///    atomic: the ruleset commits in one transaction or none of it does, and
///    `nft` reads to EOF before it commits. A truncated transfer is therefore
///    a parse failure rather than a partial policy — which matters because a
///    partial default-drop policy is a permissive one.
/// 3. **No copy of the policy is left behind.** The shape this replaced wrote
///    the ruleset to a fixed path under the VM's sticky `/tmp` and applied
///    that path in a second call. Between the two, the policy about to be
///    installed sat at a predictable location that anything running as the
///    VM's login user could rewrite — and `limactl shell` hands that user out
///    to whoever can reach the instance. The sticky bit narrows that window;
///    it does not close it. Now there is no second call, no window and no
///    file.
pub fn apply_nft_baseline_argv() -> Vec<String> {
    owned(&["sudo", "-n", "nft", "-f", "-"])
}

/// The `docker.socket` drop-in that decides who may reach the VM's Docker.
///
/// **The basename is load-bearing and must not be changed**, here or in the
/// provisioning template that writes the same file. Earlier images shipped a
/// drop-in at this exact path containing `SocketMode=0666`. systemd merges
/// every `*.conf` in the directory in name order, so writing the replacement
/// under a *new* name would leave the old one in place beside it and let it
/// win on ordering — an upgrade that reads as a hardening and lands as a
/// no-op. Overwriting the same path is what makes the old content go away.
pub const DOCKER_SOCKET_DROPIN: &str = "/etc/systemd/system/docker.socket.d/10-socketmode.conf";

/// The socket `dockerd` listens on **inside** the gateway VM — not the
/// host-side forward Lima creates from it.
pub const DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// `id -g` inside the VM — the numeric primary gid of the VM's login user.
///
/// # Why the host has to ask
///
/// The group the Docker socket must belong to exists only in the guest. Lima
/// picks it, and it is not the operator's: on a host whose operator is uid 501
/// / gid 20, the guest login user comes out uid 501 / gid 1000. So the host
/// cannot derive the value and has to read it.
///
/// It must be the login user's *primary* group specifically. Lima holds a
/// persistent `ControlPersist` SSH master, established at boot before
/// provisioning runs, and a session's supplementary groups are fixed when it
/// is established — so a group added later is not one the running forward can
/// use, however correct `/etc/group` looks. The primary group has no such
/// window.
///
/// # Why the numeric gid and not the name
///
/// The answer travels back across the seam and then into a `chgrp` on the
/// Docker socket of the VM that runs every session, so its type is a control,
/// not a formatting choice. A `u32` cannot render a leading `-`, cannot be a
/// path, and carries no shell metacharacter; a group *name* is an arbitrary
/// string, and a field holding one is the argv pass-through this op set exists
/// to avoid. Both consumers take the numeric form — `chgrp` accepts a gid, and
/// systemd resolves a numeric `SocketGroup=` — so nothing is given up by
/// refusing the name.
pub fn login_gid_argv() -> Vec<String> {
    owned(&["id", "-g"])
}

/// Read [`login_gid_argv`]'s output as a gid.
///
/// `None` for anything that is not a plain number, which is what makes an
/// unexpected answer a failure rather than a value used anyway.
pub fn parse_login_gid(output: &str) -> Option<u32> {
    output.trim().parse().ok()
}

/// The content of [`DOCKER_SOCKET_DROPIN`] for a VM whose login group is
/// `login_gid`.
///
/// Rendered from the gid on whichever side is about to write it, so the file's
/// text is never itself on the wire and there is no version of it a caller
/// could choose. Both sides build the same bytes from the same `u32`.
///
/// `SocketMode=0660` is the point of the file: the mode `docker.socket` will
/// re-create the socket with on its next start. `SocketGroup=` is numeric for
/// the reason [`login_gid_argv`] gives.
pub fn docker_socket_dropin_body(login_gid: u32) -> String {
    format!("[Socket]\nSocketGroup={login_gid}\nSocketMode=0660\n")
}

/// Write [`DOCKER_SOCKET_DROPIN`], taking its content from stdin.
///
/// `install -D` creates the drop-in directory in the same call, so there is no
/// separate `mkdir` step — which matters beyond tidiness: an op carrying a
/// stdin body must be a single step, because the executor replays the body to
/// every step it runs.
///
/// Mode and ownership are stated rather than left to the caller's umask. This
/// file decides who may reach Docker inside the VM, so it is `root:root 0644`
/// by declaration.
///
/// The body travels on **stdin** for the same reason the nftables ruleset does
/// — see [`apply_nft_baseline_argv`]. `/dev/stdin` as the source is what lets a
/// file be written without a shell redirection, and so is what keeps this op an
/// argv rather than a script.
pub fn write_docker_socket_dropin_argv() -> Vec<String> {
    owned(&[
        "sudo",
        "-n",
        "install",
        "-D",
        "-m",
        "0644",
        "-o",
        "root",
        "-g",
        "root",
        "/dev/stdin",
        DOCKER_SOCKET_DROPIN,
    ])
}

/// Narrow the VM's *running* `/var/run/docker.sock` to `login_gid`, and report
/// the mode and group it ended up with.
///
/// # Why this exists alongside the drop-in
///
/// [`write_docker_socket_dropin_argv`] takes effect only when `docker.socket`
/// next starts, and restarting it under a live VM would drop every session
/// container's connection to the daemon. The drop-in is what survives a
/// reboot; these steps are what change the socket that exists now. Neither
/// alone leaves a host correct both now and later.
///
/// # Why this runs at readiness rather than only at provisioning
///
/// The provisioning template sets the same thing at every boot, but a VM only
/// ever gets the template it was *created* with: `ensure_ready` writes a
/// template solely on the branch where the instance is absent. A gateway VM
/// created by an older daemon therefore keeps its original provisioning across
/// an upgrade, forever — so a fix made only in the template reaches new
/// installs and no existing one. This is what reaches the existing ones.
///
/// # The steps
///
/// The owner is set to `root` explicitly. It already is root on a socket
/// `dockerd` created, but the step states the property the mode depends on: a
/// session container runs at the operator's own uid, which is the same numeric
/// uid Lima gives the VM's login user, so an owner that drifted to that uid
/// would hand the container the owner bits and the group would stop being the
/// separation.
///
/// The closing `stat` is the op's evidence, not decoration. A caller reading
/// only the exit status learns that five commands returned zero, which is not
/// the property it needs — see [`docker_socket_is_closed_to_others`].
///
/// Idempotent by construction: every step writes the state it wants rather
/// than editing what is there.
pub fn harden_docker_socket_argv(login_gid: u32) -> Vec<Vec<String>> {
    vec![
        owned(&["sudo", "-n", "systemctl", "daemon-reload"]),
        owned(&["sudo", "-n", "chown", "root", DOCKER_SOCKET]),
        vec![
            "sudo".to_string(),
            "-n".to_string(),
            "chgrp".to_string(),
            login_gid.to_string(),
            DOCKER_SOCKET.to_string(),
        ],
        owned(&["sudo", "-n", "chmod", "660", DOCKER_SOCKET]),
        owned(&["stat", "-c", "%a %G", DOCKER_SOCKET]),
    ]
}

/// Does `stat -c '%a %G'` output describe a socket closed to `other`?
///
/// Parses the trailing line of [`harden_docker_socket_argv`]'s output. The
/// judgement is made from the octal mode's last digit and nothing else —
/// group and owner are reported for the log, but neither can be the control
/// here: a session container runs at the operator's own uid, which is the
/// same numeric uid Lima gives the VM's login user, so the owner bits do not
/// separate the two principals at all. Only `other` and the group do.
pub fn docker_socket_is_closed_to_others(stat_output: &str) -> bool {
    stat_output
        .split_whitespace()
        .next()
        .and_then(|mode| u32::from_str_radix(mode, 8).ok())
        .is_some_and(|mode| mode & 0o007 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_readiness_is_a_bare_docker_info() {
        assert_eq!(docker_ready_argv(), vec!["docker", "info"]);
    }

    #[test]
    fn link_show_asks_for_json() {
        assert_eq!(link_show_json_argv(), vec!["ip", "-json", "link", "show"]);
    }

    /// The `-` is the whole of why the ruleset is safe to carry as content:
    /// it is what makes `nft` read stdin instead of a path, and a path is
    /// what the previous shape had to write into `/tmp` first.
    #[test]
    fn nft_baseline_reads_the_ruleset_from_stdin() {
        assert_eq!(
            apply_nft_baseline_argv(),
            vec!["sudo", "-n", "nft", "-f", "-"]
        );
    }

    /// `sudo -n` is what guarantees the ruleset on stdin reaches `nft` rather
    /// than a password prompt. Losing the flag is a silent policy hazard, not
    /// a style change.
    #[test]
    fn privileged_steps_refuse_to_prompt() {
        assert!(apply_nft_baseline_argv().contains(&"-n".to_string()));
    }

    /// The gid is the only caller-supplied value in the whole remediation, and
    /// it is a `u32`. Asserted by differencing rather than by inspecting the
    /// words: render the builder at two gids and require that the two
    /// renderings differ in exactly one position, holding exactly the gid.
    ///
    /// Differencing is the property. An earlier form of this test scanned the
    /// rendering for words that parse as a number, on the theory that the gid
    /// would be the only one — which is false, because `chmod 660` is a
    /// numeric constant that has nothing to do with the caller. Varying the
    /// input and looking at what moves needs no such theory, and it also pins
    /// something the scan could not: that the gid reaches exactly one word.
    #[test]
    fn the_gid_is_the_only_caller_supplied_word_in_the_remediation() {
        let at_1000: Vec<String> = harden_docker_socket_argv(1000)
            .into_iter()
            .flatten()
            .collect();
        let at_4242: Vec<String> = harden_docker_socket_argv(4242)
            .into_iter()
            .flatten()
            .collect();

        assert_eq!(
            at_1000.len(),
            at_4242.len(),
            "the gid changed the shape of the remediation, not just a word in it"
        );

        let differing: Vec<(String, String)> = at_1000
            .iter()
            .zip(at_4242.iter())
            .filter(|(a, b)| a != b)
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect();

        assert_eq!(
            differing,
            vec![("1000".to_string(), "4242".to_string())],
            "exactly one word may depend on the gid, and it must be the gid"
        );
    }

    /// The socket's group is set by gid. A group *name* here would be an
    /// arbitrary string on the wire into a `chgrp` of the Docker socket of the
    /// VM that runs every session.
    #[test]
    fn the_group_is_set_by_numeric_gid() {
        let steps = harden_docker_socket_argv(1000);
        assert!(
            steps.contains(&vec![
                "sudo".to_string(),
                "-n".to_string(),
                "chgrp".to_string(),
                "1000".to_string(),
                DOCKER_SOCKET.to_string(),
            ]),
            "expected a chgrp by gid: {steps:?}"
        );
        assert_eq!(
            docker_socket_dropin_body(1000),
            "[Socket]\nSocketGroup=1000\nSocketMode=0660\n"
        );
    }

    /// `id -g`, not `id -gn`: the numeric form is what may cross the seam, and
    /// it must be the *primary* group — a supplementary one added after boot is
    /// not in the credentials of Lima's already-established SSH master.
    #[test]
    fn the_login_gid_probe_asks_for_the_numeric_primary_group() {
        assert_eq!(login_gid_argv(), vec!["id", "-g"]);
        assert_eq!(parse_login_gid("1000\n"), Some(1000));
        assert_eq!(parse_login_gid(" 1000 "), Some(1000));
        assert_eq!(parse_login_gid("olek"), None);
        assert_eq!(parse_login_gid(""), None);
        assert_eq!(parse_login_gid("1000 1001"), None);
    }

    /// The whole point of the step. A world-accessible mode reaching the
    /// socket is the escape's payoff, so neither the drop-in nor the running
    /// socket may ever be given one.
    #[test]
    fn the_remediation_never_writes_a_world_accessible_mode() {
        let mut words: Vec<String> = harden_docker_socket_argv(1000)
            .into_iter()
            .flatten()
            .collect();
        words.push(docker_socket_dropin_body(1000));
        words.extend(write_docker_socket_dropin_argv());
        for word in &words {
            for forbidden in ["666", "664", "662", "646", "o+w", "a+w"] {
                assert!(
                    !word.contains(forbidden),
                    "remediation must not grant world access (found {forbidden:?} in {word:?})"
                );
            }
        }
        assert!(words.iter().any(|w| w == "660"));
        assert!(words.iter().any(|w| w.contains("SocketMode=0660")));
    }

    /// Both halves are required: the drop-in alone leaves the running socket
    /// as it was, and the `chmod` alone is undone by the next restart.
    #[test]
    fn the_remediation_fixes_both_the_running_socket_and_the_next_restart() {
        assert!(write_docker_socket_dropin_argv().contains(&DOCKER_SOCKET_DROPIN.to_string()));
        let steps = harden_docker_socket_argv(1000);
        assert!(
            steps
                .iter()
                .any(|s| s.contains(&"daemon-reload".to_string()))
        );
        assert!(steps.iter().any(|s| s.contains(&"chmod".to_string())));
        assert_eq!(
            steps.last().map(Vec::as_slice),
            Some(
                ["stat", "-c", "%a %G", DOCKER_SOCKET]
                    .map(String::from)
                    .as_slice()
            ),
            "the op must end by reporting the state it produced"
        );
    }

    /// The drop-in is written by a single step because the executor replays a
    /// stdin body to every step of an op — a second step would receive the
    /// file's content on its own stdin.
    #[test]
    fn the_dropin_is_written_without_a_separate_mkdir() {
        let argv = write_docker_socket_dropin_argv();
        assert!(
            argv.contains(&"-D".to_string()),
            "install -D creates the parent: {argv:?}"
        );
        assert!(argv.contains(&"/dev/stdin".to_string()));
        assert!(
            argv.contains(&"-n".to_string()),
            "sudo must refuse to prompt"
        );
    }

    /// The drop-in overwrites the path older images already wrote. A new name
    /// would leave `SocketMode=0666` beside it for systemd to merge back.
    #[test]
    fn the_dropin_keeps_the_name_older_images_used() {
        assert_eq!(
            DOCKER_SOCKET_DROPIN,
            "/etc/systemd/system/docker.socket.d/10-socketmode.conf"
        );
    }

    #[test]
    fn stat_output_is_judged_on_the_other_bits() {
        assert!(docker_socket_is_closed_to_others("660 olek"));
        assert!(docker_socket_is_closed_to_others("600 olek\n"));
        assert!(docker_socket_is_closed_to_others("670 olek"));
        assert!(!docker_socket_is_closed_to_others("666 docker"));
        assert!(!docker_socket_is_closed_to_others("664 docker"));
        assert!(!docker_socket_is_closed_to_others("661 olek"));
    }

    /// An unreadable answer must not be mistaken for a good one — the caller
    /// treats `false` as "not proven closed" and fails.
    #[test]
    fn unparseable_stat_output_is_not_treated_as_closed() {
        assert!(!docker_socket_is_closed_to_others(""));
        assert!(!docker_socket_is_closed_to_others("no such file"));
        assert!(!docker_socket_is_closed_to_others("99999 x"));
    }
}
