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
/// # This one is the egress plane
///
/// The ruleset this reads is the gateway VM's `eth0` baseline: the
/// default-drop policy that makes the VM's uplink refuse anything the session
/// policy did not allow. A ruleset that arrives corrupted, truncated or not
/// at all is not a broken session — it is an unenforced one, and the failure
/// is silent from inside the sandbox.
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
}
