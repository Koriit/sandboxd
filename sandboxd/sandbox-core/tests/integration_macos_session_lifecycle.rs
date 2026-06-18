/// Integration test scaffolding for the macOS session lifecycle.
///
/// These tests require a live gateway Lima instance, socket_vmnet daemons,
/// and the full macOS infrastructure. They are well-formed and structurally
/// correct, but will NOT pass in Round 1 (no live boot — the gateway Lima
/// instance and socket_vmnet pool are not running in CI at this stage).
///
/// Round 2 (M20-S5/S6) will run these against a real booted session.
///
/// All tests are gated on `#[cfg(target_os = "macos")]` and prefixed with
/// `integration_` per the sandboxd integration-test convention:
/// - Excluded from `cargo nextest run` (default profile) — hermetic only.
/// - Included in `cargo nextest run --profile integration` — requires live infra.
/// - No `#[ignore]` attribute — membership is self-describing via the name prefix.
///
/// ## Prerequisites (for Round 2 runs)
///
/// 1. `make setup-dev-env` — installs helpers, socket_vmnet pool.
/// 2. `make gateway-image` — builds the gateway container image.
/// 3. The `sandboxd-gateway` Lima instance is running and healthy.
/// 4. socket_vmnet pool daemons (io.sandboxd.vmnet.0 … .N) are running.
#[cfg(target_os = "macos")]
mod integration_macos_session_lifecycle {
    // ---------------------------------------------------------------------------
    // Scaffolding imports (used when the tests are actually run in Round 2)
    // ---------------------------------------------------------------------------

    // These imports will be uncommented / used when the full infrastructure is
    // available. They are listed here as documentation of what Round 2 needs.
    //
    // use sandbox_core::network::{VmnetPool};
    // use sandbox_core::macos_session::{
    //     setup_macos_gateway, teardown_macos_gateway, verify_restrict_on,
    // };
    // use sandbox_core::session::SessionId;
    // use sandbox_core::gateway::GatewayManager;
    // use std::path::PathBuf;

    /// Create → verify Running → stop → verify Stopped → rm → verify Gone.
    ///
    /// Full lifecycle smoke test. Verifies:
    /// - `claim_lima_slot` reserves a slot and returns valid addresses.
    /// - `setup_macos_gateway` creates the macvlan network and gateway container.
    /// - `limactl start` boots the sandbox VM through the qemu-wrapper.
    /// - `verify_restrict_on` confirms the wrapper applied restrict=on.
    /// - Session is marked Running after verification passes.
    /// - `teardown_macos_gateway` removes the container and network cleanly.
    /// - `release_lima_slot` frees the slot (pool returns to initial state).
    ///
    /// Round 2 implementation steps:
    /// 1. Build a minimal VmnetPool and claim a slot.
    /// 2. Derive NetworkInfo from the slot addresses.
    /// 3. Discover the gateway Lima NIC via GatewayLimaManager::nic_map().
    /// 4. Call setup_macos_gateway with the gateway Lima forwarded socket.
    /// 5. Assert macvlan network exists (docker -H <sock> network inspect).
    /// 6. Assert gateway container is running (docker -H <sock> inspect).
    /// 7. Verify gateway is healthy (gateway_status == Healthy).
    /// 8. Start the sandbox VM via limactl start (through the operator's agent).
    /// 9. Call verify_restrict_on — assert Ok (wrapper marker must be present).
    /// 10. Call teardown_macos_gateway — assert Ok.
    /// 11. Assert macvlan network no longer exists.
    /// 12. Assert gateway container no longer exists.
    /// 13. Release slot — assert pool count returns to zero.
    #[test]
    fn integration_macos_create_start_stop_rm() {
        // NOTE: This scaffolding test is intentionally a no-op in Round 1.
        // Round 2 will fill in the live implementation once:
        // - The gateway Lima instance is running (M20-S2)
        // - The socket_vmnet pool is initialized (M20-S1)
        // - The qemu-wrapper marker path is confirmed (M20-S6)
        //
        // The test is present now so the nextest integration profile
        // picks it up and the orchestrator sees it in the test inventory.
    }

    /// Partial create rollback: inject failure at step 8 (gateway create),
    /// verify no slot leaked.
    ///
    /// Simulates a failure midway through `setup_macos_gateway` (e.g. the
    /// macvlan network create succeeds but the docker run fails) and verifies
    /// that the rollback path calls `teardown_macos_gateway` and
    /// `release_lima_slot`, leaving no leaked slot, container, or network.
    ///
    /// Round 2 implementation steps:
    /// 1. Claim a slot from the pool.
    /// 2. Run setup_macos_gateway with a deliberately bad NIC name (triggers
    ///    macvlan create failure after the network is partially set up).
    /// 3. Assert setup returns Err.
    /// 4. Call teardown_macos_gateway (cleanup of any partial state) — assert Ok.
    /// 5. Release the slot via release_lima_slot.
    /// 6. Assert pool.running_session_count() == 0 (no slot leaked).
    #[test]
    fn integration_macos_partial_create_rollback() {
        // NOTE: Scaffolding only — Round 2 implementation needed.
    }

    /// Confirm `verify_restrict_on` returns Ok after real limactl start.
    ///
    /// Verifies the end-to-end flow: the qemu-wrapper writes the marker
    /// file during VM boot, and `verify_restrict_on` reads it and confirms
    /// restrict=on was applied.
    ///
    /// Round 2 implementation steps:
    /// 1. Start a sandbox VM via limactl (through the operator's agent + wrapper).
    /// 2. Wait for VM to reach running state (limactl list shows Running).
    /// 3. Call verify_restrict_on with the operator's LIMA_HOME.
    /// 4. Assert Ok — the wrapper marker must exist with "restrict=on".
    /// 5. Stop and delete the VM.
    ///
    /// This test proves the M20-S6 stub gate actually works end-to-end
    /// once the qemu-wrapper marker path is confirmed against real hardware.
    #[test]
    fn integration_macos_restrict_verify_gate() {
        // NOTE: Scaffolding only — Round 2 implementation needed.
        // Requires the qemu-wrapper marker path to be confirmed on real hardware.
    }

    /// Create a session, inspect vmnet_slot on the wire, stop, confirm slot released.
    ///
    /// Verifies the full `vmnet_slot` accounting through the daemon API:
    /// - `sandbox inspect` (GET /sessions/{id}) renders vmnet_slot info when running.
    /// - After stop, the slot is released from the pool.
    /// - GET /sessions/{id} shows no vmnet_slot after stop (field absent on wire).
    ///
    /// Round 2 implementation steps:
    /// 1. POST /sessions → Running macOS session.
    /// 2. GET /sessions/{id} → assert `network.vmnet_slot` is Some.
    /// 3. Assert vmnet_slot.index == expected slot index.
    /// 4. Assert vmnet_slot.daemon_label == "io.sandboxd.vmnet.<index>".
    /// 5. POST /sessions/{id}/stop → Stopped.
    /// 6. GET /sessions/{id} → assert `network.vmnet_slot` is absent (None).
    /// 7. Assert pool.running_session_count() == 0 (slot released).
    /// 8. DELETE /sessions/{id} → verify clean removal.
    #[test]
    fn integration_macos_vmnet_slot_accounting() {
        // NOTE: Scaffolding only — Round 2 implementation needed.
    }
}
