pub mod api;
pub mod atomic_listener_writer;
pub mod backend;
pub mod bridge_conf;
pub mod ca;
pub mod caller_identity;
pub mod dns_gate;
/// macOS-only reverse byte-pump bridging the host-bound DNS-policy gate
/// UDS to the in-VM gateway container's Corefile gate path. The pure argv
/// builder is platform-neutral (compiled + tested everywhere); the async
/// accept-loop/pump runtime is macOS-only.
pub mod dns_gate_bridge;
pub mod dns_propagation;
pub mod error;
pub mod events;
pub mod gateway;
#[cfg(target_os = "macos")]
pub mod gateway_lima;
/// Gateway Lima crash-recovery orchestrator and its building blocks (latch
/// guard, session filter, bounded-concurrency loop). Platform-neutral so the
/// state-machine behaviours can be covered by hermetic unit tests on any host.
pub mod gateway_recovery;
pub mod guest;
pub mod lds_ack;
pub mod lima;
/// Pure helpers for the lite-mode container backend on macOS:
/// shared-root config, host→VM path translation, in-VM route-helper argv
/// builder. Platform-neutral — compiled and tested on all platforms so the
/// hermetic unit tests run on Linux CI without a macOS agent.
pub mod lite_macos;
/// macOS session lifecycle helpers: macvlan network + gateway container
/// setup/teardown, restrict=on verification stub, host IP-forwarding check.
/// macOS only — not compiled on Linux.
#[cfg(target_os = "macos")]
pub mod macos_session;
pub mod network;
pub mod policy;
pub mod policy_distributor;
pub mod process;
pub mod qmp;
pub mod session;
pub mod ssh;
pub mod store;
/// Test-only helpers shared across `sandbox-core`'s integration tests
/// and the daemon's `tests/` integration suite. Production code paths
/// must never reference items in this module — the module name and
/// per-item docs make that contract explicit. See
/// [`test_support::docker_path_stub`] for the rootless-Docker probe
/// substrate consumed by the daemon's integration tests.
pub mod test_support;
pub mod users_conf;
pub mod vm_network;
pub mod workspace_lock;
pub mod workspace_rsync;

pub use api::{
    CreateSessionRequest, DecisionKind, DenyLoggerEventBodyDto, DenyLoggerEventDto,
    DenyProtocolDto, DnsEventBodyDto, DnsEventDto, EnvoyConnectionDto, EnvoyEventBodyDto,
    EnvoyEventDto, EventDto, EventName, EventsFilter, EventsQueryDto, ExecRequest, ExecResponse,
    GatewayHealth, GatewayShutdownReasonDto, HealthComponentDto, LayerKind, LifecycleEventBodyDto,
    LifecycleEventDto, MitmproxyEventBodyDto, MitmproxyEventDto, NetworkHealth, NetworkingStatus,
    PolicyApplyStatusDto, PolicyDto, PolicyLevelDto, PolicyRuleDto, PropagationStatusResponse,
    SessionConfigDto, SessionDto, SessionHealth, SessionMountInfo, SessionNetworkInfo,
    SessionRootlessDockerDto, SshConfigDto, UpdatePolicyRequest, VmnetSlotDto,
    WorkspaceLockAcquireRequest, WorkspaceLockAcquireResponse, WorkspaceLockReleaseRequest,
    WorkspaceModeDetailDto, WorkspaceOpDto, WorkspaceSecurityModelDto, event_to_jsonl_line,
};
pub use atomic_listener_writer::{
    AtomicListenerWriter, ListenerWriteError, forget_cached_listener, listener_host_root,
    macos_listener_exec_argv, session_listener_host_dir, session_listener_host_path,
    write_listener_into_container,
};
#[cfg(target_os = "macos")]
pub use backend::CliDockerOpsWithSocket;
pub use backend::{
    AsyncReadWrite, BackendInfo, BackendKind, BackendSpecific, Capabilities, CliDockerOps,
    ContainerNetwork, ContainerRuntime, ContainerTransport, DEFAULT_LITE_IMAGE_TAG, DockerOps,
    EnsureImageOutcome, GuestTransport, IsolationLevel, LITE_FIRST_USE_WARNING,
    LITE_IMAGE_REPOSITORY, LITE_TAG_OVERRIDE_ENV, LimaRuntime, LimaTransport, ReaperReport,
    RuntimeHandle, RuntimeStartArgs, RuntimeStatus, SessionRuntime, SessionSpec,
    UnsupportedFeature, compute_default_resource_limits, ensure_image,
    lite_image_tag_for_daemon_probe, lite_image_tag_for_version, reap_orphans,
};
pub use ca::{CaManager, generate_ca_inject_script};
pub use caller_identity::OperatorIdentity;
pub use dns_gate::{
    DEFAULT_DEADLINE_MS, DNS_GATE_SOCKET_FILENAME, DNS_GATE_SOCKET_IN_CONTAINER,
    GATE_PROTOCOL_VERSION, GateAck, GateAckKind, GateError, GateErrorCode, GateErrorKind,
    GateRequest, GateRequestKind, GateService, GateServiceOutcome, GateStatus, bind_gate_listener,
    dns_gate_socket_host_path, log_serviced, remove_gate_socket, send_request, serve_gate_listener,
};
pub use dns_gate_bridge::gate_listener_exec_argv;
#[cfg(target_os = "macos")]
pub use dns_gate_bridge::start_gate_bridge;
pub use dns_propagation::{
    DnsCache, DnsCacheEntry, DnsChange, DnsChangeType, ResolvedMapping, ResolvedReport,
    generate_domain_ip_rules, propagate_dns_changes, read_resolved_json,
    read_resolved_json_on_socket,
};
pub use error::{ApiError, SandboxError};
pub use events::{
    DEFAULT_BROADCAST_CAPACITY, DEFAULT_RING_BUFFER_SIZE, DenyLoggerAllow, DenyLoggerDeny,
    DenyLoggerEvent, DenyProtocol, DnsEvent, EVENTS_DIR_IN_CONTAINER, EnvoyConnection, EnvoyEvent,
    Event, EventBus, EventBusConfig, EventEnvelope, EventSubscription, GatewayShutdownReason,
    HealthComponent, LifecycleEvent, MitmproxyEvent, PersistConfig, PersistentSink,
    PolicyApplyStatus, TrafficEvent, VmIpSessionMap, events_host_root, ingest::SessionIngestor,
    session_events_host_dir,
};
pub use gateway::{
    DockerHealth, GATEWAY_DENY_LOGGER_HEALTH_PORT, GATEWAY_DENY_LOGGER_TCP_PORT, GATEWAY_DNS_PORT,
    GATEWAY_ENVOY_PORT, GatewayManager, GatewayStatus, NFT_NFLOG_DENY_GROUP,
    NFT_POLICY_ALLOW_TCP_SET, NFT_POLICY_ALLOW_UDP_SET,
};
#[cfg(target_os = "macos")]
pub use gateway_lima::{
    EGRESS_BRIDGE_NAME, GATEWAY_INSTANCE_NAME, GatewayLimaManager, IpLinkEntry, MIN_LIMA_VERSION,
    NicMap, PoolResizeDecision, UBUNTU_NOBLE_ARM64_URL, VMNET_LAUNCH_DAEMONS_DIR,
    count_reachable_slot_sockets, count_vmnet_plists, decide_pool_resize,
    discover_nics_from_ip_json, generate_gateway_eth0_nft_policy, generate_gateway_template,
    nic_from_record_or_map, nic_from_verified_map, observe_vmnet_daemon_set,
    slot_for_persisted_session, slot_interface_name,
};
pub use gateway_recovery::{
    GatewayRecoveringGuard, GatewayRecoveryDeps, run_bounded_recovery, run_gateway_recovery,
    sessions_to_recover,
};
pub use guest::{
    GUEST_AGENT_PORT, GuestConnector, GuestRequest, GuestResponse, MAX_MESSAGE_SIZE, read_message,
    write_message,
};
pub use lds_ack::{
    DockerExecLdsProbe, LdsAckOutcome, LdsCounters, LdsStatsProbe, parse_lds_counters,
    wait_for_lds_ack,
};
pub use lima::{
    BaseImageMeta, BaseImageStatus, DEFAULT_BASE_VM_NAME, GUEST_BINARY_PATH_OVERRIDE_ENV,
    LimaExecutor, LimaManager, LimaManagerRegistry, LimaOp, LimaReaperReport, LimaVmDecision,
    MACOS_UNIX_PATH_MAX, PRODUCTION_GUEST_BINARY_PATH, SANDBOXD_STATE_ROOT, SetuidHelperExecutor,
    VmInfo, VmStatus, decide_lima_vm, ensure_operator_lima_home, enumerate_operator_uids_from_fs,
    guest_agent_path, instance_socket_path_fits, instance_ssh_socket_path, operator_lima_home,
    reap_lima_orphans, vm_name,
};
pub use lite_macos::{
    DEFAULT_LITE_SHARED_ROOT, IN_VM_ROUTE_HELPER_PATH, LITE_SHARED_ROOT_ENV, SharedPathError,
    build_in_vm_route_helper_argv, lite_shared_root, lite_shared_root_9p_stanza,
    translate_shared_path, validate_shared_path,
};
#[cfg(target_os = "macos")]
pub use macos_session::{
    build_macos_gateway_docker_args, macos_docker_network_name, macos_gateway_container_name,
    setup_macos_gateway, setup_macos_lite_gateway, teardown_macos_gateway,
};
pub use network::{NetworkInfo, NetworkManager};
pub use policy::{
    AssuranceLevel, BOOTSTRAP_FILE_IN_CONTAINER, CompiledPolicy, CoreDnsConfig, Destination,
    FILTER_CHAINS_BEGIN_MARKER, FILTER_CHAINS_END_MARKER, HttpFilter, HttpMethod,
    LISTENER_DIR_IN_CONTAINER, LISTENER_FILE_IN_CONTAINER, LISTENER_FILE_NAME, MitmproxyConfig,
    MitmproxyFilter, MitmproxyRule, Policy, PolicyCompiler, PolicyRule, Protocol, RuleSource,
    hash_policy,
};
pub use policy_distributor::{
    PolicyDistributor, write_file_to_container, write_file_to_container_on_socket,
};
pub use process::run_with_timeout;
pub use qmp::{QmpClient, mac_from_session_id};
pub use session::{
    Session, SessionConfig, SessionId, SessionRootlessDocker, SessionState, WorkspaceMode,
    WorkspaceModeKind, WorkspaceSecurityModel,
};
pub use ssh::{SSH_CONFIG_IDENTITY_FILE_PLACEHOLDER, SshKeypair, render_ssh_config_block};
pub use store::{OrphanInfo, ResolveOutcome, SessionStore};
// Only the daemon-side users-conf surface is re-exported at the crate
// root: `sandboxd` consumes it via `sandbox_core::*`. The helper-side
// surface (`load_users_config_route_helper`, `route_helper_users_conf_path`)
// is intentionally NOT re-exported — it is consumed only by
// `sandbox-route-helper`, which imports through the explicit
// `sandbox_core::users_conf::...` path. Keeping the asymmetry signals
// at the API surface that the privilege-aware helper entry points are
// not for general daemon-side use.
pub use users_conf::{
    Cidr4, DEFAULT_USERS_CONF_PATH, SubnetEntry, USERS_CONF_PATH_ENV, UsersConfig,
    UsersConfigError, load_users_config, load_users_config_from, users_conf_path,
};
pub use vm_network::{attach_vm_to_bridge, detach_vm_from_bridge};
pub use workspace_lock::{LockState, LockToken, WorkspaceOp};
pub use workspace_rsync::{
    Direction, SSH_TRANSPORT_TOKEN, WorkspaceRsyncOptions, build_workspace_rsync_argv,
};
