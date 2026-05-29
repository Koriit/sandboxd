pub mod api;
pub mod atomic_listener_writer;
pub mod backend;
pub mod bridge_conf;
pub mod ca;
pub mod caller_identity;
pub mod dns_gate;
pub mod dns_propagation;
pub mod error;
pub mod events;
pub mod gateway;
pub mod guest;
pub mod lds_ack;
pub mod lima;
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
    LifecycleEventDto, MitmproxyEventBodyDto, MitmproxyEventDto, NetworkHealth,
    PolicyApplyStatusDto, PolicyDto, PolicyLevelDto, PolicyRuleDto, PropagationStatusResponse,
    SessionConfigDto, SessionDto, SessionHealth, SessionMountInfo, SessionNetworkInfo,
    SessionRootlessDockerDto, SshConfigDto, UpdatePolicyRequest, WorkspaceLockAcquireRequest,
    WorkspaceLockAcquireResponse, WorkspaceLockReleaseRequest, WorkspaceModeDetailDto,
    WorkspaceOpDto, WorkspaceSecurityModelDto, event_to_jsonl_line,
};
pub use atomic_listener_writer::{
    AtomicListenerWriter, ListenerWriteError, listener_host_root, session_listener_host_dir,
    session_listener_host_path,
};
pub use backend::{
    AsyncReadWrite, BackendInfo, BackendKind, BackendSpecific, Capabilities, CliDockerOps,
    ContainerNetwork, ContainerRuntime, ContainerTransport, DEFAULT_LITE_IMAGE_TAG, DockerOps,
    EnsureImageOutcome, ExitCode, GuestTransport, IsolationLevel, LITE_FIRST_USE_WARNING,
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
pub use dns_propagation::{
    DnsCache, DnsCacheEntry, DnsChange, DnsChangeType, ResolvedMapping, ResolvedReport,
    generate_domain_ip_rules, propagate_dns_changes, read_resolved_json,
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
    LimaManager, PRODUCTION_GUEST_BINARY_PATH, VmInfo, VmStatus, guest_agent_path, vm_name,
};
pub use network::{NetworkInfo, NetworkManager};
pub use policy::{
    AssuranceLevel, BOOTSTRAP_FILE_IN_CONTAINER, CompiledPolicy, CoreDnsConfig, Destination,
    FILTER_CHAINS_BEGIN_MARKER, FILTER_CHAINS_END_MARKER, HttpFilter, HttpMethod,
    LISTENER_DIR_IN_CONTAINER, LISTENER_FILE_IN_CONTAINER, LISTENER_FILE_NAME, MitmproxyConfig,
    MitmproxyFilter, MitmproxyRule, Policy, PolicyCompiler, PolicyRule, Protocol, RuleSource,
    hash_policy,
};
pub use policy_distributor::{PolicyDistributor, write_file_to_container};
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
pub use workspace_rsync::{Direction, WorkspaceRsyncOptions, build_workspace_rsync_argv};
