pub mod api;
pub mod ca;
pub mod dns_propagation;
pub mod error;
pub mod gateway;
pub mod guest;
pub mod lima;
pub mod network;
pub mod policy;
pub mod policy_distributor;
pub mod qmp;
pub mod session;
pub mod store;
pub mod vm_network;

pub use api::{
    CreateSessionRequest, ExecRequest, ExecResponse, FileDownloadRequest,
    FileDownloadResponse, FileUploadRequest, GatewayHealth, GitRequest,
    GitResponse, NetworkHealth, SessionHealth, SessionResponse, UpdatePolicyRequest,
};
pub use ca::{CaManager, generate_ca_inject_script};
pub use dns_propagation::{
    DnsCache, DnsCacheEntry, DnsChange, DnsChangeType, ResolvedMapping, ResolvedReport,
    generate_domain_ip_rules, propagate_dns_changes, read_resolved_json,
};
pub use error::{ApiError, SandboxError};
pub use gateway::{GatewayManager, GatewayStatus};
pub use guest::{
    GuestConnector, GuestRequest, GuestResponse, GUEST_AGENT_PORT, MAX_MESSAGE_SIZE,
    read_message, write_message,
};
pub use lima::{LimaManager, VmInfo, VmStatus};
pub use network::{NetworkInfo, NetworkManager};
pub use policy::{
    AssuranceLevel, CompiledPolicy, CoreDnsConfig, Destination, HttpConstraints, MitmproxyConfig,
    MitmproxyRule, Policy, PolicyCompiler, PolicyRule, Protocol,
};
pub use policy_distributor::PolicyDistributor;
pub use qmp::{QmpClient, mac_from_uuid, tap_name_for_session};
pub use session::{Session, SessionConfig, SessionState};
pub use store::SessionStore;
pub use vm_network::{attach_vm_to_bridge, detach_vm_from_bridge};
