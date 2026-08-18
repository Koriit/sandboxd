//! Docker network-lifecycle argv builders.

/// The bridge driver's masquerade option key.
///
/// Turning masquerade *off* is what makes the pre-route window fail closed:
/// a container whose default route has not yet been rewritten to the gateway
/// cannot reach the internet through the bridge's NAT. The key is named here
/// so no call site spells it out by hand.
pub const BRIDGE_MASQUERADE_OPT: &str = "com.docker.network.bridge.enable_ip_masquerade";

/// The bridge driver's interface-name option key.
pub const BRIDGE_NAME_OPT: &str = "com.docker.network.bridge.name";

/// The network drivers the daemon creates networks with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkDriver {
    Bridge,
    Macvlan,
}

impl NetworkDriver {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkDriver::Bridge => "bridge",
            NetworkDriver::Macvlan => "macvlan",
        }
    }
}

/// A `--opt key=value` pair, restricted to the keys this crate names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkOption {
    /// `com.docker.network.bridge.name=<iface>`.
    BridgeName(String),
    /// `com.docker.network.bridge.enable_ip_masquerade=<true|false>`.
    BridgeMasquerade(bool),
    /// `parent=<host-interface>` — the macvlan driver's uplink.
    MacvlanParent(String),
    /// `macvlan_mode=private` — blocks macvlan-to-macvlan traffic on the
    /// same parent NIC.
    ///
    /// A nullary variant rather than a mode string, because `private` is the
    /// only mode this project has a reason to set: it is an L2-isolation
    /// control, and the other modes docker accepts (`bridge`, `vepa`,
    /// `passthru`) all weaken it. Naming the one we want means the others
    /// cannot arrive by accident.
    MacvlanModePrivate,
}

impl NetworkOption {
    /// The `key=value` token this option renders as.
    pub fn render(&self) -> String {
        match self {
            NetworkOption::BridgeName(iface) => format!("{BRIDGE_NAME_OPT}={iface}"),
            NetworkOption::BridgeMasquerade(enabled) => {
                format!("{BRIDGE_MASQUERADE_OPT}={enabled}")
            }
            NetworkOption::MacvlanParent(parent) => format!("parent={parent}"),
            NetworkOption::MacvlanModePrivate => "macvlan_mode=private".to_string(),
        }
    }
}

/// Every typed value `docker network create` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCreateSpec {
    pub name: String,
    pub driver: NetworkDriver,
    /// Subnet CIDR. `None` lets Docker's IPAM pick one, which is what the
    /// gateway VM's shared egress bridge does.
    pub subnet: Option<String>,
    /// Gateway address inside `subnet`.
    pub gateway: Option<String>,
    /// `sandbox.session_id=<id>` label, when the network belongs to a session.
    pub session_id: Option<String>,
    /// `sandboxd.owner=<pool>` label, when the daemon pool is known.
    pub owner_pool: Option<String>,
    /// Driver options, in emission order.
    pub options: Vec<NetworkOption>,
}

/// `docker network create --driver <d> [--subnet …] [--gateway …]
/// [--label …]… [--opt …]… <name>`.
pub fn network_create_argv(spec: &NetworkCreateSpec) -> Vec<String> {
    let mut argv = vec![
        "network".to_string(),
        "create".to_string(),
        "--driver".to_string(),
        spec.driver.as_str().to_string(),
    ];
    if let Some(subnet) = spec.subnet.as_ref() {
        argv.push("--subnet".to_string());
        argv.push(subnet.clone());
    }
    if let Some(gateway) = spec.gateway.as_ref() {
        argv.push("--gateway".to_string());
        argv.push(gateway.clone());
    }
    if let Some(session_id) = spec.session_id.as_ref() {
        argv.push("--label".to_string());
        argv.push(format!("sandbox.session_id={session_id}"));
    }
    if let Some(pool) = spec.owner_pool.as_ref() {
        argv.push("--label".to_string());
        argv.push(format!("sandboxd.owner={pool}"));
    }
    for option in &spec.options {
        argv.push("--opt".to_string());
        argv.push(option.render());
    }
    argv.push(spec.name.clone());
    argv
}

/// `docker network rm <name>`.
pub fn network_remove_argv(name: &str) -> Vec<String> {
    vec!["network".to_string(), "rm".to_string(), name.to_string()]
}

/// `docker network inspect <name>`.
pub fn network_inspect_argv(name: &str) -> Vec<String> {
    vec![
        "network".to_string(),
        "inspect".to_string(),
        name.to_string(),
    ]
}

/// The `--gw-priority` value attached to an endpoint that must never win
/// the container's default route.
///
/// Any value below Docker's default of `0` would do; a round negative
/// number is chosen so the intent is legible in `docker network inspect`
/// output rather than looking like an off-by-one.
const NEVER_DEFAULT_GATEWAY_PRIORITY: i32 = -100;

/// Which endpoint provides the container's default route, when a container
/// is attached to more than one network.
///
/// Docker elects the gateway endpoint by `--gw-priority`, and among equal
/// priorities the choice is not something to rely on: attaching a second
/// network to a *running* container has been observed to move the default
/// route onto the newly attached endpoint. That is exactly what happens to
/// the gateway container, which is started on its egress bridge and then
/// attached to each session bridge — so the session bridge silently became
/// its way out.
///
/// A nullary pair rather than a number, for the reason
/// [`NetworkOption::MacvlanModePrivate`] is nullary: the project has one
/// reason to touch this knob, and naming the intent keeps every other value
/// out of the op.
///
/// # If the flag is not supported
///
/// `--gw-priority` is verified working on Docker 29.1.3, and documented as
/// introduced in Docker 28; no lower bound has been measured, so none is
/// claimed. What has been measured is the failure: given an unsupported
/// flag, `docker network connect` exits 125, prints `unknown flag`, and
/// **does not attach the container** — so a Docker too old for this fails
/// the connect, which the caller treats as a hard error and fails the
/// create (asserted in `macos_session`'s
/// `session_bridge_attach_declines_the_default_route_and_a_refusal_fails_the_setup`).
/// The failure mode is a refused session, never a session on a network
/// wired differently from what was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointGatewayPriority {
    /// Docker's default — this endpoint takes part in the election
    /// normally.
    #[default]
    Default,
    /// This endpoint must not become the container's default route. Used
    /// for the gateway container's session-bridge leg, whose route out is
    /// the egress bridge it was started on.
    NeverDefaultGateway,
}

impl EndpointGatewayPriority {
    /// The `--gw-priority <n>` pair this renders as, if any.
    fn argv(self) -> Option<[String; 2]> {
        match self {
            EndpointGatewayPriority::Default => None,
            EndpointGatewayPriority::NeverDefaultGateway => Some([
                "--gw-priority".to_string(),
                NEVER_DEFAULT_GATEWAY_PRIORITY.to_string(),
            ]),
        }
    }
}

/// `docker network connect [--ip <addr>] [--gw-priority <n>] <network>
/// <container>`.
pub fn network_connect_argv(
    network: &str,
    container: &str,
    ip: Option<&str>,
    gateway_priority: EndpointGatewayPriority,
) -> Vec<String> {
    let mut argv = vec!["network".to_string(), "connect".to_string()];
    if let Some(ip) = ip {
        argv.push("--ip".to_string());
        argv.push(ip.to_string());
    }
    if let Some(pair) = gateway_priority.argv() {
        argv.extend(pair);
    }
    argv.push(network.to_string());
    argv.push(container.to_string());
    argv
}

/// `docker network ls --filter name=<prefix>
/// [--filter label=sandboxd.owner=<pool>] --format {{.Name}}`.
pub fn network_list_argv(name_prefix: &str, owner_pool: Option<&str>) -> Vec<String> {
    let mut argv = vec![
        "network".to_string(),
        "ls".to_string(),
        "--filter".to_string(),
        format!("name={name_prefix}"),
    ];
    if let Some(pool) = owner_pool {
        argv.push("--filter".to_string());
        argv.push(format!("label=sandboxd.owner={pool}"));
    }
    argv.push("--format".to_string());
    argv.push("{{.Name}}".to_string());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_argv_places_the_name_last() {
        let argv = network_create_argv(&NetworkCreateSpec {
            name: "sandbox-net-abc".to_string(),
            driver: NetworkDriver::Bridge,
            subnet: Some("10.209.0.0/28".to_string()),
            gateway: None,
            session_id: Some("abc".to_string()),
            owner_pool: None,
            options: vec![NetworkOption::BridgeName("sb-abc".to_string())],
        });
        assert_eq!(argv.last().map(String::as_str), Some("sandbox-net-abc"));
        assert_eq!(argv[0], "network");
        assert_eq!(argv[1], "create");
    }

    #[test]
    fn create_argv_emits_only_the_optional_fields_that_are_set() {
        let argv = network_create_argv(&NetworkCreateSpec {
            name: "sandboxd-egress".to_string(),
            driver: NetworkDriver::Bridge,
            subnet: None,
            gateway: None,
            session_id: None,
            owner_pool: None,
            options: Vec::new(),
        });
        assert_eq!(
            argv,
            vec!["network", "create", "--driver", "bridge", "sandboxd-egress"]
        );
    }

    /// Masquerade-off is the flag the fail-closed pre-route window rests on,
    /// so its rendering is pinned rather than left to `Display`.
    #[test]
    fn masquerade_option_renders_the_boolean_docker_expects() {
        assert_eq!(
            NetworkOption::BridgeMasquerade(false).render(),
            "com.docker.network.bridge.enable_ip_masquerade=false"
        );
        assert_eq!(
            NetworkOption::BridgeMasquerade(true).render(),
            "com.docker.network.bridge.enable_ip_masquerade=true"
        );
    }

    #[test]
    fn macvlan_parent_option_renders_as_a_bare_parent_key() {
        assert_eq!(
            NetworkOption::MacvlanParent("eth1".to_string()).render(),
            "parent=eth1"
        );
    }

    /// The macvlan mode is the L2-isolation control: `private` blocks
    /// macvlan-to-macvlan traffic on a shared parent NIC. Any other rendering
    /// is a weaker mode.
    #[test]
    fn macvlan_mode_renders_as_private_and_nothing_else() {
        assert_eq!(
            NetworkOption::MacvlanModePrivate.render(),
            "macvlan_mode=private"
        );
    }

    #[test]
    fn connect_argv_omits_the_ip_flag_when_no_address_is_pinned() {
        assert_eq!(
            network_connect_argv("net", "ctr", None, EndpointGatewayPriority::Default),
            vec!["network", "connect", "net", "ctr"]
        );
        assert_eq!(
            network_connect_argv(
                "net",
                "ctr",
                Some("10.209.0.2"),
                EndpointGatewayPriority::Default
            ),
            vec!["network", "connect", "--ip", "10.209.0.2", "net", "ctr"]
        );
    }

    /// Docker's default priority is `0` and the flag is how an endpoint
    /// declines the election, so the value has to be negative — a `0` or a
    /// missing flag would leave the newly attached endpoint able to take
    /// the default route, which is the whole failure this exists to stop.
    #[test]
    fn connect_argv_declines_the_default_route_with_a_negative_priority() {
        let argv = network_connect_argv(
            "net",
            "ctr",
            Some("10.209.0.2"),
            EndpointGatewayPriority::NeverDefaultGateway,
        );
        let value = argv
            .windows(2)
            .find(|w| w[0] == "--gw-priority")
            .map(|w| w[1].clone())
            .expect("the flag must be present");
        assert!(
            value.parse::<i32>().expect("a number") < 0,
            "gateway priority must be below Docker's default of 0, got {value}"
        );
        assert_eq!(argv.last().expect("container is last"), "ctr");
    }

    #[test]
    fn list_argv_adds_the_owner_filter_only_when_a_pool_is_given() {
        assert_eq!(
            network_list_argv("sandbox-net-", None),
            vec![
                "network",
                "ls",
                "--filter",
                "name=sandbox-net-",
                "--format",
                "{{.Name}}"
            ]
        );
        let argv = network_list_argv("sandbox-net-", Some("10.209.128.0/24"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--filter" && w[1] == "label=sandboxd.owner=10.209.128.0/24")
        );
    }

    #[test]
    fn remove_and_inspect_are_two_token_subcommands() {
        assert_eq!(network_remove_argv("n"), vec!["network", "rm", "n"]);
        assert_eq!(network_inspect_argv("n"), vec!["network", "inspect", "n"]);
    }
}
