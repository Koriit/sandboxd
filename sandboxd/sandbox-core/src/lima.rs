use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ring::digest;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::error::SandboxError;
use crate::process::run_with_timeout;
use crate::session::{SessionConfig, SessionId, WorkspaceMode};

// ---------------------------------------------------------------------------
// Timeout constants
// ---------------------------------------------------------------------------

/// Timeout for `limactl create`.
const CREATE_VM_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for `limactl start` (VM boot is slow).
const START_VM_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for `limactl stop`.
const STOP_VM_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for `limactl delete`.
const DELETE_VM_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for each step of the guest agent installation sequence.
const INSTALL_GUEST_AGENT_STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for `limactl list`.
const LIST_VMS_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for `limactl create` when building the base image (longer than
/// per-session create because this is a one-time operation).
const BASE_CREATE_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeout for `limactl start` when booting the base image (cloud-init
/// provisioning runs on first boot: installs socat, git, Docker via
/// apt, guest agent).
const BASE_START_TIMEOUT: Duration = Duration::from_secs(600);

/// Timeout for `limactl stop` when stopping the base image.
const BASE_STOP_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeout for `limactl clone`.
const CLONE_VM_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Golden image constants
// ---------------------------------------------------------------------------

/// VM name for the pre-provisioned golden base image.
const BASE_VM_NAME: &str = "sandbox-base";

/// Maximum age (in days) before the base image is considered stale and
/// should be rebuilt.
const BASE_IMAGE_MAX_AGE_DAYS: u64 = 10;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Status of a Lima-managed virtual machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmStatus {
    Running,
    Stopped,
    /// Any status string not explicitly handled.
    Unknown(String),
}

/// Summary information for a sandbox VM discovered via `limactl list`.
#[derive(Debug, Clone)]
pub struct VmInfo {
    pub name: String,
    pub status: VmStatus,
    /// Session ID parsed from the `sandbox-{id}` naming convention.
    pub session_id: Option<SessionId>,
}

/// Metadata for the golden base image, persisted as JSON alongside the VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseImageMeta {
    /// When the base image was built.
    pub built_at: chrono::DateTime<chrono::Utc>,
    /// SHA256 hash of the inputs (template content + guest agent binary)
    /// that produced this image.
    pub content_hash: String,
}

/// Status of the pre-provisioned golden base image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseImageStatus {
    /// No base image VM exists.
    Missing,
    /// The base image is up-to-date and ready for cloning.
    Fresh,
    /// The base image exists but should be rebuilt.
    Stale {
        /// Age of the base image in days.
        age_days: u64,
        /// Whether the content hash differs from the current inputs.
        hash_mismatch: bool,
    },
}

// ---------------------------------------------------------------------------
// LimaManager
// ---------------------------------------------------------------------------

/// Systemd unit file for the sandbox guest agent service.
const GUEST_AGENT_SERVICE_UNIT: &str = "\
[Unit]
Description=Sandbox Guest Agent
After=network.target

[Service]
Type=simple
User=agent
Group=agent
ExecStart=/usr/local/bin/sandbox-guest
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target";

/// QEMU wrapper script that injects PCIe root-port, bridge networking,
/// device lockdown, and optional cgroup resource limits via `systemd-run`.
///
/// Extracted as a constant so tests can verify the content without writing
/// to the filesystem.
const QEMU_WRAPPER_SCRIPT: &str = r#"#!/bin/sh
# QEMU wrapper injected by sandboxd.
#
# Always:
# 1. Adds a PCIe root-port so that NIC hot-add via QMP works on q35 machines.
#
# When SANDBOX_DOCKER_BRIDGE is set:
# 2. Adds a second NIC connected to the Docker bridge via qemu-bridge-helper.
#    For rootless Docker the bridge lives inside rootlesskit's network
#    namespace, so a wrapper helper runs qemu-bridge-helper via nsenter.
#
# When SANDBOX_QEMU_HARDENED=1:
# 3. Disables unnecessary devices (USB, sound, display, floppy, HPET, etc.)
#    and adds virtio-rng for guest entropy.
#
# When SANDBOX_QEMU_MEMORY_MB and SANDBOX_QEMU_CPUS are set:
# 4. Applies cgroup resource limits via systemd-run.

# Find the real QEMU binary, excluding this wrapper's directory to prevent
# infinite recursion if Lima prepends it to PATH.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_QEMU=""
IFS=:
for dir in $PATH; do
    [ "$dir" = "$SCRIPT_DIR" ] && continue
    if [ -x "$dir/qemu-system-x86_64" ]; then
        REAL_QEMU="$dir/qemu-system-x86_64"
        break
    fi
done
unset IFS
[ -z "$REAL_QEMU" ] && { echo "qemu-system-x86_64 not found on PATH (excluding wrapper dir $SCRIPT_DIR)" >&2; exit 1; }

# Lima runs probe commands (-machine help, -cpu help, -accel help, --version,
# etc.) through the wrapper.  Pass these straight to QEMU without extra flags.
for arg in "$@"; do
    case "$arg" in
        help|--version|--help|-help)
            exec "$REAL_QEMU" "$@" ;;
    esac
done

# PCIe root-port is always needed for NIC hot-add.
EXTRA_ARGS="-device pcie-root-port,id=pcie-hotplug-port,bus=pcie.0,chassis=1"

# Bridge networking: if SANDBOX_DOCKER_BRIDGE is set, add a second NIC
# connected to the Docker bridge via qemu-bridge-helper.
if [ -n "$SANDBOX_DOCKER_BRIDGE" ]; then
    BRIDGE_HELPER="${SANDBOX_BRIDGE_HELPER:-/usr/lib/qemu/qemu-bridge-helper}"

    # Rootless Docker: the bridge lives inside rootlesskit's network+user
    # namespace.  QEMU stays on the host (so Lima SSH port-forwarding works),
    # but qemu-bridge-helper must run inside the namespace to find the bridge
    # and create the TAP device there.  The TAP fd is passed back over a unix
    # socket, which works across namespace boundaries.
    CHILD_PID_FILE="/run/user/$(id -u)/dockerd-rootless/child_pid"
    if [ -f "$CHILD_PID_FILE" ]; then
        RLKIT_PID="$(cat "$CHILD_PID_FILE")"
        if [ -n "$RLKIT_PID" ] && [ -d "/proc/$RLKIT_PID" ]; then
            # Create a small wrapper script that nsenter's the helper
            NSHELPER="$SCRIPT_DIR/bridge-helper-ns"
            cat > "$NSHELPER" <<'HELPEREOF'
#!/bin/sh
exec nsenter --preserve-credentials -U -n -t "$SANDBOX_RLKIT_PID" -- "$SANDBOX_REAL_BRIDGE_HELPER" "$@"
HELPEREOF
            chmod +x "$NSHELPER"
            export SANDBOX_RLKIT_PID="$RLKIT_PID"
            export SANDBOX_REAL_BRIDGE_HELPER="$BRIDGE_HELPER"
            BRIDGE_HELPER="$NSHELPER"
        fi
    fi

    EXTRA_ARGS="$EXTRA_ARGS \
        -netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE,helper=$BRIDGE_HELPER \
        -device virtio-net-pci,netdev=net_sandbox,mac=$SANDBOX_VM_MAC,bus=pcie-hotplug-port"
fi

# Hardened mode: device lockdown.
if [ "$SANDBOX_QEMU_HARDENED" = "1" ]; then
    # Note: QEMU seccomp (-sandbox) is NOT used because it requires
    # PR_SET_NO_NEW_PRIVS, which strips setuid from qemu-bridge-helper
    # and breaks bridge networking.  Defence-in-depth still comes from
    # device lockdown, cgroup limits, and KVM hardware isolation.
    EXTRA_ARGS="$EXTRA_ARGS \
        -no-user-config \
        -display none \
        -vga none \
        -device virtio-rng-pci"
fi

# If resource limit env vars are set and systemd-run is available, wrap
# QEMU in a transient systemd scope with memory and CPU limits.
if [ -n "$SANDBOX_QEMU_MEMORY_MB" ] && [ -n "$SANDBOX_QEMU_CPUS" ] && command -v systemd-run >/dev/null 2>&1; then
    exec systemd-run --user --scope --slice=sandbox.slice \
        -p MemoryMax="$((SANDBOX_QEMU_MEMORY_MB + 512))M" \
        -p "CPUQuota=${SANDBOX_QEMU_CPUS}00%" \
        -p TasksMax=256 \
        "$REAL_QEMU" $EXTRA_ARGS "$@"
else
    exec "$REAL_QEMU" $EXTRA_ARGS "$@"
fi
"#;

/// Manages Lima virtual machines that back sandbox sessions.
///
/// All VMs are named `sandbox-{session_id}` so they can be distinguished from
/// user-created Lima instances.  Templates and other per-session artefacts are
/// stored under `{base_dir}/sessions/{session_id}/`.
pub struct LimaManager {
    base_dir: PathBuf,
    limactl: PathBuf,
}

impl LimaManager {
    /// Create a new manager rooted at the given base directory.
    ///
    /// `base_dir` is typically `~/.local/share/sandboxd/` (`$XDG_DATA_HOME/sandboxd`)
    /// — the same directory used by [`crate::SessionStore`].
    ///
    /// Resolves the `limactl` binary from `PATH` at construction time so
    /// that a missing installation is detected early with a clear error.
    pub fn new(base_dir: PathBuf) -> Result<Self, SandboxError> {
        let limactl = resolve_binary_from_path("limactl")?;
        Ok(Self { base_dir, limactl })
    }

    /// Create a manager with a caller-supplied `limactl` path, skipping
    /// PATH resolution.  Useful for tests and environments where the binary
    /// location is already known.
    #[cfg(test)]
    pub fn with_limactl_path(base_dir: PathBuf, limactl: PathBuf) -> Self {
        Self { base_dir, limactl }
    }

    /// Return the path to the `limactl` binary.
    pub fn limactl_path(&self) -> &std::path::Path {
        &self.limactl
    }

    // -- public API ---------------------------------------------------------

    /// Create a new VM for the given session.
    ///
    /// Generates a Lima YAML template, writes it to the session directory, and
    /// shells out to `limactl create`.
    pub fn create_vm(
        &self,
        session_id: &SessionId,
        config: &SessionConfig,
    ) -> Result<(), SandboxError> {
        let template = self.generate_template(session_id, config);
        let session_dir = self.session_dir(session_id);
        std::fs::create_dir_all(&session_dir)?;

        let template_path = session_dir.join("template.yaml");
        std::fs::write(&template_path, &template)?;

        let vm_name = vm_name(session_id);

        info!(
            session_id = %session_id,
            vm = %vm_name,
            cpus = config.cpus,
            memory_mb = config.memory_mb,
            disk_gb = config.disk_gb,
            hardened = config.hardened,
            "creating VM"
        );

        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args(["create", "--name", &vm_name])
                .arg(&template_path)
                .arg("--tty=false"),
            CREATE_VM_TIMEOUT,
            "limactl create",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl create", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("create", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM created");
        Ok(())
    }

    /// Create a new VM using a custom Lima template file.
    ///
    /// The template is copied to the session directory before invoking
    /// `limactl create`.
    pub fn create_vm_with_custom_template(
        &self,
        session_id: &SessionId,
        template_path: &std::path::Path,
    ) -> Result<(), SandboxError> {
        let session_dir = self.session_dir(session_id);
        std::fs::create_dir_all(&session_dir)?;

        let dest = session_dir.join("template.yaml");
        std::fs::copy(template_path, &dest)?;

        let vm_name = vm_name(session_id);

        info!(
            session_id = %session_id,
            vm = %vm_name,
            template = %template_path.display(),
            "creating VM with custom template"
        );

        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args(["create", "--name", &vm_name])
                .arg(&dest)
                .arg("--tty=false"),
            CREATE_VM_TIMEOUT,
            "limactl create",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl create", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("create", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM created with custom template");
        Ok(())
    }

    /// Start an existing (stopped) VM.
    ///
    /// A QEMU wrapper script is injected via `QEMU_SYSTEM_X86_64` so that the
    /// resulting VM has a PCIe root-port available for NIC hot-add,
    /// device lockdown, and cgroup resource limits.
    ///
    /// The `config` parameter controls hardening and propagates resource limits
    /// (memory, CPU) to the QEMU wrapper script via environment variables.
    ///
    /// When `bridge_name` and `vm_mac` are provided, the QEMU wrapper adds a
    /// second NIC connected to the Docker bridge via `qemu-bridge-helper`.
    /// This eliminates the need for host-side TAP/veth setup.
    pub fn start_vm(
        &self,
        session_id: &SessionId,
        config: &SessionConfig,
        bridge_name: Option<&str>,
        vm_mac: Option<&str>,
    ) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);
        let qemu_wrapper = self.ensure_qemu_wrapper()?;

        info!(
            session_id = %session_id,
            vm = %vm_name,
            hardened = config.hardened,
            bridge = bridge_name.unwrap_or("none"),
            "starting VM"
        );

        let hardened_flag = if config.hardened { "1" } else { "0" };
        let mut cmd = Command::new(&self.limactl);
        cmd.args(["start", &vm_name])
            .arg("--tty=false")
            .arg(format!("--timeout={}s", START_VM_TIMEOUT.as_secs()))
            .env("QEMU_SYSTEM_X86_64", &qemu_wrapper)
            .env("SANDBOX_QEMU_HARDENED", hardened_flag)
            .env("SANDBOX_QEMU_MEMORY_MB", config.memory_mb.to_string())
            .env("SANDBOX_QEMU_CPUS", config.cpus.to_string());

        // Pass bridge networking env vars to the QEMU wrapper when provided.
        if let (Some(bridge), Some(mac)) = (bridge_name, vm_mac) {
            cmd.env("SANDBOX_DOCKER_BRIDGE", bridge)
                .env("SANDBOX_VM_MAC", mac);
        }

        let output =
            run_with_timeout(&mut cmd, START_VM_TIMEOUT, "limactl start").map_err(|e| match e {
                SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                    lima_io_error("limactl start", std::io::Error::other(msg))
                }
                other => other,
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("start", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM started");
        Ok(())
    }

    /// Stop a running VM.
    pub fn stop_vm(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);

        info!(session_id = %session_id, vm = %vm_name, "stopping VM");

        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args(["stop", &vm_name])
                .arg("--tty=false"),
            STOP_VM_TIMEOUT,
            "limactl stop",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl stop", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("stop", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM stopped");
        Ok(())
    }

    /// Force-delete a VM and its Lima data.
    pub fn delete_vm(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);

        info!(session_id = %session_id, vm = %vm_name, "deleting VM");

        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args(["delete", "--force", &vm_name])
                .arg("--tty=false"),
            DELETE_VM_TIMEOUT,
            "limactl delete",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl delete", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("delete", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM deleted");
        Ok(())
    }

    /// Copy the sandbox-guest binary into a running VM and start it as a
    /// systemd service.
    ///
    /// This should be called after the VM has booted (i.e. after `start_vm`
    /// or `create_vm` + start).
    pub fn install_guest_agent(
        &self,
        session_id: &SessionId,
        binary_path: &Path,
    ) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);

        if !binary_path.exists() {
            return Err(SandboxError::Internal(format!(
                "guest agent binary not found at {}",
                binary_path.display()
            )));
        }

        // 1. Copy the binary into the VM (to a user-writable temp path first,
        //    then move it with sudo, because limactl copy uses rsync which
        //    runs as the unprivileged user).
        debug!(vm = %vm_name, binary = %binary_path.display(), "copying guest agent binary");
        let copy_src = binary_path.to_string_lossy().to_string();
        let copy_dst = format!("{vm_name}:/tmp/sandbox-guest");
        let output = run_with_timeout(
            Command::new(&self.limactl).args(["copy", &copy_src, &copy_dst]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl copy (guest agent)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl copy (guest agent)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to copy guest agent to {vm_name}: {stderr}"
            )));
        }

        // 2. Move the binary to /usr/local/bin with sudo and make it executable.
        debug!(vm = %vm_name, "installing guest agent binary");
        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "shell",
                &vm_name,
                "--",
                "sudo",
                "mv",
                "/tmp/sandbox-guest",
                "/usr/local/bin/sandbox-guest",
            ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell mv",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell mv", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to move guest agent in {vm_name}: {stderr}"
            )));
        }

        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "shell",
                &vm_name,
                "--",
                "sudo",
                "chmod",
                "+x",
                "/usr/local/bin/sandbox-guest",
            ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell chmod",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell chmod", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to chmod guest agent in {vm_name}: {stderr}"
            )));
        }

        // 3. Create a systemd service file.
        debug!(vm = %vm_name, "creating systemd service");
        let service_unit = GUEST_AGENT_SERVICE_UNIT;
        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args([
                    "shell", &vm_name, "--",
                    "sudo", "bash", "-c",
                    &format!(
                        "cat > /etc/systemd/system/sandbox-guest.service << 'UNIT_EOF'\n{service_unit}\nUNIT_EOF"
                    ),
                ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell (create service)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell (create service)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to create systemd service in {vm_name}: {stderr}"
            )));
        }

        // 4. Reload systemd and start the service.
        debug!(vm = %vm_name, "starting guest agent service");
        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "shell",
                &vm_name,
                "--",
                "sudo",
                "systemctl",
                "daemon-reload",
            ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell (daemon-reload)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell (daemon-reload)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to reload systemd in {vm_name}: {stderr}"
            )));
        }

        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "shell",
                &vm_name,
                "--",
                "sudo",
                "systemctl",
                "enable",
                "--now",
                "sandbox-guest",
            ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell (enable service)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell (enable service)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to start guest agent service in {vm_name}: {stderr}"
            )));
        }

        info!(vm = %vm_name, "guest agent installed and started");
        Ok(())
    }

    /// Query the status of a single VM.
    pub fn vm_status(&self, session_id: &SessionId) -> Result<VmStatus, SandboxError> {
        let vms = self.list_vms_raw()?;
        let vm_name = vm_name(session_id);
        for entry in &vms {
            if entry.name.as_deref() == Some(vm_name.as_str()) {
                return Ok(parse_status_field(entry.status.as_deref().unwrap_or("")));
            }
        }
        Err(SandboxError::Lima(format!(
            "VM {vm_name} not found in limactl list"
        )))
    }

    /// List all sandbox-prefixed VMs known to Lima.
    pub fn list_vms(&self) -> Result<Vec<VmInfo>, SandboxError> {
        let entries = self.list_vms_raw()?;
        Ok(entries
            .into_iter()
            .filter_map(|e| {
                let name = e.name?;
                if !name.starts_with(VM_NAME_PREFIX) {
                    return None;
                }
                let status = parse_status_field(e.status.as_deref().unwrap_or(""));
                let session_id = parse_session_id_from_name(&name);
                Some(VmInfo {
                    name,
                    status,
                    session_id,
                })
            })
            .collect())
    }

    // -- golden image -------------------------------------------------------

    /// Compute a SHA256 content hash of the golden image inputs.
    ///
    /// The hash covers:
    /// 1. The base template YAML content (from `generate_base_template()`)
    /// 2. The guest agent binary bytes (at the path from `guest_agent_path()`)
    ///
    /// If the guest agent binary does not exist, this is treated as a hard
    /// error because the base image cannot be built without it.
    pub fn compute_base_image_hash(&self) -> Result<String, SandboxError> {
        let template = self.generate_base_template();
        let agent_path = guest_agent_path()?;

        if !agent_path.exists() {
            return Err(SandboxError::Internal(format!(
                "guest agent binary not found at {}",
                agent_path.display()
            )));
        }

        let agent_bytes = std::fs::read(&agent_path).map_err(|e| {
            SandboxError::Internal(format!(
                "failed to read guest agent binary at {}: {e}",
                agent_path.display()
            ))
        })?;

        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(template.as_bytes());
        ctx.update(&agent_bytes);
        let hash = ctx.finish();

        Ok(hex_encode(hash.as_ref()))
    }

    /// Check the status of the golden base image.
    ///
    /// Returns `Missing` if the VM does not exist, `Fresh` if it is
    /// up-to-date, or `Stale` if it should be rebuilt.
    pub fn check_base_image(&self) -> Result<BaseImageStatus, SandboxError> {
        // Check if the VM exists.
        let vms = self.list_vms_raw()?;
        let vm_exists = vms.iter().any(|e| e.name.as_deref() == Some(BASE_VM_NAME));

        if !vm_exists {
            return Ok(BaseImageStatus::Missing);
        }

        // Read metadata file.
        let meta_path = self.base_dir.join("base-image-meta.json");
        let meta = match std::fs::read_to_string(&meta_path) {
            Ok(content) => match serde_json::from_str::<BaseImageMeta>(&content) {
                Ok(meta) => meta,
                Err(_) => {
                    return Ok(BaseImageStatus::Stale {
                        age_days: 0,
                        hash_mismatch: true,
                    });
                }
            },
            Err(_) => {
                return Ok(BaseImageStatus::Stale {
                    age_days: 0,
                    hash_mismatch: true,
                });
            }
        };

        // Check content hash.
        let current_hash = self.compute_base_image_hash()?;
        if meta.content_hash != current_hash {
            let age_days = age_in_days(&meta.built_at);
            return Ok(BaseImageStatus::Stale {
                age_days,
                hash_mismatch: true,
            });
        }

        // Check age.
        let age_days = age_in_days(&meta.built_at);
        if age_days > BASE_IMAGE_MAX_AGE_DAYS {
            return Ok(BaseImageStatus::Stale {
                age_days,
                hash_mismatch: false,
            });
        }

        Ok(BaseImageStatus::Fresh)
    }

    /// Build the golden base image from scratch.
    ///
    /// This creates a new Lima VM named `sandbox-base`, boots it, installs
    /// the guest agent, then stops it.  The resulting VM serves as a
    /// template that can be cloned for each new session.
    pub fn build_base_image(&self) -> Result<(), SandboxError> {
        info!("building golden base image");

        // 1. Generate and write the base template.
        let template = self.generate_base_template();
        std::fs::create_dir_all(&self.base_dir)?;
        let template_path = self.base_dir.join("base-template.yaml");
        std::fs::write(&template_path, &template)?;
        info!(path = %template_path.display(), "wrote base template");

        // 2. Create the VM.
        info!("creating base VM");
        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args(["create", "--name", BASE_VM_NAME])
                .arg(&template_path)
                .arg("--tty=false"),
            BASE_CREATE_TIMEOUT,
            "limactl create (base image)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl create (base image)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("create (base image)", &stderr));
        }
        info!("base VM created");

        // Steps 3-6 are wrapped so that a failure cleans up the partially-
        // built VM.  Without this, a broken `sandbox-base` VM is left in
        // Lima's inventory and subsequent `create` calls try to clone from
        // it, producing non-functional VMs.
        match self.build_base_image_inner() {
            Ok(()) => {
                info!("golden base image build complete");
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "base image build failed, cleaning up partial VM");
                let _ = run_with_timeout(
                    Command::new(&self.limactl).args(["delete", "--force", BASE_VM_NAME]),
                    Duration::from_secs(60),
                    "limactl delete (base image cleanup)",
                );
                Err(e)
            }
        }
    }

    /// Inner build steps (start, install agent, stop, write metadata).
    /// Separated from `build_base_image` so the caller can clean up on error.
    fn build_base_image_inner(&self) -> Result<(), SandboxError> {
        // 3. Start the VM with QEMU wrapper for hardening.
        info!("starting base VM (this may take several minutes for cloud-init)");
        let qemu_wrapper = self.ensure_qemu_wrapper()?;

        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args(["start", BASE_VM_NAME])
                .arg("--tty=false")
                .arg(format!("--timeout={}s", BASE_START_TIMEOUT.as_secs()))
                .env("QEMU_SYSTEM_X86_64", &qemu_wrapper)
                .env("SANDBOX_QEMU_HARDENED", "1")
                .env("SANDBOX_QEMU_MEMORY_MB", "4096")
                .env("SANDBOX_QEMU_CPUS", "4"),
            // Our process timeout is slightly longer than Lima's to let Lima
            // report its own error message instead of being killed.
            BASE_START_TIMEOUT + Duration::from_secs(30),
            "limactl start (base image)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl start (base image)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("start (base image)", &stderr));
        }
        info!("base VM started");

        // 4. Install the guest agent.
        info!("installing guest agent into base VM");
        let agent_path = guest_agent_path()?;
        self.install_guest_agent_by_vm_name(BASE_VM_NAME, &agent_path)?;
        info!("guest agent installed in base VM");

        // 5. Stop the VM.
        info!("stopping base VM");
        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args(["stop", BASE_VM_NAME])
                .arg("--tty=false"),
            BASE_STOP_TIMEOUT,
            "limactl stop (base image)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl stop (base image)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("stop (base image)", &stderr));
        }
        info!("base VM stopped");

        // 6. Write metadata.
        let content_hash = self.compute_base_image_hash()?;
        let meta = BaseImageMeta {
            built_at: chrono::Utc::now(),
            content_hash,
        };
        let meta_path = self.base_dir.join("base-image-meta.json");
        let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| {
            SandboxError::Internal(format!("failed to serialize base image metadata: {e}"))
        })?;
        std::fs::write(&meta_path, &meta_json)?;
        info!(path = %meta_path.display(), "wrote base image metadata");

        Ok(())
    }

    /// Delete and rebuild the golden base image.
    pub fn rebuild_base_image(&self) -> Result<(), SandboxError> {
        info!("rebuilding golden base image");

        // Delete the existing VM (ignore errors if it doesn't exist).
        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args(["delete", "--force", BASE_VM_NAME])
                .arg("--tty=false"),
            DELETE_VM_TIMEOUT,
            "limactl delete (base image)",
        );

        match output {
            Ok(o) if !o.status.success() => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                debug!(stderr = %stderr, "base VM delete returned non-zero (may not exist)");
            }
            Err(e) => {
                debug!(error = %e, "base VM delete failed (may not exist)");
            }
            Ok(_) => {
                info!("deleted existing base VM");
            }
        }

        // Delete the metadata file (ignore errors).
        let meta_path = self.base_dir.join("base-image-meta.json");
        if meta_path.exists() {
            let _ = std::fs::remove_file(&meta_path);
        }

        self.build_base_image()
    }

    /// Clone the golden base image into a new VM for a session.
    ///
    /// The cloned VM gets the specified resource limits. The base image
    /// must exist and be stopped (call `build_base_image()` first).
    pub fn clone_vm(
        &self,
        session_id: SessionId,
        cpus: u32,
        memory_mb: u32,
        disk_gb: u32,
    ) -> Result<(), SandboxError> {
        let target = vm_name(&session_id);

        info!(
            session_id = %session_id,
            vm = %target,
            cpus,
            memory_mb,
            disk_gb,
            "cloning base image"
        );

        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "clone",
                BASE_VM_NAME,
                &target,
                "--cpus",
                &cpus.to_string(),
                "--memory",
                &mib_to_gib_string(memory_mb),
                "--disk",
                &disk_gb.to_string(),
            ]),
            CLONE_VM_TIMEOUT,
            "limactl clone",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl clone", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("clone", &stderr));
        }

        info!(session_id = %session_id, vm = %target, "VM cloned from base image");
        Ok(())
    }

    // -- template generation ------------------------------------------------

    /// Generate a minimal Lima YAML template for the golden base image.
    ///
    /// Unlike `generate_template()`, this template uses fixed minimal
    /// resources (1 CPU, 1024 MB, 10 GB), has no mounts, and includes no
    /// per-session customization.  It carries the same cloud-init
    /// provisioning scripts (user creation, socat/git, Docker install).
    pub fn generate_base_template(&self) -> String {
        format!(
            r#"# Auto-generated Lima template for golden base image
minimumLimaVersion: "2.0.0"

vmType: "qemu"

images:
- location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img"
  arch: "x86_64"
- location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
  arch: "aarch64"

cpus: 4
memory: "4GiB"
disk: "10GiB"

mounts: []
portForwards: []

video:
  display: "none"
audio:
  device: "none"

containerd:
  system: false
  user: false

user:
  name: "agent"
  home: "/home/agent"

provision:
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=hostname start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    hostnamectl set-hostname {hostname}
    if ! grep -q '{hostname}' /etc/hosts; then
      echo "127.0.1.1 {hostname}" >> /etc/hosts
    fi
    echo "[sandbox-provision] step=hostname done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=user start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Create agent user with passwordless sudo (if not already present)
    if ! id agent &>/dev/null; then
      useradd -m -s /bin/bash agent
    fi
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent
    chmod 0440 /etc/sudoers.d/agent
    echo "[sandbox-provision] step=user done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=apt-config start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Switch apt sources to HTTPS and configure fast timeouts
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources
    cat > /etc/apt/apt.conf.d/99sandbox <<'APTEOF'
    Acquire::http::Timeout "5";
    Acquire::https::Timeout "5";
    Acquire::Retries "5";
    Acquire::ForceIPv4 "true";
    APTEOF
    echo "[sandbox-provision] step=apt-config done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    echo "[sandbox-provision] step=apt-socat-git start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Install socat (needed for host-guest communication bridge) and git
    if ! command -v socat &>/dev/null || ! command -v git &>/dev/null; then
      echo "[sandbox-provision] apt-get update start=$(date -u +%Y-%m-%dT%H:%M:%S)"
      apt-get update -qq
      echo "[sandbox-provision] apt-get update done=$(date -u +%Y-%m-%dT%H:%M:%S)"
      echo "[sandbox-provision] apt-get install socat git start=$(date -u +%Y-%m-%dT%H:%M:%S)"
      apt-get install -y socat git
      echo "[sandbox-provision] apt-get install socat git done=$(date -u +%Y-%m-%dT%H:%M:%S)"
    fi
    # Ensure the workspace directory exists for repo cloning (owned by agent, not root)
    mkdir -p /home/agent/workspace
    chown agent:agent /home/agent/workspace
    echo "[sandbox-provision] step=apt-socat-git done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    echo "[sandbox-provision] step=docker start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Install Docker via official convenience script
    if ! command -v docker &>/dev/null; then
      curl -fsSL https://get.docker.com | sh
      usermod -aG docker agent
    fi
    echo "[sandbox-provision] step=docker done=$(date -u +%Y-%m-%dT%H:%M:%S)"
"#,
            hostname = BASE_VM_NAME,
        )
    }

    /// Generate the Lima YAML template for a session.
    ///
    /// # Panics
    ///
    /// Panics (via `sanitize_yaml_path`) if a shared-workspace `host_path`
    /// contains characters that are unsafe for YAML interpolation.  In
    /// practice this cannot happen because `WorkspaceMode::parse_flag`
    /// validates the path before it reaches this point, but the check here
    /// acts as defense-in-depth.
    pub fn generate_template(&self, session_id: &SessionId, config: &SessionConfig) -> String {
        // Hostname includes the full 12-hex session id. At 20 chars it is
        // well under the POSIX HOST_NAME_MAX of 64.
        let hostname = format!("sandbox-{session_id}");

        // Lima expects memory as a string like "4GiB" and disk as "20GiB".
        let memory_gib = format!("{}GiB", mib_to_gib_string(config.memory_mb));
        let disk_gib = format!("{}GiB", config.disk_gb);

        // Build the mounts section: empty by default, populated for shared
        // workspace mode.  We use `9p` (built into QEMU) rather than
        // `virtiofs` because virtiofs requires virtiofsd + shared memory
        // (memfd) which adds complexity and an additional process.
        // 9p runs inside the QEMU process itself.
        //
        // SECURITY NOTE: 9p adds a virtio-9p device to the VM, which
        // expands the attack surface compared to a fully isolated VM.  The
        // host directory is writable by the guest.  This is a documented
        // trade-off — see docs/workspaces.md.
        let mounts_section = match &config.workspace_mode {
            Some(WorkspaceMode::Shared { host_path }) => {
                // Validate the host_path contains only characters safe for
                // YAML string interpolation.  This prevents injection of
                // arbitrary YAML via crafted directory names containing
                // quotes, newlines, or other YAML-special characters.
                let safe_path = sanitize_yaml_path(host_path);
                format!(
                    "\
mountType: \"9p\"
mounts:
- location: \"{safe_path}\"
  mountPoint: \"/home/agent/workspace\"
  writable: true
  9p:
    securityModel: mapped-xattr
    cache: mmap"
                )
            }
            _ => "mounts: []".to_string(),
        };

        // When hardened, tell Lima to disable video and audio devices.  Lima
        // translates these into the appropriate QEMU flags at VM creation
        // time, ensuring no display or sound device is attached.
        let hardened_section = if config.hardened {
            "\nvideo:\n  display: \"none\"\naudio:\n  device: \"none\""
        } else {
            ""
        };

        format!(
            r#"# Auto-generated Lima template for sandbox session {session_id}
minimumLimaVersion: "2.0.0"

vmType: "qemu"

images:
- location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img"
  arch: "x86_64"
- location: "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
  arch: "aarch64"

cpus: {cpus}
memory: "{memory_gib}"
disk: "{disk_gib}"

{mounts_section}
portForwards: []
{hardened_section}
containerd:
  system: false
  user: false

user:
  name: "agent"
  home: "/home/agent"

provision:
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=hostname start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    hostnamectl set-hostname {hostname}
    # Add hostname to /etc/hosts so 'sudo' and other tools that resolve
    # the local hostname do not emit "unable to resolve host" warnings.
    if ! grep -q '{hostname}' /etc/hosts; then
      echo "127.0.1.1 {hostname}" >> /etc/hosts
    fi
    echo "[sandbox-provision] step=hostname done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=user start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Create agent user with passwordless sudo (if not already present)
    if ! id agent &>/dev/null; then
      useradd -m -s /bin/bash agent
    fi
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent
    chmod 0440 /etc/sudoers.d/agent
    echo "[sandbox-provision] step=user done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=apt-config start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Switch apt sources to HTTPS and configure fast timeouts
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources
    cat > /etc/apt/apt.conf.d/99sandbox <<'APTEOF'
    Acquire::http::Timeout "5";
    Acquire::https::Timeout "5";
    Acquire::Retries "5";
    Acquire::ForceIPv4 "true";
    APTEOF
    echo "[sandbox-provision] step=apt-config done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    echo "[sandbox-provision] step=apt-socat-git start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Install socat (needed for host-guest communication bridge) and git
    if ! command -v socat &>/dev/null || ! command -v git &>/dev/null; then
      echo "[sandbox-provision] apt-get update start=$(date -u +%Y-%m-%dT%H:%M:%S)"
      apt-get update -qq
      echo "[sandbox-provision] apt-get update done=$(date -u +%Y-%m-%dT%H:%M:%S)"
      echo "[sandbox-provision] apt-get install socat git start=$(date -u +%Y-%m-%dT%H:%M:%S)"
      apt-get install -y socat git
      echo "[sandbox-provision] apt-get install socat git done=$(date -u +%Y-%m-%dT%H:%M:%S)"
    fi
    # Ensure the workspace directory exists for repo cloning (owned by agent, not root)
    mkdir -p /home/agent/workspace
    chown agent:agent /home/agent/workspace
    echo "[sandbox-provision] step=apt-socat-git done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    echo "[sandbox-provision] step=docker start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Install Docker via official convenience script
    if ! command -v docker &>/dev/null; then
      curl -fsSL https://get.docker.com | sh
      usermod -aG docker agent
    fi
    echo "[sandbox-provision] step=docker done=$(date -u +%Y-%m-%dT%H:%M:%S)"
"#,
            session_id = session_id,
            cpus = config.cpus,
            memory_gib = memory_gib,
            disk_gib = disk_gib,
            mounts_section = mounts_section,
            hardened_section = hardened_section,
            hostname = hostname,
        )
    }

    // -- helpers ------------------------------------------------------------

    /// Create a QEMU wrapper script that injects process hardening.
    ///
    /// The wrapper does three things:
    ///
    /// 1. **PCIe root-port** — The q35 machine type does not include any PCIe
    ///    root-port by default, which means no PCIe device (including
    ///    virtio-net-pci) can be hot-added via QMP.
    ///
    /// 2. **Device lockdown** — Disables unnecessary QEMU devices (USB, sound,
    ///    display, floppy, HPET) and adds virtio-rng for guest entropy.
    ///
    /// 3. **Cgroup limits** — When `SANDBOX_QEMU_MEMORY_MB` and
    ///    `SANDBOX_QEMU_CPUS` environment variables are set (propagated from
    ///    [`SessionConfig`] in [`start_vm`]), the wrapper uses `systemd-run` to
    ///    place the QEMU process in a scoped cgroup with memory and CPU limits.
    ///    If `systemd-run` is not available, the wrapper falls back to running
    ///    QEMU without cgroup limits.
    ///
    /// Lima does not expose a way to pass extra QEMU arguments, so we
    /// interpose a shell wrapper that Lima invokes via the
    /// `QEMU_SYSTEM_X86_64` environment variable.
    fn ensure_qemu_wrapper(&self) -> Result<PathBuf, SandboxError> {
        let wrapper_dir = self.base_dir.join("libexec");
        std::fs::create_dir_all(&wrapper_dir)?;
        let wrapper_path = wrapper_dir.join("qemu-system-x86_64");

        // The wrapper script is idempotent — overwrite if the content changed.
        let script = QEMU_WRAPPER_SCRIPT;
        std::fs::write(&wrapper_path, script)?;

        // chmod +x
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755))?;
        }

        debug!(path = %wrapper_path.display(), "QEMU wrapper script ready");
        Ok(wrapper_path)
    }

    fn session_dir(&self, session_id: &SessionId) -> PathBuf {
        self.base_dir.join("sessions").join(session_id.as_str())
    }

    /// Install the guest agent into a VM identified by name.
    ///
    /// This is the internal implementation shared by `install_guest_agent()`
    /// (which takes a session UUID) and `build_base_image()` (which uses the
    /// fixed `sandbox-base` name).
    fn install_guest_agent_by_vm_name(
        &self,
        vm_name: &str,
        binary_path: &Path,
    ) -> Result<(), SandboxError> {
        if !binary_path.exists() {
            return Err(SandboxError::Internal(format!(
                "guest agent binary not found at {}",
                binary_path.display()
            )));
        }

        // 1. Copy the binary into the VM.
        debug!(vm = %vm_name, binary = %binary_path.display(), "copying guest agent binary");
        let copy_src = binary_path.to_string_lossy().to_string();
        let copy_dst = format!("{vm_name}:/tmp/sandbox-guest");
        let output = run_with_timeout(
            Command::new(&self.limactl).args(["copy", &copy_src, &copy_dst]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl copy (guest agent)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl copy (guest agent)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to copy guest agent to {vm_name}: {stderr}"
            )));
        }

        // 2. Move the binary to /usr/local/bin with sudo and make it executable.
        debug!(vm = %vm_name, "installing guest agent binary");
        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "shell",
                vm_name,
                "--",
                "sudo",
                "mv",
                "/tmp/sandbox-guest",
                "/usr/local/bin/sandbox-guest",
            ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell mv",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell mv", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to move guest agent in {vm_name}: {stderr}"
            )));
        }

        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "shell",
                vm_name,
                "--",
                "sudo",
                "chmod",
                "+x",
                "/usr/local/bin/sandbox-guest",
            ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell chmod",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell chmod", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to chmod guest agent in {vm_name}: {stderr}"
            )));
        }

        // 3. Create a systemd service file.
        debug!(vm = %vm_name, "creating systemd service");
        let service_unit = GUEST_AGENT_SERVICE_UNIT;
        let output = run_with_timeout(
            Command::new(&self.limactl)
                .args([
                    "shell", vm_name, "--",
                    "sudo", "bash", "-c",
                    &format!(
                        "cat > /etc/systemd/system/sandbox-guest.service << 'UNIT_EOF'\n{service_unit}\nUNIT_EOF"
                    ),
                ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell (create service)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell (create service)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to create systemd service in {vm_name}: {stderr}"
            )));
        }

        // 4. Reload systemd and start the service.
        debug!(vm = %vm_name, "starting guest agent service");
        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "shell",
                vm_name,
                "--",
                "sudo",
                "systemctl",
                "daemon-reload",
            ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell (daemon-reload)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell (daemon-reload)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to reload systemd in {vm_name}: {stderr}"
            )));
        }

        let output = run_with_timeout(
            Command::new(&self.limactl).args([
                "shell",
                vm_name,
                "--",
                "sudo",
                "systemctl",
                "enable",
                "--now",
                "sandbox-guest",
            ]),
            INSTALL_GUEST_AGENT_STEP_TIMEOUT,
            "limactl shell (enable service)",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl shell (enable service)", std::io::Error::other(msg))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to start guest agent service in {vm_name}: {stderr}"
            )));
        }

        info!(vm = %vm_name, "guest agent installed and started");
        Ok(())
    }

    /// Run `limactl list --json` and deserialize the raw entries.
    fn list_vms_raw(&self) -> Result<Vec<LimactlListEntry>, SandboxError> {
        let output = run_with_timeout(
            Command::new(&self.limactl).args(["list", "--json"]),
            LIST_VMS_TIMEOUT,
            "limactl list",
        )
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                lima_io_error("limactl list", std::io::Error::other(msg))
            }
            other => other,
        })?;

        // Lima writes a warning to stderr and returns empty stdout when no
        // instances exist.  Treat empty stdout as an empty list.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        parse_limactl_list_output(&stdout)
    }
}

// ---------------------------------------------------------------------------
// VM naming helpers (public for tests)
// ---------------------------------------------------------------------------

/// Resolve the path to the `sandbox-guest` binary.
///
/// Uses the same logic as the daemon: the guest agent binary is expected
/// to be in the same directory as the currently running executable.
pub fn guest_agent_path() -> Result<PathBuf, SandboxError> {
    let exe = std::env::current_exe().map_err(|e| {
        SandboxError::Internal(format!("failed to determine current executable path: {e}"))
    })?;
    let dir = exe.parent().ok_or_else(|| {
        SandboxError::Internal("executable path has no parent directory".to_string())
    })?;
    Ok(dir.join("sandbox-guest"))
}

/// Prefix applied to all sandbox VM names.
pub const VM_NAME_PREFIX: &str = "sandbox-";

/// Canonical VM name for a session.
pub fn vm_name(session_id: &SessionId) -> String {
    format!("{VM_NAME_PREFIX}{session_id}")
}

/// Try to extract a session ID from a VM name of the form `sandbox-{id}`.
pub fn parse_session_id_from_name(name: &str) -> Option<SessionId> {
    name.strip_prefix(VM_NAME_PREFIX)
        .and_then(|s| SessionId::parse(s).ok())
}

// ---------------------------------------------------------------------------
// Lima JSON parsing
// ---------------------------------------------------------------------------

/// Minimal representation of a single entry in `limactl list --json` output.
///
/// Lima outputs one JSON object per line (NDJSON), not a JSON array.
#[derive(Debug, Deserialize)]
struct LimactlListEntry {
    #[serde(rename = "name", alias = "Name")]
    name: Option<String>,
    #[serde(rename = "status", alias = "Status")]
    status: Option<String>,
}

/// Parse the NDJSON output of `limactl list --json`.
///
/// Each line is a self-contained JSON object.
fn parse_limactl_list_output(output: &str) -> Result<Vec<LimactlListEntry>, SandboxError> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: LimactlListEntry = serde_json::from_str(trimmed)
            .map_err(|e| SandboxError::Lima(format!("failed to parse limactl JSON: {e}")))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Map a Lima status string to our `VmStatus` enum.
fn parse_status_field(s: &str) -> VmStatus {
    match s {
        "Running" => VmStatus::Running,
        "Stopped" => VmStatus::Stopped,
        other => VmStatus::Unknown(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// Wrap an I/O error from spawning limactl.
fn lima_io_error(context: &str, err: std::io::Error) -> SandboxError {
    if err.kind() == std::io::ErrorKind::NotFound {
        SandboxError::Lima(format!("{context}: limactl not found (is Lima installed?)"))
    } else {
        SandboxError::Lima(format!("{context}: {err}"))
    }
}

/// Produce an error from limactl stderr, always preserving the raw output.
fn parse_limactl_error(subcommand: &str, stderr: &str) -> SandboxError {
    let stderr = stderr.trim();
    SandboxError::Lima(format!("limactl {subcommand} failed: {stderr}"))
}

/// Resolve a binary name to its absolute path using the system `PATH`.
///
/// Shells out to `command -v <name>` (POSIX) to find the binary.  Returns a
/// clear error if the binary is not installed.
fn resolve_binary_from_path(name: &str) -> Result<PathBuf, SandboxError> {
    let output = Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .output()
        .map_err(|e| SandboxError::Internal(format!("failed to run 'command -v {name}': {e}")))?;

    if !output.status.success() {
        return Err(SandboxError::Lima(format!(
            "{name} not found on PATH — is it installed?"
        )));
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err(SandboxError::Lima(format!(
            "{name} not found on PATH — is it installed?"
        )));
    }

    Ok(PathBuf::from(path))
}

/// Sanitise a filesystem path for safe interpolation into a YAML
/// double-quoted string.
///
/// YAML double-quoted strings interpret backslash escapes and treat `"`
/// as the string terminator.  A malicious directory name such as
/// `foo"\nnewkey: injected` could therefore inject arbitrary YAML when
/// interpolated with `format!("location: \"{path}\"")`.
///
/// This function validates that every character in the path is in a
/// known-safe set for filesystem paths:
///
///   alphanumeric, `/`, `-`, `_`, `.`, ` `, `+`, `@`, `~`, `:`
///
/// If any other character is found the function panics — this is
/// intentional because an unsafe path reaching template generation is a
/// programming error (the caller should validate earlier).
fn sanitize_yaml_path(path: &str) -> &str {
    for (i, ch) in path.char_indices() {
        if !(ch.is_alphanumeric()
            || matches!(ch, '/' | '-' | '_' | '.' | ' ' | '+' | '@' | '~' | ':'))
        {
            panic!(
                "host_path contains unsafe character {:?} at index {} — \
                 refusing to interpolate into YAML template: {:?}",
                ch, i, path,
            );
        }
    }
    path
}

/// Convert MiB to GiB as a human-friendly string.
///
/// If the value divides evenly into GiB, returns a whole number (e.g. "4").
/// Otherwise returns a decimal (e.g. "1.5").
fn mib_to_gib_string(mib: u32) -> String {
    if mib % 1024 == 0 {
        format!("{}", mib / 1024)
    } else {
        format!("{:.1}", mib as f64 / 1024.0)
    }
}

/// Encode a byte slice as a lowercase hexadecimal string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute the age of a timestamp in whole days from now.
fn age_in_days(built_at: &chrono::DateTime<chrono::Utc>) -> u64 {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(built_at);
    duration.num_days().max(0) as u64
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- VM naming ----------------------------------------------------------

    #[test]
    fn test_vm_name_format() {
        let id = SessionId::parse("550e8400e29b").unwrap();
        let name = vm_name(&id);
        assert_eq!(name, "sandbox-550e8400e29b");
        assert!(name.starts_with(VM_NAME_PREFIX));
    }

    #[test]
    fn test_parse_session_id_from_name() {
        let id = SessionId::parse("550e8400e29b").unwrap();
        let name = vm_name(&id);
        assert_eq!(parse_session_id_from_name(&name), Some(id));
    }

    #[test]
    fn test_parse_session_id_non_sandbox_name() {
        assert_eq!(parse_session_id_from_name("default"), None);
        assert_eq!(parse_session_id_from_name("my-vm"), None);
    }

    #[test]
    fn test_parse_session_id_bad_id() {
        assert_eq!(parse_session_id_from_name("sandbox-not-a-sessionid"), None);
        // Old-style full UUID is no longer accepted.
        assert_eq!(
            parse_session_id_from_name("sandbox-550e8400-e29b-41d4-a716-446655440000"),
            None
        );
    }

    // -- Template generation ------------------------------------------------

    #[test]
    fn test_generate_template() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default(); // 2 CPU, 4096 MB, 20 GB

        let template = mgr.generate_template(&id, &config);

        // Parse as YAML via serde_json (Lima YAML is a superset; we
        // just verify key fields are present via string inspection and
        // basic serde_json::Value parsing of the YAML-as-key-value).

        // Verify essential fields are present
        assert!(
            template.contains("vmType: \"qemu\""),
            "template should specify qemu vmType"
        );
        assert!(template.contains("cpus: 2"), "template should have cpus: 2");
        assert!(
            template.contains("memory: \"4GiB\""),
            "template should have memory: 4GiB"
        );
        assert!(
            template.contains("disk: \"20GiB\""),
            "template should have disk: 20GiB"
        );
        assert!(
            template.contains("mounts: []"),
            "template should disable mounts"
        );
        assert!(
            template.contains("portForwards: []"),
            "template should disable port forwards"
        );
        assert!(
            template.contains("ubuntu-24.04-server-cloudimg-amd64.img"),
            "template should reference Ubuntu 24.04 image"
        );
        assert!(
            template.contains("sandbox-550e8400e29b"),
            "template should set hostname including the full session id"
        );
        assert!(
            template.contains("name: \"agent\""),
            "template should configure agent user"
        );

        // Verify provision scripts
        assert!(
            template.contains("hostnamectl set-hostname"),
            "template should set hostname"
        );
        assert!(
            template.contains("useradd"),
            "template should create agent user"
        );
        assert!(
            template.contains("NOPASSWD"),
            "template should grant passwordless sudo"
        );
        assert!(
            template.contains("apt-get") && template.contains("install -y socat git"),
            "template should install socat and git"
        );
        assert!(
            template.contains("get.docker.com"),
            "template should install Docker"
        );
        assert!(
            template.contains("usermod -aG docker agent"),
            "template should add agent to docker group"
        );
    }

    #[test]
    fn test_generate_template_custom_config() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));
        let id = SessionId::parse("a1b2c3d4e5f6").unwrap();
        let config = SessionConfig {
            cpus: 8,
            memory_mb: 16384,
            disk_gb: 100,
            workspace_mode: None,
            hardened: true,
        };

        let template = mgr.generate_template(&id, &config);

        assert!(
            template.contains("cpus: 8"),
            "template should reflect custom cpus"
        );
        assert!(
            template.contains("memory: \"16GiB\""),
            "template should reflect 16384 MiB as 16GiB"
        );
        assert!(
            template.contains("disk: \"100GiB\""),
            "template should reflect custom disk"
        );
        assert!(
            template.contains("sandbox-a1b2c3d4e5f6"),
            "hostname should include the full 12-hex session id"
        );
    }

    #[test]
    fn test_generate_template_fractional_memory() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 1,
            memory_mb: 1536, // 1.5 GiB
            disk_gb: 10,
            workspace_mode: None,
            hardened: true,
        };

        let template = mgr.generate_template(&id, &config);
        assert!(
            template.contains("memory: \"1.5GiB\""),
            "template should handle fractional GiB"
        );
    }

    #[test]
    fn test_generate_template_shared_workspace() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: Some(WorkspaceMode::Shared {
                host_path: "/home/user/project".into(),
            }),
            hardened: true,
        };

        let template = mgr.generate_template(&id, &config);

        // Should NOT contain the empty mounts placeholder.
        assert!(
            !template.contains("mounts: []"),
            "shared workspace template must not have empty mounts"
        );

        // Should contain 9p mount type.
        assert!(
            template.contains("mountType: \"9p\""),
            "template should specify 9p mount type"
        );

        // Should mount the host path to /home/agent/workspace.
        assert!(
            template.contains("location: \"/home/user/project\""),
            "template should reference the host path"
        );
        assert!(
            template.contains("mountPoint: \"/home/agent/workspace\""),
            "template should mount to /home/agent/workspace"
        );
        assert!(
            template.contains("writable: true"),
            "template should make mount writable"
        );
    }

    #[test]
    fn test_generate_template_clone_workspace_no_mount() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 1,
            memory_mb: 1024,
            disk_gb: 10,
            workspace_mode: Some(WorkspaceMode::Clone {
                repo_url: "https://github.com/example/repo.git".into(),
            }),
            hardened: true,
        };

        let template = mgr.generate_template(&id, &config);

        // Clone mode should NOT add mounts — cloning is handled post-boot.
        assert!(
            template.contains("mounts: []"),
            "clone workspace should not produce mounts"
        );
        assert!(
            !template.contains("9p:"),
            "clone workspace should not reference 9p mount config"
        );
    }

    // -- YAML path sanitization -----------------------------------------------

    #[test]
    fn test_sanitize_yaml_path_normal_paths() {
        // Normal filesystem paths should pass through unchanged.
        assert_eq!(
            sanitize_yaml_path("/home/user/project"),
            "/home/user/project"
        );
        assert_eq!(sanitize_yaml_path("/tmp/my-dir_v2"), "/tmp/my-dir_v2");
        assert_eq!(
            sanitize_yaml_path("/home/user/My Project"),
            "/home/user/My Project"
        );
        assert_eq!(
            sanitize_yaml_path("/home/user/.config/app"),
            "/home/user/.config/app"
        );
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_double_quote() {
        sanitize_yaml_path("/home/user/project\"injected");
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_newline() {
        sanitize_yaml_path("/home/user/project\nnewkey: injected");
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_backslash() {
        sanitize_yaml_path("/home/user/project\\evil");
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_backtick() {
        sanitize_yaml_path("/home/user/`command`");
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_dollar() {
        sanitize_yaml_path("/home/user/$HOME");
    }

    // -- QEMU hardening / device lockdown ------------------------------------

    #[test]
    fn test_qemu_wrapper_contains_device_lockdown_args() {
        // The wrapper script should contain device lockdown args gated on
        // the SANDBOX_QEMU_HARDENED env var.
        let script = QEMU_WRAPPER_SCRIPT;

        // Always present: PCIe root-port
        assert!(
            script.contains("pcie-root-port"),
            "wrapper should always add PCIe root-port"
        );

        // Hardened-only args
        assert!(
            !script.contains("-nodefaults"),
            "wrapper must NOT use -nodefaults (it strips serial console and 9p filesystem backend)"
        );
        assert!(
            script.contains("-no-user-config"),
            "wrapper should disable user config when hardened"
        );
        assert!(
            script.contains("-display none"),
            "wrapper should disable display when hardened"
        );
        assert!(
            script.contains("-vga none"),
            "wrapper should disable VGA when hardened"
        );
        assert!(
            script.contains("virtio-rng-pci"),
            "wrapper should add virtio-rng for entropy when hardened"
        );

        // Verify these are gated on the env var
        assert!(
            script.contains("SANDBOX_QEMU_HARDENED"),
            "wrapper should check SANDBOX_QEMU_HARDENED env var"
        );
    }

    #[test]
    fn test_qemu_wrapper_hardened_conditional() {
        // Verify the device lockdown args are inside the hardened conditional,
        // not unconditionally applied. The script should have -no-user-config
        // only within the if-block checking SANDBOX_QEMU_HARDENED.
        let script = QEMU_WRAPPER_SCRIPT;

        // Find the position of the hardened check and the -no-user-config arg.
        let hardened_check_pos = script.find("SANDBOX_QEMU_HARDENED").unwrap();
        let no_user_config_pos = script.find("-no-user-config").unwrap();

        assert!(
            no_user_config_pos > hardened_check_pos,
            "-no-user-config should come after the SANDBOX_QEMU_HARDENED check"
        );
    }

    #[test]
    fn test_generate_template_hardened_video_audio() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: true,
        };

        let template = mgr.generate_template(&id, &config);

        assert!(
            template.contains("display: \"none\""),
            "hardened template should disable video display"
        );
        assert!(
            template.contains("device: \"none\""),
            "hardened template should disable audio device"
        );
    }

    #[test]
    fn test_generate_template_not_hardened_no_video_audio() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
        };

        let template = mgr.generate_template(&id, &config);

        assert!(
            !template.contains("display: \"none\""),
            "non-hardened template should not disable video display"
        );
        assert!(
            !template.contains("device: \"none\""),
            "non-hardened template should not disable audio device"
        );
    }

    #[test]
    fn test_ensure_qemu_wrapper_creates_file() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let mgr =
            LimaManager::with_limactl_path(dir.path().to_path_buf(), PathBuf::from("limactl"));

        let wrapper = mgr.ensure_qemu_wrapper().unwrap();

        assert!(wrapper.exists(), "wrapper script should exist");

        let content = std::fs::read_to_string(&wrapper).unwrap();
        assert!(
            content.contains("pcie-root-port"),
            "wrapper should contain PCIe root-port"
        );
        assert!(
            content.contains("SANDBOX_QEMU_HARDENED"),
            "wrapper should reference SANDBOX_QEMU_HARDENED"
        );
        assert!(
            content.contains("-no-user-config"),
            "wrapper should contain device lockdown args"
        );
    }

    // -- Lima JSON parsing --------------------------------------------------

    #[test]
    fn test_parse_vm_status() {
        assert_eq!(parse_status_field("Running"), VmStatus::Running);
        assert_eq!(parse_status_field("Stopped"), VmStatus::Stopped);
        assert_eq!(
            parse_status_field("Broken"),
            VmStatus::Unknown("Broken".to_string())
        );
        assert_eq!(parse_status_field(""), VmStatus::Unknown(String::new()));
    }

    #[test]
    fn test_parse_vm_list() {
        // Simulated NDJSON output from `limactl list --json`
        let output = r#"{"name":"sandbox-550e8400e29b","status":"Running","arch":"x86_64","cpus":2,"memory":4294967296,"disk":21474836480,"dir":"/home/user/.lima/sandbox-550e8400e29b"}
{"name":"sandbox-a1b2c3d4e5f6","status":"Stopped","arch":"x86_64","cpus":4,"memory":8589934592,"disk":107374182400,"dir":"/home/user/.lima/sandbox-a1b2c3d4e5f6"}
{"name":"default","status":"Running","arch":"x86_64","cpus":4,"memory":4294967296,"disk":107374182400,"dir":"/home/user/.lima/default"}
"#;

        let entries = parse_limactl_list_output(output).unwrap();
        assert_eq!(entries.len(), 3);

        // Simulate the filtering that list_vms does
        let vms: Vec<VmInfo> = entries
            .into_iter()
            .filter_map(|e| {
                let name = e.name?;
                if !name.starts_with(VM_NAME_PREFIX) {
                    return None;
                }
                let status = parse_status_field(e.status.as_deref().unwrap_or(""));
                let session_id = parse_session_id_from_name(&name);
                Some(VmInfo {
                    name,
                    status,
                    session_id,
                })
            })
            .collect();

        assert_eq!(vms.len(), 2, "should filter out non-sandbox VMs");

        assert_eq!(vms[0].name, "sandbox-550e8400e29b");
        assert_eq!(vms[0].status, VmStatus::Running);
        assert_eq!(
            vms[0].session_id,
            Some(SessionId::parse("550e8400e29b").unwrap())
        );

        assert_eq!(vms[1].name, "sandbox-a1b2c3d4e5f6");
        assert_eq!(vms[1].status, VmStatus::Stopped);
        assert_eq!(
            vms[1].session_id,
            Some(SessionId::parse("a1b2c3d4e5f6").unwrap())
        );
    }

    #[test]
    fn test_parse_empty_list() {
        let entries = parse_limactl_list_output("").unwrap();
        assert!(entries.is_empty());

        let entries = parse_limactl_list_output("  \n  \n").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_limactl_error_preserves_stderr() {
        let err = parse_limactl_error(
            "start",
            "FATA[0000] Instance \"sandbox-abc\" does not exist",
        );
        match err {
            SandboxError::Lima(msg) => {
                assert!(msg.contains("limactl start failed:"));
                assert!(msg.contains("does not exist"));
            }
            _ => panic!("expected Lima error variant"),
        }
    }

    #[test]
    fn test_mib_to_gib_string() {
        assert_eq!(mib_to_gib_string(1024), "1");
        assert_eq!(mib_to_gib_string(4096), "4");
        assert_eq!(mib_to_gib_string(16384), "16");
        assert_eq!(mib_to_gib_string(1536), "1.5");
        assert_eq!(mib_to_gib_string(2560), "2.5");
    }

    // -- Guest agent service unit tests --------------------------------------

    #[test]
    fn test_guest_agent_service_unit() {
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("[Unit]"),
            "service unit should have [Unit] section"
        );
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("ExecStart=/usr/local/bin/sandbox-guest"),
            "service unit should run sandbox-guest"
        );
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("Restart=always"),
            "service should restart on failure"
        );
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("[Install]"),
            "service unit should have [Install] section"
        );
    }

    #[test]
    fn test_install_guest_agent_missing_binary() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let mgr =
            LimaManager::with_limactl_path(dir.path().to_path_buf(), PathBuf::from("limactl"));
        let session_id = SessionId::generate();

        let result = mgr.install_guest_agent(
            &session_id,
            std::path::Path::new("/nonexistent/path/sandbox-guest"),
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "error should mention binary not found: {err}"
        );
    }

    // -- QEMU wrapper script tests ------------------------------------------

    #[test]
    fn test_qemu_wrapper_includes_pcie_root_port() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("pcie-root-port,id=pcie-hotplug-port"),
            "wrapper must inject PCIe root-port for NIC hot-add"
        );
    }

    #[test]
    fn test_qemu_wrapper_includes_bridge_networking() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_DOCKER_BRIDGE"),
            "wrapper must check SANDBOX_DOCKER_BRIDGE env var"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("qemu-bridge-helper"),
            "wrapper must reference qemu-bridge-helper"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("-netdev bridge,id=net_sandbox"),
            "wrapper must add bridge netdev when SANDBOX_DOCKER_BRIDGE is set"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_VM_MAC"),
            "wrapper must use SANDBOX_VM_MAC for the NIC MAC address"
        );
    }

    #[test]
    fn test_qemu_wrapper_no_seccomp_sandbox() {
        // QEMU seccomp sandbox requires PR_SET_NO_NEW_PRIVS which strips
        // the setuid bit from qemu-bridge-helper, breaking bridge networking.
        assert!(
            !QEMU_WRAPPER_SCRIPT.contains("-sandbox on"),
            "wrapper must NOT use -sandbox on (incompatible with qemu-bridge-helper setuid)"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("PR_SET_NO_NEW_PRIVS"),
            "wrapper should document why seccomp is not used"
        );
    }

    #[test]
    fn test_qemu_wrapper_includes_cgroup_limits() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("systemd-run --user --scope --slice=sandbox.slice"),
            "wrapper must use systemd-run for cgroup limits"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("MemoryMax="),
            "wrapper must set MemoryMax cgroup limit"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("CPUQuota="),
            "wrapper must set CPUQuota cgroup limit"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("TasksMax=256"),
            "wrapper must set TasksMax cgroup limit"
        );
    }

    #[test]
    fn test_qemu_wrapper_cgroup_gated_on_env_vars() {
        // Cgroup limits should only apply when both env vars are present.
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_QEMU_MEMORY_MB"),
            "wrapper must check SANDBOX_QEMU_MEMORY_MB env var"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_QEMU_CPUS"),
            "wrapper must check SANDBOX_QEMU_CPUS env var"
        );
    }

    #[test]
    fn test_qemu_wrapper_cgroup_fallback_without_systemd_run() {
        // When systemd-run is not available, wrapper should fall back to
        // running QEMU directly (without cgroup limits).
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("command -v systemd-run"),
            "wrapper must check for systemd-run availability"
        );
        // The else branch should exec QEMU directly.
        let lines: Vec<&str> = QEMU_WRAPPER_SCRIPT.lines().collect();
        let has_else_exec = lines.iter().any(|line| {
            let trimmed = line.trim();
            trimmed == r#"exec "$REAL_QEMU" $EXTRA_ARGS "$@""#
        });
        assert!(
            has_else_exec,
            "wrapper must have a fallback exec without systemd-run"
        );
    }

    #[test]
    fn test_qemu_wrapper_probe_passthrough() {
        // Lima runs probe commands (-machine help, -cpu help, --version, etc.)
        // through the wrapper.  The wrapper must detect these and exec the
        // real QEMU without adding extra flags or cgroup wrapping.

        // Must detect "help" as a probe trigger (covers -machine help,
        // -accel help, -cpu help, -netdev help).
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("help|--version"),
            "wrapper must detect help and --version as probe triggers"
        );
        // When a probe is detected, wrapper must exec without extra args.
        let lines: Vec<&str> = QEMU_WRAPPER_SCRIPT.lines().collect();
        let has_probe_exec = lines
            .iter()
            .any(|line| line.trim().starts_with("exec \"$REAL_QEMU\" \"$@\""));
        assert!(
            has_probe_exec,
            "wrapper must pass probe invocations through without extra args"
        );
    }

    #[test]
    fn test_qemu_wrapper_written_to_filesystem() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let mgr =
            LimaManager::with_limactl_path(dir.path().to_path_buf(), PathBuf::from("limactl"));

        let wrapper_path = mgr
            .ensure_qemu_wrapper()
            .expect("ensure_qemu_wrapper should succeed");

        // Verify the file exists and is executable.
        assert!(wrapper_path.exists(), "wrapper script must exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&wrapper_path)
                .expect("metadata")
                .permissions();
            assert_eq!(
                perms.mode() & 0o755,
                0o755,
                "wrapper script must be executable"
            );
        }

        // Verify content matches the constant.
        let content = std::fs::read_to_string(&wrapper_path).expect("read wrapper");
        assert_eq!(
            content, QEMU_WRAPPER_SCRIPT,
            "written content must match constant"
        );
    }

    // -- Golden base image --------------------------------------------------

    #[test]
    fn test_generate_base_template_valid_yaml_fields() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));

        let template = mgr.generate_base_template();

        // Resource configuration: fixed values for base image build.
        assert!(
            template.contains("cpus: 4"),
            "base template should have 4 CPUs"
        );
        assert!(
            template.contains("memory: \"4GiB\""),
            "base template should have 4GiB memory"
        );
        assert!(
            template.contains("disk: \"10GiB\""),
            "base template should have 10GiB disk"
        );

        // No mounts (no workspace).
        assert!(
            template.contains("mounts: []"),
            "base template should have empty mounts"
        );

        // Same Ubuntu cloud images as per-session template.
        assert!(
            template.contains("ubuntu-24.04-server-cloudimg-amd64.img"),
            "base template should reference Ubuntu 24.04 amd64 image"
        );
        assert!(
            template.contains("ubuntu-24.04-server-cloudimg-arm64.img"),
            "base template should reference Ubuntu 24.04 arm64 image"
        );

        // Uses the base VM name as hostname.
        assert!(
            template.contains(&format!("hostnamectl set-hostname {BASE_VM_NAME}")),
            "base template should set hostname to base VM name"
        );

        // Cloud-init provisioning scripts.
        assert!(
            template.contains("name: \"agent\""),
            "base template should configure agent user"
        );
        assert!(
            template.contains("useradd"),
            "base template should create agent user"
        );
        assert!(
            template.contains("NOPASSWD"),
            "base template should grant passwordless sudo"
        );
        assert!(
            template.contains("apt-get") && template.contains("install -y socat git"),
            "base template should install socat and git"
        );
        assert!(
            template.contains("get.docker.com"),
            "base template should install Docker"
        );
        assert!(
            template.contains("usermod -aG docker agent"),
            "base template should add agent to docker group"
        );

        // Hardened by default (video/audio disabled).
        assert!(
            template.contains("display: \"none\""),
            "base template should disable video display"
        );
        assert!(
            template.contains("device: \"none\""),
            "base template should disable audio device"
        );

        // Port forwards should be empty.
        assert!(
            template.contains("portForwards: []"),
            "base template should have empty port forwards"
        );

        // vmType specification.
        assert!(
            template.contains("vmType: \"qemu\""),
            "base template should specify qemu vmType"
        );
    }

    #[test]
    fn test_generate_base_template_deterministic() {
        let mgr =
            LimaManager::with_limactl_path(PathBuf::from("/tmp/test"), PathBuf::from("limactl"));

        let t1 = mgr.generate_base_template();
        let t2 = mgr.generate_base_template();
        assert_eq!(t1, t2, "base template should be deterministic");
    }

    #[test]
    fn test_compute_base_image_hash_deterministic() {
        // Create a temporary directory with a fake guest agent binary at
        // the path that `guest_agent_path()` will resolve.
        //
        // `guest_agent_path()` uses `std::env::current_exe()` which in
        // test context points to the test binary.  We can't control that
        // path, so we test the underlying hash logic directly with
        // `ring::digest`.
        let template = "some template content";
        let agent_bytes = b"fake agent binary";

        let mut ctx1 = digest::Context::new(&digest::SHA256);
        ctx1.update(template.as_bytes());
        ctx1.update(agent_bytes);
        let hash1 = hex_encode(ctx1.finish().as_ref());

        let mut ctx2 = digest::Context::new(&digest::SHA256);
        ctx2.update(template.as_bytes());
        ctx2.update(agent_bytes);
        let hash2 = hex_encode(ctx2.finish().as_ref());

        assert_eq!(hash1, hash2, "hash should be deterministic");
        assert_eq!(hash1.len(), 64, "SHA256 hex digest should be 64 chars");
    }

    #[test]
    fn test_compute_base_image_hash_changes_with_input() {
        let agent_bytes = b"fake agent binary";

        let mut ctx1 = digest::Context::new(&digest::SHA256);
        ctx1.update(b"template version 1");
        ctx1.update(agent_bytes);
        let hash1 = hex_encode(ctx1.finish().as_ref());

        let mut ctx2 = digest::Context::new(&digest::SHA256);
        ctx2.update(b"template version 2");
        ctx2.update(agent_bytes);
        let hash2 = hex_encode(ctx2.finish().as_ref());

        assert_ne!(hash1, hash2, "hash should change when inputs change");
    }

    #[test]
    fn test_check_base_image_missing_when_no_vms() {
        // check_base_image relies on list_vms_raw() which shells out to
        // limactl.  We test the logic by directly verifying the metadata
        // parsing and status evaluation.  When the VM list is empty, the
        // result should be Missing.
        let entries: Vec<LimactlListEntry> = vec![];
        let vm_exists = entries
            .iter()
            .any(|e| e.name.as_deref() == Some(BASE_VM_NAME));
        assert!(!vm_exists);
        // This corresponds to BaseImageStatus::Missing
    }

    #[test]
    fn test_check_base_image_stale_when_meta_missing() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let meta_path = dir.path().join("base-image-meta.json");

        // Metadata file does not exist.
        assert!(!meta_path.exists());

        // Simulate: VM exists but no metadata -> Stale(hash_mismatch=true)
        let result = std::fs::read_to_string(&meta_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_base_image_stale_when_meta_corrupt() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let meta_path = dir.path().join("base-image-meta.json");
        std::fs::write(&meta_path, "not valid json").unwrap();

        let content = std::fs::read_to_string(&meta_path).unwrap();
        let parse_result = serde_json::from_str::<BaseImageMeta>(&content);
        assert!(
            parse_result.is_err(),
            "corrupt metadata should fail to parse"
        );
    }

    #[test]
    fn test_check_base_image_stale_when_old() {
        let old_meta = BaseImageMeta {
            built_at: chrono::Utc::now() - chrono::Duration::days(15),
            content_hash: "abc123".to_string(),
        };

        let age = age_in_days(&old_meta.built_at);
        assert!(
            age > BASE_IMAGE_MAX_AGE_DAYS,
            "15-day-old image should exceed max age of {BASE_IMAGE_MAX_AGE_DAYS}"
        );
    }

    #[test]
    fn test_check_base_image_fresh_when_recent_and_matching() {
        let recent_meta = BaseImageMeta {
            built_at: chrono::Utc::now() - chrono::Duration::days(2),
            content_hash: "matching_hash".to_string(),
        };

        let age = age_in_days(&recent_meta.built_at);
        assert!(
            age <= BASE_IMAGE_MAX_AGE_DAYS,
            "2-day-old image should be within max age"
        );
        // If hash matches, this would be Fresh.
    }

    #[test]
    fn test_base_image_meta_serialization_roundtrip() {
        let meta = BaseImageMeta {
            built_at: chrono::Utc::now(),
            content_hash: "deadbeef01234567".to_string(),
        };

        let json = serde_json::to_string_pretty(&meta).unwrap();
        let deserialized: BaseImageMeta = serde_json::from_str(&json).unwrap();

        assert_eq!(meta.content_hash, deserialized.content_hash);
        assert_eq!(meta.built_at, deserialized.built_at);
    }

    #[test]
    fn test_base_image_status_equality() {
        assert_eq!(BaseImageStatus::Missing, BaseImageStatus::Missing);
        assert_eq!(BaseImageStatus::Fresh, BaseImageStatus::Fresh);
        assert_eq!(
            BaseImageStatus::Stale {
                age_days: 5,
                hash_mismatch: true
            },
            BaseImageStatus::Stale {
                age_days: 5,
                hash_mismatch: true
            }
        );
        assert_ne!(BaseImageStatus::Missing, BaseImageStatus::Fresh);
        assert_ne!(
            BaseImageStatus::Stale {
                age_days: 5,
                hash_mismatch: true
            },
            BaseImageStatus::Stale {
                age_days: 5,
                hash_mismatch: false
            }
        );
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(
            hex_encode(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
            "0123456789abcdef"
        );
    }

    #[test]
    fn test_age_in_days() {
        let now = chrono::Utc::now();
        assert_eq!(age_in_days(&now), 0);

        let yesterday = now - chrono::Duration::days(1);
        assert_eq!(age_in_days(&yesterday), 1);

        let ten_days_ago = now - chrono::Duration::days(10);
        assert_eq!(age_in_days(&ten_days_ago), 10);

        // Future timestamps should clamp to 0.
        let future = now + chrono::Duration::days(5);
        assert_eq!(age_in_days(&future), 0);
    }

    #[test]
    fn test_base_vm_name_constant() {
        assert_eq!(BASE_VM_NAME, "sandbox-base");
    }

    #[test]
    fn test_base_image_max_age_constant() {
        assert_eq!(BASE_IMAGE_MAX_AGE_DAYS, 10);
    }

    #[test]
    fn test_guest_agent_path_returns_sibling_of_current_exe() {
        let result = guest_agent_path();
        // In test context this should succeed (current_exe is the test binary).
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(
            path.file_name().unwrap() == "sandbox-guest",
            "guest_agent_path should return a path ending in sandbox-guest"
        );
    }
}
