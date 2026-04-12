use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use tracing::{debug, info};
use uuid::Uuid;

use crate::error::SandboxError;
use crate::session::SessionConfig;

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
    /// Session ID parsed from the `sandbox-{uuid}` naming convention.
    pub session_id: Option<Uuid>,
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
ExecStart=/usr/local/bin/sandbox-guest
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target";

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
    /// `base_dir` is typically `~/.sandboxd/` — the same directory used by
    /// [`crate::SessionStore`].
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            limactl: PathBuf::from("/usr/local/bin/limactl"),
        }
    }

    /// Override the path to `limactl` (useful for testing).
    #[cfg(test)]
    pub fn with_limactl(mut self, path: PathBuf) -> Self {
        self.limactl = path;
        self
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
        session_id: &Uuid,
        config: &SessionConfig,
    ) -> Result<(), SandboxError> {
        let template = self.generate_template(session_id, config);
        let session_dir = self.session_dir(session_id);
        std::fs::create_dir_all(&session_dir)?;

        let template_path = session_dir.join("template.yaml");
        std::fs::write(&template_path, &template)?;

        let vm_name = vm_name(session_id);
        let output = Command::new(&self.limactl)
            .args(["create", "--name", &vm_name])
            .arg(&template_path)
            .arg("--tty=false")
            .output()
            .map_err(|e| lima_io_error("limactl create", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("create", &stderr));
        }

        Ok(())
    }

    /// Create a new VM using a custom Lima template file.
    ///
    /// The template is copied to the session directory before invoking
    /// `limactl create`.
    pub fn create_vm_with_custom_template(
        &self,
        session_id: &Uuid,
        template_path: &std::path::Path,
    ) -> Result<(), SandboxError> {
        let session_dir = self.session_dir(session_id);
        std::fs::create_dir_all(&session_dir)?;

        let dest = session_dir.join("template.yaml");
        std::fs::copy(template_path, &dest)?;

        let vm_name = vm_name(session_id);
        let output = Command::new(&self.limactl)
            .args(["create", "--name", &vm_name])
            .arg(&dest)
            .arg("--tty=false")
            .output()
            .map_err(|e| lima_io_error("limactl create", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("create", &stderr));
        }

        Ok(())
    }

    /// Start an existing (stopped) VM.
    pub fn start_vm(&self, session_id: &Uuid) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);
        let output = Command::new(&self.limactl)
            .args(["start", &vm_name])
            .arg("--tty=false")
            .output()
            .map_err(|e| lima_io_error("limactl start", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("start", &stderr));
        }

        Ok(())
    }

    /// Stop a running VM.
    pub fn stop_vm(&self, session_id: &Uuid) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);
        let output = Command::new(&self.limactl)
            .args(["stop", &vm_name])
            .arg("--tty=false")
            .output()
            .map_err(|e| lima_io_error("limactl stop", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("stop", &stderr));
        }

        Ok(())
    }

    /// Force-delete a VM and its Lima data.
    pub fn delete_vm(&self, session_id: &Uuid) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);
        let output = Command::new(&self.limactl)
            .args(["delete", "--force", &vm_name])
            .arg("--tty=false")
            .output()
            .map_err(|e| lima_io_error("limactl delete", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("delete", &stderr));
        }

        Ok(())
    }

    /// Copy the sandbox-guest binary into a running VM and start it as a
    /// systemd service.
    ///
    /// This should be called after the VM has booted (i.e. after `start_vm`
    /// or `create_vm` + start).
    pub fn install_guest_agent(
        &self,
        session_id: &Uuid,
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
        let output = Command::new(&self.limactl)
            .args(["copy", &copy_src, &copy_dst])
            .output()
            .map_err(|e| lima_io_error("limactl copy (guest agent)", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to copy guest agent to {vm_name}: {stderr}"
            )));
        }

        // 2. Move the binary to /usr/local/bin with sudo and make it executable.
        debug!(vm = %vm_name, "installing guest agent binary");
        let output = Command::new(&self.limactl)
            .args([
                "shell", &vm_name, "--",
                "sudo", "mv", "/tmp/sandbox-guest", "/usr/local/bin/sandbox-guest",
            ])
            .output()
            .map_err(|e| lima_io_error("limactl shell mv", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to move guest agent in {vm_name}: {stderr}"
            )));
        }

        let output = Command::new(&self.limactl)
            .args([
                "shell", &vm_name, "--",
                "sudo", "chmod", "+x", "/usr/local/bin/sandbox-guest",
            ])
            .output()
            .map_err(|e| lima_io_error("limactl shell chmod", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to chmod guest agent in {vm_name}: {stderr}"
            )));
        }

        // 3. Create a systemd service file.
        debug!(vm = %vm_name, "creating systemd service");
        let service_unit = GUEST_AGENT_SERVICE_UNIT;
        let output = Command::new(&self.limactl)
            .args([
                "shell", &vm_name, "--",
                "sudo", "bash", "-c",
                &format!(
                    "cat > /etc/systemd/system/sandbox-guest.service << 'UNIT_EOF'\n{service_unit}\nUNIT_EOF"
                ),
            ])
            .output()
            .map_err(|e| lima_io_error("limactl shell (create service)", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to create systemd service in {vm_name}: {stderr}"
            )));
        }

        // 4. Reload systemd and start the service.
        debug!(vm = %vm_name, "starting guest agent service");
        let output = Command::new(&self.limactl)
            .args([
                "shell", &vm_name, "--",
                "sudo", "systemctl", "daemon-reload",
            ])
            .output()
            .map_err(|e| lima_io_error("limactl shell (daemon-reload)", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "failed to reload systemd in {vm_name}: {stderr}"
            )));
        }

        let output = Command::new(&self.limactl)
            .args([
                "shell", &vm_name, "--",
                "sudo", "systemctl", "enable", "--now", "sandbox-guest",
            ])
            .output()
            .map_err(|e| lima_io_error("limactl shell (enable service)", e))?;

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
    pub fn vm_status(&self, session_id: &Uuid) -> Result<VmStatus, SandboxError> {
        let vms = self.list_vms_raw()?;
        let vm_name = vm_name(session_id);
        for entry in &vms {
            if entry.name.as_deref() == Some(vm_name.as_str()) {
                return Ok(parse_status_field(
                    entry.status.as_deref().unwrap_or(""),
                ));
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
                let status =
                    parse_status_field(e.status.as_deref().unwrap_or(""));
                let session_id = parse_session_id_from_name(&name);
                Some(VmInfo {
                    name,
                    status,
                    session_id,
                })
            })
            .collect())
    }

    // -- template generation ------------------------------------------------

    /// Generate the Lima YAML template for a session.
    pub fn generate_template(
        &self,
        session_id: &Uuid,
        config: &SessionConfig,
    ) -> String {
        let short_id = &session_id.to_string()[..8];
        let hostname = format!("sandbox-{short_id}");

        // Lima expects memory as a string like "4GiB" and disk as "20GiB".
        let memory_gib = format!("{}GiB", mib_to_gib_string(config.memory_mb));
        let disk_gib = format!("{}GiB", config.disk_gb);

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

mounts: []
portForwards: []

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
    hostnamectl set-hostname {hostname}
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    # Create agent user with passwordless sudo (if not already present)
    if ! id agent &>/dev/null; then
      useradd -m -s /bin/bash agent
    fi
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent
    chmod 0440 /etc/sudoers.d/agent
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    # Install socat (needed for host-guest communication bridge)
    if ! command -v socat &>/dev/null; then
      apt-get update -qq
      apt-get install -y socat
    fi
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    # Install Docker via official convenience script
    if ! command -v docker &>/dev/null; then
      curl -fsSL https://get.docker.com | sh
      usermod -aG docker agent
    fi
"#,
            session_id = session_id,
            cpus = config.cpus,
            memory_gib = memory_gib,
            disk_gib = disk_gib,
            hostname = hostname,
        )
    }

    // -- helpers ------------------------------------------------------------

    fn session_dir(&self, session_id: &Uuid) -> PathBuf {
        self.base_dir
            .join("sessions")
            .join(session_id.to_string())
    }

    /// Run `limactl list --json` and deserialize the raw entries.
    fn list_vms_raw(&self) -> Result<Vec<LimactlListEntry>, SandboxError> {
        let output = Command::new(&self.limactl)
            .args(["list", "--json"])
            .output()
            .map_err(|e| lima_io_error("limactl list", e))?;

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

/// Prefix applied to all sandbox VM names.
pub const VM_NAME_PREFIX: &str = "sandbox-";

/// Canonical VM name for a session.
pub fn vm_name(session_id: &Uuid) -> String {
    format!("{VM_NAME_PREFIX}{session_id}")
}

/// Try to extract a session UUID from a VM name of the form `sandbox-{uuid}`.
pub fn parse_session_id_from_name(name: &str) -> Option<Uuid> {
    name.strip_prefix(VM_NAME_PREFIX)
        .and_then(|s| Uuid::parse_str(s).ok())
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
fn parse_limactl_list_output(
    output: &str,
) -> Result<Vec<LimactlListEntry>, SandboxError> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: LimactlListEntry =
            serde_json::from_str(trimmed).map_err(|e| {
                SandboxError::Lima(format!(
                    "failed to parse limactl JSON: {e}"
                ))
            })?;
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
        SandboxError::Lima(format!(
            "{context}: limactl not found (is Lima installed?)"
        ))
    } else {
        SandboxError::Lima(format!("{context}: {err}"))
    }
}

/// Attempt to produce a more specific error from limactl stderr.
fn parse_limactl_error(subcommand: &str, stderr: &str) -> SandboxError {
    let stderr = stderr.trim();

    if stderr.contains("already exists") {
        SandboxError::Lima(format!(
            "limactl {subcommand}: VM already exists"
        ))
    } else if stderr.contains("does not exist")
        || stderr.contains("not found")
    {
        SandboxError::Lima(format!(
            "limactl {subcommand}: VM not found"
        ))
    } else if stderr.contains("KVM") || stderr.contains("kvm") {
        SandboxError::Lima(format!(
            "limactl {subcommand}: KVM not available — is /dev/kvm accessible?"
        ))
    } else {
        SandboxError::Lima(format!(
            "limactl {subcommand} failed: {stderr}"
        ))
    }
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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- VM naming ----------------------------------------------------------

    #[test]
    fn test_vm_name_format() {
        let id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let name = vm_name(&id);
        assert_eq!(name, "sandbox-550e8400-e29b-41d4-a716-446655440000");
        assert!(name.starts_with(VM_NAME_PREFIX));
    }

    #[test]
    fn test_parse_session_id_from_name() {
        let id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let name = vm_name(&id);
        assert_eq!(parse_session_id_from_name(&name), Some(id));
    }

    #[test]
    fn test_parse_session_id_non_sandbox_name() {
        assert_eq!(parse_session_id_from_name("default"), None);
        assert_eq!(parse_session_id_from_name("my-vm"), None);
    }

    #[test]
    fn test_parse_session_id_bad_uuid() {
        assert_eq!(
            parse_session_id_from_name("sandbox-not-a-uuid"),
            None
        );
    }

    // -- Template generation ------------------------------------------------

    #[test]
    fn test_generate_template() {
        let mgr = LimaManager::new(PathBuf::from("/tmp/test"));
        let id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
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
        assert!(
            template.contains("cpus: 2"),
            "template should have cpus: 2"
        );
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
            template.contains("sandbox-550e8400"),
            "template should set hostname with short ID"
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
            template.contains("apt-get install -y socat"),
            "template should install socat for host-guest communication"
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
        let mgr = LimaManager::new(PathBuf::from("/tmp/test"));
        let id =
            Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap();
        let config = SessionConfig {
            cpus: 8,
            memory_mb: 16384,
            disk_gb: 100,
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
            template.contains("sandbox-a1b2c3d4"),
            "hostname should use first 8 chars of custom session ID"
        );
    }

    #[test]
    fn test_generate_template_fractional_memory() {
        let mgr = LimaManager::new(PathBuf::from("/tmp/test"));
        let id = Uuid::new_v4();
        let config = SessionConfig {
            cpus: 1,
            memory_mb: 1536, // 1.5 GiB
            disk_gb: 10,
        };

        let template = mgr.generate_template(&id, &config);
        assert!(
            template.contains("memory: \"1.5GiB\""),
            "template should handle fractional GiB"
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
        assert_eq!(
            parse_status_field(""),
            VmStatus::Unknown(String::new())
        );
    }

    #[test]
    fn test_parse_vm_list() {
        // Simulated NDJSON output from `limactl list --json`
        let output = r#"{"name":"sandbox-550e8400-e29b-41d4-a716-446655440000","status":"Running","arch":"x86_64","cpus":2,"memory":4294967296,"disk":21474836480,"dir":"/home/user/.lima/sandbox-550e8400-e29b-41d4-a716-446655440000"}
{"name":"sandbox-a1b2c3d4-e5f6-7890-abcd-ef1234567890","status":"Stopped","arch":"x86_64","cpus":4,"memory":8589934592,"disk":107374182400,"dir":"/home/user/.lima/sandbox-a1b2c3d4-e5f6-7890-abcd-ef1234567890"}
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
                let status =
                    parse_status_field(e.status.as_deref().unwrap_or(""));
                let session_id = parse_session_id_from_name(&name);
                Some(VmInfo {
                    name,
                    status,
                    session_id,
                })
            })
            .collect();

        assert_eq!(vms.len(), 2, "should filter out non-sandbox VMs");

        assert_eq!(
            vms[0].name,
            "sandbox-550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(vms[0].status, VmStatus::Running);
        assert_eq!(
            vms[0].session_id,
            Some(
                Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
                    .unwrap()
            )
        );

        assert_eq!(
            vms[1].name,
            "sandbox-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        );
        assert_eq!(vms[1].status, VmStatus::Stopped);
        assert_eq!(
            vms[1].session_id,
            Some(
                Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
                    .unwrap()
            )
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
    fn test_parse_limactl_error_already_exists() {
        let err = parse_limactl_error(
            "create",
            "FATA[0000] Instance \"sandbox-abc\" already exists",
        );
        match err {
            SandboxError::Lima(msg) => {
                assert!(msg.contains("already exists"));
            }
            _ => panic!("expected Lima error variant"),
        }
    }

    #[test]
    fn test_parse_limactl_error_not_found() {
        let err = parse_limactl_error(
            "start",
            "FATA[0000] Instance \"sandbox-abc\" does not exist",
        );
        match err {
            SandboxError::Lima(msg) => {
                assert!(msg.contains("not found"));
            }
            _ => panic!("expected Lima error variant"),
        }
    }

    #[test]
    fn test_parse_limactl_error_kvm() {
        let err = parse_limactl_error(
            "create",
            "FATA[0000] Failed to initialize KVM: Permission denied",
        );
        match err {
            SandboxError::Lima(msg) => {
                assert!(msg.contains("KVM not available"));
            }
            _ => panic!("expected Lima error variant"),
        }
    }

    #[test]
    fn test_parse_limactl_error_generic() {
        let err = parse_limactl_error(
            "stop",
            "FATA[0000] Something completely unexpected happened",
        );
        match err {
            SandboxError::Lima(msg) => {
                assert!(msg.contains("Something completely unexpected"));
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
        let mgr = LimaManager::new(dir.path().to_path_buf());
        let session_id = Uuid::new_v4();

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

    // -- Integration tests (ignored by default) -----------------------------

    #[test]
    #[ignore]
    fn test_lima_create_and_delete() {
        // This test actually creates and deletes a Lima VM.
        // Run with: cargo test --package sandbox-core test_lima_create_and_delete -- --ignored
        //
        // Requirements:
        //   - limactl available at /usr/local/bin/limactl
        //   - KVM available (run `newgrp kvm` if needed)
        //   - Network access to download Ubuntu cloud image (first run only)
        //
        // WARNING: This is slow (minutes) — the VM must download the cloud
        // image and boot.

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let mgr = LimaManager::new(dir.path().to_path_buf());

        let session_id = Uuid::new_v4();
        let config = SessionConfig {
            cpus: 1,
            memory_mb: 1024,
            disk_gb: 10,
        };

        // Create the VM
        mgr.create_vm(&session_id, &config)
            .expect("create_vm should succeed");

        // Verify it appears in the list
        let vms = mgr.list_vms().expect("list_vms should succeed");
        let our_vm = vms
            .iter()
            .find(|v| v.session_id == Some(session_id))
            .expect("our VM should appear in list");
        assert_eq!(our_vm.name, vm_name(&session_id));

        // Clean up — force delete
        mgr.delete_vm(&session_id)
            .expect("delete_vm should succeed");

        // Verify it's gone
        let vms = mgr.list_vms().expect("list_vms after delete");
        assert!(
            !vms.iter().any(|v| v.session_id == Some(session_id)),
            "VM should no longer appear after deletion"
        );
    }
}
