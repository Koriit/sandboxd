//! Integration tests for Lima VM lifecycle.
//!
//! Requirements:
//!   - `limactl` available on PATH
//!   - KVM available (run `newgrp kvm` if needed)
//!   - Network access to download Ubuntu cloud image (first run only)
//!
//! WARNING: This is slow (minutes) -- the VM must download the cloud image
//! and boot.

use sandbox_core::lima::{vm_name, LimaManager};
use sandbox_core::session::{SessionConfig, SessionId};

#[test]
fn test_lima_create_and_delete() {
    let dir = tempfile::TempDir::new().expect("create temp dir");
    let mgr = LimaManager::new(dir.path().to_path_buf())
        .expect("limactl must be on PATH for integration test");

    let session_id = SessionId::generate();
    let config = SessionConfig {
        cpus: 1,
        memory_mb: 1024,
        disk_gb: 10,
        workspace_mode: None,
        hardened: true,
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

    // Clean up -- force delete
    mgr.delete_vm(&session_id)
        .expect("delete_vm should succeed");

    // Verify it's gone
    let vms = mgr.list_vms().expect("list_vms after delete");
    assert!(
        !vms.iter().any(|v| v.session_id == Some(session_id)),
        "VM should no longer appear after deletion"
    );
}
