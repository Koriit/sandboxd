//! Per-session CA certificate lifecycle management.
//!
//! Each sandbox session gets its own CA keypair for HTTPS interception via
//! mitmproxy. The CA certificate is:
//!
//! - Generated at session creation time
//! - Mounted into the gateway container (for mitmproxy)
//! - Injected into the VM's trust store (so intercepted traffic is trusted)
//! - Cleaned up when the session is deleted
//!
//! The CA uses ECDSA P-256 for fast key generation and small certificate size.

use std::fs;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose,
};
use ring::digest;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::SandboxError;

// ---------------------------------------------------------------------------
// CaManager
// ---------------------------------------------------------------------------

/// Manages per-session CA certificates for HTTPS interception.
///
/// This is a stateless helper — all state lives on disk in the session's
/// `ca/` directory. Each method is idempotent where possible.
pub struct CaManager;

impl CaManager {
    /// Generate a per-session CA keypair and write to the session's `ca/`
    /// directory.
    ///
    /// Returns the path to the CA directory.
    ///
    /// Files written:
    /// - `cert.pem` — CA certificate (public only)
    /// - `key.pem` — CA private key (PKCS#8 PEM)
    /// - `mitmproxy-ca.pem` — key + cert concatenated (mitmproxy format)
    /// - `mitmproxy-ca-cert.pem` — cert only (mitmproxy alias)
    pub fn generate_session_ca(
        base_dir: &Path,
        session_id: &Uuid,
    ) -> Result<PathBuf, SandboxError> {
        let ca_dir = Self::ca_dir(base_dir, session_id);
        let short_id = &session_id.to_string()[..8];

        info!(
            session_id = %session_id,
            ca_dir = %ca_dir.display(),
            "generating per-session CA certificate"
        );

        // Create the directory (and parents).
        fs::create_dir_all(&ca_dir).map_err(|e| {
            SandboxError::Ca(format!(
                "failed to create CA directory {}: {e}",
                ca_dir.display()
            ))
        })?;

        // Generate ECDSA P-256 key pair.
        let key_pair =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| {
                SandboxError::Ca(format!("failed to generate CA key pair: {e}"))
            })?;

        // Compute Subject Key Identifier as SHA-1 of the raw public key
        // (RFC 5280 section 4.2.1.2, method 1).  This matches how Python's
        // cryptography library (used by mitmproxy) computes the Authority
        // Key Identifier when signing intercepted certificates.  Without
        // this, rcgen's default (SHA-256 truncated, RFC 7093) produces a
        // different SKI and the cert chain verification fails.
        let raw_pubkey = key_pair.public_key_raw();
        let ski_sha1 = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, raw_pubkey);
        let ski_bytes = ski_sha1.as_ref()[..20].to_vec();

        // Build self-signed CA certificate.
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("Sandbox CA {short_id}"));
        params
            .distinguished_name
            .push(DnType::OrganizationName, "claude-sandbox");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        // No extended_key_usages for a CA cert — EKU on a CA restricts
        // what it can sign for, and even `anyExtendedKeyUsage` causes
        // OpenSSL to reject the cert as "unsuitable certificate purpose"
        // when verifying TLS server certs signed by it.
        params.key_identifier_method =
            KeyIdMethod::PreSpecified(ski_bytes);
        // 1-year validity — generous to avoid clock-skew issues in
        // short-lived sessions.
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after =
            params.not_before + time::Duration::days(365);

        let cert = params.self_signed(&key_pair).map_err(|e| {
            SandboxError::Ca(format!(
                "failed to self-sign CA certificate: {e}"
            ))
        })?;

        // Serialize.
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Write files.
        let cert_path = ca_dir.join("cert.pem");
        let key_path = ca_dir.join("key.pem");
        let mitm_ca_path = ca_dir.join("mitmproxy-ca.pem");
        let mitm_cert_path = ca_dir.join("mitmproxy-ca-cert.pem");

        fs::write(&cert_path, &cert_pem).map_err(|e| {
            SandboxError::Ca(format!(
                "failed to write cert.pem: {e}"
            ))
        })?;
        fs::write(&key_path, &key_pem).map_err(|e| {
            SandboxError::Ca(format!(
                "failed to write key.pem: {e}"
            ))
        })?;

        // mitmproxy-ca.pem: key + cert concatenated (mitmproxy reads
        // both from a single file).
        let mitm_combined = format!("{key_pem}{cert_pem}");
        fs::write(&mitm_ca_path, &mitm_combined).map_err(|e| {
            SandboxError::Ca(format!(
                "failed to write mitmproxy-ca.pem: {e}"
            ))
        })?;

        // mitmproxy-ca-cert.pem: cert only (some tools want just the
        // public cert).
        fs::write(&mitm_cert_path, &cert_pem).map_err(|e| {
            SandboxError::Ca(format!(
                "failed to write mitmproxy-ca-cert.pem: {e}"
            ))
        })?;

        debug!(
            session_id = %session_id,
            cert = %cert_path.display(),
            key = %key_path.display(),
            "CA certificate files written"
        );

        Ok(ca_dir)
    }

    /// Remove the CA directory for a session (cleanup).
    ///
    /// Best-effort: logs a warning and returns Ok if the directory does
    /// not exist.
    pub fn remove_session_ca(
        base_dir: &Path,
        session_id: &Uuid,
    ) -> Result<(), SandboxError> {
        let ca_dir = Self::ca_dir(base_dir, session_id);

        if !ca_dir.exists() {
            debug!(
                session_id = %session_id,
                ca_dir = %ca_dir.display(),
                "CA directory does not exist, nothing to remove"
            );
            return Ok(());
        }

        info!(
            session_id = %session_id,
            ca_dir = %ca_dir.display(),
            "removing CA directory"
        );

        fs::remove_dir_all(&ca_dir).map_err(|e| {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to remove CA directory (best-effort)"
            );
            SandboxError::Ca(format!(
                "failed to remove CA directory {}: {e}",
                ca_dir.display()
            ))
        })?;

        Ok(())
    }

    /// Get the CA directory path for a session.
    pub fn ca_dir(base_dir: &Path, session_id: &Uuid) -> PathBuf {
        base_dir
            .join("sessions")
            .join(session_id.to_string())
            .join("ca")
    }
}

// ---------------------------------------------------------------------------
// CA injection script for VMs
// ---------------------------------------------------------------------------

/// Generate a shell script that installs a CA certificate into a VM's
/// trust store and sets environment variables so common tools (curl,
/// Python requests, Node.js, etc.) trust HTTPS traffic intercepted by
/// mitmproxy.
///
/// The script:
/// 1. Writes the cert to `/usr/local/share/ca-certificates/sandbox-ca.crt`
/// 2. Runs `update-ca-certificates` to add it to the system bundle
/// 3. Sets env vars in `/etc/environment` (for non-interactive processes)
/// 4. Writes `/etc/profile.d/sandbox-ca.sh` (for interactive shells)
pub fn generate_ca_inject_script(cert_pem: &str) -> String {
    // Escape single quotes in the PEM (shouldn't happen in valid PEM,
    // but defensive coding).
    let escaped_cert = cert_pem.replace('\'', "'\\''");

    format!(
        r#"#!/bin/bash
set -euo pipefail

# Write the sandbox CA certificate.
cat > /usr/local/share/ca-certificates/sandbox-ca.crt << 'CERT_EOF'
{escaped_cert}
CERT_EOF

# Update the system certificate store.
update-ca-certificates

# Set environment variables for non-interactive processes.
# Remove any existing sandbox CA env vars first, then append.
sed -i '/^SSL_CERT_FILE=/d; /^REQUESTS_CA_BUNDLE=/d; /^NODE_EXTRA_CA_CERTS=/d; /^CURL_CA_BUNDLE=/d' /etc/environment 2>/dev/null || true
cat >> /etc/environment << 'ENV_EOF'
SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/sandbox-ca.crt
CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV_EOF

# Write profile.d script for interactive shells.
cat > /etc/profile.d/sandbox-ca.sh << 'PROFILE_EOF'
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/sandbox-ca.crt
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
PROFILE_EOF

chmod 644 /etc/profile.d/sandbox-ca.sh

echo "sandbox CA certificate installed successfully"
"#
    )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- CaManager tests ----------------------------------------------------

    #[test]
    fn test_ca_dir_path() {
        let base = Path::new("/tmp/sandboxd");
        let id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        let dir = CaManager::ca_dir(base, &id);
        assert_eq!(
            dir,
            PathBuf::from(
                "/tmp/sandboxd/sessions/550e8400-e29b-41d4-a716-446655440000/ca"
            )
        );
    }

    #[test]
    fn test_generate_session_ca_creates_files() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = Uuid::new_v4();

        let ca_dir =
            CaManager::generate_session_ca(base, &id).unwrap();

        // Verify directory exists.
        assert!(ca_dir.exists());
        assert!(ca_dir.is_dir());

        // Verify all expected files exist.
        assert!(
            ca_dir.join("cert.pem").exists(),
            "cert.pem should exist"
        );
        assert!(
            ca_dir.join("key.pem").exists(),
            "key.pem should exist"
        );
        assert!(
            ca_dir.join("mitmproxy-ca.pem").exists(),
            "mitmproxy-ca.pem should exist"
        );
        assert!(
            ca_dir.join("mitmproxy-ca-cert.pem").exists(),
            "mitmproxy-ca-cert.pem should exist"
        );
    }

    #[test]
    fn test_generate_session_ca_cert_is_valid_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = Uuid::new_v4();

        let ca_dir =
            CaManager::generate_session_ca(base, &id).unwrap();

        let cert_pem =
            fs::read_to_string(ca_dir.join("cert.pem")).unwrap();
        let key_pem =
            fs::read_to_string(ca_dir.join("key.pem")).unwrap();

        // Verify PEM markers.
        assert!(
            cert_pem.contains("-----BEGIN CERTIFICATE-----"),
            "cert should have PEM header"
        );
        assert!(
            cert_pem.contains("-----END CERTIFICATE-----"),
            "cert should have PEM footer"
        );
        assert!(
            key_pem.contains("-----BEGIN PRIVATE KEY-----"),
            "key should have PKCS#8 PEM header"
        );
        assert!(
            key_pem.contains("-----END PRIVATE KEY-----"),
            "key should have PKCS#8 PEM footer"
        );
    }

    #[test]
    fn test_mitmproxy_ca_pem_is_key_plus_cert() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = Uuid::new_v4();

        let ca_dir =
            CaManager::generate_session_ca(base, &id).unwrap();

        let cert_pem =
            fs::read_to_string(ca_dir.join("cert.pem")).unwrap();
        let key_pem =
            fs::read_to_string(ca_dir.join("key.pem")).unwrap();
        let mitm_pem =
            fs::read_to_string(ca_dir.join("mitmproxy-ca.pem")).unwrap();

        // mitmproxy-ca.pem should be key + cert.
        let expected = format!("{key_pem}{cert_pem}");
        assert_eq!(mitm_pem, expected);
    }

    #[test]
    fn test_mitmproxy_ca_cert_pem_matches_cert() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = Uuid::new_v4();

        let ca_dir =
            CaManager::generate_session_ca(base, &id).unwrap();

        let cert_pem =
            fs::read_to_string(ca_dir.join("cert.pem")).unwrap();
        let mitm_cert_pem =
            fs::read_to_string(ca_dir.join("mitmproxy-ca-cert.pem"))
                .unwrap();

        assert_eq!(cert_pem, mitm_cert_pem);
    }

    #[test]
    fn test_different_sessions_get_different_certs() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let dir1 =
            CaManager::generate_session_ca(base, &id1).unwrap();
        let dir2 =
            CaManager::generate_session_ca(base, &id2).unwrap();

        // Directories should be different.
        assert_ne!(dir1, dir2);

        // Certificates should be different (different key pairs).
        let cert1 =
            fs::read_to_string(dir1.join("cert.pem")).unwrap();
        let cert2 =
            fs::read_to_string(dir2.join("cert.pem")).unwrap();
        assert_ne!(cert1, cert2);
    }

    #[test]
    fn test_remove_session_ca() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = Uuid::new_v4();

        let ca_dir =
            CaManager::generate_session_ca(base, &id).unwrap();
        assert!(ca_dir.exists());

        CaManager::remove_session_ca(base, &id).unwrap();
        assert!(!ca_dir.exists());
    }

    #[test]
    fn test_remove_session_ca_nonexistent_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = Uuid::new_v4();

        // Removing a non-existent CA dir should succeed.
        CaManager::remove_session_ca(base, &id).unwrap();
    }

    #[test]
    fn test_generate_idempotent() {
        // Generating twice should overwrite without error.
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = Uuid::new_v4();

        let dir1 =
            CaManager::generate_session_ca(base, &id).unwrap();
        let cert1 =
            fs::read_to_string(dir1.join("cert.pem")).unwrap();

        let dir2 =
            CaManager::generate_session_ca(base, &id).unwrap();
        let cert2 =
            fs::read_to_string(dir2.join("cert.pem")).unwrap();

        // Same directory.
        assert_eq!(dir1, dir2);
        // But new keypair (not truly idempotent, just non-failing).
        assert_ne!(cert1, cert2);
    }

    // -- Inject script tests ------------------------------------------------

    #[test]
    fn test_generate_ca_inject_script_contains_cert() {
        let cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
        let script = generate_ca_inject_script(cert);

        assert!(
            script.contains("-----BEGIN CERTIFICATE-----"),
            "script should embed the certificate"
        );
        assert!(
            script.contains("-----END CERTIFICATE-----"),
            "script should embed the certificate"
        );
    }

    #[test]
    fn test_generate_ca_inject_script_updates_ca_store() {
        let cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
        let script = generate_ca_inject_script(cert);

        assert!(
            script.contains("update-ca-certificates"),
            "script should update system CA store"
        );
    }

    #[test]
    fn test_generate_ca_inject_script_sets_env_vars() {
        let cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
        let script = generate_ca_inject_script(cert);

        assert!(
            script.contains("SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"),
            "script should set SSL_CERT_FILE"
        );
        assert!(
            script.contains("REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt"),
            "script should set REQUESTS_CA_BUNDLE"
        );
        assert!(
            script.contains("NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/sandbox-ca.crt"),
            "script should set NODE_EXTRA_CA_CERTS"
        );
        assert!(
            script.contains("CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt"),
            "script should set CURL_CA_BUNDLE"
        );
    }

    #[test]
    fn test_generate_ca_inject_script_writes_profile_d() {
        let cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
        let script = generate_ca_inject_script(cert);

        assert!(
            script.contains("/etc/profile.d/sandbox-ca.sh"),
            "script should write profile.d file"
        );
        assert!(
            script.contains("export SSL_CERT_FILE"),
            "profile.d should export SSL_CERT_FILE"
        );
    }

    #[test]
    fn test_generate_ca_inject_script_writes_to_ca_certificates() {
        let cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
        let script = generate_ca_inject_script(cert);

        assert!(
            script.contains("/usr/local/share/ca-certificates/sandbox-ca.crt"),
            "script should write cert to ca-certificates directory"
        );
    }

    #[test]
    fn test_generate_ca_inject_script_is_bash() {
        let cert = "test cert";
        let script = generate_ca_inject_script(cert);

        assert!(
            script.starts_with("#!/bin/bash"),
            "script should start with bash shebang"
        );
        assert!(
            script.contains("set -euo pipefail"),
            "script should use strict mode"
        );
    }
}
