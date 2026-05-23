//! Integration test for policy persistence.
//!
//! Exercises the daemon-side contract:
//!
//!   1. A `Policy` written via `SessionStore::set_policy` survives a
//!      drop-and-reopen of the store on the same `base_dir` — this is
//!      the on-disk side of the restart-survival guarantee.
//!   2. `SessionStore::load_all_policies` yields the persisted policies
//!      in a form that can be fed straight into the daemon's
//!      `session_policies` `HashMap`.  The startup-hydration code in
//!      `sandboxd::main` collects from exactly this iterator, so if the
//!      mapping drifts, that path will drift too.
//!
//! These are `cargo test` integration tests (live next to
//! `log_file.rs`) so they run with the `sandboxd` crate's dependencies
//! but *do not* spawn the actual daemon binary — we need the in-process
//! store type, not the socket interface.

use std::collections::HashMap;

use sandbox_core::{
    AssuranceLevel, Destination, HttpFilter, HttpMethod, Policy, PolicyRule, Protocol,
    SessionConfig, SessionId, SessionStore,
};
use tempfile::TempDir;

/// Username every test-side caller is stamped as. The per-caller
/// `owner_username` filter requires every store call to
/// carry the same identity so the fixture session is visible to later
/// reads.
const TEST_CALLER: &str = "test-operator";

fn restrictive_policy() -> Policy {
    Policy {
        version: "2.0.0".into(),
        rules: vec![
            PolicyRule {
                host: Destination::Domain("github.com".into()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("fetch repo metadata".into()),
                level: AssuranceLevel::Http {
                    http_filters: vec![HttpFilter {
                        method: HttpMethod::Get,
                        path: "/*".into(),
                    }],
                },
            },
            PolicyRule {
                host: Destination::Cidr("0.0.0.0/0".into()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("default deny".into()),
                level: AssuranceLevel::Deny,
            },
        ],
    }
}

/// Apply a policy, drop the store, reopen, and assert the policy is
/// reassembled byte-for-byte (up to serde round-trip).
#[test]
fn policy_survives_store_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let base_dir = dir.path().to_path_buf();

    let session_id: SessionId;
    let expected_json: serde_json::Value;

    {
        let (store, _orphans) = SessionStore::new(base_dir.clone()).expect("open store");
        let session = store
            .create_session(
                SessionConfig::default(),
                Some("restart-test".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create session");
        session_id = session.id;

        let policy = restrictive_policy();
        expected_json = serde_json::to_value(&policy).expect("serialize policy");

        store
            .set_policy(&session_id, TEST_CALLER, &policy)
            .expect("set_policy");
    }

    // Reopen the store on the same directory (simulates a daemon
    // restart).  The rehydrated policy must equal the original — we
    // compare via serde JSON so we catch any field drift, not just
    // struct field identity.
    let (reopened, _orphans) = SessionStore::new(base_dir).expect("reopen store");

    let loaded = reopened
        .get_policy(&session_id, TEST_CALLER)
        .expect("get_policy after reopen")
        .expect("policy must be present after reopen");

    let loaded_json = serde_json::to_value(&loaded).expect("serialize loaded");
    assert_eq!(
        loaded_json, expected_json,
        "policy JSON must round-trip through the store unchanged"
    );
}

/// The daemon builds its `session_policies: HashMap<SessionId, Policy>`
/// on startup from `store.load_all_policies()` — this test mirrors that
/// hydration path and asserts the collected map is exactly equal to
/// the policies we persisted.
#[test]
fn load_all_policies_hydrates_in_memory_map() {
    let dir = TempDir::new().expect("tempdir");
    let base_dir = dir.path().to_path_buf();

    let (store, _orphans) = SessionStore::new(base_dir.clone()).expect("open store");

    let s1 = store
        .create_session(
            SessionConfig::default(),
            Some("alpha".into()),
            TEST_CALLER,
            0,
            "",
        )
        .expect("create alpha");
    let s2 = store
        .create_session(
            SessionConfig::default(),
            Some("beta".into()),
            TEST_CALLER,
            0,
            "",
        )
        .expect("create beta");
    let _s3 = store
        .create_session(
            SessionConfig::default(),
            Some("no-policy".into()),
            TEST_CALLER,
            0,
            "",
        )
        .expect("create no-policy");

    let p1 = restrictive_policy();
    let p2 = Policy {
        version: "2.0.0".into(),
        rules: vec![PolicyRule {
            host: Destination::Domain("example.com".into()),
            port: 443,
            protocol: Protocol::Tcp,
            reason: None,
            level: AssuranceLevel::Transport,
        }],
    };

    store.set_policy(&s1.id, TEST_CALLER, &p1).expect("set p1");
    store.set_policy(&s2.id, TEST_CALLER, &p2).expect("set p2");

    // Drop and reopen — the same pattern the daemon uses on startup.
    drop(store);
    let (reopened, _orphans) = SessionStore::new(base_dir).expect("reopen");

    // This is the exact call `sandboxd::main` uses to hydrate.
    let hydrated: HashMap<SessionId, Policy> = reopened
        .load_all_policies()
        .expect("load_all_policies")
        .into_iter()
        .collect();

    assert_eq!(
        hydrated.len(),
        2,
        "sessions without an applied policy must not appear in the hydrated map"
    );

    let json1 = serde_json::to_value(&p1).unwrap();
    let json2 = serde_json::to_value(&p2).unwrap();

    assert_eq!(
        serde_json::to_value(hydrated.get(&s1.id).unwrap()).unwrap(),
        json1
    );
    assert_eq!(
        serde_json::to_value(hydrated.get(&s2.id).unwrap()).unwrap(),
        json2
    );
}
