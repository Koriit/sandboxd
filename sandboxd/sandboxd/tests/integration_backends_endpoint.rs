//! Integration test for `GET /backends`.
//!
//! Drives `sandboxd::backends_http::backends_router` via
//! `tower::ServiceExt::oneshot` against a `BackendsApiState` populated
//! with a real `LimaRuntime`. The router is the same one
//! `sandboxd::main::app` merges into the top-level router, so this test
//! pins the wire shape the CLI deserializes (spec § "CLI learns
//! capabilities via `GET /backends`") without booting Lima/gateway/
//! network/CA-manager.
//!
//! Test names start with `integration_backends_endpoint_` so they are
//! selected by the `integration` nextest profile (see
//! `sandboxd/.config/nextest.toml`). `LimaManager::new` resolves
//! `limactl` from `PATH`, which the integration profile has by
//! convention; the test only exercises `kind()` / `capabilities()` on
//! the runtime, neither of which shells out, so no real VM is touched.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use sandbox_core::backend::{BackendInfo, BackendKind, IsolationLevel, SessionRuntime};
use sandbox_core::{LimaManager, LimaRuntime};
use sandboxd::backends_http::{BackendsApiState, backends_router};

#[tokio::test]
async fn integration_backends_endpoint_lists_registered_backends_in_stable_order() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = Arc::new(LimaManager::new(tmp.path().to_path_buf()).expect("LimaManager::new"));
    let lima = LimaRuntime::new(manager);

    let mut runtimes: HashMap<BackendKind, Arc<dyn SessionRuntime>> = HashMap::new();
    runtimes.insert(BackendKind::Lima, lima);
    let state = Arc::new(BackendsApiState::new(Arc::new(runtimes)));

    let router = backends_router(state);
    let resp = router
        .oneshot(
            Request::get("/backends")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router responded");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let infos: Vec<BackendInfo> = serde_json::from_slice(&bytes).expect("deserialize body");

    assert_eq!(infos.len(), 1, "exactly Lima registered today");
    assert_eq!(infos[0].kind, BackendKind::Lima);
    // Pin the isolation level (and the embedded `kind` field on
    // `Capabilities`) — these prove we got Lima's capability matrix
    // back, not a default-constructed placeholder. Pinning every
    // capability field would brittle-ify the test against future
    // backend tuning; the per-field source-of-truth is
    // `Capabilities::for_lima` and the regression tests in
    // `sandbox-core::backend::lima::tests`.
    assert_eq!(infos[0].capabilities.kind, BackendKind::Lima);
    assert_eq!(infos[0].capabilities.isolation, IsolationLevel::Vm);

    // Spec wire format: top-level array of `{kind, capabilities}`
    // objects with lowercase backend tags. Re-parse as untyped JSON so
    // a stray `#[serde(tag = ...)]` on `BackendInfo` is caught here
    // even if `BackendInfo`'s own deserializer would tolerate it.
    let raw: serde_json::Value = serde_json::from_slice(&bytes).expect("re-parse as json");
    let arr = raw.as_array().expect("top-level array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["kind"], serde_json::json!("lima"));
    assert!(arr[0]["capabilities"].is_object());
}
