//! Small helpers for the two shared [`HttpFilter`] shapes built-in
//! presets emit.
//!
//! Every consume-only preset (`npm`, `pypi`, `cargo`, `goproxy`,
//! `maven`, `gradle`, `dockerhub`, and the GitHub asset-CDN hosts
//! under `github:`) shares the same `GET /**` + `HEAD /**` filter
//! posture. The interactive GitHub hosts (`github.com`,
//! `api.github.com` under `github:`) share a single `ANY /**` filter.
//! Keeping these as named constructors (instead of inlining the
//! two-element / one-element `Vec` literals at every call site)
//! prevents accidental drift — a typo that turns one preset's `/**`
//! into `/*` or drops `HEAD` wouldn't be caught by the validator
//! (both shapes are perfectly valid policies) but would silently
//! weaken the preset's posture.
//!
//! The two postures reflect the consume-only vs. interactive access pattern:
//! read-only registries need only GET/HEAD, while interactive hosts
//! (e.g. github.com) need arbitrary methods.

use sandbox_core::{HttpFilter, HttpMethod};

/// The consume-only posture: `[GET /**, HEAD /**]`.
///
/// Recursive-wildcard path matcher: `/**` matches every request path under the host. The
/// two-method split is deliberate — `HEAD` requests are used by
/// package registries and CDN tooling for cheap existence / ETag
/// probes, so allowing `HEAD` alongside `GET` matches the
/// consume-only happy path without permitting writes.
pub fn get_head() -> Vec<HttpFilter> {
    vec![
        HttpFilter {
            method: HttpMethod::Get,
            path: "/**".to_string(),
        },
        HttpFilter {
            method: HttpMethod::Head,
            path: "/**".to_string(),
        },
    ]
}

/// The interactive-surface posture: `[ANY /**]`.
///
/// Used by the plain `github:` preset on `github.com` and
/// `api.github.com`, where legitimate workflows routinely POST
/// (git-receive-pack, REST API writes, OAuth). Method-level
/// enforcement is traded for mitmproxy's per-request audit log — a
/// compromised agent cannot hide its writes even though the preset
/// does not block them.
pub fn any_all_paths() -> Vec<HttpFilter> {
    vec![HttpFilter {
        method: HttpMethod::Any,
        path: "/**".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_head_has_two_entries_get_then_head_on_recursive_wildcard() {
        let filters = get_head();
        assert_eq!(filters.len(), 2, "expected exactly GET + HEAD");
        assert_eq!(filters[0].method, HttpMethod::Get);
        assert_eq!(filters[0].path, "/**");
        assert_eq!(filters[1].method, HttpMethod::Head);
        assert_eq!(filters[1].path, "/**");
    }

    #[test]
    fn any_all_paths_has_single_any_on_recursive_wildcard() {
        let filters = any_all_paths();
        assert_eq!(filters.len(), 1, "expected exactly one ANY /** entry");
        assert_eq!(filters[0].method, HttpMethod::Any);
        assert_eq!(filters[0].path, "/**");
    }
}
