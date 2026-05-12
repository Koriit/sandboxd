//! `sandbox update` orchestration — Spec 5 § 3.1 (pre-flight) and
//! § 2.2 / § 2.3 (`--check` and `--dry-run` output shapes).
//!
//! M16-S2 lands the *read-only* half: the pre-flight, `--check`,
//! `--dry-run`, and the lock-file mechanics. Stateful steps
//! (§§ 3.2.13–3.2.30) are deferred to M16-S3.

pub mod fetch;
pub mod lock;
