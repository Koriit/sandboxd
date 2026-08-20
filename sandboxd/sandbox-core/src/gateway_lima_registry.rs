//! One [`GatewayLimaManager`] per owner uid, keyed by uid.
//!
//! The manager's behaviour is unchanged — there is simply room for more than
//! one of them, each naming the gateway instance its owner uid derives (see
//! [`crate::gateway_lima::gateway_instance_name`]). While per-operator
//! gateways are off, every uid derives the same instance name, so a registry
//! holding several managers is holding several handles onto one VM. That is
//! harmless and it is the point: the shape is in place before the arrangement
//! it describes exists.
//!
//! # Why the lookup cannot fail
//!
//! [`GatewayLimaManager::new`] is pure — it joins two paths and derives a
//! name. There is no directory to provision, no account to resolve, no range
//! to be out of, so there is nothing for a lookup to fail at, and
//! [`GatewayLimaManagerRegistry::get_or_create`] returns the manager rather
//! than a `Result`. The two sibling registries are fallible for reasons that
//! do not apply here: `LimaManagerRegistry::get_or_create` provisions a
//! per-operator LIMA_HOME (a `mkdir` plus an ACL shell-out) on the first call
//! for a uid, and `VmnetPoolRegistry::pool_for` refuses an operator who has no
//! slot range and no shared remainder to fall back on. A `Result` here would
//! be an error type no code path could produce, and every caller would have to
//! invent a response to it.
//!
//! # How a manager gets built
//!
//! By a caller-supplied closure, not by fields on the registry. Composing a
//! manager for a uid means choosing a LIMA_HOME, a Docker route and an in-VM
//! route for it, and those choices belong with the startup code that already
//! makes them for the daemon's own manager. Reproducing them here would put a
//! second, unexercised opinion about routing in the library, which is exactly
//! the kind of duplicate the first per-operator gateway would find wrong.
//!
//! # Locking
//!
//! One `Mutex<HashMap<u32, _>>`, held only across a lookup or an insert, with
//! the map growing monotonically — the discipline `VmnetPoolRegistry` uses.
//! The builder runs outside the lock even though today's builder is cheap:
//! it is supplied from outside this module, so its cost is not this module's
//! to assume.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::gateway_lima::GatewayLimaManager;

/// Per-owner [`GatewayLimaManager`] instances, keyed by the uid that owns the
/// gateway VM.
pub struct GatewayLimaManagerRegistry {
    /// Per-owner manager map. Entries are never removed; the map grows as
    /// owners are looked up. Every entry is fully constructed and ready for
    /// use — construction has no fallible step to leave one half-built.
    managers: Mutex<HashMap<u32, Arc<GatewayLimaManager>>>,
    /// Builds the manager for an owner uid on that uid's first lookup.
    build: Box<dyn Fn(u32) -> GatewayLimaManager + Send + Sync>,
}

impl GatewayLimaManagerRegistry {
    /// Build a registry over a manager-construction closure.
    ///
    /// `build` is called with an owner uid on the first lookup for that uid,
    /// and never again for it. It must be infallible; see the module docs for
    /// why that is not a restriction in practice.
    pub fn new<F>(build: F) -> Self
    where
        F: Fn(u32) -> GatewayLimaManager + Send + Sync + 'static,
    {
        Self {
            managers: Mutex::new(HashMap::new()),
            build: Box::new(build),
        }
    }

    /// The manager for `owner_uid`, building one if this is the first lookup.
    ///
    /// The returned `Arc` is stable for the daemon's lifetime: repeated
    /// lookups for a uid yield the same manager, so the NIC map one of them
    /// cached is the one the next caller reads. Handing back a fresh manager
    /// would hand back an empty map and a second opinion about the same VM.
    ///
    /// # Concurrency
    ///
    /// Double-checked insert: the map lock is held for the fast lookup and for
    /// the insert, never across the caller's builder. Two threads racing on
    /// one uid may both build; `entry().or_insert_with` keeps whichever landed
    /// first and both callers receive it, so the "same `Arc` per uid" property
    /// holds under the race as well as outside it.
    ///
    /// A poisoned lock is recovered rather than propagated. The map's values
    /// are `Arc`s inserted whole; a panic elsewhere cannot leave it in a state
    /// that makes a later lookup wrong, and refusing every gateway lookup for
    /// the rest of the process is a worse answer than continuing.
    pub fn get_or_create(&self, owner_uid: u32) -> Arc<GatewayLimaManager> {
        {
            let managers = self.managers.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(mgr) = managers.get(&owner_uid) {
                return Arc::clone(mgr);
            }
        } // lock released before the caller's builder runs

        let built = Arc::new((self.build)(owner_uid));

        let mut managers = self.managers.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(
            managers
                .entry(owner_uid)
                .or_insert_with(|| Arc::clone(&built)),
        )
    }

    /// Number of owners with a manager. Exposed for tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.managers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::DockerRoute;
    use crate::error::SandboxError;
    use crate::in_vm::{InVmOp, InVmRoute};
    use crate::lima::{LimaExecutor, LimaOp};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Neither seam is reachable from anything these tests do: the registry
    /// hands out managers, and a manager that has only been constructed has
    /// issued no operation. Panicking makes an accidental one a failure here
    /// rather than a silent shell-out from a unit test.
    struct UnusedLimaExecutor;

    #[async_trait::async_trait]
    impl LimaExecutor for UnusedLimaExecutor {
        fn run(
            &self,
            _op_uid: u32,
            _op: LimaOp<'_>,
            _timeout: Duration,
            label: &str,
        ) -> Result<std::process::Output, SandboxError> {
            unreachable!("a registry lookup issues no limactl op; got {label}");
        }

        async fn guest_socat(
            &self,
            _op_uid: u32,
            _vm: &str,
        ) -> Result<Box<dyn crate::backend::AsyncReadWrite + Send + Unpin>, SandboxError> {
            unreachable!("a registry lookup opens no guest stream");
        }
    }

    struct UnusedInVmExecutor;

    impl crate::in_vm::InVmExecutor for UnusedInVmExecutor {
        fn run(
            &self,
            _op_uid: u32,
            _op: InVmOp,
            _timeout: Duration,
            label: &str,
        ) -> Result<std::process::Output, SandboxError> {
            unreachable!("a registry lookup issues no in-VM op; got {label}");
        }
    }

    /// A registry over inert managers, plus the count of managers it built.
    fn registry() -> (GatewayLimaManagerRegistry, Arc<AtomicUsize>) {
        let built = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&built);
        let registry = GatewayLimaManagerRegistry::new(move |owner_uid| {
            counter.fetch_add(1, Ordering::SeqCst);
            GatewayLimaManager::new(
                PathBuf::from(format!("/var/lib/sandboxd/60/{owner_uid}/lima")),
                Arc::new(UnusedLimaExecutor),
                DockerRoute::Host,
                InVmRoute::new(owner_uid, Arc::new(UnusedInVmExecutor)),
                owner_uid,
            )
        });
        (registry, built)
    }

    /// Repeated lookups return the same manager: the registry grows
    /// monotonically and never rebuilds an owner's manager underneath a
    /// cached NIC map.
    #[test]
    fn a_lookup_is_stable_for_the_daemons_lifetime() {
        let (registry, built) = registry();

        let first = registry.get_or_create(501);
        let second = registry.get_or_create(501);

        assert!(
            Arc::ptr_eq(&first, &second),
            "the second lookup for one owner built a second manager"
        );
        assert_eq!(built.load(Ordering::SeqCst), 1);
        assert_eq!(registry.len(), 1);
    }

    /// Two owners get two managers, each naming its own LIMA_HOME.
    #[test]
    fn distinct_owners_get_distinct_managers() {
        let (registry, built) = registry();

        let a = registry.get_or_create(501);
        let b = registry.get_or_create(502);

        assert!(!Arc::ptr_eq(&a, &b));
        assert_ne!(a.gateway_docker_socket(), b.gateway_docker_socket());
        assert_eq!(built.load(Ordering::SeqCst), 2);
        assert_eq!(registry.len(), 2);
    }

    /// The map grows by one per new owner and not at all for a repeat.
    #[test]
    fn the_map_grows_monotonically_with_new_owners() {
        let (registry, _) = registry();

        assert_eq!(registry.len(), 0);
        for (n, uid) in [501u32, 502, 501, 503, 502].into_iter().enumerate() {
            registry.get_or_create(uid);
            let expected = [1, 2, 2, 3, 3][n];
            assert_eq!(registry.len(), expected, "after {} lookups", n + 1);
        }
    }

    /// Threads racing the first lookup for one owner all get one manager.
    ///
    /// The builder runs outside the lock, so more than one thread can build —
    /// what must not happen is two of them being handed different managers,
    /// which would give one owner two views of the same VM.
    #[test]
    fn racing_threads_receive_one_manager() {
        let (registry, _) = registry();
        let registry = Arc::new(registry);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                std::thread::spawn(move || registry.get_or_create(501))
            })
            .collect();

        let managers: Vec<Arc<GatewayLimaManager>> = handles
            .into_iter()
            .map(|h| h.join().expect("no thread may panic"))
            .collect();

        let first = &managers[0];
        for mgr in &managers {
            assert!(
                Arc::ptr_eq(first, mgr),
                "a racing lookup was handed a different manager"
            );
        }
        assert_eq!(registry.len(), 1);
    }
}
