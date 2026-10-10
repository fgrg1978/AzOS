// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for the `#[cfg(test)] mod tests` suites that live inside
//! `crates/core/ipc/src/{lease,port,irq_bind,io_ring,shm,cap,objref}.rs` (IPC-3
//! task-exit reclamation, IPC-6 lease ownership, event ports, io_ring, shared
//! memory and the object generation, and the capability table), and for the
//! integration tests under `tests/`. `cap_store.rs` is compiled here as a
//! dependency and carries no tests of its own.
//!
//! Same trick as `tests/host/cap-tests`: the whole `azos_ipc` crate cannot be
//! built for the host (RV64-only dependencies), so each module is pulled in
//! directly with `#[path]` and its embedded `#[cfg(test)] mod tests` runs
//! here. The kernel crates those modules call into (`azos_sync`,
//! `azos_sched`, `azos_mm`, `azos_arch`) are replaced by the host
//! shims under `shims/` via a Cargo dependency rename — the kernel build never
//! sees them.
//!
//! What is not covered here, and why, is listed at the bottom of this file.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `ipc_lease_test_drivers`.
extern crate ipc_lease_test_drivers as azos_drv_irqchip;

#[path = "../../../../crates/core/ipc/src/lease.rs"]
pub mod lease;

// `port.rs`'s typed `port_*_cap` wrappers reference `crate::cap` and
// `crate::cap_store`, so both must exist under those exact paths.
#[path = "../../../../crates/core/ipc/src/cap.rs"]
pub mod cap;

#[path = "../../../../crates/core/ipc/src/cap_store.rs"]
pub mod cap_store;

#[path = "../../../../crates/core/ipc/src/port.rs"]
pub mod port;

// The link a bound channel or io_ring stores (`port.rs` and `io_ring.rs`).
#[path = "../../../../crates/core/ipc/src/port_link.rs"]
pub mod port_link;

// The IRQ→port binding and its delivery, which compares the port's generation
// and epoch (RFC-0040 gap 1). Needs only `port.rs` and `azos_sync`.
#[path = "../../../../crates/core/ipc/src/irq_bind.rs"]
pub mod irq_bind;

// `lease_grant_as` asks `shm_owner` whether the lessor owns the region, so the
// region table is here too. It allocates from `shims/mm` and zeroes pages with
// `shims/arch`'s page size.
#[path = "../../../../crates/core/ipc/src/shm.rs"]
pub mod shm;

// Wave 6: notify/wait. Needs only `azos_sync` and the limits; its wait
// loop runs here against a scripted `NotifyEnv`, not the scheduler.
#[path = "../../../../crates/core/ipc/src/notify.rs"]
pub mod notify;

// The futex table's own unit tests (wave 15 N9). `notify` above files into
// the copy the sched shim pulls in; this one is tested on its own.
#[path = "../../../../crates/core/sched/src/futex_table.rs"]
pub mod futex_table;

// `io_ring.rs` allocates one physical page per ring; the page allocator is
// stood in for by `shims/mm`. Its `IoRingOps` dispatch table is a struct of
// plain `fn` pointers declared in the module itself — no driver crate is
// involved — so the whole submit path is drivable from the host.
#[path = "../../../../crates/core/ipc/src/io_ring.rs"]
pub mod io_ring;

// RFC-0040 gap 2. `endpoint.rs` needs exactly what `port.rs` needs — `crate::cap`,
// `crate::cap_store` and `azos_sync` — so it runs under this harness rather
// than in a crate of its own. Its suite takes the same serial lock: a generation
// wrap sweep walks every cap table, which the port, shm and io_ring suites share.
#[path = "../../../../crates/core/ipc/src/endpoint.rs"]
pub mod endpoint;

// ── One serial lock for the suites that share the host shims ───────────────
//
// Same shape as `tests/host/syscall-tests/src/harness.rs`. The lease and io_ring
// suites both write the `azos_sched` shim's current-task registers
// and read its wake records, and io_ring counts `azos_mm` pages. With one
// `Mutex` per module each suite serialised against itself only, so one
// suite's `shim_reset()` or `shim_set_current()` could land inside another's
// test: a lease test lost its recorded wake, and an io_ring test created a
// ring with the wrong privilege. `cargo test` runs test functions on several
// threads, so such a verdict depends on scheduling.
//
// The port and irq_bind suites take it too since RFC-0040 gap 1: they record
// port wakes on the sched shim, share the port table, and a generation wrap
// sweep walks every cap table the shm and io_ring suites use. The cap suite
// keeps its own lock: it does not call the sched shim and uses local tables. `tests/*.rs` are separate processes with their own locks.
//
// `#[cfg(test)]`: only the unit-test build of this lib runs those suites. The
// kernel does not compile this file, and in `crates/core/ipc` the callers sit inside
// `#[cfg(test)] mod tests`.
#[cfg(test)]
pub(crate) mod harness {
    use std::sync::{Mutex, MutexGuard};

    pub static SERIAL: Mutex<()> = Mutex::new(());

    /// Take the crate-wide lock and reset both shared shims: kernel context
    /// (`tid 0`, `user_pt 0`), no recorded wakes, boosts or priorities, and no
    /// pages allocated or freed. Each suite then resets its own table and sets
    /// the identity it needs.
    pub fn serial() -> MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        azos_sched::shim_reset();
        azos_mm::shim_reset();
        g
    }
}

// ── RFC-0040 gap 3: fork-time bootstrap capability grant ───────────────────
//
// `endpoint::endpoint_inherit_at_fork` (this crate's `endpoint.rs` mount)
// mints the child's capabilities at fork. These tests pin the RELATION it
// must express — `owner_tid == parent_tid`, not capability CLASS — which is
// exactly what the design reverted on 2026-09-21 got wrong: it inherited
// every `Endpoint` cap the parent HELD, including ones a third party OWNED.
// See that function's own doc for the property; these tests are its proof.
//
// TIDs 55/56/57 are unused by every other suite this crate hosts (lease
// uses 1-4, 21-22, 2000s; port uses 5, 31-34; irq_bind uses 7, 41-42;
// io_ring uses 1-4, 4242; endpoint's own suite uses 1-3) — picked to avoid
// leaning on `harness::serial()` alone to keep this suite's `cap_store`
// state from being observed mid-mutation by another suite that also uses a
// low TID.
#[cfg(test)]
mod fork_grant_tests {
    use crate::cap::{targets::Endpoint, Cap, CapError, CapPerms};
    use crate::cap_store;
    use crate::endpoint;
    use azos_abi::cap::{CapHandle, CapKind};

    const PARENT: u32 = 55;
    const CHILD: u32 = 56;
    const THIRD: u32 = 57;

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        endpoint::__endpoint_reset_for_tests();
        cap_store::reset(PARENT);
        cap_store::reset(CHILD);
        cap_store::reset(THIRD);
        g
    }

    /// The handle a fork grant lands at, for a child whose table started
    /// this test empty. `CapTable::allocate_slot` takes the lowest free
    /// index and `bump_generation` on a virgin (never-granted) slot starts
    /// at 1 — both documented invariants in `crates/core/ipc/src/cap.rs`, not
    /// this test's own assumption — so the FIRST capability ever granted
    /// into an empty table is deterministically `(slot 0, generation 1)`.
    /// The kind/perms bits `CapHandle::pack` also encodes are never read by
    /// `CapTable::get_uncontained` (only `slot()`/`generation()` are), so
    /// which values are passed there does not matter; `Endpoint`/`WRITE`
    /// are used only for readability.
    fn first_grant_handle() -> CapHandle {
        CapHandle::pack(CapKind::Endpoint, CapPerms::WRITE, 1, 0)
    }

    /// **The relation holds.** A child inherits a capability reaching an
    /// endpoint its parent itself owns — through the exact path
    /// `fast_ipc_call_ep`/`endpoint_dest_for` uses — and with `WRITE` only:
    /// the relation fork preserves is "the child may reach its parent", not
    /// "the child may serve in its parent's place".
    #[test]
    fn a_child_inherits_a_capability_to_its_parents_own_endpoint() {
        let _g = setup();
        assert!(
            endpoint::endpoint_create_cap(PARENT, CapPerms::RW).is_some(),
            "a fresh pool has room"
        );

        let minted = endpoint::endpoint_inherit_at_fork(PARENT, CHILD);
        assert_eq!(minted, 1, "exactly one endpoint was the parent's own");
        assert_eq!(cap_store::occupied(CHILD), 1);

        let child_cap: Cap<Endpoint> = Cap::from_raw(first_grant_handle());
        assert_eq!(
            endpoint::endpoint_dest_for(CHILD, child_cap.raw().as_raw()),
            Ok(PARENT),
            "the inherited capability does not reach the parent",
        );
        assert!(
            cap_store::get(CHILD, child_cap, CapPerms::WRITE).is_ok(),
            "the child cannot even send with the capability it inherited",
        );
        assert_eq!(
            cap_store::get(CHILD, child_cap, CapPerms::READ),
            Err(CapError::MissingPerms),
            "the child got more than WRITE — it could act as the server",
        );
    }

    /// **The relation is tight — the case the reverted design got wrong.**
    /// The parent holds `WRITE` on an endpoint a THIRD PARTY owns (a real
    /// scenario once drivers sit behind endpoints, RFC-0040 gap 8) alongside
    /// an endpoint it owns itself. Fork must inherit the second and never
    /// the first: filtering by capability CLASS ("every `Endpoint` cap the
    /// parent holds") would hand the child both.
    #[test]
    fn a_capability_the_parent_only_holds_is_not_inherited() {
        let _g = setup();
        // THIRD owns an endpoint; PARENT is handed a plain WRITE capability
        // to it directly (as a capability MOVE would leave the receiver:
        // `cap_store::grant` with the raw resource, exactly what
        // `move_cap`/`objref::grant_packed` install, without needing gap 2
        // stage 4's live move machinery just to set this up).
        let third_ref = endpoint::endpoint_create(THIRD).expect("pool has room");
        let held_on_third: Cap<Endpoint> =
            cap_store::grant(PARENT, CapPerms::WRITE, third_ref).expect("table has room");
        assert_eq!(
            endpoint::endpoint_dest_for(PARENT, held_on_third.raw().as_raw()),
            Ok(THIRD),
            "test setup: PARENT must actually reach THIRD's endpoint",
        );

        // PARENT also owns one of its own.
        assert!(endpoint::endpoint_create_cap(PARENT, CapPerms::RW).is_some());

        let minted = endpoint::endpoint_inherit_at_fork(PARENT, CHILD);
        assert_eq!(minted, 1, "only the OWNED endpoint should be inherited, not the held one");
        assert_eq!(cap_store::occupied(CHILD), 1, "a second, unowned capability leaked through");

        // The one the child got must resolve to the PARENT, not to THIRD.
        let child_cap: Cap<Endpoint> = Cap::from_raw(first_grant_handle());
        assert_eq!(
            endpoint::endpoint_dest_for(CHILD, child_cap.raw().as_raw()),
            Ok(PARENT),
            "the child's only capability must reach its parent",
        );
        // And nothing in the child's table reaches THIRD: with one occupied
        // slot total (asserted above) and that slot proven to resolve to
        // PARENT, there is no second slot left that could resolve to THIRD
        // — the tight form of "not inherited" this test exists to prove,
        // rather than merely checking a handle the child was never given.
    }

    /// Owner decision 2026-09-26 (O3.4): a fork-minted endpoint capability is
    /// non-transferable. `endpoint_inherit_at_fork` mints `WRITE` only, never
    /// `DUP`, and `cap_store::move_cap` now refuses any capability lacking
    /// `DUP` before touching either table. So a READ-only server's child —
    /// which inherits `WRITE` on the parent's endpoint, the relation
    /// `a_child_inherits_a_capability_to_its_parents_own_endpoint` proves —
    /// cannot hand that reach to a third party via `move_cap`: `CAPS.TOML`
    /// stays the whole authority graph, not a lower bound on it.
    ///
    /// **RED before this change.** `move_cap` had no `DUP` check at all, so
    /// the `move_cap` call below answered `Ok`, and THIRD received the
    /// capability to call PARENT that only PARENT and CHILD were meant to
    /// hold.
    ///
    /// **Canary.** Drop the `DUP` check from `move_cap`: this test's `Err`
    /// assertion fails with `Ok(_)`.
    #[test]
    fn a_forked_childs_endpoint_capability_cannot_be_moved_to_a_third_party() {
        let _g = setup();
        // PARENT serves its own endpoint with READ (the role a server
        // declares); CHILD inherits WRITE on it via fork.
        assert!(endpoint::endpoint_create_cap(PARENT, CapPerms::READ).is_some());
        let minted = endpoint::endpoint_inherit_at_fork(PARENT, CHILD);
        assert_eq!(minted, 1, "precondition: the child inherited the endpoint");

        let child_cap: Cap<Endpoint> = Cap::from_raw(first_grant_handle());
        assert!(
            cap_store::get(CHILD, child_cap, CapPerms::WRITE).is_ok(),
            "precondition: CHILD's inherited capability works"
        );

        // CHILD tries to hand its inherited reach to THIRD.
        let moved = cap_store::move_cap(CHILD, THIRD, child_cap.raw(), None);
        assert_eq!(moved, Err(CapError::MissingPerms), "no DUP: the move is refused");
        assert_eq!(cap_store::occupied(THIRD), 0, "THIRD received nothing");
        // CHILD's own capability is untouched — `move_cap` refused before
        // touching either table.
        assert!(
            cap_store::get(CHILD, child_cap, CapPerms::WRITE).is_ok(),
            "CHILD keeps its own capability to its parent"
        );
    }
}

// ── What is NOT covered here, and why ──────────────────────────────────────
//
//  * `lease_wait_return`'s blocking loop. It parks on
//    `azos_sched::wq_block_current()`, which on the host has nothing to
//    block on — the shim panics there deliberately rather than spinning
//    forever. The *guard* on that function is tested (a stranger returns
//    immediately and donates no priority); the block/wake handshake itself
//    needs the real scheduler and belongs in QEMU.
//  * `ring_cap_ok` under containment. The `dispatch_sqe` matrix in
//    `io_ring.rs` asserts its answers against `cap_store` grants at the FULL
//    degrade level; the uncontained presence check it calls is asserted
//    degraded in `cap.rs` (`presence_checks_refuse_packed_kinds_and_only_one_is_contained`),
//    where the degrade level has its own serial lock.
