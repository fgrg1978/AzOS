// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Topology → cap_store bridge — RFC-0003/RFC-0005 migration phase P1
//! (wave "W2" of the capability migration).
//!
//! `crates/core/topology` parses `CAPS.TOML` into `CapSpec { kind, perms,
//! target }` triples, but that crate deliberately has **no** dependency on
//! `crates/core/ipc` (see its `Cargo.toml`) — parsing static configuration and
//! minting live kernel capabilities are different layers. Nothing in the
//! tree ever closed that loop: `default_minimal()`'s cap grants, and any
//! future signed `CAPS.TOML`, were parsed and then never consumed. This
//! module is the missing link, callable from the one place that already
//! depends on both crates: the kernel binary.
//!
//! ## Ordering (load-bearing — read before calling this from anywhere new)
//!
//! [`cap_store::grant`] resolves `tid` through `cap_store::slot_for`, which
//! calls `claim_slot` — and `claim_slot` **wipes** the slot's table if the
//! slot's recorded owner does not already match `tid` (see
//! `crates/core/ipc/src/cap_store.rs` module doc, "Slot reuse"). Consequences:
//!
//!   - Minting for a `tid` whose task-pool slot has not been claimed yet
//!     (i.e. before `azos_sched`'s spawn path has run for it) has no
//!     defined outcome: `idx_for_tid` will not resolve an unclaimed TID and
//!     every mint here returns `None`.
//!   - The FIRST `cap_store` call for a freshly-claimed slot is what
//!     performs the owner-mismatch wipe. As long as this function's mints
//!     are the first (or among the first) `cap_store` operations for `tid`,
//!     that wipe — if it fires at all — clears out only the previous
//!     occupant's leftovers, never anything this function just wrote.
//!
//! **The only call site today (`kernel/src/tasks/loader.rs`'s autorun block) is
//! safe by construction, not by care**: it calls
//! `azos_sched::current_task_tid()` from *inside* the already-running
//! autorun task, i.e. strictly after that task's own pool slot was claimed
//! by the scheduler's spawn path.
//!
//! **Verified true (2026-09-06 audit), by reading the call site rather than
//! trusting the sentence above it.** `kernel/src/tasks/loader.rs` reads
//! `let tid = azos_sched::current_task_tid();` from directly inside the
//! P1 migration block quoted in that function's own doc, which executes
//! inside the autorun task ("The TID does not change across `exec_user` — the
//! autorun kernel task becomes the user process"). There is no other production caller (`grep` for
//! `cap_seed::` outside `tests/host/topology-tests`, which drives its own host
//! shim, turns up only this one), so the claim reduces to reading one call
//! site, which is what makes "by construction" earned here rather than
//! aspirational.
//!
//! Since RFC-0043 there is a second production caller:
//! `crates/core/syscall/src/spawn.rs` (`seed_caps`) seeds a child that
//! `spawn_prepare` created parked, whose slot is already claimed and which
//! has run no instruction yet.
//!
//! A future
//! caller that tries to seed a TID *before* spawning it (e.g. a hypothetical
//! "pre-provision caps for a not-yet-created task" path) would violate this
//! and must not use this function that way.
//!
//! ## The only minter
//!
//! Every arm below bottoms out in [`cap_store::grant`] (via the `*_grant_cap`
//! minters — see [`seed_one_cap`]'s doc). Verified by reading the minters,
//! each a one-line `cap_store::grant` wrapper. There used to be a delegation
//! producer, ring-3 `SYS_CAP_GRANT`/`cap_store::delegate`, with its own
//! inbound-quota bookkeeping this module deliberately never touched; it was
//! removed 2026-09-03 (boot-only caps, RFC-0003). `cap_store::grant` is NOT
//! otherwise this module's alone, though: `DOMAIN_CREATE_PORT`,
//! `SYS_MO_CREATE` and `SYS_RING_SETUP` (`crates/core/ipc/src/
//! port.rs`, `memobj.rs`, `io_ring.rs`) call it too, at runtime, from ring 3.
//! That is not a second `SYS_CAP_GRANT` — each mints into the *same* `tid`
//! that just created the object (self-mint, per RFC-0003's "mint what you
//! create, never delegate"), never into another task's table. This module
//! is the sole *boot-seed* mint path; `cap_store::grant` itself has several
//! self-mint callers by design.

use crate::cap::{CapHandle, CapKind, CapPerms};

/// Mint one typed capability for `tid` from a topology `CapSpec`'s decoded
/// fields (`kind`, `perms`, `target` — see `azos_topology::CapSpec`).
///
/// `target`'s syntax is kind-specific and matches the conventions already
/// documented in `crates/core/topology/src/types.rs` and RFC-0005:
///
///   - `DriverRegistry`: `"drv.<DRV_KIND_* as decimal>"` (e.g. `"drv.1"` for
///     `DRV_KIND_GPIO = 0x0001`) — decimal, not hex, because every other
///     dotted target here is decimal and one exception would be a trap
///   - `Device` (MMIO): `"mmio.<selector>"` (e.g. `"mmio.dt:google,goldfish-rtc"`,
///     `"mmio.pci:1af4:1041"`, `"mmio.virtio:2#1"`) — the device of the
///     hardware bus (`azos_drv_bus::hwbus`) the selector names, RFC-0043
///   - `Endpoint`: `"endpoint.<name>"` for a task-hosted endpoint, or a
///     kernel-hosted interface of `azos_devif`, `"<iface>[.<resource>]"`
///     (`"entropy"`, `"power"`, `"gpio.20"`, `"i2c.0.0x68"`, `"pwm.4"`,
///     `"sensor.3"` the rangefinder...):
///     the interface says what the resource spelling means, and the rights
///     are its op classes.
///   - `Trace`: the bare word `"trace"` — one tracer per kernel (wave 15),
///     `READ`/`WRITE` only.
///
/// Returns `None` if the kind has no typed minter yet, if `target` does not
/// parse under its kind's convention, or if the underlying minter itself
/// refuses (unknown tid / cap-table full / out-of-range pin).
///
/// ## Kinds with no minter — the full list, named rather than implied
///
/// The `_ => None` arm below is fail-closed, so every kind absent from the
/// match is simply un-mintable. Naming them is what stops "absent" from being
/// read as "handled":
///
///   - (`MmioRegion` was here until RFC-0043; it now has a minter — see
///     `crates/core/ipc/src/mmio_cap.rs`.)
///   - (`Irq` was here until U03-2; it now has a minter — see the
///     `CapKind::Device` arm below. This bullet used to still list it after
///     that landed; caught reading the code, not trusting this comment.)
///   - `IoRing`, `Port` — no minter and no typed syscall. (`Task` was here
///     until wave 12; it now mints the one target `"tasks"`, the full
///     `/proc` task view — see the `CapKind::Domain` arm.) (`Shm` was here until wave 11: a
///     kernel sensor stream,
///     `stream.<name>`, now mints through the hook below — see the
///     `CapKind::MemObj` arm. Any other `Shm` target is refused.)
///   - `Socket` — it has a typed family (`DOMAIN_SOCKET`), and a
///     boot-time minter on purpose does not exist: the capability names a
///     socket index, so seeding one would mean the kernel opening a socket on
///     the task's behalf before it runs. A task mints its own by creating the
///     object — "mint what you create". A `File` naming a DESCRIPTOR is the
///     same; a `File` naming a directory TREE (wave 10, the authority for
///     mkdir/unlink/rmdir/rename/truncate) is minted here — see the
///     `CapKind::Node` arm and `crate::file_cap`.
///
/// What a seed attempt did.
///
/// **Why this is not a `bool` or an `Option`.** Both call sites used to count a
/// `None` as "skipped" and print "no typed minter yet, or target did not
/// parse". Those are different events and only one of them is benign: a kind
/// with no minter is a documented gap, while a kind that HAS a minter and was
/// REFUSED means the topology declared a capability the task did not get — a
/// second server on one endpoint name, a full pool, a target that does not
/// parse. The program then runs with less authority than its topology says it
/// has, and the log blamed a cause that was not true.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeedOutcome {
    /// The capability was minted into the task's table.
    Minted(CapHandle),
    /// This kind has no typed minter. A documented gap — see this module's
    /// doc for the full list — not a failure of this topology.
    NoMinter,
    /// The kind has a minter and the minter said no.
    Refused,
}

/// [`seed_one_cap`], keeping WHY a seed produced nothing.
///
/// This is the real body; `seed_one_cap` is the `Option` view of it for the
/// callers that only need the handle. One match, so the two answers cannot
/// drift apart the way a separate `has_minter` list would.
pub fn seed_one_cap_outcome(
    tid: u32,
    kind: CapKind,
    perms: CapPerms,
    target: &str,
) -> SeedOutcome {
    fn done(o: Option<CapHandle>) -> SeedOutcome {
        match o {
            Some(h) => SeedOutcome::Minted(h),
            None => SeedOutcome::Refused,
        }
    }
    // The kind says what object a row grants; the target says which class of
    // it (a device kind holds an interrupt line, an MMIO region or a driver
    // slot, a node of the name space a directory tree or an image to start).
    done(match kind {
        // Wave 15 (TRACE): the kernel tracer, the bare word `"trace"`, READ
        // and WRITE only (mapping the rings and setting the mask).
        CapKind::Log if CapPerms::RW.contains(perms) => parse_bare_name(target, "trace")
            .and_then(|()| crate::cap::trace_grant_cap(tid, perms))
            .map(|c| c.raw()),
        CapKind::Log => None,
        // The class is the target's prefix, and a target in none of them is
        // refused.
        CapKind::Device => device_seed(tid, perms, target),
        // Wave 10: a directory tree, target its absolute root path
        // (`crate::file_cap`). Never a descriptor: those are minted by the
        // task that opens the file. A target that is relative, has a `.`/`..`
        // component or is too long is refused, not guessed at.
        // RFC-0055 (wave 11): otherwise the target is an image name
        // (`"TOOLBOX.ELF"`), interned by `crate::launch_cap`; only `EXEC` is
        // granted, anything else is refused rather than trimmed.
        CapKind::Node if target.starts_with('/') => crate::file_cap::file_tree_grant_cap(tid, target, perms)
            .map(|c| c.raw()),
        CapKind::Node => crate::launch_cap::launch_grant_cap(tid, target, perms)
            .map(|c| c.raw()),
        // RFC-0040 gap 2. A target in the interface registry (`azos_devif`,
        // `"gpio.17"`, `"entropy"`) is a capability to the endpoint the KERNEL
        // hosts under that interface, badged with the resource the spelling
        // means; its rights are the interface's op classes, as the row spells
        // them. Any other target is a task-hosted endpoint,
        // `endpoint.<name>`; the two spellings never meet.
        //
        // A target that is anything other than the bare kind name is REFUSED
        // rather than ignored. `"endpoint.0"` looks like it selects endpoint
        // zero and would silently create an unrelated one; a refusal at boot
        // is a message, a wrong grant is not.
        CapKind::Endpoint => match azos_devif::parse_target(target) {
            // M40: the drivetrain's endpoints are minted only by a build with
            // the actuation profile, as the `Motor` kind was.
            #[cfg(not(feature = "profile-actuation"))]
            Some((iface, _)) if iface.key == azos_devif::key::MOTOR => None,
            // RFC-0048 P3: a partition the kernel did not find cannot be
            // minted (the capability would otherwise name a range some later
            // table might give a different meaning), and a partition grants
            // read and/or write, nothing else.
            Some((iface, badge))
                if iface.key == azos_devif::key::BLOCK && !block_grantable(badge, perms) => None,
            Some((iface, badge)) => crate::endpoint::kernel_endpoint_cap(tid, perms, iface.key, badge)
                .map(|c| c.raw()),
            None => parse_endpoint_name(target)
                .and_then(|n| crate::endpoint::endpoint_named_cap(tid, perms, n))
                .map(|c| c.raw()),
        },
        // Wave 12 (owner round 48): the full task list. `/proc/tasks` and
        // `/proc/<tid>` show a reader only itself and its descendants unless
        // its table holds this (`kernel/src/boot/procfs.rs`). One target,
        // `"tasks"`, resource 0, and `READ` only: there is nothing to write,
        // and a broader permission is refused rather than trimmed, as
        // `Launch` refuses anything but `EXEC`. Any other target is refused:
        // `"task.7"` reads as a grant over one task, which this is not.
        CapKind::Domain if target == "tasks" && perms == CapPerms::READ => {
            crate::cap_store::grant::<crate::cap::targets::Task>(tid, perms, 0)
                .map(|c| c.raw())
        }
        CapKind::Domain => None,
        // Wave 11 (SHMRING): a kernel sensor stream, `stream.<name>`, through
        // the minter the kernel installs ([`set_shm_stream_minter`];
        // `crate::stream_ring::stream_seed_mint`). Owner decision 2026-10-03:
        // this grant IS the authority to read the stream, with no
        // per-frame check after it. Any other memory-object target is refused,
        // not read as "no minter": a region that does not exist at boot has no
        // name to seed. Without an installed minter (a host test, or a kernel
        // with every stream off) a stream target is refused too.
        CapKind::MemObj if target.starts_with("stream.") => shm_stream_mint(tid, target, perms),
        CapKind::MemObj => None,
        // No typed minter yet — see the doc comment above for the full list
        // and why each one is a documented gap, not an oversight. Returned
        // early so it reads as `NoMinter`, never as a refusal.
        _ => return SeedOutcome::NoMinter,
    })
}

/// A `Device` row: `"irq.<N>"` (the target convention `crates/core/topology`'s
/// parser accepts; `irq_grant_cap` PLIC-range-checks `N`), `"msi.<k>"` (a
/// message-signalled slot; refused where the platform has none for ring 3),
/// `"mmio.<selector>"`
/// (RFC-0043: the register window of the hardware-bus device the selector
/// names; refused for a device that is not there, one a kernel driver owns
/// and a permission no mapping could honour) or `"drv.<DRV_KIND_* as
/// decimal>"` (the right to register as that driver). Anything else is refused.
fn device_seed(tid: u32, perms: CapPerms, target: &str) -> Option<CapHandle> {
    if let Some(n) = parse_dotted(target, "irq") {
        return crate::irq_bind::irq_grant_cap(tid, n, perms).map(|c| c.raw());
    }
    if let Some(k) = parse_dotted(target, "msi") {
        return crate::irq_bind::irq_grant_msi_cap(tid, k, perms).map(|c| c.raw());
    }
    if let Some(selector) = target.strip_prefix("mmio.") {
        return crate::mmio_cap::mmio_grant_cap(tid, selector, perms).map(|c| c.raw());
    }
    if let Some(k) = parse_dotted(target, "drv") {
        return crate::drvreg_cap::drvreg_grant_cap(tid, k, perms).map(|c| c.raw());
    }
    None
}

/// The `Shm` stream minter, as a function address (0 = none installed).
/// A hook rather than a call because `crate::stream_ring` reaches the frame
/// allocator and the shm table, which this module's host suite
/// (`tests/host/topology-tests`) does not carry.
static SHM_STREAM_MINTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// What [`set_shm_stream_minter`] installs.
pub type ShmStreamMinter = fn(u32, &str, CapPerms) -> Option<CapHandle>;

/// Install the `Shm` stream minter. Called once by the kernel at boot,
/// before any task is seeded.
pub fn set_shm_stream_minter(f: ShmStreamMinter) {
    SHM_STREAM_MINTER.store(f as usize, core::sync::atomic::Ordering::Release);
}

fn shm_stream_mint(tid: u32, target: &str, perms: CapPerms) -> Option<CapHandle> {
    let p = SHM_STREAM_MINTER.load(core::sync::atomic::Ordering::Acquire);
    if p == 0 {
        return None;
    }
    // SAFETY: the only non-zero value ever stored is a `ShmStreamMinter`
    // (`set_shm_stream_minter`), and fn pointers are `usize`-sized.
    let f: ShmStreamMinter = unsafe { core::mem::transmute::<usize, ShmStreamMinter>(p) };
    f(tid, target, perms)
}

/// Grant `tid` its half of the name service: `WRITE` on `endpoint.names`,
/// badged `badge` (the importing row's identity, non-zero).
///
/// This is how a row's `imports` list becomes authority. The row names what
/// it may ask for; the kernel hands it the one capability that can ask,
/// stamped with who it is, and the name server (`NAMESD.ELF`) answers only
/// what that identity's row lists. `Refused` when the badge cannot be
/// stamped (0, or Kconfig CAP_SLOT_EXT off): a name server that cannot tell
/// callers apart must not be reachable at all.
pub fn seed_names_import(tid: u32, badge: u32) -> SeedOutcome {
    match crate::endpoint::endpoint_named_cap_badged(tid, CapPerms::WRITE, NAMES_ENDPOINT, badge) {
        Some(c) => SeedOutcome::Minted(c.raw()),
        None => SeedOutcome::Refused,
    }
}

/// The name of the name server's endpoint (`azos_topology::NAMES_ENDPOINT`,
/// which this crate cannot depend on).
pub const NAMES_ENDPOINT: &[u8] = b"names";

/// Mint one typed capability, as an `Option`. The historical shape, kept for
/// the callers and tests that only want the handle.
pub fn seed_one_cap(
    tid: u32,
    kind: CapKind,
    perms: CapPerms,
    target: &str,
) -> Option<CapHandle> {
    match seed_one_cap_outcome(tid, kind, perms, target) {
        SeedOutcome::Minted(h) => Some(h),
        _ => None,
    }
}

/// Create the endpoint a topology grant `target` (`"endpoint.<name>"`)
/// names, unclaimed, if it does not exist yet (`endpoint_declare`). The
/// kernel calls it for every `Endpoint` grant, in row order, once the
/// topology is installed and before anything is spawned. `true` = created.
pub fn declare_topology_endpoint(target: &str) -> bool {
    parse_endpoint_name(target).is_some_and(crate::endpoint::endpoint_declare)
}

/// Parse `"endpoint.<name>"` and return `<name>` as bytes.
///
/// Dotted like every other target here, but the tail is a NAME, not an index:
/// an endpoint has no board-fixed numbering to select from, and two sides of a
/// service have to agree on something a human wrote in `CAPS.TOML`.
///
/// Refused — so the grant is refused — for a missing prefix, an empty name, a
/// name longer than `ENDPOINT_NAME_MAX`, or any byte outside
/// `[A-Za-z0-9_-]`. The character rule is not decoration: a name containing a
/// further `.` would read as a second level that does not exist, and a
/// non-ASCII byte would compare by bytes while looking identical to another
/// name on screen.
fn parse_endpoint_name(target: &str) -> Option<&[u8]> {
    let name = target.strip_prefix("endpoint.")?;
    let b = name.as_bytes();
    if b.is_empty() || b.len() > crate::endpoint::ENDPOINT_NAME_MAX {
        return None;
    }
    if !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-') {
        return None;
    }
    Some(b)
}

/// Parse `"<prefix>.<u32>"`, e.g. `"motor.0"`, `"irq.3"`, `"drv.1"`.
fn parse_dotted(s: &str, prefix: &str) -> Option<u32> {
    let rest = s.strip_prefix(prefix)?.strip_prefix('.')?;
    rest.parse::<u32>().ok()
}

/// The console capability every task is admitted with (D6): `READ|WRITE` on
/// the kernel console. Not a topology word: the console is where any program
/// reports, and what a confined image may do with it is the image profile's
/// op-class mask (`azos_sched::seccomp`), which a capability cannot narrow
/// below the kernel's own refusal of a missing right.
pub fn seed_console(tid: u32) -> Option<CapHandle> {
    crate::cap::console_grant_cap(tid).map(|c| c.raw())
}

/// May a `block` endpoint for `badge` (partition `badge - 1`) be minted with
/// `perms`? The partition must be in the table the kernel published at boot,
/// and the rights read and/or write.
fn block_grantable(badge: u32, perms: CapPerms) -> bool {
    let bits = perms.bits();
    bits != 0
        && bits & !CapPerms::RW.bits() == 0
        && badge >= 1
        && azos_drv_block::partition::partition(badge - 1).is_some()
}

/// Match a target against one exact bare word — `"trace"`. The kind names no
/// sub-resource (see [`seed_one_cap`]'s doc), so unlike `gpio.5` there is
/// nothing to select and anything
/// other than the word itself is refused, the same rule
/// [`parse_endpoint_name`] applies to `"endpoint.0"`.
fn parse_bare_name(target: &str, want: &str) -> Option<()> {
    if target == want { Some(()) } else { None }
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────
//
// These tests — like the modules above — only run when pulled in by a host test
// crate that supplies stand-ins for `azos_sync`/`azos_sched`. See
// `tests/host/topology-tests`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::CapError;

    /// Every task is admitted with the console: `READ|WRITE`, found by the
    /// console type, and it is a `Log` of class `CONSOLE`, which a topology row
    /// cannot ask for (the parser has no word for it).
    ///
    /// **Canary.** Seed `READ` only in `seed_console`: the `WRITE` check is red.
    #[test]
    fn the_console_is_seeded_read_and_write() {
        let _g = crate::harness::serial();
        let tid = tests_support::fresh_tid();
        let h = seed_console(tid).expect("the console is minted");
        assert_eq!(h.kind(), azos_abi::cap::ty::CONSOLE.raw());
        assert!(crate::cap_store::get(tid, crate::cap::Cap::<crate::cap::targets::Console>::from_raw(h), CapPerms::RW).is_ok());
        let again = crate::cap_store::read_table(tid, |t| t.lookup(azos_abi::cap::ty::CONSOLE, 0)).flatten();
        assert_eq!(again, Some(h));
        assert!(seed_one_cap(tid, CapKind::Log, CapPerms::RW, "console").is_none(), "no row word names the console");
    }

    /// **A refusal and an absent minter are different events.** Both used to
    /// be `None`, and both call sites reported them under the same wording —
    /// "no typed minter yet" — so a topology that declared a capability the
    /// minter refused was logged under a cause that was not true, and the task
    /// ran with less authority than its topology says it has.
    ///
    /// **Canary.** Make the `_` arm of `seed_one_cap_outcome` return
    /// `Refused`: `Port`, which has no minter, is then reported as a refusal
    /// and this test goes red.
    #[test]
    fn a_kind_with_no_minter_is_not_reported_as_a_refusal() {
        let _g = crate::harness::serial();
        let tid = tests_support::fresh_tid();

        // No minter at all: a documented gap in the kernel.
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Port, CapPerms::RW, "port"),
            SeedOutcome::NoMinter,
        );

        // Has a minter, and the minter says no — a malformed target. A
        // kernel-hosted `pwm` endpoint stands in for any always-minted kind
        // (`motor` is gated behind `profile-actuation`, M40, and this
        // property does not depend on it).
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::WRITE, "pwm.left"),
            SeedOutcome::Refused,
        );

        // Has a minter and succeeds.
        crate::endpoint::__endpoint_reset_for_tests();
        assert!(matches!(
            seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::WRITE, "pwm.0"),
            SeedOutcome::Minted(_),
        ));

        // The `Option` view keeps its old meaning: nothing minted, either way.
        assert!(seed_one_cap(tid, CapKind::Port, CapPerms::RW, "port").is_none());
        assert!(seed_one_cap(tid, CapKind::Endpoint, CapPerms::WRITE, "pwm.left").is_none());
    }

    /// An endpoint grant is refused, not silently skipped, when the name
    /// already has a live server: the second task would otherwise start as a
    /// client with nobody saying so.
    #[test]
    fn a_second_server_on_one_endpoint_name_is_a_refusal_not_a_gap() {
        // The endpoint pool is process-global and `endpoint.rs`'s suite wipes
        // it in its `setup()` under this lock. Without it a wipe between the
        // two `READ` grants below turned the refusal into a mint, and this
        // test's `svc` server refused that suite's own `svc` server
        // (topology-tests under load: all three failed in one run).
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let server = tests_support::fresh_tid();
        let other = tests_support::fresh_tid();
        assert!(matches!(
            seed_one_cap_outcome(server, CapKind::Endpoint, CapPerms::READ, "endpoint.svc"),
            SeedOutcome::Minted(_),
        ));
        assert_eq!(
            seed_one_cap_outcome(other, CapKind::Endpoint, CapPerms::READ, "endpoint.svc"),
            SeedOutcome::Refused,
            "a second declared server was reported as a missing minter",
        );
        // A caller on the same name is still admitted.
        assert!(matches!(
            seed_one_cap_outcome(other, CapKind::Endpoint, CapPerms::WRITE, "endpoint.svc"),
            SeedOutcome::Minted(_),
        ));
        // And a target that is not `endpoint.<name>` is a refusal, not a gap.
        assert_eq!(
            seed_one_cap_outcome(other, CapKind::Endpoint, CapPerms::WRITE, "svc"),
            SeedOutcome::Refused,
        );
    }

    /// **A row's `imports` become one badged capability on the name service,
    /// and the badge is the kernel's, not the holder's.** Two importing rows
    /// share the `names` endpoint and carry different badges; a badge of 0 is
    /// refused (an unbadged caller is unidentifiable); a `READ` grant carries
    /// none (it would make the holder the server).
    ///
    /// **Canaries.** Make `seed_names_import` call `endpoint_named_cap` (no
    /// badge): the badge reads 0 and the first assertion goes red. Drop the
    /// `READ` refusal in `endpoint_named_cap_badged`: the last assertion goes
    /// red.
    #[test]
    fn the_names_import_carries_the_rows_badge() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let a = tests_support::fresh_tid();
        let b = tests_support::fresh_tid();
        let server = tests_support::fresh_tid();
        assert!(matches!(
            seed_one_cap_outcome(server, CapKind::Endpoint, CapPerms::READ, "endpoint.names"),
            SeedOutcome::Minted(_)
        ));
        let SeedOutcome::Minted(ha) = seed_names_import(a, 7) else { panic!("row a refused") };
        let SeedOutcome::Minted(hb) = seed_names_import(b, 9) else { panic!("row b refused") };
        let badge_of = |tid: u32, h: CapHandle| {
            crate::cap_store::with_table(tid, |t| t.ext_of(h)).flatten().map(|e| e.badge)
        };
        assert_eq!(badge_of(a, ha), Some(7));
        assert_eq!(badge_of(b, hb), Some(9));
        // The server's own capability carries no badge.
        let sh = crate::cap_store::with_table(server, |t| t.lookup(crate::cap::ty::ENDPOINT, 0)).flatten().unwrap();
        assert_eq!(badge_of(server, sh), Some(0));
        // Both reach the server's endpoint.
        assert_eq!(
            crate::endpoint::endpoint_dest_for(a, ha.as_raw()),
            crate::endpoint::endpoint_dest_for(b, hb.as_raw())
        );
        // Unidentifiable, or a server's capability with a badge: refused.
        assert_eq!(seed_names_import(tests_support::fresh_tid(), 0), SeedOutcome::Refused);
        assert!(crate::endpoint::endpoint_named_cap_badged(a, CapPerms::READ, b"fresh", 3).is_none());
        assert!(crate::endpoint::endpoint_named_cap_badged(a, CapPerms::RW, b"fresh", 3).is_none());
        assert!(crate::cap_store::grant_badged::<crate::cap::targets::Endpoint>(a, CapPerms::WRITE, 0, 0).is_none());
    }

    #[test]
    fn seeds_device_endpoints_by_target_convention() {
        let _g = crate::harness::serial();
        let tid = tests_support::fresh_tid();
        crate::endpoint::__endpoint_reset_for_tests();
        let gpio = seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, "gpio.5").unwrap();
        let i2c = seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, "i2c.0.0x68").unwrap();
        let pwm = seed_one_cap(tid, CapKind::Endpoint, CapPerms::WRITE, "pwm.2").unwrap();

        // A device is an endpoint the kernel hosts; the badge is the resource
        // the spelling means (a pin, `bus << 8 | addr`).
        let _ = (gpio, i2c, pwm);
        let holds = |key: u16, badge: u32, need: CapPerms| {
            crate::cap_store::with_table(tid, |t| crate::endpoint::table_holds_host_badge_right(t, key, badge, need))
                .unwrap()
        };
        use azos_devif::{i2c as i2c_if, key};
        assert!(holds(key::GPIO, 5, CapPerms::READ) && !holds(key::GPIO, 6, CapPerms::READ));
        assert!(holds(key::I2C, i2c_if::badge(0, 0x68), CapPerms::WRITE));
        assert!(!holds(key::I2C, i2c_if::badge(0, 0x69), CapPerms::READ));
        assert!(holds(key::PWM, 2, CapPerms::WRITE) && !holds(key::PWM, 2, CapPerms::READ));
    }

    /// M40 (audit U10-6, owner-confirmed 2026-09-26): the drivetrain's
    /// endpoints have no live minting path in a build without
    /// `profile-actuation` -- the parser refuses the target and the builder
    /// cannot declare a row for it, and now the seeder refuses it too, so a
    /// caller that reaches this function with `motor.0` anyway falls into the
    /// same refusal a malformed target gets.
    #[test]
    #[cfg(not(feature = "profile-actuation"))]
    fn motor_has_no_minter_without_the_actuation_profile() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let tid = tests_support::fresh_tid();
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::RW, "motor.0"),
            SeedOutcome::Refused,
        );
        assert!(seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, "motor.0").is_none());
    }

    /// The other half of the M40 pair: with `profile-actuation` on, the wheels
    /// mint exactly like the other endpoints do -- a malformed target is a
    /// refusal and a well-formed one mints with the wheel as its badge.
    #[test]
    #[cfg(feature = "profile-actuation")]
    fn motor_mints_when_the_actuation_profile_is_enabled() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let tid = tests_support::fresh_tid();
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::RW, "motor.left"),
            SeedOutcome::Refused,
            "a malformed target",
        );
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::RW, "motor.2"),
            SeedOutcome::Refused,
            "a wheel the drivetrain does not have",
        );
        assert!(seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, "motor.0").is_some());
        assert!(seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, "motor.1").is_some());
        let holds = |badge: u32| {
            crate::cap_store::with_table(tid, |t| {
                crate::endpoint::table_holds_host_badge_right(t, azos_devif::key::MOTOR, badge, CapPerms::WRITE)
            })
            .unwrap()
        };
        assert!(holds(0) && holds(1));
    }

    #[test]
    fn unparseable_or_unminted_kinds_are_skipped_not_panicked() {
        let tid = tests_support::fresh_tid();
        // A queue is created by its owner, never granted by a row.
        assert!(seed_one_cap(tid, CapKind::Queue, CapPerms::READ, "7").is_none());
        // A sensor endpoint is `sensor.<type>`: a bare interface, a name and
        // a type the kernel does not dispatch are all skipped.
        assert!(seed_one_cap(tid, CapKind::Endpoint, CapPerms::READ, "sensor").is_none());
        assert!(seed_one_cap(tid, CapKind::Endpoint, CapPerms::READ, "sensor.imu").is_none());
        assert!(seed_one_cap(tid, CapKind::Endpoint, CapPerms::READ, "sensor.10").is_none());
        // `Task` mints only `"tasks"` (wave 12): the bare kind name is not it.
        assert!(seed_one_cap(tid, CapKind::Domain, CapPerms::READ, "task").is_none());
    }

    /// Wave 12 (owner round 48): `Cap<Task>` mints the full `/proc` task view
    /// for the one target `"tasks"` with `READ`, as resource 0, and refuses
    /// (not skips) every other shape: a per-task target, and any permission
    /// beyond `READ`.
    ///
    /// **Canary.** Drop the `perms == CapPerms::READ` condition from the arm:
    /// the `RW` grant is then minted and this test goes red.
    #[test]
    fn the_task_view_grant_is_read_on_tasks_only() {
        let tid = tests_support::fresh_tid();
        match seed_one_cap_outcome(tid, CapKind::Domain, CapPerms::READ, "tasks") {
            SeedOutcome::Minted(_) => {}
            _ => panic!("Cap<Task> READ on \"tasks\" must mint"),
        }
        assert!(crate::cap_store::with_table(tid, |t| {
            t.holds_kind_resource_with(crate::cap::ty::TASK, 0, CapPerms::READ)
        }).unwrap_or(false));
        let other = tests_support::fresh_tid();
        assert_eq!(seed_one_cap_outcome(other, CapKind::Domain, CapPerms::RW, "tasks"), SeedOutcome::Refused);
        assert_eq!(seed_one_cap_outcome(other, CapKind::Domain, CapPerms::READ, "task.7"), SeedOutcome::Refused);
        assert_eq!(seed_one_cap_outcome(other, CapKind::Domain, CapPerms::READ, "task"), SeedOutcome::Refused);
        assert!(!crate::cap_store::with_table(other, |t| {
            t.holds_kind_resource_with(crate::cap::ty::TASK, 0, CapPerms::READ)
        }).unwrap_or(false));
    }

    /// U03-2: `Cap<Irq>` gained a minter (the "irq.<N>" convention
    /// `crates/core/topology`'s parser already accepted). A well-formed line
    /// mints; line 0 (never a real PLIC source — SBI/M-mode reserved) and a
    /// line at or past `MAX_IRQS` are refused, the PLIC-range check U03-8
    /// asked for.
    #[test]
    fn irq_cap_mints_within_the_plic_range_and_refuses_outside_it() {
        let tid = tests_support::fresh_tid();
        let irq3 = seed_one_cap(tid, CapKind::Device, CapPerms::READ, "irq.3").unwrap();
        use crate::cap::{targets, Cap};
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::Irq>::from_raw(irq3), CapPerms::READ),
            Ok(3)
        );
        assert!(seed_one_cap(tid, CapKind::Device, CapPerms::READ, "irq.0").is_none(), "line 0");
        assert!(
            seed_one_cap(tid, CapKind::Device, CapPerms::READ, "irq.999999").is_none(),
            "past MAX_IRQS"
        );
        assert!(seed_one_cap(tid, CapKind::Device, CapPerms::READ, "irq").is_none(), "malformed target");
    }

    /// An `msi.<k>` target is read as a message-signalled slot, and refused where
    /// the platform has none (the host here); a malformed slot is refused too.
    #[test]
    fn an_msi_slot_is_not_minted_without_platform_msi() {
        let tid = tests_support::fresh_tid();
        assert!(seed_one_cap(tid, CapKind::Device, CapPerms::READ, "msi.3").is_none());
        assert!(seed_one_cap(tid, CapKind::Device, CapPerms::READ, "msi.x").is_none(), "malformed slot");
    }

    #[test]
    fn without_seeding_the_typed_consumer_path_sees_stale() {
        // Mirrors what a typed handler (`crates/core/syscall/src/handlers.rs`)
        // does: decode a raw handle the caller never actually received, and
        // dereference it through cap_store.
        use crate::cap::{targets::Socket, Cap};
        let tid = tests_support::fresh_tid();
        let forged: Cap<Socket> = Cap::NULL;
        assert_eq!(
            crate::cap_store::get(tid, forged, CapPerms::WRITE),
            Err(CapError::Stale)
        );
    }

    /// Test-only TID allocation, matching the pattern `tests/host/cap-tests`
    /// uses: `azos_sched::shim_bind` publishes an identity in the host
    /// scheduler shim, so `cap_store::slot_for` can resolve it.
    mod tests_support {
        use std::sync::atomic::{AtomicU32, Ordering};
        /// From 8, not 1: `endpoint.rs`'s suite, mounted beside this one,
        /// uses the fixed TIDs 1..=4 and wipes their tables in its `setup()`,
        /// which would empty a table a test here is still reading.
        static NEXT_ID: AtomicU32 = AtomicU32::new(8);

        pub fn fresh_tid() -> u32 {
            let tid = NEXT_ID.fetch_add(1, Ordering::SeqCst);
            let slot = tid as usize;
            // `tests/host/topology-tests` mounts this module beside its own
            // counter, which starts at 32 (its `FIRST_TID`): stay below it,
            // or the two suites share a slot's table.
            assert!(
                tid < 32,
                "cap_seed tests reached the topology bridge's TID range (32..)"
            );
            azos_sched::shim_bind(tid, slot);
            tid
        }
    }
}
