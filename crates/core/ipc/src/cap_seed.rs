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
//! minters — see [`seed_one_cap`]'s doc). Verified by reading `gpio_cap.rs`,
//! `i2c_cap.rs`, `pwm_cap.rs` and `motor_cap.rs`, one-line `cap_store::grant`
//! wrappers, and `channel.rs`'s `channel_grant_cap`, which reads the live
//! channel's generation under the pool lock and mints through
//! `objref::grant_packed` (RFC-0040 gap 1). There used to be a delegation
//! producer, ring-3 `SYS_CAP_GRANT`/`cap_store::delegate`, with its own
//! inbound-quota bookkeeping this module deliberately never touched; it was
//! removed 2026-09-03 (boot-only caps, RFC-0003). `cap_store::grant` is NOT
//! otherwise this module's alone, though: `SYS_PORT_CREATE_TYPED`,
//! `SYS_SHM_CREATE_TYPED` and `SYS_IORING_CREATE_TYPED` (`crates/core/ipc/src/
//! port.rs`, `shm.rs`, `io_ring.rs`) call it too, at runtime, from ring 3.
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
///   - `Gpio`:   `"gpio.<pin>"`               (e.g. `"gpio.5"`)
///   - `Pwm`:    `"pwm.<channel>"`             (e.g. `"pwm.0"`)
///   - `Motor`:  `"motor.<motor_id>"`          (e.g. `"motor.0"`, `"motor.1"`)
///   - `I2c`:    `"bus.<bus>/0x<addr hex>"`    (e.g. `"bus.0/0x68"`)
///   - `Channel`: a bare decimal `u32` channel id (e.g. `"3"`)
///   - `Sensor`: `"sensor.<type>"` (e.g. `"sensor.3"` for the rangefinder) —
///     the type, not an instance, the resource `sys_sensor_read_typed` reads
///   - `DriverRegistry`: `"drv.<DRV_KIND_* as decimal>"` (e.g. `"drv.1"` for
///     `DRV_KIND_GPIO = 0x0001`) — decimal, not hex, because every other
///     dotted target here is decimal and one exception would be a trap
///   - `MmioRegion`: `"mmio.<index>"` (e.g. `"mmio.0"`) — an index into the
///     board's MMIO region table (`azos_drv_base::platform`), RFC-0043
///   - `Power`: the bare word `"power"` — see `crate::cap::power_grant_cap`'s
///     doc for why there is exactly one power domain to name, so unlike
///     `gpio.5` there is no sub-resource to select. Wave 3, 2026-09-26.
///   - `Disk`: `"disk.part.<n>"` (e.g. `"disk.part.0"`) — partition `n` of
///     the table the kernel parsed at boot (`azos_drv_block::partition`),
///     minted as resource `n + 1`; see `crate::disk_cap`. RFC-0048 P3, wave 8.
///     The whole-disk resource 0 has no minter.
///   - `Trace`: the bare word `"trace"` — one tracer per kernel (wave 15),
///     `READ`/`WRITE` only.
///   - `AiSession`: the bare word `"ai.session"`, same reason and same wave.
///     `"ai-session"`/`"service-call"` are also valid `CapKind` *words* in
///     `crates/core/topology/src/parser.rs` (a signed TOML can spell the KIND
///     either way), but the TARGET this arm accepts is only the one string
///     above — a `service-call` row naming, say, `"policy.run"` now gets a
///     real `Refused` (it has a minter and the target does not match)
///     instead of the previous `NoMinter`.
///
/// Returns `None` if the kind has no typed minter yet, if `target` does not
/// parse under its kind's convention, or if the underlying minter itself
/// refuses (unknown tid / cap-table full / out-of-range pin or channel).
///
/// ## Kinds with no minter — the full list, named rather than implied
///
/// The `_ => None` arm below is fail-closed, so every kind absent from the
/// match is simply un-mintable. Naming them is what stops "absent" from being
/// read as "handled":
///
///   - (`Sensor` was here until 2026-09-07; it now has a minter — see the
///     `CapKind::Sensor` arm and `crates/core/ipc/src/sensor_cap.rs`.)
///   - (`MmioRegion` was here until RFC-0043; it now has a minter — see
///     `crates/core/ipc/src/mmio_cap.rs`.)
///   - (`Irq` was here until U03-2; it now has a minter — see the
///     `CapKind::Irq` arm below. This bullet used to still list it after
///     that landed; caught reading the code, not trusting this comment.)
///   - `IoRing`, `Port` — no minter and no typed syscall. (`Task` was here
///     until wave 12; it now mints the one target `"tasks"`, the full
///     `/proc` task view — see the `CapKind::Task` arm.) (`Shm` was here until wave 11: a
///     kernel sensor stream,
///     `stream.<name>`, now mints through the hook below — see the
///     `CapKind::Shm` arm. Any other `Shm` target is refused.)
///   - (`Power` and `AiSession` were here until wave 3, 2026-09-26; they now
///     have minters — see the `CapKind::Power`/`CapKind::AiSession` arms and
///     `crate::cap::power_grant_cap`/`ai_session_grant_cap`. Owner decision:
///     one authority per irreversible effect, closing the gap the next
///     bullet's four remaining kinds still describe.)
///   - `Socket` — it has a typed family (`SYS_SOCKET_TYPED`), and a
///     boot-time minter on purpose does not exist: the capability names a
///     socket index, so seeding one would mean the kernel opening a socket on
///     the task's behalf before it runs. A task mints its own by creating the
///     object — "mint what you create". A `File` naming a DESCRIPTOR is the
///     same; a `File` naming a directory TREE (wave 10, the authority for
///     mkdir/unlink/rmdir/rename/truncate) is minted here — see the
///     `CapKind::File` arm and `crate::file_cap`.
///   - (`Disk` was in the next bullet until RFC-0048 P3, wave 8; it now has a
///     minter for ONE PARTITION — see the `CapKind::Disk` arm and
///     `crate::disk_cap`. The whole-disk resource 0 still has none.)
///   - `Adc`, `Buzzer`, `NetConfig` — added to `CapKind` 2026-09-06
///     alongside `Power`/`DriverRegistry` when the kind field was widened,
///     and still deliberately left with no minter, **no topology name** (see
///     `parse_cap_kind` in `crates/core/topology/src/parser.rs`) and no typed
///     syscall. Each is gated from ring 3 by the untyped `cap_check` against
///     the caller's capability table, which nothing grants any of the three
///     into — so they are currently unreachable from ring 3, and giving them
///     a mint path would open that door rather than close a hole.
///     `DriverRegistry` and `Power` were migrated instead precisely because
///     each has a real consumer already gating on it (a live task's
///     registration, `sys_shutdown`/`sys_reboot`).
///
/// **`Channel` gap, documented rather than guessed at.** Topology's actual
/// default channel targets are name-like paths (`"/safety/estop"`,
/// `"/brain/control"` — see `crates/core/topology/src/builder.rs`), not numeric
/// ids; there is no name→channel-id registry in the tree yet (nothing
/// creates a topology-declared channel by name at boot). A bare-integer
/// target is accepted here because it is the only convention a boot-time
/// mint could use without inventing that registry; path-shaped targets are
/// correctly skipped (`None`), not silently mis-parsed.
///
/// **Why `Channel` mints here and not in `crates/core/syscall`**: `azos_syscall`
/// depends on `azos_ipc`, so the reverse dependency (`ipc → syscall`)
/// would be a cycle. The arm below mints through `channel::channel_grant_cap`,
/// kept local so this module's only kernel-facing dependency stays
/// `azos_ipc` itself — which is also what keeps it host-testable via the same
/// `#[path]` + shim trick `tests/host/cap-tests`/`tests/host/ipc-lease-tests` use
/// (see `tests/host/topology-tests`).
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
    done(match kind {
        CapKind::Gpio => parse_dotted(target, "gpio")
            .and_then(|pin| crate::gpio_cap::gpio_grant_cap(tid, pin, perms))
            .map(|c| c.raw()),
        CapKind::Pwm => parse_dotted(target, "pwm")
            .and_then(|ch| crate::pwm_cap::pwm_grant_cap(tid, ch, perms))
            .map(|c| c.raw()),
        // M40 (audit U10-6, 2026-09-26): gated to match
        // `crates/core/topology/src/parser.rs`'s `"motor" => CapKind::Motor` arm
        // and `crates/core/topology/src/builder.rs`'s `CapSpec{kind: Motor, ..}`
        // rows — ALL THREE places that could put a drivetrain grant into a
        // running kernel now require the same feature, so a non-actuating
        // build has no live path to mint one: the parser cannot produce the
        // `CapKind` from a signed TOML, the builder cannot declare a
        // `CapSpec` for it, and now this function refuses even if handed
        // one some other way. Falls through to `NoMinter`/`None` below, the
        // same shape as any other kind without a minter.
        #[cfg(feature = "profile-actuation")]
        CapKind::Motor => parse_dotted(target, "motor")
            .and_then(|id| crate::motor_cap::motor_grant_cap(tid, id, perms))
            .map(|c| c.raw()),
        CapKind::I2c => parse_i2c(target)
            .and_then(|(bus, addr)| crate::i2c_cap::i2c_grant_cap(tid, bus, addr, perms))
            .map(|c| c.raw()),
        // Wave 3 (2026-09-26): the MINTER `crate::cap` had targets for but
        // nothing granted. Bare-name target, like `Endpoint`'s
        // `parse_endpoint_name` refusing `"endpoint.0"`: neither kind names a
        // sub-resource, so anything other than the exact word is refused
        // rather than guessed at.
        CapKind::Power => parse_bare_name(target, "power")
            .and_then(|()| crate::cap::power_grant_cap(tid, perms))
            .map(|c| c.raw()),
        // Wave 15 (TRACE): the kernel tracer, the bare word `"trace"`, READ
        // and WRITE only (mapping the rings and setting the mask).
        CapKind::Trace if CapPerms::RW.contains(perms) => parse_bare_name(target, "trace")
            .and_then(|()| crate::cap::trace_grant_cap(tid, perms))
            .map(|c| c.raw()),
        CapKind::Trace => None,
        CapKind::AiSession => parse_bare_name(target, "ai.session")
            .and_then(|()| crate::cap::ai_session_grant_cap(tid, perms))
            .map(|c| c.raw()),
        // U03-2: the "irq.<N>" target convention `crates/core/topology`'s parser
        // already accepts (`irq_cap_declaration_parses_end_to_end`) now has
        // a minter on this side too — `irq_grant_cap` PLIC-range-checks `N`.
        CapKind::Irq => parse_dotted(target, "irq")
            .and_then(|n| crate::irq_bind::irq_grant_cap(tid, n, perms))
            .map(|c| c.raw()),
        // RFC-0040 gap 1: the capability carries the channel's generation, read
        // under the channel pool's lock, so an inactive channel mints nothing.
        CapKind::Channel => parse_plain_u32(target)
            .and_then(|id| crate::channel::channel_grant_cap(tid, id as usize, perms))
            .map(|c| c.raw()),
        CapKind::Sensor => parse_dotted(target, "sensor")
            .and_then(|t| crate::sensor_cap::sensor_grant_cap(tid, t, perms))
            .map(|c| c.raw()),
        CapKind::DriverRegistry => parse_dotted(target, "drv")
            .and_then(|k| crate::drvreg_cap::drvreg_grant_cap(tid, k, perms))
            .map(|c| c.raw()),
        // RFC-0043: the index into the board's MMIO region table, refused
        // outside the table and for a permission the region cannot honour.
        CapKind::MmioRegion => parse_dotted(target, "mmio")
            .and_then(|i| crate::mmio_cap::mmio_grant_cap(tid, i, perms))
            .map(|c| c.raw()),
        // RFC-0040 gap 2. The target names no sub-resource: an endpoint does
        // not exist before it is created, so unlike `gpio.5` there is nothing
        // to select. A seed CREATES one owned by the seeded task — the
        // topology's way of saying "this task serves an endpoint" without the
        // task issuing a syscall at start.
        //
        // A target that is anything other than the bare kind name is REFUSED
        // rather than ignored. `"endpoint.0"` looks like it selects endpoint
        // zero and would silently create an unrelated one; a refusal at boot
        // is a message, a wrong grant is not.
        // Wave 10: a directory tree, target its absolute root path
        // (`crate::file_cap`). Never a descriptor: those are minted by the
        // task that opens the file. A target that is relative, has a `.`/`..`
        // component or is too long is refused, not guessed at.
        CapKind::File => crate::file_cap::file_tree_grant_cap(tid, target, perms)
            .map(|c| c.raw()),
        CapKind::Disk => parse_dotted(target, "disk.part")
            .and_then(|i| crate::disk_cap::disk_part_grant_cap(tid, i, perms))
            .map(|c| c.raw()),
        CapKind::Endpoint => parse_endpoint_name(target)
            .and_then(|n| crate::endpoint::endpoint_named_cap(tid, perms, n))
            .map(|c| c.raw()),
        // U06-9 (2026-09-26). Singleton, like `Buzzer` — but unlike
        // `Buzzer`/`Adc`/`Disk`/`NetConfig` this kind DOES have a minter:
        // `SYS_LINK_KEY_READ_TYPED` needs a `Cap<LinkKey>` to reach ring 3 at
        // all, and there is exactly one key per board, so the resource this
        // grants is always `0`. Same rule as `Endpoint` above: a target
        // other than the bare kind name is REFUSED rather than ignored, so a
        // typo in `CAPS.TOML` cannot be mistaken for "no grant" —
        // `"linkkey.0"` looks like it selects something and would otherwise
        // silently mint the one and only key anyway.
        CapKind::LinkKey if target == "linkkey" => {
            crate::cap_store::grant::<crate::cap::targets::LinkKey>(tid, perms, 0)
                .map(|c| c.raw())
        }
        CapKind::LinkKey => None,
        // Wave 9 (P9): `SYS_ENTROPY_READ_TYPED`'s capability. Singleton and
        // minted, same shape and same bare-name rule as `LinkKey` above —
        // `"entropy.0"` is refused rather than read as a grant.
        CapKind::Entropy if target == "entropy" => {
            crate::cap_store::grant::<crate::cap::targets::Entropy>(tid, perms, 0)
                .map(|c| c.raw())
        }
        CapKind::Entropy => None,
        // Wave 12 (owner round 48): the full task list. `/proc/tasks` and
        // `/proc/<tid>` show a reader only itself and its descendants unless
        // its table holds this (`kernel/src/boot/procfs.rs`). One target,
        // `"tasks"`, resource 0, and `READ` only: there is nothing to write,
        // and a broader permission is refused rather than trimmed, as
        // `Launch` refuses anything but `EXEC`. Any other target is refused:
        // `"task.7"` reads as a grant over one task, which this is not.
        CapKind::Task if target == "tasks" && perms == CapPerms::READ => {
            crate::cap_store::grant::<crate::cap::targets::Task>(tid, perms, 0)
                .map(|c| c.raw())
        }
        CapKind::Task => None,
        // RFC-0055 (wave 11): named in the parser AND minted here in the same
        // commit. The target is an image name (`"TOOLBOX.ELF"`), interned by
        // `crate::launch_cap`; only `EXEC` is granted, anything else is
        // refused rather than trimmed.
        CapKind::Launch => crate::launch_cap::launch_grant_cap(tid, target, perms)
            .map(|c| c.raw()),
        // Wave 11 (SHMRING): a kernel sensor stream, `stream.<name>`, through
        // the minter the kernel installs ([`set_shm_stream_minter`];
        // `crate::stream_ring::stream_seed_mint`). Owner decision 2026-10-03:
        // this grant IS the authority to read the stream, with no
        // per-frame check after it. Any other `Shm` target is refused, not
        // read as "no minter": a region that does not exist at boot has no
        // name to seed. Without an installed minter (a host test, or a kernel
        // with every stream off) a stream target is refused too.
        CapKind::Shm if target.starts_with("stream.") => shm_stream_mint(tid, target, perms),
        CapKind::Shm => None,
        // No typed minter yet — see the doc comment above for the full list
        // and why each one is a documented gap, not an oversight. Returned
        // early so it reads as `NoMinter`, never as a refusal.
        _ => return SeedOutcome::NoMinter,
    })
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

/// Parse `"<prefix>.<u32>"`, e.g. `"motor.0"`, `"gpio.5"`, `"pwm.2"`.
fn parse_dotted(s: &str, prefix: &str) -> Option<u32> {
    let rest = s.strip_prefix(prefix)?.strip_prefix('.')?;
    rest.parse::<u32>().ok()
}

/// Parse `"bus.<u8>/0x<hex u8>"`, e.g. `"bus.0/0x68"` — the I2C target
/// convention documented in `crates/core/topology/src/types.rs` and RFC-0005.
fn parse_i2c(s: &str) -> Option<(u8, u8)> {
    let rest = s.strip_prefix("bus.")?;
    let (bus_s, addr_s) = rest.split_once('/')?;
    let bus = bus_s.parse::<u8>().ok()?;
    let addr_hex = addr_s.strip_prefix("0x")?;
    u8::from_str_radix(addr_hex, 16).ok().map(|addr| (bus, addr))
}

/// Parse a bare decimal `u32` — see [`seed_one_cap`]'s `Channel` doc for why
/// this, and only this, is accepted for channel targets today.
fn parse_plain_u32(s: &str) -> Option<u32> {
    s.parse::<u32>().ok()
}

/// Match a target against one exact bare word — `"power"`, `"ai.session"`.
/// `Power` and `AiSession` name no sub-resource (see [`seed_one_cap`]'s doc
/// for both), so unlike `gpio.5` there is nothing to select and anything
/// other than the word itself is refused, the same rule
/// [`parse_endpoint_name`] applies to `"endpoint.0"`.
fn parse_bare_name(target: &str, want: &str) -> Option<()> {
    if target == want { Some(()) } else { None }
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────
//
// `gpio_cap.rs`/`i2c_cap.rs`/`pwm_cap.rs`/`motor_cap.rs` all reach into
// `azos_drv_*`, which is RV64-only (via `azos_arch`), so these
// tests — like the modules above — only run when pulled in by a host test
// crate that supplies stand-ins for `azos_sync`/`azos_sched`/
// `azos_drv_*`. See `tests/host/topology-tests`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::CapError;

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
        let tid = tests_support::fresh_tid();

        // No minter at all: a documented gap in the kernel.
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Port, CapPerms::RW, "port"),
            SeedOutcome::NoMinter,
        );

        // Has a minter, and the minter says no — a malformed target. `Pwm`
        // stands in for any always-minted kind (`Motor` is gated behind
        // `profile-actuation`, M40, and this property does not depend on it).
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Pwm, CapPerms::WRITE, "pwm.left"),
            SeedOutcome::Refused,
        );

        // Has a minter and succeeds.
        assert!(matches!(
            seed_one_cap_outcome(tid, CapKind::Pwm, CapPerms::WRITE, "pwm.0"),
            SeedOutcome::Minted(_),
        ));

        // The `Option` view keeps its old meaning: nothing minted, either way.
        assert!(seed_one_cap(tid, CapKind::Port, CapPerms::RW, "port").is_none());
        assert!(seed_one_cap(tid, CapKind::Pwm, CapPerms::WRITE, "pwm.left").is_none());
    }

    /// An endpoint grant is refused, not silently skipped, when the name
    /// already has a live server: the second task would otherwise start as a
    /// client with nobody saying so.
    #[test]
    fn a_second_server_on_one_endpoint_name_is_a_refusal_not_a_gap() {
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

    #[test]
    fn seeds_gpio_i2c_pwm_and_channel_by_target_convention() {
        let tid = tests_support::fresh_tid();
        // A Channel capability names a live channel's generation (RFC-0040
        // gap 1), so channel 7 must exist: `channel_create` is first-free.
        let _pool = tests_support::channel_pool();
        for _ in 0..=7 {
            crate::channel::channel_create().expect("channel pool");
        }

        let gpio = seed_one_cap(tid, CapKind::Gpio, CapPerms::RW, "gpio.5").unwrap();
        let i2c = seed_one_cap(tid, CapKind::I2c, CapPerms::RW, "bus.0/0x68").unwrap();
        let pwm = seed_one_cap(tid, CapKind::Pwm, CapPerms::WRITE, "pwm.2").unwrap();
        let chan = seed_one_cap(tid, CapKind::Channel, CapPerms::READ, "7").unwrap();
        let live7 = crate::channel::channel_ref(7).expect("channel 7 is live");

        use crate::cap::{targets, Cap};
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::Gpio>::from_raw(gpio), CapPerms::READ),
            Ok(5)
        );
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::I2c>::from_raw(i2c), CapPerms::READ),
            Ok((0u32 << 8) | 0x68)
        );
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::Pwm>::from_raw(pwm), CapPerms::WRITE),
            Ok(2)
        );
        // The packed (index, generation) of the live channel 7, not the bare 7.
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::Channel>::from_raw(chan), CapPerms::READ),
            Ok(live7)
        );
        assert_eq!(crate::cap::objref::CHANNEL.idx(live7), 7);
        assert_ne!(crate::cap::objref::CHANNEL.gen(live7), 0);
        assert_ne!(live7, 7, "the capability carries the generation");
        // An inactive channel mints nothing.
        assert!(seed_one_cap(tid, CapKind::Channel, CapPerms::READ, "8").is_none());
    }

    /// M40 (audit U10-6, owner-confirmed 2026-09-26): `CapKind::Motor` has no
    /// live minting path in a build without `profile-actuation` — the parser
    /// cannot produce the kind from a signed TOML, the builder cannot declare
    /// a `CapSpec` for it, and now `seed_one_cap_outcome`'s own match has no
    /// arm for it either, so a caller that reaches this function with
    /// `CapKind::Motor` anyway (this test, standing in for "some other way")
    /// falls into the same `NoMinter` every other kind without a minter gets.
    #[test]
    #[cfg(not(feature = "profile-actuation"))]
    fn motor_has_no_minter_without_the_actuation_profile() {
        let tid = tests_support::fresh_tid();
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Motor, CapPerms::RW, "motor.0"),
            SeedOutcome::NoMinter,
        );
        assert!(seed_one_cap(tid, CapKind::Motor, CapPerms::RW, "motor.0").is_none());
    }

    /// The other half of the M40 pair: with `profile-actuation` on, `Motor`
    /// mints exactly like `Pwm`/`Gpio` do — a malformed target is a genuine
    /// `Refused`, not `NoMinter`, and a well-formed one mints.
    #[test]
    #[cfg(feature = "profile-actuation")]
    fn motor_mints_when_the_actuation_profile_is_enabled() {
        let tid = tests_support::fresh_tid();
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Motor, CapPerms::RW, "motor.left"),
            SeedOutcome::Refused,
            "has a minter, and the minter says no — a malformed target",
        );
        let motor0 = seed_one_cap(tid, CapKind::Motor, CapPerms::RW, "motor.0").unwrap();
        use crate::cap::{targets, Cap};
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::Motor>::from_raw(motor0), CapPerms::WRITE),
            Ok(0)
        );
    }

    #[test]
    fn unparseable_or_unminted_kinds_are_skipped_not_panicked() {
        let tid = tests_support::fresh_tid();
        // Path-shaped channel target — no name→id registry, must be skipped.
        assert!(seed_one_cap(tid, CapKind::Channel, CapPerms::READ, "/safety/estop").is_none());
        // Malformed motor target.
        assert!(seed_one_cap(tid, CapKind::Motor, CapPerms::RW, "motor").is_none());
        assert!(seed_one_cap(tid, CapKind::Motor, CapPerms::RW, "motor.left").is_none());
        // `Sensor` gained a minter on 2026-09-07, so it moved from "no minter"
        // to "minted, with its own bound": a malformed target is still
        // skipped, and so is a type the kernel does not dispatch.
        assert!(seed_one_cap(tid, CapKind::Sensor, CapPerms::READ, "sensor").is_none());
        assert!(seed_one_cap(tid, CapKind::Sensor, CapPerms::READ, "sensor.imu").is_none());
        assert!(seed_one_cap(tid, CapKind::Sensor, CapPerms::READ, "sensor.10").is_none());
        // `Task` mints only `"tasks"` (wave 12): the bare kind name is not it.
        assert!(seed_one_cap(tid, CapKind::Task, CapPerms::READ, "task").is_none());
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
        match seed_one_cap_outcome(tid, CapKind::Task, CapPerms::READ, "tasks") {
            SeedOutcome::Minted(_) => {}
            _ => panic!("Cap<Task> READ on \"tasks\" must mint"),
        }
        assert!(crate::cap_store::with_table(tid, |t| {
            t.holds_kind_resource_with(CapKind::Task, 0, CapPerms::READ)
        }).unwrap_or(false));
        let other = tests_support::fresh_tid();
        assert_eq!(seed_one_cap_outcome(other, CapKind::Task, CapPerms::RW, "tasks"), SeedOutcome::Refused);
        assert_eq!(seed_one_cap_outcome(other, CapKind::Task, CapPerms::READ, "task.7"), SeedOutcome::Refused);
        assert_eq!(seed_one_cap_outcome(other, CapKind::Task, CapPerms::READ, "task"), SeedOutcome::Refused);
        assert!(!crate::cap_store::with_table(other, |t| {
            t.holds_kind_resource_with(CapKind::Task, 0, CapPerms::READ)
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
        let irq3 = seed_one_cap(tid, CapKind::Irq, CapPerms::READ, "irq.3").unwrap();
        use crate::cap::{targets, Cap};
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::Irq>::from_raw(irq3), CapPerms::READ),
            Ok(3)
        );
        assert!(seed_one_cap(tid, CapKind::Irq, CapPerms::READ, "irq.0").is_none(), "line 0");
        assert!(
            seed_one_cap(tid, CapKind::Irq, CapPerms::READ, "irq.999999").is_none(),
            "past MAX_IRQS"
        );
        assert!(seed_one_cap(tid, CapKind::Irq, CapPerms::READ, "irq").is_none(), "malformed target");
    }

    /// Wave 3 (2026-09-26): `Power`/`AiSession` gained minters. The bare
    /// target mints; anything else (including the shapes `service-call`
    /// TOML rows have historically used, like `"policy.run"`) is a real
    /// `Refused` now, not the old `NoMinter`.
    #[test]
    fn power_and_ai_session_mint_on_the_bare_target_and_refuse_anything_else() {
        let tid = tests_support::fresh_tid();
        use crate::cap::{targets, Cap};

        let power = seed_one_cap(tid, CapKind::Power, CapPerms::WRITE, "power").unwrap();
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::Power>::from_raw(power), CapPerms::WRITE),
            Ok(0)
        );
        let ai = seed_one_cap(tid, CapKind::AiSession, CapPerms::WRITE, "ai.session").unwrap();
        assert_eq!(
            crate::cap_store::get(tid, Cap::<targets::AiSession>::from_raw(ai), CapPerms::WRITE),
            Ok(0)
        );

        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Power, CapPerms::WRITE, "power.0"),
            SeedOutcome::Refused,
        );
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::AiSession, CapPerms::WRITE, "policy.run"),
            SeedOutcome::Refused,
            "a service-call-shaped target has a minter now and must be refused, not skipped",
        );
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::AiSession, CapPerms::WRITE, "ai-session"),
            SeedOutcome::Refused,
            "the KIND word and the TARGET word are different strings",
        );
    }

    #[test]
    fn without_seeding_the_typed_consumer_path_sees_stale() {
        // Mirrors exactly what `crates/core/syscall/src/handlers.rs`'s
        // `sys_motor_set_target_typed` does: decode a raw handle the caller
        // never actually received, and dereference it through cap_store.
        use crate::cap::{targets::Motor, Cap};
        let tid = tests_support::fresh_tid();
        let forged: Cap<Motor> = Cap::NULL;
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
        static NEXT_ID: AtomicU32 = AtomicU32::new(1);

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

        /// The channel pool is process-global. The test that creates channels
        /// holds this and starts from an empty pool.
        pub fn channel_pool() -> std::sync::MutexGuard<'static, ()> {
            static POOL: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let g = POOL.lock().unwrap_or_else(|e| e.into_inner());
            crate::channel::__channel_reset_for_tests();
            g
        }
    }
}
