// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Typed capability wrapper — RFC-0003.
//!
//! `Cap<T>` is a `#[repr(transparent)]` newtype over the wire-format
//! `CapHandle` from [`azos_abi::cap`]. The type parameter `T` is a
//! marker carrying the kind at compile time — so `Cap<Port>` and
//! `Cap<Socket>` are distinct types that the type system refuses to
//! interchange.
//!
//! ## Why typed?
//!
//! Today (W1) the kernel still accepts integer handles end-to-end — see
//! [`super::handle`]. From W3 onwards new syscalls take `Cap<T>` directly:
//!
//! ```ignore
//! // The old, kind-erased shape:
//! pub fn sys_file_write(handle: u32, data_ptr: *const u8, len: usize) -> i64;
//!
//! // The new, kind-typed shape:
//! pub fn sys_file_write(cap: Cap<Port>, data_ptr: *const u8, len: usize) -> Result<usize, Errno>;
//! ```
//!
//! A `Cap<Port>` cannot be passed where `Cap<Socket>` is expected;
//! that's a compile error, not a runtime check.
//!
//! ## Forgery resistance
//!
//! On **dereference** (`cap_table::get(&cap)`) the kernel verifies:
//!
//! 1. The slot index is in range.
//! 2. The slot is occupied (`generation > 0`).
//! 3. The handle's generation matches the slot's generation.
//! 4. The handle's kind tag matches `T::TYPE`.
//! 5. The handle's permission bits ⊆ slot's permission bits.
//!
//! Any failure returns [`Errno::ECAPSTALE`], [`Errno::ECAPKIND`], or
//! [`Errno::ECAPPERMS`].
//!
//! ## Generation rollover
//!
//! The slot generation is 13 bits (`CapHandle::GEN_BITS` in `azos_abi`).
//! It never wraps: a slot whose generation reaches
//! [`CapHandle::MAX_GENERATION`] is retired instead of starting over, so a
//! revoked handle can never validate again against a later grant of the same
//! slot. Generation `0` means an empty slot and is never issued.
//!
//! ## Object generation
//!
//! The slot generation answers "is this still the capability that was
//! granted". Whether the object it names is still the object it was granted
//! on is answered, for the kinds [`objref::is_packed_kind`] names, by the
//! object generation packed into [`CapSlot::resource`]; see [`objref`].

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

pub use azos_abi::cap::{slot_word, ty, CapHandle, CapKind, CapPerms, CapType, CAP_NULL};
use wcet_macro::wcet;

// ──────────────────────────────────────────────────────────────────────────
// Graded degraded mode — capability containment + speed ceiling (RFC-0037)
// ──────────────────────────────────────────────────────────────────────────
//
// Generalises the binary RFC-0036 armed/cleared flag into an ordered level
// so the brain can select a graded restriction. Higher = more restrictive.
//
// The level taxonomy is defined here, in the crate that holds the level state
// and enforces containment at `CapTable::get`. The level -> speed-ceiling
// mapping is motor policy and stays in the robot domain's dep-free leaf
// `azos_degrade_policy` (domains/robot/degrade-policy), which declares the
// same five numbers for its own mapping; `azos_behavior::safety` asserts
// at compile time that the two agree. Wave 11 (DOMAIN): until then this file
// re-exported the levels and the speed ceilings from that leaf, so every image
// linked a robot crate for five constants.
//
// The level is *sticky*: it stays until the brain sends a new `PKT_SEMANTIC_LEVEL`
// or a `PKT_DEGRADE`/`MODE_CMD`. Fail-closed-on-link-loss is provided by the
// existing motor watchdog (500 ms), not by a TTL here — same pattern as
// `CMD_LOW_CONF` in `safety.rs`.
//
// Constrain-only: this can only deny / slow, never grant — a hallucinating brain
// can at worst over-contain (fail-safe). It is a global (set at packet ingest,
// read at each chokepoint); coarse but correct and conservative.

/// No extra restriction — normal operation.
pub const DEGRADE_LEVEL_FULL: u8 = 0;
/// Cautious operation (RFC-0037).
pub const DEGRADE_LEVEL_CAUTIOUS: u8 = 1;
/// Slow operation (RFC-0037).
pub const DEGRADE_LEVEL_SLOW: u8 = 2;
/// Full containment: every user-task write/actuation capability is denied at
/// `CapTable::get` (RFC-0036 semantics).
pub const DEGRADE_LEVEL_CONTAINED: u8 = 3;
/// Maximum valid level; anything above is clamped to it (fail-closed).
pub const DEGRADE_LEVEL_MAX: u8 = DEGRADE_LEVEL_CONTAINED;

static DEGRADE_LEVEL: AtomicU8 = AtomicU8::new(DEGRADE_LEVEL_FULL);

/// Set the graded degrade level (RFC-0037). Any value greater than
/// `DEGRADE_LEVEL_MAX` is clamped to `DEGRADE_LEVEL_CONTAINED` (fail-closed on
/// out-of-range wire input — never panic).
pub fn degrade_level_set(level: u8) {
    let clamped = level.min(DEGRADE_LEVEL_MAX);
    DEGRADE_LEVEL.store(clamped, Ordering::Release);
}

/// Current graded degrade level. `DEGRADE_LEVEL_FULL` (0) means normal
/// operation; higher values impose progressively tighter constraints.
#[inline]
pub fn degrade_level() -> u8 {
    DEGRADE_LEVEL.load(Ordering::Acquire)
}

// ── RFC-0036 back-compat shim ─────────────────────────────────────────────
//
// All existing callers (`PKT_DEGRADE` handler, `MODE_CMD` handler, Kani proofs,
// unit tests) continue to use `degraded_set` / `degraded_active` unchanged.
// Internally they now delegate to the graded level so the two APIs stay
// consistent — `degraded_active() == true` iff `degrade_level() == CONTAINED`.

/// Arm or clear degraded mode (RFC-0036 back-compat). `true` → CONTAINED;
/// `false` → FULL. Use `degrade_level_set` for graded control.
pub fn degraded_set(on: bool) {
    if on {
        degrade_level_set(DEGRADE_LEVEL_CONTAINED);
    } else {
        degrade_level_set(DEGRADE_LEVEL_FULL);
    }
}

/// Whether full containment (RFC-0036) is currently active.
/// Returns `true` only at `DEGRADE_LEVEL_CONTAINED`; CAUTIOUS and SLOW do NOT
/// trip cap-denial — they only clamp speed via `motor_envelope`.
#[inline]
pub fn degraded_active() -> bool {
    degrade_level() == DEGRADE_LEVEL_CONTAINED
}

// ──────────────────────────────────────────────────────────────────────────
// Cap<T> — typed handle
// ──────────────────────────────────────────────────────────────────────────

/// Marker trait implemented by every capability target type. Carries the
/// `CapType` (kind and class) at compile time.
///
/// New targets are added as zero-sized marker types in [`mod targets`].
pub trait CapTarget: 'static {
    /// The type (kind and class) this target type stands for.
    const TYPE: CapType;
}

/// A typed capability handle.
///
/// `Cap<T>` is `#[repr(transparent)]` over [`CapHandle`] so that it has
/// the same ABI as the wire format. The `PhantomData<T>` is zero-sized.
#[repr(transparent)]
pub struct Cap<T: CapTarget> {
    raw: CapHandle,
    _phantom: PhantomData<fn() -> T>,
}

// Manual `Clone` / `Copy` so we can stay generic over `T` without
// requiring `T: Clone`.
impl<T: CapTarget> Clone for Cap<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: CapTarget> Copy for Cap<T> {}

impl<T: CapTarget> PartialEq for Cap<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}
impl<T: CapTarget> Eq for Cap<T> {}

impl<T: CapTarget> Cap<T> {
    /// The null typed cap.
    pub const NULL: Self = Self {
        raw: CAP_NULL,
        _phantom: PhantomData,
    };

    /// Construct from a wire-format `CapHandle`. Does **not** verify the
    /// kind matches `T`; that check happens on dereference via
    /// `cap_table::get`.
    #[inline]
    pub const fn from_raw(raw: CapHandle) -> Self {
        Self { raw, _phantom: PhantomData }
    }

    /// Get the underlying wire-format handle.
    #[inline]
    pub const fn raw(self) -> CapHandle {
        self.raw
    }

    /// Returns `true` iff this is the null cap.
    #[inline]
    pub const fn is_null(self) -> bool {
        self.raw.is_null()
    }
}

impl<T: CapTarget> core::fmt::Debug for Cap<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cap<{}>({:?})", core::any::type_name::<T>(), self.raw)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Marker types for each capability target
// ──────────────────────────────────────────────────────────────────────────

/// Zero-sized marker types used as the `T` in `Cap<T>`.
pub mod targets {
    use super::{ty, CapTarget, CapType};

    macro_rules! target {
        ($name:ident, $ty:ident, $doc:literal) => {
            #[doc = $doc]
            pub struct $name;
            impl CapTarget for $name {
                const TYPE: CapType = ty::$ty;
            }
        };
    }

    target!(Shm,        SHM,        "Shared memory region.");
    target!(Port,       PORT,       "Event port.");
    target!(Irq,        IRQ,        "Hardware IRQ binding.");
    target!(MmioRegion, MMIO, "A hardware-bus device's register window.");
    target!(IoRing,     IORING,     "IO ring.");
    target!(File,       FILE,       "File descriptor.");
    target!(Socket,     SOCKET,     "Socket descriptor.");
    target!(Task,       TASK,       "Process / task handle.");
    // A marker type is inert on its own — it is what a `Cap<T>` is
    // parameterised by, not a grant.
    target!(DriverRegistry, DRIVER_REGISTRY,
            "The right to register as the driver for one `DRV_KIND_*`.");
    // RFC-0040 gap 2 (2026-09-19). Unlike the five above, this one is minted
    // from the start (`crate::endpoint`): an endpoint capability that nothing
    // can hold would close no hole, and a kind declared but never minted is
    // exactly the trap `ty::TASK` fell into until wave 12 — nameable in
    // `CAPS.TOML`, silently granting nothing.
    target!(Endpoint,   ENDPOINT,   "Fast-IPC endpoint: the right to send a request to the service listening on it.");
    // Wave 9. Minted only by `MEMOBJ_LEASE_GRANT` (never by a topology row:
    // `cap_seed` has no arm for it and the parser no name), revoked by
    // `lease::lease_free`.
    target!(Lease,      LEASE,      "One lease, held by its lessor: the right to wait on it (and donate to its lessee).");
    // RFC-0055 (wave 11). Minted only by `DOMAIN_CREATE_PIPE`, into the caller's
    // own table (never by a topology row): `crate::pipe`.
    target!(Pipe,       PIPE,       "One end of a pipe: READ for the read end, WRITE for the write end.");
    // RFC-0055 (wave 11). Seeded from the topology word `"launch"`; the
    // resource is an interned image name (`crate::launch_cap`).
    target!(Launch,     LAUNCH,     "The right to start one image with SYS_SPAWN_EX.");
    // Wave 15 (TRACE). Seeded from the topology word `"trace"`; resource 0.
    target!(Trace,      TRACE,      "The kernel tracer: map its rings, read and set its class mask.");
    // D6. Seeded into every task at admission (`cap_seed::seed_console`), never
    // by a topology row; resource 0.
    target!(Console,    CONSOLE,    "The console: WRITE puts bytes on it, READ waits for input on it.");
}

// ──────────────────────────────────────────────────────────────────────────
// Trace minter — RFC-0003 W5, wave 3 (2026-09-26)
// ──────────────────────────────────────────────────────────────────────────
//
// Owner decision (2026-09-26): one authority per irreversible effect. Each of
// these is the one-function-over-`cap_store::grant` shape every typed kind uses
// (compare `motor_cap::motor_grant_cap`). Single-resource, not pair-wide: there is
// one tracer, one time warrant and one AI-inference-session slot to name, so
// each mints and checks at `resource = 0`.

/// Mint a `Cap<Console>` for `tid` (D6), `READ|WRITE`. Resource `0`: one
/// console per kernel.
pub fn console_grant_cap(tid: u32) -> Option<Cap<targets::Console>> {
    crate::cap_store::grant::<targets::Console>(tid, CapPerms::RW, 0)
}

/// Mint a `Cap<Trace>` for `tid` (wave 15). `resource` is always `0`: one
/// tracer per kernel.
pub fn trace_grant_cap(tid: u32, perms: CapPerms) -> Option<Cap<targets::Trace>> {
    crate::cap_store::grant::<targets::Trace>(tid, perms, 0)
}

// ──────────────────────────────────────────────────────────────────────────
// Per-task cap table — kernel-internal
// ──────────────────────────────────────────────────────────────────────────

/// Maximum cap-table slots per task. RFC-0003 sets this in `SCHED.TOML`
/// per partition; the build-time constant is the *upper bound*.
///
/// **Imported, not restated (2026-09-18).** This was `= 256`, hardcoded,
/// while `config/Kconfig.limits` declared the same name with per-profile values
/// (32 embedded / 256 edge / 512 fleet) and generated it into
/// `azos_limits`. So building any profile other than edge left the cap
/// table the wrong size — RFC-0026's entire point, silently defeated — and,
/// worse, the assert below could never fire on it: it compared against this
/// local copy rather than the configured value. `crates/core/topology/src/types.rs`
/// was already importing its neighbours `MAX_TASKS`/`MAX_CAPS_TOTAL` this way.
pub use azos_limits::MAX_CAPS_PER_TASK;

/// The slot field in a packed [`CapHandle`] must be able to address every one
/// of those slots.
///
/// `crates/core/abi` is dependency-free by design, so it cannot import this
/// constant and carries a mirror of it instead. That mirror's own assert binds
/// only itself — it would still hold if THIS number grew — so the pair is
/// closed from this side. Without it the failure is silent and ugly: raising
/// `MAX_CAPS_PER_TASK` past 256 would make `pack()` truncate slot indices, and
/// two different capabilities would answer to the same handle.
///
/// Written the day four independent tables of syscall numbers were collapsed
/// into one. A constant restated in a second crate is the same shape, and the
/// answer when the import is genuinely impossible is an assertion, not a
/// comment asking the next reader to remember.
const _: () = assert!(
    (1usize << azos_abi::cap::CapHandle::SLOT_BITS) >= MAX_CAPS_PER_TASK,
    "MAX_CAPS_PER_TASK outgrew the slot field in CapHandle — widen SLOT_BITS \
     (there are reserved bits next to it) or lower this constant"
);

/// One slot in a per-task cap table.
///
/// **Occupancy** is tracked by `kind`: `CapType::NULL` means the slot
/// is free for reuse. **Generation** is a monotonic per-slot counter
/// that survives revoke; it is *only* reset when the slot has never
/// been granted. This separation is what makes a stale cap impossible
/// to confuse with a freshly granted cap on the same slot.
#[derive(Clone, Copy)]
pub struct CapSlot {
    /// Kind of the resource this slot points to. `CapType::NULL` ⇒ slot
    /// is empty.
    pub ty: CapType,
    /// Permissions granted on this slot.
    pub perms: CapPerms,
    /// Monotonic generation counter, always non-zero on a granted slot.
    /// Survives revoke so that a re-grant gets a fresh generation and the
    /// previous holder's `Cap` is detectably stale.
    ///
    /// **It does not wrap.** It used to: `255 → 1`, with no sweep, which made
    /// the 256th grant of a slot reissue a generation a previous holder still
    /// held — its revoked handle validated again, against whatever object now
    /// sat in the slot. A use-after-revoke, reachable from ring 3 by creating
    /// and destroying an object in a loop. At [`CapHandle::MAX_GENERATION`]
    /// (8,191 with the 13-bit field) the slot is **retired** instead:
    /// [`CapTable::grant_raw`] never allocates it again, so no generation is
    /// ever reissued. A task that exhausts every slot this way gets `None`
    /// from its own grants and breaks nothing but itself; `retired()` counts
    /// them so the condition is observable rather than silent.
    pub generation: u16,
    /// Resource-specific value; the resource subsystem owns interpreting it.
    /// For the kinds [`objref::is_packed_kind`] names (Port, Shm,
    /// IoRing) it is a packed `(pool index, object generation)`. For every
    /// other kind it is the bare id (motor, pin, sensor type, ...).
    pub resource: u32,
}

impl CapSlot {
    /// Construct a fresh, never-granted slot.
    pub const EMPTY: Self = Self {
        ty: CapType::NULL,
        perms: CapPerms::NONE,
        generation: 0,
        resource: 0,
    };

    /// Returns `true` iff the slot currently holds a granted cap.
    #[inline]
    pub const fn is_occupied(&self) -> bool {
        self.ty.raw() != CapType::NULL.raw()
    }

    /// Spent: its generation has reached the field's maximum, so granting it
    /// again could only reissue a generation some previous holder still has.
    /// Never allocated again, occupied or not.
    #[inline]
    pub const fn is_retired(&self) -> bool {
        self.generation >= CapHandle::MAX_GENERATION
    }
}

/// One slot as stored: a [`CapSlot`] packed into one 64-bit word, so a
/// lock-free reader (`cap_store`'s QSBR reads, Kconfig RCU_QSBR) sees a
/// slot whole or not at all, never the old kind with the new resource.
/// Bits 0..8 kind, 8..16 permissions, 16..32 generation, 32..64 resource.
/// Writers still serialise on the table's lock; every access is one atomic
/// load or store, a plain one on every ISA.
struct CapSlotCell(core::sync::atomic::AtomicU64);

impl CapSlotCell {
    /// The encoding of [`CapSlot::EMPTY`] is 0 (kind Null is 0): the tables
    /// start in `.bss` and a wipe stores 0.
    const EMPTY: Self = CapSlotCell(core::sync::atomic::AtomicU64::new(0));

    #[inline(always)]
    const fn encode(s: CapSlot) -> u64 {
        slot_word::encode(s.ty, s.perms, s.generation, s.resource)
    }

    #[inline(always)]
    fn decode(w: u64) -> CapSlot {
        CapSlot {
            ty: slot_word::ty(w),
            perms: slot_word::perms(w),
            generation: slot_word::generation(w),
            resource: slot_word::resource(w),
        }
    }

    #[inline(always)]
    fn word(&self) -> u64 {
        self.0.load(core::sync::atomic::Ordering::Relaxed)
    }

    // The fields of a word, without decoding the kind (a scan's hot loop).
    #[inline(always)]
    const fn w_occupied(w: u64) -> bool {
        slot_word::occupied(w)
    }
    #[inline(always)]
    const fn w_ty_is(w: u64, k: CapType) -> bool {
        slot_word::ty_is(w, k)
    }
    #[inline(always)]
    const fn w_perms(w: u64) -> CapPerms {
        slot_word::perms(w)
    }
    #[inline(always)]
    const fn w_generation(w: u64) -> u16 {
        slot_word::generation(w)
    }
    #[inline(always)]
    const fn w_resource(w: u64) -> u32 {
        slot_word::resource(w)
    }

    #[inline(always)]
    fn load(&self) -> CapSlot {
        Self::decode(self.word())
    }

    /// A test seeds a slot with it; the kernel's stores go through
    /// `grant_warranted`, which publishes the warrant first.
    #[cfg(test)]
    fn store(&self, s: CapSlot) {
        self.0.store(Self::encode(s), core::sync::atomic::Ordering::Relaxed);
    }

    /// Free the slot, keeping its generation (bumped on the next grant).
    #[inline(always)]
    fn clear(&self) {
        let w = self.word();
        self.0.store(slot_word::cleared(w), core::sync::atomic::Ordering::Relaxed);
    }
}

const _: () = assert!(CapSlotCell::encode(CapSlot::EMPTY) == 0, "an empty slot must encode as 0");

impl CapSlotCell {
    /// Hot-word bit 12, above the four permission bits: the slot's warrant
    /// carries a deadline. A reader that loads only this word sees the flag and
    /// goes to the warrant for the deadline; the word a lock-free resolve
    /// cache compares ([`CapTable::word_grants`]) never grants while it is set,
    /// so an expiring capability is never answered from a cache. Cleared with
    /// the slot (`clear` keeps only the generation).
    const EXPIRES: u64 = slot_word::EXPIRES;

    #[inline(always)]
    const fn w_expires(w: u64) -> bool {
        slot_word::expires(w)
    }
}

// ── The second word of a slot (wave 15 N11, owner Q9) ───────────────────────
//
// A slot is 128 bits, CHERI-representable: the hot word above (kind 8 |
// permissions 8 | generation 16 | resource 32, unchanged) and this extension
// word. The hot word is the only one a v1 path reads; the extension word is
// read only by the paths that need what it holds (the badge on a v2 call),
// so the v1 fast call loads exactly what it loaded before.
//
//   ext bits  0..32  badge: the per-client identity a server sees on a call
//                     through this capability (0: unbadged)
//   ext bits 32..48  unused (0)
//   ext bits 48..56  rights width: eight more permission bits, reserved (0)
//   ext bits 56..64  unused (0)
//
// The parent link and the expiry are the slot's WARRANT (`Warrant`), a third
// record beside these two words: a parent is a slot of any domain, which 16
// bits of a table-local index could not name.
//
// The rights byte of the hot word has no spare bit: "rights width" is the
// byte here, read together with it once a right needs it.
//
// Kconfig CAP_SLOT_EXT: off, the extension array has no element, every slot
// reads as `CapExt::NONE` and minting a badged capability is refused.

/// Kconfig `CAP_SLOT_EXT`: slots carry the extension word.
pub const SLOT_EXT: bool = azos_limits::CAP_SLOT_EXT;

/// Canary (wave 15 N11b): [`CapTable::install_at`], the fork copy, leaves
/// the slot's extension word as the table's previous owner left it, so a
/// fork child can read a stranger's badge.
static CANARY_INSTALL_KEEPS_EXT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm (`true`) or disarm the `install_at` extension-word canary.
pub fn canary_install_keeps_ext(on: bool) {
    CANARY_INSTALL_KEEPS_EXT.store(on, core::sync::atomic::Ordering::Relaxed);
}
const EXT_SLOTS: usize = if SLOT_EXT { MAX_CAPS_PER_TASK } else { 0 };

/// The extension word of a slot, decoded (see the layout above).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapExt {
    /// Per-client identity a server sees on a call through the capability.
    pub badge: u32,
    /// Reserved: eight more permission bits.
    pub rights_hi: u8,
}

impl CapExt {
    /// No badge, nothing reserved in use.
    pub const NONE: Self = CapExt { badge: 0, rights_hi: 0 };

    /// The word as stored.
    #[inline(always)]
    pub const fn encode(self) -> u64 {
        (self.badge as u64) | ((self.rights_hi as u64) << 48)
    }

    /// The word decoded.
    #[inline(always)]
    pub const fn decode(w: u64) -> Self {
        CapExt { badge: w as u32, rights_hi: (w >> 48) as u8 }
    }
}

const _: () = assert!(CapExt::NONE.encode() == 0, "a fresh extension word must encode as 0");
/// Two words: the slot fits the 128 bits of a CHERI capability (Q9).
const _: () = assert!(
    core::mem::size_of::<CapSlotCell>() + core::mem::size_of::<u64>() == 16,
    "a capability slot is 128 bits"
);

// ── The warrant of a slot (owner decision D3/L4) ────────────────────────────
//
// Every capability slot records where it came from: its PARENT, the slot of
// any domain it was derived from (a dup transfer, a badged mint), by domain
// key, slot and generation; its DEPTH below the root it descends from; an
// optional EXPIRY (a monotonic deadline) and QUOTA (a count or a number of
// bytes, a field for later charging). A slot minted from nothing (a boot
// grant, a kernel object's capability, a fork copy) is a root: parent 0.
//
// The parent is a reference, not a pointer, and it is checked, not trusted:
// a parent is alive iff its domain still owns its table and the slot still
// holds the generation the reference names. A slot's generation never repeats
// and a domain key's does not within 65,535 reuses (`azos_sched::domain`), so
// a reference to a revoked, wiped or reused slot is dead for good, and a
// descendant of it is revoked by the sweep (`cap_store`).
//
// Rights only narrow down a chain ([`derive_warrant`]); so does an expiry
// (the earlier of the parent's and the one asked) and a quota (never more
// than the parent's, in the parent's unit).
//
// Three words a slot, in a parallel array of the table (the 128-bit slot
// itself is full):
//   parent  domain key 32 | slot 16 | generation 16   (0: a root)
//   expiry  nanoseconds on the monotonic clock (0: never)
//   meta    quota amount 0..56 | depth 56..60 | quota in bytes 60 |
//           "may have children" 61
//
// "May have children" is a hint set when a slot is derived from and cleared
// with the slot: it tells a clear that a sweep is worth running, nothing
// more. Every word is written under the table lock, before the hot word that
// publishes the grant.

/// Kconfig `WARRANT_DEPTH_MAX`: the longest derivation chain below a root.
pub const WARRANT_DEPTH_MAX: usize = azos_limits::WARRANT_DEPTH_MAX as usize;
const _: () = assert!(WARRANT_DEPTH_MAX >= 1 && WARRANT_DEPTH_MAX <= 15, "the depth is 4 bits of the meta word");

/// A budget a warrant carries for later charging: `amount` of something
/// counted or measured in bytes. 0 is none.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Quota {
    pub bytes: bool,
    pub amount: u64,
}

impl Quota {
    /// No quota.
    pub const NONE: Self = Quota { bytes: false, amount: 0 };
    /// The largest amount a warrant stores (56 bits).
    pub const MAX: u64 = (1 << 56) - 1;
}

/// The warrant of one slot, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Warrant {
    /// `domain_key << 32 | slot << 16 | generation` of the slot this one was
    /// derived from; 0 for a root.
    pub parent: u64,
    /// Links between this slot and its root.
    pub depth: u8,
    /// Monotonic deadline in nanoseconds; 0 never.
    pub expiry_ns: u64,
    pub quota: Quota,
}

impl Warrant {
    /// A root: no parent, no deadline, no quota.
    pub const ROOT: Self = Warrant { parent: 0, depth: 0, expiry_ns: 0, quota: Quota::NONE };
}

const META_DEPTH_SHIFT: u32 = 56;
const META_BYTES: u64 = 1 << 60;
const META_KIDS: u64 = 1 << 61;

/// One slot's warrant as stored (three atomic words).
struct WarrantCell {
    parent: core::sync::atomic::AtomicU64,
    expiry: core::sync::atomic::AtomicU64,
    meta: core::sync::atomic::AtomicU64,
}

impl WarrantCell {
    const EMPTY: Self = WarrantCell {
        parent: core::sync::atomic::AtomicU64::new(0),
        expiry: core::sync::atomic::AtomicU64::new(0),
        meta: core::sync::atomic::AtomicU64::new(0),
    };

    #[inline(always)]
    fn store(&self, w: &Warrant) {
        use core::sync::atomic::Ordering::Relaxed;
        self.parent.store(w.parent, Relaxed);
        self.expiry.store(w.expiry_ns, Relaxed);
        let meta = (w.quota.amount & Quota::MAX)
            | (w.depth as u64) << META_DEPTH_SHIFT
            | if w.quota.bytes { META_BYTES } else { 0 };
        self.meta.store(meta, Relaxed);
    }

    #[inline(always)]
    fn load(&self) -> Warrant {
        use core::sync::atomic::Ordering::Relaxed;
        let m = self.meta.load(Relaxed);
        Warrant {
            parent: self.parent.load(Relaxed),
            depth: ((m >> META_DEPTH_SHIFT) & 0xf) as u8,
            expiry_ns: self.expiry.load(Relaxed),
            quota: Quota { bytes: m & META_BYTES != 0, amount: m & Quota::MAX },
        }
    }
}

/// What a derive asks for. Rights can only be kept or lowered; a deadline and a
/// quota can only be kept or tightened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeriveSpec {
    /// `None` keeps the source's rights, `Some(r)` lowers to exactly `r`.
    pub rights: Option<CapPerms>,
    /// A deadline for the copy; 0 inherits the source's (if any).
    pub expiry_ns: u64,
    /// A quota for the copy; `Quota::NONE` inherits the source's (if any).
    pub quota: Quota,
}

impl DeriveSpec {
    /// Keep rights, deadline and quota as the source has them.
    pub const SAME: Self = DeriveSpec { rights: None, expiry_ns: 0, quota: Quota::NONE };
}

/// The rights and warrant of a copy of the slot `src_ref` names, which holds
/// `src_perms` under `src`.
///
/// **Attenuation only.** The copy's rights are the source's or a subset (a
/// request for a bit the source lacks is `MissingPerms`, not masked: a caller
/// asking for authority it cannot give is a bug, and masking it would hide the
/// bug behind a working call); its deadline is the earlier of the source's and
/// the one asked; its quota is the source's or smaller, in the source's unit
/// (`MissingPerms` for more, or for the other unit). A chain already
/// [`WARRANT_DEPTH_MAX`] deep takes no more links (`NoSpace`).
pub fn derive_warrant(
    src_ref: u64,
    src_perms: CapPerms,
    src: &Warrant,
    spec: &DeriveSpec,
) -> Result<(CapPerms, Warrant), CapError> {
    if src.depth as usize >= WARRANT_DEPTH_MAX {
        return Err(CapError::NoSpace);
    }
    let (perms, narrowed) = narrow_warrant(src_perms, src, spec)?;
    Ok((perms, Warrant { parent: src_ref, depth: src.depth + 1, ..narrowed }))
}

/// [`derive_warrant`]'s attenuation without the new link: the rights, deadline
/// and quota of a capability that keeps `src`'s place in the tree (a MOVE that
/// lowers what it carries). The warrant it returns has `src`'s parent and depth.
pub fn narrow_warrant(src_perms: CapPerms, src: &Warrant, spec: &DeriveSpec) -> Result<(CapPerms, Warrant), CapError> {
    let perms = match spec.rights {
        None => src_perms,
        Some(r) if src_perms.contains(r) => r,
        Some(_) => return Err(CapError::MissingPerms),
    };
    let expiry_ns = match (src.expiry_ns, spec.expiry_ns) {
        (0, e) | (e, 0) => e,
        (a, b) => a.min(b),
    };
    if spec.quota.amount > Quota::MAX {
        return Err(CapError::MissingPerms);
    }
    let quota = if src.quota.amount == 0 {
        spec.quota
    } else if spec.quota.amount == 0 {
        src.quota
    } else if spec.quota.bytes != src.quota.bytes || spec.quota.amount > src.quota.amount {
        return Err(CapError::MissingPerms);
    } else {
        spec.quota
    };
    Ok((perms, Warrant { parent: src.parent, depth: src.depth, expiry_ns, quota }))
}

/// The monotonic clock a deadline is read against, in nanoseconds: the kernel
/// registers `azos_drv_sys::timebase::now()` converted (boot), a host test its
/// own. Unset, it reads as the end of time, so a warrant WITH a deadline is
/// expired (fail closed) and one without is unaffected.
static CLOCK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Register the clock ([`CLOCK`]). Boot, once (host suites per test).
pub fn set_clock(f: fn() -> u64) {
    CLOCK.store(f as usize, core::sync::atomic::Ordering::Release);
}

#[inline]
fn now_ns() -> u64 {
    let raw = CLOCK.load(core::sync::atomic::Ordering::Acquire);
    if raw == 0 {
        return u64::MAX;
    }
    // SAFETY: only `set_clock` stores here, and it stores a `fn() -> u64`.
    let f: fn() -> u64 = unsafe { core::mem::transmute::<usize, fn() -> u64>(raw) };
    f()
}

/// A slot that other slots were derived from was cleared (or a table holding
/// one was wiped): `cap_store` has descendants to find. Set under the table
/// lock, taken by the sweep.
static SWEEP_PENDING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Is a sweep owed? One load, for `cap_store`'s post-lock path.
#[inline(always)]
pub fn sweep_pending() -> bool {
    SWEEP_PENDING.load(core::sync::atomic::Ordering::Acquire)
}

/// Take the duty of a sweep: `true` for the one caller that finds it owed.
#[inline]
pub fn sweep_take() -> bool {
    SWEEP_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel)
}

/// Owe a sweep again (a sweep that ran out of passes).
#[inline]
pub fn sweep_owed() {
    SWEEP_PENDING.store(true, core::sync::atomic::Ordering::Release);
}

/// Layout of [`CapSlot::resource`] for the kinds that carry an object
/// generation (RFC-0040 gap 1). Declared here rather than at the crate root so
/// every host crate that `#[path]`-mounts this file compiles it as well.
#[path = "objref.rs"]
pub mod objref;

/// Kconfig CAP_LOOKUP_CACHE: direct-mapped lookup-cache entries per table.
const LOOKUP_CACHE: usize = azos_limits::CAP_LOOKUP_CACHE as usize;
const _: () = assert!(
    LOOKUP_CACHE == 0 || LOOKUP_CACHE.is_power_of_two(),
    "CAP_LOOKUP_CACHE must be 0 or a power of two"
);

/// The cache entry for a lookup of (`kind`, `resource`).
#[inline(always)]
const fn cache_index(kind: u8, resource: u32) -> usize {
    ((resource ^ ((kind as u32) << 24)).wrapping_mul(0x9E37_79B1) >> 16) as usize & (LOOKUP_CACHE - 1)
}

/// For each raw kind byte (a handle's kind field is 6 bits), the mask of a
/// resource's index half: the pool index for the packed kinds
/// ([`objref::layout`]), every bit otherwise. One load where a `match` on
/// the kind was a jump table, on the lookup path.
const IDX_MASK: [u32; 64] = {
    let mut t = [u32::MAX; 64];
    let mut i = 0;
    while i < 64 {
        if let Some(k) = CapType::from_raw(i as u8) {
            if let Some(l) = objref::layout(k) {
                t[i] = l.idx_mask();
            }
        }
        i += 1;
    }
    t
};

const _: () = {
    // Every kind fits the 6-bit index of `IDX_MASK` (and a handle's field).
    let mut i = 64;
    while i < 256 {
        assert!(CapType::from_raw(i as u8).is_none(), "a CapKind past 63 outgrew IDX_MASK");
        i += 1;
    }
};

/// Send capabilities to endpoints, counted where the slots change (wave 15
/// N5b, Kconfig `IPC_PORT_NOTICES`): the count behind an endpoint's
/// no-senders notice.
///
/// A **send capability** is a `Cap<Endpoint>` with `WRITE` and without
/// `READ`. `READ` is the right to serve (accept), so the server's own `RW`
/// capability is its receive right and is not counted: otherwise the
/// creator of every endpoint (`endpoint_create_cap` mints `RW | DUP`) and a
/// topology server (`RW`, "a server that may also call itself") would hold
/// a sender for as long as it lives and the count could never reach zero.
/// The property is the slot's own, so the count needs no holder lookup and
/// survives a change of serving task.
///
/// Every write of a slot goes through [`CapTable`]'s few store and clear
/// points (`grant_raw`, `install_at`, `clear_at`, `clear_all`), so the count
/// is exact through every caller: `cap_store`'s grant, revoke, move and exit
/// wipe, the fork copy (`natfork`'s `install_at` / `grant_raw` /
/// `clear_slot`), and an exec's `revoke_where`. Each change calls the delta
/// hook (`endpoint::sender_delta`) with the slot's resource, under the
/// table's lock; the hook only adjusts an atomic count and, on a fall to
/// zero, marks the endpoint for a notice. Posting the notice takes the port
/// pool and wakes a waiter, so it runs later, from [`flush`], which
/// `cap_store` calls after it releases the table lock.
pub mod senders {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::{ty, CapPerms, CapType};

    /// `fn(resource, delta) -> bool`: apply `delta` (+1 / -1) to the count
    /// of the endpoint `resource` (its packed reference) names; `true` when
    /// it fell to zero and a notice is now pending.
    pub type DeltaHook = fn(u32, i32) -> bool;
    /// Post the pending notices (no table lock held).
    pub type FlushHook = fn();

    static DELTA: AtomicUsize = AtomicUsize::new(0);
    static FLUSH: AtomicUsize = AtomicUsize::new(0);
    /// Some notice is pending: one load is the whole cost of [`flush`]
    /// otherwise.
    static PENDING: AtomicBool = AtomicBool::new(false);
    /// Runtime canary `ipc-no-senders-wipe`: a table wipe (a task's exit)
    /// forgets to count its send capabilities out.
    static CANARY_NO_WIPE: AtomicBool = AtomicBool::new(false);

    /// Register the hooks. Boot, once, before the first user task (host
    /// suites per test). Unregistered, nothing is counted outside the
    /// tables' own tallies.
    pub fn set_hooks(delta: DeltaHook, flush: FlushHook) {
        DELTA.store(delta as usize, Ordering::Release);
        FLUSH.store(flush as usize, Ordering::Release);
    }

    /// Arm the `ipc-no-senders-wipe` canary (runtime `canary=` flag, boot).
    pub fn canary_no_wipe() {
        CANARY_NO_WIPE.store(true, Ordering::Relaxed);
    }

    #[inline(always)]
    pub(super) fn canary_armed() -> bool {
        CANARY_NO_WIPE.load(Ordering::Relaxed)
    }

    /// Is a slot of `kind` with `perms` a send capability?
    #[inline(always)]
    pub const fn counted(kind: CapType, perms: CapPerms) -> bool {
        kind.raw() == ty::ENDPOINT.raw()
            && perms.contains(CapPerms::WRITE)
            && !perms.contains(CapPerms::READ)
    }

    /// Tell the hook a send capability to `resource` came (`+1`) or went
    /// (`-1`). Table lock held.
    #[inline]
    pub(super) fn delta(resource: u32, d: i32) {
        let raw = DELTA.load(Ordering::Acquire);
        if raw != 0 {
            // SAFETY: only `set_hooks` stores here, and it stores a `DeltaHook`.
            let f: DeltaHook = unsafe { core::mem::transmute::<usize, DeltaHook>(raw) };
            if f(resource, d) {
                PENDING.store(true, Ordering::Release);
            }
        }
    }

    /// Post the notices pending since the last flush. Called with no table
    /// lock held (and no pool lock: it takes the endpoint and port pools).
    /// One load when nothing is pending.
    #[inline]
    pub fn flush() {
        if !PENDING.load(Ordering::Acquire) || !PENDING.swap(false, Ordering::AcqRel) {
            return;
        }
        let raw = FLUSH.load(Ordering::Acquire);
        if raw != 0 {
            // SAFETY: only `set_hooks` stores here, and it stores a `FlushHook`.
            let f: FlushHook = unsafe { core::mem::transmute::<usize, FlushHook>(raw) };
            f();
        }
    }
}

/// Per-task cap table.
///
/// Every method takes `&self`: the slots are atomic words, so a reader that
/// holds no lock sees each slot whole (wave 15 N4, `cap_store`'s QSBR
/// reads). Writers serialise on the lock `cap_store` keeps beside each
/// table; a `CapTable` on its own (a host test, a Kani proof) is a plain
/// single-owner value.
pub struct CapTable {
    slots: [CapSlotCell; MAX_CAPS_PER_TASK],
    /// Kconfig CAP_LOOKUP_CACHE: for a (kind, resource) key's entry, the
    /// handle the last [`lookup`](Self::lookup) of it returned (0: none;
    /// no handle is 0, its kind is never Null). Only a hint: every hit is
    /// checked against the slot it names, generation included.
    cache: [core::sync::atomic::AtomicU32; LOOKUP_CACHE],
    /// One past the highest slot ever granted since the table was last
    /// wiped: every occupied slot is below it, so a search stops there
    /// instead of at MAX_CAPS_PER_TASK. Raised (release) after the slot's
    /// store; a reader loads it (acquire) before the slots.
    used: core::sync::atomic::AtomicU16,
    /// Every slot below it is occupied or retired: a grant's search for a
    /// free slot starts here, not at slot 0. Lowered by every slot freed,
    /// raised past the slot a grant takes. Writers only (under the lock).
    free_from: core::sync::atomic::AtomicU16,
    /// Send capabilities this table holds ([`senders`]): a wipe walks the
    /// table for them only when this is not 0. Writers only.
    senders: core::sync::atomic::AtomicU16,
    /// Kconfig CAP_SLOT_EXT: each slot's extension word ([`CapExt`]), the
    /// second half of its 128 bits. Written under the lock before the hot
    /// word that publishes the grant; read lock-free by [`Self::ext_of`].
    ext: [core::sync::atomic::AtomicU64; EXT_SLOTS],
    /// Each slot's warrant ([`Warrant`]); written under the lock before the
    /// hot word that publishes the grant.
    warrant: [WarrantCell; MAX_CAPS_PER_TASK],
    /// Occupied slots with a parent. The subtree sweep skips a table with none.
    derived: core::sync::atomic::AtomicU16,
    /// Occupied slots something was derived from ("may have children").
    kids: core::sync::atomic::AtomicU16,
    /// Slots the sweep revoked here that their holder has not yet been told
    /// of: each failed use of a dead handle takes one and answers `Revoked`.
    notices: core::sync::atomic::AtomicU16,
}

impl CapTable {
    /// Build a fresh empty cap table.
    pub const fn empty() -> Self {
        Self {
            slots: [CapSlotCell::EMPTY; MAX_CAPS_PER_TASK],
            cache: [const { core::sync::atomic::AtomicU32::new(0) }; LOOKUP_CACHE],
            used: core::sync::atomic::AtomicU16::new(0),
            free_from: core::sync::atomic::AtomicU16::new(0),
            senders: core::sync::atomic::AtomicU16::new(0),
            ext: [const { core::sync::atomic::AtomicU64::new(0) }; EXT_SLOTS],
            warrant: [WarrantCell::EMPTY; MAX_CAPS_PER_TASK],
            derived: core::sync::atomic::AtomicU16::new(0),
            kids: core::sync::atomic::AtomicU16::new(0),
            notices: core::sync::atomic::AtomicU16::new(0),
        }
    }

    /// A slot holding word `w` was just written (`d = 1`) or cleared
    /// (`d = -1`): count a send capability in or out ([`senders`]).
    #[inline(always)]
    fn note_sender(&self, w: u64, d: i32) {
        if CapSlotCell::w_ty_is(w, ty::ENDPOINT)
            && senders::counted(ty::ENDPOINT, CapSlotCell::w_perms(w))
        {
            let n = self.senders.load(core::sync::atomic::Ordering::Relaxed);
            self.senders.store(n.wrapping_add(d as u16), core::sync::atomic::Ordering::Relaxed);
            senders::delta(CapSlotCell::w_resource(w), d);
        }
    }

    /// Send capabilities this table holds ([`senders`]).
    pub fn senders_held(&self) -> usize {
        self.senders.load(core::sync::atomic::Ordering::Relaxed) as usize
    }

    /// Free slot `i` (keeping its generation) and let the next grant's
    /// search start at it if it is the lowest free one.
    #[inline(always)]
    fn clear_at(&self, i: usize, cell: &CapSlotCell) {
        let w = cell.word();
        cell.clear();
        self.note_sender(w, -1);
        self.release_warrant(i);
        let f = &self.free_from;
        if (i as u16) < f.load(core::sync::atomic::Ordering::Relaxed) {
            f.store(i as u16, core::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Slot `i` was just freed: its warrant goes (a slot something was derived
    /// from owes a sweep, one with a parent leaves the table's count).
    #[inline(always)]
    fn release_warrant(&self, i: usize) {
        use core::sync::atomic::Ordering::{Relaxed, Release};
        let wc = &self.warrant[i];
        let m = wc.meta.load(Relaxed);
        if m & META_KIDS != 0 {
            self.kids.store(self.kids.load(Relaxed).wrapping_sub(1), Relaxed);
            SWEEP_PENDING.store(true, Release);
        }
        if wc.parent.load(Relaxed) != 0 {
            self.derived.store(self.derived.load(Relaxed).wrapping_sub(1), Release);
            wc.parent.store(0, Relaxed);
        }
        wc.expiry.store(0, Relaxed);
        wc.meta.store(0, Relaxed);
    }

    /// The slots a search must look at: those below [`Self::used`].
    #[inline(always)]
    fn live(&self) -> &[CapSlotCell] {
        let n = self.used.load(core::sync::atomic::Ordering::Acquire) as usize;
        &self.slots[..n.min(MAX_CAPS_PER_TASK)]
    }

    /// Slot `i` was just written occupied: raise the bound past it.
    #[inline(always)]
    fn note_used(&self, i: usize) {
        let n = (i + 1) as u16;
        if self.used.load(core::sync::atomic::Ordering::Relaxed) < n {
            self.used.store(n, core::sync::atomic::Ordering::Release);
        }
    }

    /// Forget the lookup cache's entry for (`kind`, `resource`): a slot
    /// lower than the one it names may now hold the key.
    #[inline(always)]
    fn uncache(&self, kind: CapType, resource: u32) {
        if LOOKUP_CACHE != 0 {
            let r = resource & IDX_MASK[(kind.raw() & 63) as usize];
            self.cache[cache_index(kind.raw(), r)].store(0, core::sync::atomic::Ordering::Relaxed);
        }
    }

    fn uncache_all(&self) {
        for e in self.cache.iter() {
            e.store(0, core::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Wipe every slot, generations included (a table handed to a new
    /// owner, `cap_store`'s claim and exit reset). The warrant cells are left
    /// as they were: nothing reads the warrant of a free slot, and every
    /// writer of a hot word (`grant_warranted`, `install_at`) stores the
    /// slot's warrant first.
    pub fn clear_all(&self) {
        // The send capabilities go too ([`senders`]): counted out before the
        // wipe, which keeps nothing to count from. Canary
        // `ipc-no-senders-wipe`: skipped.
        if self.senders.load(core::sync::atomic::Ordering::Relaxed) != 0 && !senders::canary_armed() {
            for cell in self.live() {
                self.note_sender(cell.word(), -1);
            }
        }
        self.senders.store(0, core::sync::atomic::Ordering::Relaxed);
        // What was derived from a slot here goes with it (the sweep finds
        // those, whose parent is now dead); no warrant is read for a free slot.
        if self.kids.load(core::sync::atomic::Ordering::Relaxed) != 0 {
            SWEEP_PENDING.store(true, core::sync::atomic::Ordering::Release);
        }
        self.kids.store(0, core::sync::atomic::Ordering::Relaxed);
        self.derived.store(0, core::sync::atomic::Ordering::Release);
        self.notices.store(0, core::sync::atomic::Ordering::Relaxed);
        // Eight stores a turn: the plain `*table = empty()` this replaced was
        // a memset; one atomic store a turn cost three instructions a slot
        // (measured on riscv64: a fork and an exit each wipe a table).
        let mut it = self.slots.chunks_exact(8);
        for c in &mut it {
            for s in c {
                s.0.store(0, core::sync::atomic::Ordering::Relaxed);
            }
        }
        for s in it.remainder() {
            s.0.store(0, core::sync::atomic::Ordering::Relaxed);
        }
        self.uncache_all();
        self.used.store(0, core::sync::atomic::Ordering::Release);
        self.free_from.store(0, core::sync::atomic::Ordering::Relaxed);
    }

    /// Grant a fresh cap, returning a typed handle.
    ///
    /// Returns `None` if every slot is occupied (`EMFILE`).
    pub fn grant<T: CapTarget>(&self, perms: CapPerms, resource: u32) -> Option<Cap<T>> {
        // Single allocation path shared with `grant_raw` on purpose: the
        // generation invariant (never 0, always bumped on reuse) is what makes
        // a stale handle detectable, and two copies of that arithmetic is how
        // it silently drifts. `T::TYPE` is never `Null`, so `grant_raw`'s
        // Null-kind refusal below can never fire on this path.
        self.grant_raw(T::TYPE, perms, resource).map(Cap::from_raw)
    }

    /// Kind-erased `grant`.
    ///
    /// **WHY kind-erased.** This used to also serve the ring-3 delegation
    /// path (`SYS_CAP_GRANT`, removed 2026-09-03 — boot-only caps,
    /// RFC-0003), which read a runtime `CapKind` out of a grantor's slot and
    /// had no `T` to be generic over. That caller is gone, but `grant<T>`
    /// above still shares this allocation path on purpose: the generation
    /// invariant (never 0, always bumped on reuse) is what makes a stale
    /// handle detectable, and two copies of that arithmetic is how it
    /// silently drifts.
    ///
    /// Refuses `CapType::NULL`: occupancy is encoded *as* `kind != Null`
    /// ([`CapSlot::is_occupied`]), so writing a Null-kind slot would produce
    /// an entry that reads as free while `bump_generation` has already moved
    /// on — a torn slot. `T::TYPE` is never `Null`, so this can only fire on
    /// a caller passing runtime kind bits directly, which today is only the
    /// test in this module exercising the refusal itself.
    pub fn grant_raw(
        &self,
        kind: CapType,
        perms: CapPerms,
        resource: u32,
    ) -> Option<CapHandle> {
        self.grant_warranted(kind, perms, resource, CapExt::NONE, Warrant::ROOT)
    }

    /// [`grant_raw`](Self::grant_raw) with the slot's extension word
    /// (Kconfig CAP_SLOT_EXT; ignored when it is off) and its warrant.
    ///
    /// The warrant and the extension word are stored before the hot word that
    /// publishes the grant, behind a release fence, and the hot word with
    /// release: a lock-free [`ext_of`](Self::ext_of) or
    /// [`warrant_of`](Self::warrant_of) that sees the new generation sees
    /// them, and one that read older words sees the hot word change under it
    /// and retries nothing (it answers `None`). A warrant with a deadline sets
    /// the hot word's expiry flag.
    pub fn grant_warranted(
        &self,
        kind: CapType,
        perms: CapPerms,
        resource: u32,
        ext: CapExt,
        warrant: Warrant,
    ) -> Option<CapHandle> {
        if kind == CapType::NULL {
            return None;
        }
        let slot = self.allocate_slot()?;
        let slot_idx = slot as usize;
        let next_gen = self.bump_generation(slot_idx)?;
        let s = CapSlot { ty: kind, perms, generation: next_gen, resource };
        let flag = if warrant.expiry_ns != 0 { CapSlotCell::EXPIRES } else { 0 };
        self.warrant[slot_idx].store(&warrant);
        if warrant.parent != 0 {
            let d = self.derived.load(core::sync::atomic::Ordering::Relaxed);
            self.derived.store(d.wrapping_add(1), core::sync::atomic::Ordering::Release);
        }
        if let Some(e) = self.ext.get(slot_idx) {
            e.store(ext.encode(), core::sync::atomic::Ordering::Relaxed);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.slots[slot_idx].0.store(CapSlotCell::encode(s) | flag, core::sync::atomic::Ordering::Release);
        self.note_sender(self.slots[slot_idx].word(), 1);
        self.note_used(slot_idx);
        // Every slot below this one was occupied or retired (the search
        // started at `free_from` and took the first free one).
        self.free_from.store(slot + 1, core::sync::atomic::Ordering::Relaxed);
        self.uncache(kind, resource);
        Some(CapHandle::pack(kind, perms, next_gen, slot))
    }

    /// Find the handle for a capability this table already holds.
    ///
    /// # Why this exists: 21 typed syscalls had no possible caller
    ///
    /// A capability minted at boot lands in the task's `CapTable` and the task
    /// has no way to learn the handle. `SYS_CAP_GRANT` was removed (owner
    /// decision, 2026-09-03, boot-only caps) and nothing replaced it with a
    /// *read* path, so of the thirty typed syscalls (528-557) only three
    /// return a handle they mint (`PORT_CREATE`, `SHM_CREATE`,
    /// `IORING_CREATE`) and six more are reachable through those. The other
    /// **twenty-one — every hardware family plus Port — had never been
    /// callable from ring 3**, with a green gate over all of them. That is the
    /// same class as a field promising a protection nothing applies, inverted:
    /// a protection applied that nothing can use.
    ///
    /// # This is a lookup, NOT a grant
    ///
    /// The distinction is the whole reason this is compatible with removing
    /// `SYS_CAP_GRANT`. It mints nothing, delegates nothing, and creates no
    /// authority: it answers "which handle names the GPIO(5) I already hold?"
    /// and, for a capability the table does not hold, `None`.
    ///
    /// **The security property, and the canary for it: a lookup that returns a
    /// handle for a capability you do not hold IS a mint.** Test it by asking
    /// for a resource index the table was never granted.
    ///
    /// # Deliberately NOT filtered by permissions or by degraded mode
    ///
    /// It returns whatever the holder holds — the perms ride in the handle,
    /// and `get` is what enforces them at use. Containment likewise belongs at
    /// use, not here: `get` returns `Contained` for a write while degraded
    /// mode is armed, and refusing to even name the capability would tell a
    /// task its authority was revoked when it was only suspended.
    ///
    /// # First match wins
    ///
    /// Nothing stops a table holding two slots with the same kind and
    /// resource — `grant_raw` does not dedupe. The lowest slot index is
    /// returned. Both name the same object, so the choice is arbitrary rather
    /// than wrong, but it is stated because the answer must not look unique
    /// when it is not.
    ///
    /// # Packed kinds: the query is the pool index
    ///
    /// For a kind [`objref::is_packed_kind`] names, `resource` is compared with
    /// the index half of the stored value. Ring 3 and the untyped releases know
    /// an object by its index; the generation is the kernel's. A handle whose
    /// object has since been freed or reused is still returned, and resolution
    /// answers `Stale` for it: the lookup mints nothing and decides nothing.
    pub fn lookup(&self, kind: CapType, resource: u32) -> Option<CapHandle> {
        if kind == CapType::NULL {
            // Occupancy is encoded AS `kind != Null`, so a Null query would
            // match every free slot. Refused for the same reason `grant_raw`
            // refuses to write one.
            return None;
        }
        // One word per slot: the kind byte and the resource's index half
        // compared in place (the packed-kind mask decided once, not per slot).
        let k = kind.raw();
        let mask = IDX_MASK[(k & 63) as usize];
        let hit = |w: u64| w as u8 == k && ((w >> 32) as u32) & mask == resource;
        let pack = |w: u64, i: usize| {
            let slot = CapSlotCell::decode(w);
            CapHandle::pack(slot.ty, slot.perms, slot.generation, i as u16)
        };
        // Kconfig CAP_LOOKUP_CACHE: the slot the last lookup of this key
        // found, checked against the slot itself.
        let ci = if LOOKUP_CACHE != 0 { cache_index(k, resource) } else { 0 };
        if LOOKUP_CACHE != 0 {
            let e = self.cache[ci].load(core::sync::atomic::Ordering::Relaxed);
            if e != 0 {
                let h = CapHandle::from_raw(e);
                if let Some(cell) = self.slots.get(h.slot() as usize) {
                    let w = cell.word();
                    if hit(w) && CapSlotCell::w_generation(w) == h.generation() {
                        return Some(h);
                    }
                }
            }
        }
        for (i, cell) in self.live().iter().enumerate() {
            let w = cell.word();
            if hit(w) {
                let h = pack(w, i);
                if LOOKUP_CACHE != 0 {
                    self.cache[ci].store(h.as_raw(), core::sync::atomic::Ordering::Relaxed);
                }
                return Some(h);
            }
        }
        None
    }

    /// The lowest-slot capability of `kind` whose stored resource word, badge
    /// and rights satisfy `pred(resource, badge, perms)` (the badge is the extension
    /// word's, 0 for an unbadged slot or without Kconfig CAP_SLOT_EXT). For a
    /// query the resource word alone cannot answer: an endpoint capability
    /// names the endpoint by pool reference, and the kernel-hosted interface
    /// it belongs to and the resource its badge stands for are what a task
    /// asks by. Same rules as [`lookup`](Self::lookup): nothing is checked or
    /// minted, a freed object's handle is still returned.
    pub fn lookup_where(&self, kind: CapType, mut pred: impl FnMut(u32, u32, CapPerms) -> bool) -> Option<CapHandle> {
        if kind == CapType::NULL {
            return None;
        }
        let k = kind.raw();
        for (i, cell) in self.live().iter().enumerate() {
            let w = cell.word();
            if w as u8 != k {
                continue;
            }
            let slot = CapSlotCell::decode(w);
            let h = CapHandle::pack(slot.ty, slot.perms, slot.generation, i as u16);
            let badge = self.ext_of(h).map_or(0, |e| e.badge);
            if pred((w >> 32) as u32, badge, slot.perms) {
                return Some(h);
            }
        }
        None
    }

    /// Look up a typed cap and verify kind + generation + permissions, then
    /// apply degraded-mode containment.
    ///
    /// Returns the resource ID if the cap is valid; otherwise an error.
    #[wcet(20_us)]
    pub fn get<T: CapTarget>(
        &self,
        cap: Cap<T>,
        need: CapPerms,
    ) -> Result<u32, CapError> {
        let resource = match self.get_uncontained(cap, need) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        // RFC-0036: degraded-mode containment. Applied AFTER the forgery checks
        // (a stale/wrong-kind/under-permissioned cap still fails first, so the
        // Kani forgery proofs are unchanged). Denies write/actuation through any
        // user-task cap; READ stays live. Skipped entirely when not degraded.
        if need.contains(CapPerms::WRITE) && degraded_active() {
            return Err(CapError::Contained);
        }
        Ok(resource)
    }

    /// [`get`](Self::get) without its containment step: the same forgery,
    /// kind and permission checks in the same order, and nothing else.
    ///
    /// **Who may call it.** Operations containment is not meant to stop, by
    /// owner decision 2026-09-13:
    ///
    /// * releasing an object the caller holds — `port_destroy_cap`,
    ///   `io_ring_destroy_cap`, `drvreg_kind_for_release`. Destroying and
    ///   unregistering stay live the way closing a socket does, and still need
    ///   `WRITE`;
    /// * commanding a wheel — `motor_speed_cap_id`. The motor layer applies
    ///   the halt rule itself (`motor_set_reporting`: brake and coast
    ///   admitted, a direction change refused), so a stop is not refused one
    ///   level up while a drive is refused at the same place for both families.
    ///
    /// Every other `WRITE` resolves through `get`.
    ///
    /// `get` is this function plus containment, so the two cannot drift, and
    /// the Kani forgery proofs on `get` exercise every check here.
    #[inline]
    pub fn get_uncontained<T: CapTarget>(
        &self,
        cap: Cap<T>,
        need: CapPerms,
    ) -> Result<u32, CapError> {
        if cap.is_null() {
            return Err(CapError::Stale);
        }
        let raw = cap.raw();
        let slot_idx = raw.slot() as usize;
        // The slot field is 9 bits, wider than the table on edge/embedded:
        // the index is masked so a mispredicted check cannot read the next
        // task's table (Spectre v1, `azos_limits::nospec`).
        let Some(cell) = azos_limits::nospec::get(&self.slots, slot_idx) else {
            return Err(CapError::Stale);
        };
        // One load: the checks below see one version of the slot.
        let w = cell.word();
        if !CapSlotCell::w_occupied(w) {
            return Err(self.stale());
        }
        if CapSlotCell::w_generation(w) != raw.generation() {
            return Err(self.stale());
        }
        if !CapSlotCell::w_ty_is(w, T::TYPE) {
            return Err(CapError::WrongKind);
        }
        if !CapSlotCell::w_perms(w).contains(need) {
            return Err(CapError::MissingPerms);
        }
        // A warrant past its deadline fails as a revoked one does.
        if CapSlotCell::w_expires(w) && self.past_expiry(slot_idx) {
            return Err(CapError::Revoked);
        }
        Ok(CapSlotCell::w_resource(w))
    }

    /// The refusal for a handle that names no live slot: `Revoked` if the
    /// sweep revoked a slot of this table that nobody has been told of yet
    /// (one notice taken), else `Stale`. Out of line: the refusal path only.
    #[cold]
    #[inline(never)]
    fn stale(&self) -> CapError {
        use core::sync::atomic::Ordering::Relaxed;
        match self.notices.fetch_update(Relaxed, Relaxed, |n| n.checked_sub(1)) {
            Ok(_) => CapError::Revoked,
            Err(_) => CapError::Stale,
        }
    }

    /// Record that the sweep revoked a slot of this table (under its lock):
    /// the holder is told by the next refusal of a dead handle, whichever it is.
    #[inline]
    pub fn post_notice(&self) {
        let _ = self.notices.fetch_update(
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
            |n| Some(n.saturating_add(1)),
        );
    }

    /// The slot word `w` of slot `i` is not past its deadline (one test of the
    /// word for a slot with none). For the presence tests: a capability whose
    /// warrant expired is not held.
    #[inline(always)]
    fn unexpired(&self, i: usize, w: u64) -> bool {
        !CapSlotCell::w_expires(w) || !self.past_expiry(i)
    }

    /// Is slot `i`'s deadline reached? (Reads the warrant, for a slot whose
    /// hot word carries the expiry flag.)
    #[inline]
    fn past_expiry(&self, i: usize) -> bool {
        let e = self.warrant[i].expiry.load(core::sync::atomic::Ordering::Relaxed);
        e != 0 && now_ns() >= e
    }

    /// Is the capability `handle` names past its deadline? `false` for a stale
    /// handle and for a slot with no deadline.
    pub fn is_expired(&self, handle: CapHandle) -> bool {
        let i = handle.slot() as usize;
        match azos_limits::nospec::get(&self.slots, i) {
            Some(cell) => {
                let w = cell.word();
                CapSlotCell::w_occupied(w)
                    && CapSlotCell::w_generation(w) == handle.generation()
                    && CapSlotCell::w_expires(w)
                    && self.past_expiry(i)
            }
            None => false,
        }
    }

    /// The stored word of the slot `raw` names, loaded as
    /// [`get_uncontained`] loads it (the same masked index), or 0 (an empty
    /// slot) for an index past the table. For the endpoint resolve cache
    /// (`crate::endpoint::resolve_cache`), which compares it with the word a
    /// full resolution accepted.
    ///
    /// [`get_uncontained`]: Self::get_uncontained
    #[inline(always)]
    pub fn slot_word(&self, raw: CapHandle) -> u64 {
        match azos_limits::nospec::get(&self.slots, raw.slot() as usize) {
            Some(cell) => cell.word(),
            None => 0,
        }
    }

    /// The resource field of a stored slot word (no check: see
    /// [`word_grants`](Self::word_grants)).
    #[inline(always)]
    pub const fn word_resource(w: u64) -> u32 {
        CapSlotCell::w_resource(w)
    }

    /// The resource a stored slot word `w` grants through `raw` to a `kind`
    /// capability with `need`: [`get_uncontained`]'s checks (not null,
    /// occupied, `raw`'s generation, the kind, the permissions) on a word
    /// already loaded, `None` where it would refuse. No containment, as in
    /// `get_uncontained`. A word carrying the expiry flag grants nothing here:
    /// its deadline is in the warrant, which a word alone cannot answer for,
    /// so a cache keyed on the word never holds an expiring capability.
    ///
    /// [`get_uncontained`]: Self::get_uncontained
    #[inline]
    pub fn word_grants(w: u64, raw: CapHandle, kind: CapType, need: CapPerms) -> Option<u32> {
        (!raw.is_null()
            && !CapSlotCell::w_expires(w)
            && CapSlotCell::w_occupied(w)
            && CapSlotCell::w_generation(w) == raw.generation()
            && CapSlotCell::w_ty_is(w, kind)
            && CapSlotCell::w_perms(w).contains(need))
        .then_some(CapSlotCell::w_resource(w))
    }

    /// Revoke a cap. Subsequent dereferences return `Stale`.
    ///
    /// **Preserves** the slot's generation counter so that a future
    /// `grant` on the same slot yields a *different* generation —
    /// without that, a freshly minted cap could collide with a stale
    /// one on the same slot. Only `kind` / `perms` / `resource` are
    /// cleared; the next `grant` bumps `generation` further.
    ///
    /// Idempotent: revoking an already-empty slot is a no-op.
    pub fn revoke<T: CapTarget>(&self, cap: Cap<T>) {
        if cap.is_null() {
            return;
        }
        let raw = cap.raw();
        let slot_idx = raw.slot() as usize;
        let Some(cell) = azos_limits::nospec::get(&self.slots, slot_idx) else {
            return;
        };
        let w = cell.word();
        if CapSlotCell::w_occupied(w) && CapSlotCell::w_generation(w) == raw.generation() {
            // generation deliberately preserved; bumped on next grant.
            self.clear_at(slot_idx, cell);
        }
    }

    /// Read a slot through a kind-erased handle, without removing it.
    ///
    /// Returns `(kind, perms, resource)` for a handle this table currently
    /// holds, or `None` for one it does not — an unoccupied slot, an
    /// out-of-range slot index, or a generation that no longer matches, which
    /// is the stale-handle case [`CapSlot::generation`] exists to catch.
    ///
    /// **Kind-erased on purpose (RFC-0040 gap 2 stage 4).** A capability MOVE
    /// carries whatever kind the sender held; the mover has no `T` to be
    /// generic over, exactly as the removed `SYS_CAP_GRANT` had none. It reads
    /// and does not remove, so a move can check the receiver can take the
    /// capability **before** the sender loses it.
    pub fn peek_raw(&self, handle: CapHandle) -> Option<(CapType, CapPerms, u32)> {
        let slot_idx = handle.slot() as usize;
        let slot = azos_limits::nospec::get(&self.slots, slot_idx)?.load();
        if !slot.is_occupied() || slot.generation != handle.generation() {
            return None;
        }
        Some((slot.ty, slot.perms, slot.resource))
    }

    /// Kind-erased [`revoke`](Self::revoke), for the same reason
    /// [`peek_raw`](Self::peek_raw) is.
    ///
    /// Returns whether a slot was actually cleared, so a mover can assert that
    /// the entry it peeked is the entry it removed rather than assuming it.
    pub fn revoke_raw(&self, handle: CapHandle) -> bool {
        let slot_idx = handle.slot() as usize;
        let Some(cell) = azos_limits::nospec::get(&self.slots, slot_idx) else {
            return false;
        };
        let w = cell.word();
        if CapSlotCell::w_occupied(w) && CapSlotCell::w_generation(w) == handle.generation() {
            self.clear_at(slot_idx, cell);
            // Generation preserved, bumped on the next grant — same rule as
            // the typed `revoke`, and what makes the sender's handle stale
            // the instant the move lands.
            return true;
        }
        false
    }

    /// Revoke every occupied slot for which `pred(kind, resource)` is true;
    /// how many. Wave 13: a Linux `execve` into another topology row drops
    /// the old row's authority (everything but the handles its inherited
    /// descriptors stand on) before the new row's is seeded.
    pub fn revoke_where(&self, mut pred: impl FnMut(CapType, u32) -> bool) -> usize {
        let mut n = 0;
        for (i, cell) in self.live().iter().enumerate() {
            if !CapSlotCell::w_occupied(cell.word()) {
                continue;
            }
            let slot = cell.load();
            if slot.is_occupied() && pred(slot.ty, slot.resource) {
                self.clear_at(i, cell);
                n += 1;
            }
        }
        n
    }

    /// Install a capability at exactly `handle`: its slot, its generation,
    /// and the kind and permissions packed in it, naming `resource`.
    ///
    /// **Why a fork needs the exact handle (wave 13, NATFORK).** A native
    /// program names a file or pipe by the raw handle, and keeps those names
    /// in its own memory (libsys's small-fd table). A forked child gets a
    /// copy-on-write copy of that memory, so a descriptor it inherits is only
    /// usable if the child's table answers to the very same value.
    ///
    /// `warrant` is the copied slot's ([`Self::warrant_of`]): see the comment at
    /// the store below.
    ///
    /// Refused (`false`) for a null kind, a generation of 0 or past
    /// [`CapHandle::MAX_GENERATION`], a slot outside the table, an occupied
    /// slot, or a slot whose own counter already reached the handle's
    /// generation: a slot's generation only ever rises (the rule `grant_raw`
    /// keeps), so a stale handle this table issued earlier never validates
    /// again. A fork's child table was wiped when its slot was claimed, so
    /// every counter in it starts at 0.
    pub fn install_at(&self, handle: CapHandle, resource: u32, warrant: &Warrant) -> bool {
        let Some(kind) = CapType::from_raw(handle.kind()) else { return false };
        let gen = handle.generation();
        if kind == CapType::NULL || gen == 0 || gen > CapHandle::MAX_GENERATION {
            return false;
        }
        let Some(cell) = azos_limits::nospec::get(&self.slots, handle.slot() as usize) else {
            return false;
        };
        let w = cell.word();
        if CapSlotCell::w_occupied(w) || CapSlotCell::w_generation(w) >= gen {
            return false;
        }
        // Wave 15 N11b: the slot's extension word is written too, NONE: the
        // fork copy (the only caller) never carries a badge, and a wiped
        // table keeps the previous owner's extension words, so without this
        // store the child's capability would read a stranger's badge.
        // Same order as `grant_warranted`: extension word, then the hot word
        // that publishes it. Canary [`canary_install_keeps_ext`]: skip the
        // store (one load on the fork copy, never on a syscall's check).
        // The fork copy carries the warrant of the slot it copies, verbatim
        // (same parent, same depth, same deadline and quota): a SIBLING of the
        // original, not a child. A fork is a duplicate of a descriptor, not a
        // delegation, so it must not outlive the original's own end (the
        // original may be closed at once) nor fail on the depth bound; but it
        // must stay under every ancestor, so revoking one still reaches it and
        // it cannot shed a deadline by forking.
        let s = CapSlot { ty: kind, perms: handle.perms(), generation: gen, resource };
        let flag = if warrant.expiry_ns != 0 { CapSlotCell::EXPIRES } else { 0 };
        self.warrant[handle.slot() as usize].store(warrant);
        if warrant.parent != 0 {
            let d = self.derived.load(core::sync::atomic::Ordering::Relaxed);
            self.derived.store(d.wrapping_add(1), core::sync::atomic::Ordering::Release);
        }
        if let Some(e) = self.ext.get(handle.slot() as usize) {
            if !CANARY_INSTALL_KEEPS_EXT.load(core::sync::atomic::Ordering::Relaxed) {
                e.store(CapExt::NONE.encode(), core::sync::atomic::Ordering::Relaxed);
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        cell.0.store(CapSlotCell::encode(s) | flag, core::sync::atomic::Ordering::Release);
        self.note_sender(cell.word(), 1);
        self.note_used(handle.slot() as usize);
        self.uncache(kind, resource);
        true
    }

    /// Copy out the occupied slots at index `from` and above whose kind
    /// `want` accepts, as `(handle, resource)`, into `out`. Returns how many
    /// were written and the index to resume from (the table's length when
    /// the scan is done). Bounded by `out`, so a caller walks a table in
    /// chunks without holding its lock across what it does with each one.
    pub fn scan(
        &self,
        from: usize,
        out: &mut [(CapHandle, u32)],
        mut want: impl FnMut(CapType) -> bool,
    ) -> (usize, usize) {
        let mut n = 0usize;
        let mut i = from;
        let end = self.live().len();
        while i < end && n < out.len() {
            let w = self.slots[i].word();
            let s = if CapSlotCell::w_occupied(w) { CapSlotCell::decode(w) } else { CapSlot::EMPTY };
            if s.is_occupied() && want(s.ty) && !(CapSlotCell::w_expires(w) && self.past_expiry(i)) {
                out[n] = (CapHandle::pack(s.ty, s.perms, s.generation, i as u16), s.resource);
                n += 1;
            }
            i += 1;
        }
        // Past the last slot ever granted: done, as at the table's end.
        if i >= end {
            i = self.slots.len();
        }
        (n, i)
    }

    /// Free slot `idx` whatever it holds, keeping its generation (so every
    /// handle on it is stale from now on). Out of range is a no-op.
    pub fn clear_slot(&self, idx: usize) {
        if let Some(cell) = azos_limits::nospec::get(&self.slots, idx) {
            self.clear_at(idx, cell);
        }
    }

    /// Can this table take one more capability?
    ///
    /// A move must answer this on the RECEIVER **before** the sender's entry
    /// is removed: owner decision 38 makes the move a single step, so there is
    /// no half-moved state to roll back from, and the only way to keep that
    /// promise is to refuse before touching the sender.
    pub fn has_free_slot(&self) -> bool {
        self.allocate_slot().is_some()
    }

    /// Slots a grant could still take: free and not retired. A transfer of
    /// several capabilities checks this before the sender loses any.
    pub fn free_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| {
                let w = s.word();
                !CapSlotCell::w_occupied(w) && CapSlotCell::w_generation(w) < CapHandle::MAX_GENERATION
            })
            .count()
    }

    /// The extension word of the capability `handle` names (wave 15 N11), or
    /// `None` when the handle is stale. Lock-free: the hot word is read
    /// before and after the extension word, and a slot's generation never
    /// repeats, so equal hot words mean the extension word belongs to them.
    /// [`CapExt::NONE`] for every live handle when Kconfig CAP_SLOT_EXT is
    /// off.
    pub fn ext_of(&self, handle: CapHandle) -> Option<CapExt> {
        use core::sync::atomic::Ordering;
        let i = handle.slot() as usize;
        let cell = azos_limits::nospec::get(&self.slots, i)?;
        let w1 = cell.0.load(Ordering::Acquire);
        if !CapSlotCell::w_occupied(w1) || CapSlotCell::w_generation(w1) != handle.generation() {
            return None;
        }
        let Some(e) = self.ext.get(i) else { return Some(CapExt::NONE) };
        let x = e.load(Ordering::Relaxed);
        core::sync::atomic::fence(Ordering::Acquire);
        if cell.0.load(Ordering::Relaxed) != w1 {
            return None;
        }
        Some(CapExt::decode(x))
    }

    /// Mint, in this table, a badged copy of the unbadged endpoint
    /// capability `handle` (wave 15 N11): the copy carries `badge`, the
    /// rights `rights` (a subset of the source's, never more), and the source
    /// as its warrant parent ([`derive_warrant`]; `owner_key` is this table's
    /// domain key, which the parent reference names). A server mints one per
    /// client and moves it to the client; every call through it shows the
    /// server `badge`, and revoking the source revokes every copy.
    ///
    /// Refused: a stale handle (`Stale`); a source past its deadline
    /// (`Revoked`); a source that is not an endpoint (`WrongKind`); a source
    /// without `DUP`, a badge of 0, a source that is already badged (a badge is
    /// set once, never changed), rights the source lacks, or Kconfig
    /// CAP_SLOT_EXT off (`MissingPerms`); a chain at its depth limit or no free
    /// slot (`NoSpace`). Caller holds the table's lock.
    pub fn mint_badged(
        &self,
        owner_key: u32,
        handle: CapHandle,
        badge: u32,
        rights: CapPerms,
    ) -> Result<CapHandle, CapError> {
        self.mint_badged_until(owner_key, handle, badge, rights, 0)
    }

    /// [`mint_badged`](Self::mint_badged) with a deadline for the copy:
    /// `expiry_ns` absolute on the MONO clock, 0 none; the earlier of it and
    /// the source's own is kept ([`derive_warrant`]).
    pub fn mint_badged_until(
        &self,
        owner_key: u32,
        handle: CapHandle,
        badge: u32,
        rights: CapPerms,
        expiry_ns: u64,
    ) -> Result<CapHandle, CapError> {
        let (kind, perms, resource) = self.peek_raw(handle).ok_or(CapError::Stale)?;
        if !matches!(kind, ty::ENDPOINT) {
            return Err(CapError::WrongKind);
        }
        if self.is_expired(handle) {
            return Err(CapError::Revoked);
        }
        let src = self.ext_of(handle).ok_or(CapError::Stale)?;
        if !SLOT_EXT || badge == 0 || src.badge != 0 || !perms.contains(CapPerms::DUP) {
            return Err(CapError::MissingPerms);
        }
        let sw = self.warrant_of(handle).ok_or(CapError::Stale)?;
        let src_ref = azos_decision::warrant_ref(owner_key, handle.slot(), handle.generation());
        let spec = DeriveSpec { rights: Some(rights), expiry_ns, ..DeriveSpec::SAME };
        let (granted, w) = derive_warrant(src_ref, perms, &sw, &spec)?;
        let h = self
            .grant_warranted(kind, granted, resource, CapExt { badge, ..CapExt::NONE }, w)
            .ok_or(CapError::NoSpace)?;
        self.note_child(handle);
        Ok(h)
    }

    /// The warrant of the capability `handle` names, or `None` when the handle
    /// is stale. Lock-free, as [`ext_of`](Self::ext_of) is: the hot word is
    /// read before and after the warrant, and a slot's generation never
    /// repeats, so equal hot words mean the warrant belongs to them.
    pub fn warrant_of(&self, handle: CapHandle) -> Option<Warrant> {
        use core::sync::atomic::Ordering;
        let i = handle.slot() as usize;
        let cell = azos_limits::nospec::get(&self.slots, i)?;
        let w1 = cell.0.load(Ordering::Acquire);
        if !CapSlotCell::w_occupied(w1) || CapSlotCell::w_generation(w1) != handle.generation() {
            return None;
        }
        let r = self.warrant[i].load();
        core::sync::atomic::fence(Ordering::Acquire);
        if cell.0.load(Ordering::Relaxed) != w1 {
            return None;
        }
        Some(r)
    }

    /// Note that a copy was derived from the capability `handle` names: the
    /// slot is marked "may have children", so clearing it owes a sweep. The
    /// caller holds this table's lock (the copy was made under it and the
    /// copy's table's).
    pub fn note_child(&self, handle: CapHandle) {
        use core::sync::atomic::Ordering::Relaxed;
        let i = handle.slot() as usize;
        let Some(cell) = azos_limits::nospec::get(&self.slots, i) else { return };
        let w = cell.word();
        if CapSlotCell::w_occupied(w) && CapSlotCell::w_generation(w) == handle.generation() {
            let old = self.warrant[i].meta.fetch_or(META_KIDS, Relaxed);
            if old & META_KIDS == 0 {
                self.kids.store(self.kids.load(Relaxed).wrapping_add(1), Relaxed);
            }
        }
    }

    /// Slots here that were derived from another: the subtree sweep skips a
    /// table where this is 0.
    #[inline]
    pub fn derived(&self) -> usize {
        self.derived.load(core::sync::atomic::Ordering::Acquire) as usize
    }

    /// Does slot `slot` of this table hold generation `generation`? The test
    /// of a warrant reference whose domain still owns the table.
    #[inline]
    pub fn slot_holds(&self, slot: u16, generation: u16) -> bool {
        match azos_limits::nospec::get(&self.slots, slot as usize) {
            Some(cell) => {
                let w = cell.word();
                CapSlotCell::w_occupied(w) && CapSlotCell::w_generation(w) == generation
            }
            None => false,
        }
    }

    /// One pass of the subtree sweep over this table, the caller holding its
    /// lock: free every slot whose parent `alive` says is gone, tell its holder
    /// ([`Self::post_notice`]) and call `each(handle, kind, perms, resource,
    /// parent)` for it. Returns (slots examined, slots freed). A slot freed
    /// here that something was derived from owes the sweep another pass, which
    /// the caller's loop makes.
    pub fn sweep_dead(
        &self,
        alive: impl Fn(u64) -> bool,
        mut each: impl FnMut(CapHandle, CapType, CapPerms, u32, u64),
    ) -> (usize, usize) {
        let live = self.live();
        let mut cleared = 0;
        for (i, cell) in live.iter().enumerate() {
            let w = cell.word();
            if !CapSlotCell::w_occupied(w) {
                continue;
            }
            let parent = self.warrant[i].parent.load(core::sync::atomic::Ordering::Relaxed);
            if parent == 0 || alive(parent) {
                continue;
            }
            let s = CapSlotCell::decode(w);
            self.clear_at(i, cell);
            self.post_notice();
            each(CapHandle::pack(s.ty, s.perms, s.generation, i as u16), s.ty, s.perms, s.resource, parent);
            cleared += 1;
        }
        (live.len(), cleared)
    }

    /// Count slots retired by generation exhaustion — for diagnostics. A table
    /// whose count is climbing is a task churning capabilities; one whose count
    /// equals its size can grant nothing more.
    pub fn retired(&self) -> usize {
        self.slots.iter().filter(|s| CapSlotCell::w_generation(s.word()) >= CapHandle::MAX_GENERATION).count()
    }

    /// Count occupied slots — for diagnostics and quota enforcement.
    pub fn occupied(&self) -> usize {
        self.live().iter().filter(|s| CapSlotCell::w_occupied(s.word())).count()
    }

    /// Does this table hold **any** occupied cap of `kind` whose permissions
    /// are a superset of `need`?
    ///
    /// A *presence* test over the caller's own table, not a dereference, and
    /// deliberately weaker than `get`: it proves the caller was granted
    /// authority over a kind, not over one specific resource within it. Where
    /// a call can take a capability handle it should, and a kernel-hosted
    /// interface asks about its own endpoints
    /// (`endpoint::table_holds_host_right`).
    ///
    /// O(`MAX_CAPS_PER_TASK`) with no locking of its own (the caller holds
    /// the table lock) — one linear pass, no interrupt toggling.
    pub fn holds_kind_with(&self, kind: CapType, need: CapPerms) -> bool {
        // A null "kind" would match empty slots; refuse it explicitly rather
        // than let a caller accidentally assert that every task is authorized.
        if kind == CapType::NULL {
            return false;
        }
        // `kind` is not Null here, so a kind match is an occupied slot.
        self.live().iter().enumerate().any(|(i, c)| {
            let w = c.word();
            CapSlotCell::w_ty_is(w, kind) && CapSlotCell::w_perms(w).contains(need) && self.unexpired(i, w)
        })
    }

    /// Does this table hold an occupied cap of `kind` **for this specific
    /// `resource`** whose permissions are a superset of `need`?
    ///
    /// The stronger question than [`holds_kind_with`] (per-resource
    /// granularity, RFC-0003 P1): "does the caller hold write on resource 0
    /// *and* on resource 1 specifically", because a task holding only
    /// resource 0 must not pass by having the presence check degrade into
    /// "some cap of the kind exists". Filtering on `resource` is what makes
    /// that distinction possible.
    ///
    /// **Containment is checked here too, unlike `holds_kind_with`.** A write
    /// check is for an actuation path, so the RFC-0036 degraded-mode denial
    /// has to apply here exactly as it does inside `get()` -- otherwise a
    /// task could drive through containment via the "other leg" check while
    /// `get()`'s own containment correctly denies the leg it dereferences
    /// directly.
    ///
    /// O(`MAX_CAPS_PER_TASK`), same shape as `holds_kind_with`.
    ///
    /// **Refuses the packed kinds** ([`objref::is_packed_kind`]: Port,
    /// Shm, IoRing). Their capabilities store a packed `(index, generation)`
    /// that a bare id cannot match, and answering on the index half would call
    /// a capability to a freed object "held". No caller asks about those kinds:
    /// the callers are File and Socket.
    pub fn holds_kind_resource_with(&self, kind: CapType, resource: u32, need: CapPerms) -> bool {
        if need.contains(CapPerms::WRITE) && degraded_active() {
            return false;
        }
        self.holds_kind_resource_uncontained(kind, resource, need)
    }

    /// [`holds_kind_resource_with`](Self::holds_kind_resource_with) without its
    /// containment step: the same kind, resource and permission test, and the
    /// same refusal of `Null` and of the packed kinds.
    ///
    /// **Who may call it.** A presence check that containment does not decide.
    /// Today that is `io_ring`'s per-opcode check (`ring_cap_ok`), which was
    /// written against the handle table and never consulted containment. A
    /// ring's submit is contained where the submit is authorized: the typed
    /// call resolves its `Cap<IoRing>` through `get`.
    pub fn holds_kind_resource_uncontained(&self, kind: CapType, resource: u32, need: CapPerms) -> bool {
        if kind == CapType::NULL || objref::is_packed_kind(kind) {
            return false;
        }
        self.live().iter().enumerate().any(|(i, c)| {
            let w = c.word();
            CapSlotCell::w_ty_is(w, kind)
                && CapSlotCell::w_resource(w) == resource
                && CapSlotCell::w_perms(w).contains(need)
                && self.unexpired(i, w)
        })
    }

    /// Does this table hold an occupied cap of (unpacked) `kind` with
    /// permissions a superset of `need` whose resource satisfies `pred`?
    ///
    /// For a kind whose resource is a RANGE rather than one object — a
    /// directory-tree `File` capability admits every path under its tree — so
    /// the caller asks "does any capability I hold cover this", not "do I hold
    /// resource r". Same refusals and the
    /// same lack of a containment step as
    /// [`holds_kind_resource_uncontained`](Self::holds_kind_resource_uncontained).
    pub fn holds_kind_where(&self, kind: CapType, need: CapPerms, mut pred: impl FnMut(u32) -> bool) -> bool {
        if kind == CapType::NULL || objref::is_packed_kind(kind) {
            return false;
        }
        self.live().iter().enumerate().any(|(i, c)| {
            let w = c.word();
            CapSlotCell::w_ty_is(w, kind)
                && CapSlotCell::w_perms(w).contains(need)
                && pred(CapSlotCell::w_resource(w))
                && self.unexpired(i, w)
        })
    }

    /// Does this table hold an occupied cap of packed `kind` whose stored
    /// reference is exactly `r` — index AND generation — with permissions a
    /// superset of `need`?
    ///
    /// **Only for the packed kinds** ([`objref::is_packed_kind`]); every other
    /// kind answers `false` (those have
    /// [`holds_kind_resource_uncontained`](Self::holds_kind_resource_uncontained)).
    /// The caller obtains `r` from the object's own pool (`memobj_ref` for a
    /// region), so a capability to a freed or reissued object, whose generation
    /// differs, is not held.
    ///
    /// **Why not [`lookup`](Self::lookup) and a dereference.** `lookup`
    /// compares the index half only and returns the first matching slot, so a
    /// table holding a stale and a live capability to one index would answer
    /// from whichever sits lower. This scans every slot for the exact value.
    ///
    /// No containment step: the caller decides whether containment applies.
    /// O(`MAX_CAPS_PER_TASK`); the caller holds the table lock and must not
    /// hold the object's pool lock (lock order: table, then pool).
    pub fn holds_packed_ref(&self, kind: CapType, r: u32, need: CapPerms) -> bool {
        if !objref::is_packed_kind(kind) {
            return false;
        }
        // A packed kind is never Null, so a kind match is an occupied slot.
        self.live().iter().enumerate().any(|(i, c)| {
            let w = c.word();
            CapSlotCell::w_ty_is(w, kind)
                && CapSlotCell::w_resource(w) == r
                && CapSlotCell::w_perms(w).contains(need)
                && self.unexpired(i, w)
        })
    }

    /// Revoke every capability of `kind` in this table whose packed resource
    /// names pool index `idx`, and return how many. `kind` a non-packed kind
    /// or `Null` revokes nothing (there is no index to compare).
    ///
    /// For the per-slot generation wrap sweep (`objref::sweep_index`, RFC-0040
    /// gap 1 revised): scoped to one pool slot's index rather than every
    /// object of `kind`, so a live capability on another index of the same
    /// kind is untouched. Same slot rule as [`revoke`](Self::revoke): kind,
    /// perms and resource are cleared and the cap-table slot's own generation
    /// is kept.
    pub fn revoke_kind_at_index(&self, kind: CapType, idx: u32) -> usize {
        if !objref::is_packed_kind(kind) {
            return 0;
        }
        let mut revoked = 0;
        for (i, cell) in self.live().iter().enumerate() {
            let w = cell.word();
            if CapSlotCell::w_ty_is(w, kind) && objref::idx(kind, CapSlotCell::w_resource(w)) == idx {
                self.clear_at(i, cell);
                revoked += 1;
            }
        }
        revoked
    }

    /// Revoke every capability of `kind` and call `f(perms, resource)` for
    /// each, in slot order. Returns how many. RFC-0055: a dying task's
    /// `Cap<Pipe>` ends are dropped one by one before its table is wiped, so
    /// the pipe they name learns that an end is gone.
    pub fn drain_kind(&self, kind: CapType, mut f: impl FnMut(CapPerms, u32)) -> usize {
        let mut n = 0;
        for (i, cell) in self.live().iter().enumerate() {
            let w = cell.word();
            if CapSlotCell::w_occupied(w) && CapSlotCell::w_ty_is(w, kind) {
                let (perms, resource) = (CapSlotCell::w_perms(w), CapSlotCell::w_resource(w));
                self.clear_at(i, cell);
                f(perms, resource);
                n += 1;
            }
        }
        n
    }

    /// Revoke every capability of an UNPACKED `kind` whose resource is exactly
    /// `resource`. Returns how many. The object-teardown twin of
    /// [`Self::revoke_kind_at_index`] for kinds whose resource carries no
    /// object generation — `Cap<Lease>` (wave 9), revoked by `lease_free` so
    /// a freed lease id reissued to another lessor is never named by the old
    /// lessor's handle. A packed kind is refused (0): its resource is a
    /// packed reference and has its own sweep.
    pub fn revoke_kind_resource(&self, kind: CapType, resource: u32) -> usize {
        if objref::is_packed_kind(kind) || kind == CapType::NULL {
            return 0;
        }
        let mut revoked = 0;
        for (i, cell) in self.live().iter().enumerate() {
            let w = cell.word();
            if CapSlotCell::w_ty_is(w, kind) && CapSlotCell::w_resource(w) == resource {
                self.clear_at(i, cell);
                revoked += 1;
            }
        }
        revoked
    }

    // Pick the next free slot index, or `None` if the table has no slot that
    // can still be granted. A retired slot is skipped even when free: its
    // generation cannot advance, so re-granting it would reissue one.
    fn allocate_slot(&self) -> Option<u16> {
        let from = (self.free_from.load(core::sync::atomic::Ordering::Relaxed) as usize).min(MAX_CAPS_PER_TASK);
        for (i, cell) in self.slots.iter().enumerate().skip(from) {
            let w = cell.word();
            if !CapSlotCell::w_occupied(w) && CapSlotCell::w_generation(w) < CapHandle::MAX_GENERATION {
                return Some(i as u16);
            }
        }
        None
    }

    // The slot's next generation, or `None` if it is spent. Never wraps: see
    // `CapSlot::generation`. `allocate_slot` already refuses a retired slot, so
    // `None` here is defence in depth against a second caller of this path.
    fn bump_generation(&self, slot_idx: usize) -> Option<u16> {
        let next = CapSlotCell::w_generation(self.slots[slot_idx].word()).checked_add(1)?;
        if next > CapHandle::MAX_GENERATION { None } else { Some(next) }
    }
}

/// Error returned by [`CapTable::get`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapError {
    /// The handle's generation is stale (slot empty or reused).
    Stale,
    /// The handle's kind does not match the expected `T`.
    WrongKind,
    /// The slot does not have the required permission bits.
    MissingPerms,
    /// Degraded mode (RFC-0036) is armed and this is a write/actuation: the
    /// capability is valid but its use is contained until degraded mode clears.
    Contained,
    /// The RECEIVING table of a capability move has no free slot.
    ///
    /// RFC-0040 gap 2 stage 4. It is its own variant rather than being folded
    /// into `Stale` because the two say opposite things about the sender: on
    /// `NoSpace` the sender still holds the capability and nothing moved, and a
    /// caller that cannot tell those apart cannot know whether to retry or to
    /// give up.
    NoSpace,
    /// The capability's warrant ended: it expired, or the sweep revoked it
    /// because the warrant it descends from was revoked. Answered where
    /// `Stale` would be (a dead handle) once the holder has a notice pending,
    /// and for a use past the deadline.
    Revoked,
}

impl CapError {
    /// The reason code written into a `SAFETY_CAP_DENIED_TYPED` record.
    ///
    /// Frozen like every other number that reaches the black box: append,
    /// never renumber. `Contained` is numbered even though it is never
    /// recorded (see `logger.rs`'s `SAFETY_CAP_DENIED_TYPED` doc) — closing
    /// the space is what stops a later "it needs a code" from taking one that
    /// already means something else.
    ///
    /// The four that ARE recorded are four different events, and collapsing
    /// them would waste the one thing this path knows that the untyped one
    /// does not: `Stale` is a handle to an object that is gone or was reused —
    /// the forgery shape; `WrongKind` is a handle to a real object of another
    /// family — the confusion shape; `MissingPerms` is the right object with
    /// insufficient rights — the escalation shape; `Revoked` is a handle that
    /// was real and whose warrant ended (revoked with an ancestor, or past its
    /// deadline) — a holder using authority it was told it lost.
    pub const fn code(self) -> u32 {
        match self {
            CapError::Stale => 1,
            CapError::WrongKind => 2,
            CapError::MissingPerms => 3,
            CapError::Contained => 4,
            // Appended, never renumbered — the rule stated above. Numbered
            // although it is not recorded either: a full receiving table is
            // the receiver's resource limit, not an attempt on authority, and
            // recording it would put the sender in the denial ring for
            // something the sender did not do.
            CapError::NoSpace => 5,
            // Appended, never renumbered. A revoked or expired warrant is the
            // forgery shape's honest twin: the handle was real.
            CapError::Revoked => 6,
        }
    }

    /// Is this refusal a capability DENIAL, or the safety system working?
    ///
    /// `Contained` is the second: degraded mode refusing a write from a task
    /// that holds the capability. Recording it as a denial would bury every
    /// real one under a containment episode. See `SAFETY_CAP_DENIED_TYPED`.
    pub const fn is_denial(self) -> bool {
        !matches!(self, CapError::Contained)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────
// Kani harnesses (RFC-0003 / RFC-0006)
// ──────────────────────────────────────────────────────────────────────────
//
// These compile only under `cargo kani --features kani` and prove the
// forgery-resistance properties of `CapTable::get`.
#[cfg(kani)]
mod kani_proofs {
    use super::targets::Port;
    use super::*;

    /// A handle whose slot is empty must always fail with `Stale`.
    #[kani::proof]
    fn cap_forge_impossible_empty_slot() {
        let t = CapTable::empty();
        let raw_bits: u32 = kani::any();
        let forged: Cap<Port> = Cap::from_raw(CapHandle::from_raw(raw_bits));
        // No slot is occupied ⇒ every dereference must fail Stale.
        match t.get(forged, CapPerms::READ) {
            Err(CapError::Stale) => (),
            Err(CapError::WrongKind) => (),  // also acceptable
            _ => panic!("forged cap into empty table must not succeed"),
        }
    }

    /// After grant + revoke, the cap is never re-validated.
    #[kani::proof]
    fn cap_revoked_stale() {
        let t = CapTable::empty();
        let resource: u32 = kani::any();
        let perms_bits: u8 = kani::any();
        kani::assume(perms_bits <= 0b1111);
        let perms = CapPerms::from_bits_truncate(perms_bits);
        let cap: Cap<Port> = match t.grant(perms, resource) {
            Some(c) => c,
            None => return, // table was full (impossible from empty, but Kani must accept)
        };
        t.revoke(cap);
        let need = CapPerms::READ;
        let got = t.get(cap, need);
        // Either Stale (slot now empty) or some other rejection — never Ok.
        match got {
            Err(_) => (),
            Ok(_) => panic!("revoked cap returned Ok"),
        }
    }

    /// RFC-0036: in degraded mode, a write through any (otherwise valid) cap is
    /// contained — never `Ok`. Read access is unaffected.
    #[kani::proof]
    fn cap_contained_when_degraded() {
        let t = CapTable::empty();
        let resource: u32 = kani::any();
        // A cap that DOES carry WRITE, so the perms check passes and the
        // containment check is what rejects it.
        let cap: Cap<Port> = match t.grant(CapPerms::RW, resource) {
            Some(c) => c,
            None => return,
        };
        degraded_set(true);
        let w = t.get(cap, CapPerms::WRITE);
        let r = t.get(cap, CapPerms::READ);
        degraded_set(false);
        // Write is contained; read still resolves.
        assert!(matches!(w, Err(CapError::Contained)));
        assert!(matches!(r, Ok(_)));
    }

    /// D3/L4: whatever is asked, a derive never widens. The copy's rights are
    /// a subset of the source's; its deadline is no later and its quota no
    /// larger, in the same unit, where the source has one; it is exactly one
    /// link deeper and never past `WARRANT_DEPTH_MAX`.
    #[kani::proof]
    fn cap_derive_never_widens() {
        let src_perms = CapPerms::from_bits_truncate(kani::any());
        let src = Warrant {
            parent: kani::any(),
            depth: kani::any(),
            expiry_ns: kani::any(),
            quota: Quota { bytes: kani::any(), amount: kani::any() },
        };
        kani::assume(src.depth as usize <= WARRANT_DEPTH_MAX);
        kani::assume(src.quota.amount <= Quota::MAX);
        let spec = DeriveSpec {
            rights: if kani::any() { Some(CapPerms::from_bits_truncate(kani::any())) } else { None },
            expiry_ns: kani::any(),
            quota: Quota { bytes: kani::any(), amount: kani::any() },
        };
        if let Ok((p, w)) = derive_warrant(kani::any(), src_perms, &src, &spec) {
            assert!(src_perms.contains(p));
            if src.expiry_ns != 0 {
                assert!(w.expiry_ns != 0 && w.expiry_ns <= src.expiry_ns);
            }
            if src.quota.amount != 0 {
                assert!(w.quota.amount != 0 && w.quota.amount <= src.quota.amount && w.quota.bytes == src.quota.bytes);
            }
            assert!(w.depth == src.depth + 1 && (w.depth as usize) <= WARRANT_DEPTH_MAX);
        }
    }

    /// Granted cap with insufficient perms is rejected.
    #[kani::proof]
    fn cap_perms_required() {
        let t = CapTable::empty();
        let cap: Cap<Port> = match t.grant(CapPerms::READ, 0) {
            Some(c) => c,
            None => return,
        };
        match t.get(cap, CapPerms::WRITE) {
            Err(CapError::MissingPerms) => (),
            other => panic!("expected MissingPerms, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::targets::{Port, Socket};
    use super::*;

    /// Serialises every test that touches the process-global degrade level.
    ///
    /// `DEGRADE_LEVEL` is one static and `cargo test` runs test functions in
    /// parallel, so the six tests below were racing each other: e.g.
    /// `degraded_set_false_maps_to_full` sets FULL and asserts FULL, while
    /// `degrade_level_roundtrip` is free to store CAUTIOUS in between. The
    /// old comment on `degraded_mode_contains_writes` claimed it was "the
    /// only test touching the global DEGRADED flag" — that stopped being
    /// true when the RFC-0037 graded-level tests were added, and the suite
    /// has been latently flaky since. Held for the whole body, poison
    /// recovered so one failure does not cascade into five.
    ///
    /// **A test that asserts a WRITE answer succeeds takes it too**, even if
    /// it never sets the level: `get` and `holds_kind_resource_with` refuse
    /// WRITE while a sibling holds the level at CONTAINED.
    /// `holds_kind_resource_with_is_resource_specific` did not, and read red
    /// once in 1000 full-binary runs at 32 threads (2026-09-14).
    static DEGRADE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn degrade_guard() -> std::sync::MutexGuard<'static, ()> {
        DEGRADE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn grant_and_get_roundtrip() {
        let t = CapTable::empty();
        let c: Cap<Port> = t.grant(CapPerms::RW, 42).unwrap();
        let resource = t.get(c, CapPerms::READ).unwrap();
        assert_eq!(resource, 42);
    }

    #[test]
    fn wrong_kind_fails() {
        let t = CapTable::empty();
        let c: Cap<Port> = t.grant(CapPerms::RW, 7).unwrap();
        // Forge a Cap<Socket> with the same raw handle bits — not a real
        // attack vector since Cap<T> is private to the kernel, but
        // verifies the runtime check.
        let forged = Cap::<Socket>::from_raw(c.raw());
        let kind_ok = matches!(t.get(forged, CapPerms::READ), Err(CapError::WrongKind));
        assert!(kind_ok);
    }

    #[test]
    fn revoked_cap_is_stale() {
        let t = CapTable::empty();
        let c: Cap<Port> = t.grant(CapPerms::RW, 1).unwrap();
        t.revoke(c);
        assert_eq!(t.get(c, CapPerms::READ), Err(CapError::Stale));
    }

    #[test]
    fn missing_perms_rejected() {
        let t = CapTable::empty();
        let c: Cap<Port> = t.grant(CapPerms::READ, 9).unwrap();
        assert_eq!(t.get(c, CapPerms::WRITE), Err(CapError::MissingPerms));
    }

    #[test]
    fn generation_bump_after_reuse() {
        let t = CapTable::empty();
        let c1: Cap<Port> = t.grant(CapPerms::RW, 1).unwrap();
        let g1 = c1.raw().generation();
        t.revoke(c1);
        let c2: Cap<Port> = t.grant(CapPerms::RW, 2).unwrap();
        let g2 = c2.raw().generation();
        // Same slot reused with a new generation.
        assert_eq!(c1.raw().slot(), c2.raw().slot());
        assert_ne!(g1, g2);
        // The original cap is now stale.
        assert_eq!(t.get(c1, CapPerms::READ), Err(CapError::Stale));
    }

    /// **The use-after-revoke this rule exists to stop.** The counter used to
    /// wrap `255 → 1`, so the 256th grant of a slot reissued a generation a
    /// previous holder still had, and that holder's revoked `Cap` validated
    /// again — against whatever object the slot now names. Ring 3 reaches this
    /// by creating and destroying an object in a loop.
    ///
    /// Now the slot is retired at `MAX_GENERATION`. The test drives one slot to
    /// exhaustion and asserts the two halves: no generation is ever seen twice,
    /// and the slot is never handed out again.
    #[test]
    fn an_exhausted_slot_is_retired_and_never_reissues_a_generation() {
        let t = CapTable::empty();
        // A bitmap over the generation space, not a Vec: this crate is `no_std`
        // and its test scope has no `alloc`.
        let mut seen = [0u64; (CapHandle::MAX_GENERATION as usize + 64) / 64];
        let mut count = 0usize;
        let mut last_slot = None;
        // One slot at a time: grant, record, revoke. The table keeps handing
        // back the same (lowest free) slot until that slot is spent.
        loop {
            let Some(c) = t.grant::<Port>(CapPerms::RW, 1) else { break };
            let raw = c.raw();
            if last_slot.is_none() {
                last_slot = Some(raw.slot());
            }
            if raw.slot() != last_slot.unwrap() {
                // The first slot retired and allocation moved on: that is the
                // property under test, and the loop's job is done.
                break;
            }
            let g = raw.generation() as usize;
            let (w, b) = (g / 64, 1u64 << (g % 64));
            assert!(
                seen[w] & b == 0,
                "generation {} reissued on slot {} — a revoked cap just became valid again",
                raw.generation(), raw.slot(),
            );
            seen[w] |= b;
            count += 1;
            t.revoke(c);
        }
        let first = last_slot.expect("the empty table must grant at least once");
        assert_eq!(
            count,
            CapHandle::MAX_GENERATION as usize,
            "a slot must yield exactly MAX_GENERATION distinct generations before retiring",
        );
        assert!(seen[0] & 1 == 0, "generation 0 is the null handle and must never be granted");
        assert_eq!(t.retired(), 1, "the spent slot must be counted as retired");
        // And it is gone for good: every later grant is a different slot.
        let next: Cap<Port> = t.grant(CapPerms::RW, 2).expect("other slots remain");
        assert_ne!(next.raw().slot(), first, "a retired slot was handed out again");
    }

    /// **The non-wrap contract, tested where it lives.**
    ///
    /// `allocate_slot` refuses a retired slot, so a table-level test can never
    /// reach `bump_generation` with a spent slot — which means it cannot see the
    /// counter wrap. Found by mutation: restoring the original `8191 -> 1` wrap
    /// left every table-level test green. The two defences are redundant on
    /// purpose, and each needs its own assertion or the redundancy hides a
    /// regression in either one.
    #[test]
    fn bump_generation_refuses_a_spent_slot_instead_of_wrapping() {
        let t = CapTable::empty();
        assert_eq!(t.bump_generation(0), Some(1), "a fresh slot starts at 1");
        t.slots[0].store(CapSlot { generation: CapHandle::MAX_GENERATION - 1, ..t.slots[0].load() });
        assert_eq!(
            t.bump_generation(0),
            Some(CapHandle::MAX_GENERATION),
            "the last usable generation must still be issued",
        );
        t.slots[0].store(CapSlot { generation: CapHandle::MAX_GENERATION, ..t.slots[0].load() });
        assert_eq!(
            t.bump_generation(0), None,
            "a spent slot must refuse, not wrap: wrapping reissues a generation a \
             revoked holder still has",
        );
    }

    /// Exhausting the whole table is a refusal, not a wrap. A ring-3 task that
    /// churns capabilities breaks only its own table, and `retired()` says so.
    #[test]
    fn a_table_of_retired_slots_refuses_instead_of_wrapping() {
        let t = CapTable::empty();
        // Retire every slot by hand — driving 512 slots x 8191 grants through
        // the real path would be 4.2M operations for the same assertion.
        for slot in t.slots.iter() {
            slot.store(CapSlot { generation: CapHandle::MAX_GENERATION, ..slot.load() });
        }
        assert_eq!(t.retired(), MAX_CAPS_PER_TASK);
        assert!(t.grant::<Port>(CapPerms::RW, 1).is_none(), "a spent table must refuse");
        assert_eq!(t.occupied(), 0, "and must not have written a slot while refusing");
    }

    #[test]
    fn degraded_mode_contains_writes() {
        let _serial = degrade_guard();
        // RFC-0036: degraded mode denies WRITE through a valid cap but leaves
        // READ live; clearing it restores writes; and a cap lacking WRITE still
        // reports MissingPerms (forgery/perms checks run first). Single test so
        // it is the only one asserting the get()-side containment behaviour.
        // The global flag itself is shared with the RFC-0037 level tests, so
        // every one of them takes `DEGRADE_LOCK` — see its doc.
        let t = CapTable::empty();
        let rw: Cap<Port> = t.grant(CapPerms::RW, 77).unwrap();
        let ro: Cap<Port> = t.grant(CapPerms::READ, 5).unwrap();

        // Normal: write resolves.
        assert_eq!(t.get(rw, CapPerms::WRITE), Ok(77));

        degraded_set(true);
        assert_eq!(t.get(rw, CapPerms::WRITE), Err(CapError::Contained));
        assert_eq!(t.get(rw, CapPerms::READ), Ok(77)); // reads stay live
        // perms check runs before containment → MissingPerms, not Contained.
        assert_eq!(t.get(ro, CapPerms::WRITE), Err(CapError::MissingPerms));
        degraded_set(false);

        // Cleared: write resolves again.
        assert_eq!(t.get(rw, CapPerms::WRITE), Ok(77));
    }

    /// `get_uncontained` is `get` minus containment and nothing else: every
    /// forgery, kind and permission refusal is the same in both states, and a
    /// write through a held capability resolves while degraded — where `get`
    /// answers `Contained` for the same handle.
    ///
    /// **Canaries.** Put the containment step into `get_uncontained`: the
    /// degraded `Ok(77)` reads `Contained`. Drop its permission check: the
    /// `MissingPerms` lines read `Ok(5)`.
    #[test]
    fn get_uncontained_is_get_without_containment() {
        let _serial = degrade_guard();
        let t = CapTable::empty();
        let rw: Cap<Port> = t.grant(CapPerms::RW, 77).unwrap();
        let ro: Cap<Port> = t.grant(CapPerms::READ, 5).unwrap();
        let gone: Cap<Port> = t.grant(CapPerms::RW, 9).unwrap();
        t.revoke(gone);
        let confused = Cap::<Socket>::from_raw(rw.raw());

        for degraded in [false, true] {
            degraded_set(degraded);
            assert_eq!(t.get_uncontained(rw, CapPerms::WRITE), Ok(77), "degraded={degraded}");
            assert_eq!(t.get_uncontained(ro, CapPerms::READ), Ok(5), "degraded={degraded}");
            assert_eq!(t.get_uncontained(ro, CapPerms::WRITE), Err(CapError::MissingPerms), "degraded={degraded}");
            assert_eq!(t.get_uncontained(gone, CapPerms::WRITE), Err(CapError::Stale), "degraded={degraded}");
            assert_eq!(t.get_uncontained(confused, CapPerms::READ), Err(CapError::WrongKind), "degraded={degraded}");
            assert_eq!(t.get_uncontained::<Port>(Cap::NULL, CapPerms::READ), Err(CapError::Stale), "degraded={degraded}");
        }
        // Still degraded: the same handle through `get` is contained.
        assert_eq!(t.get(rw, CapPerms::WRITE), Err(CapError::Contained));
        degraded_set(false);
    }

    // ── RFC-0037 graded degrade level tests ───────────────────────────────

    #[test]
    fn degrade_level_roundtrip() {
        let _serial = degrade_guard();
        // Reset to FULL after each variant so tests are independent of run order.
        degrade_level_set(DEGRADE_LEVEL_FULL);
        assert_eq!(degrade_level(), DEGRADE_LEVEL_FULL);

        degrade_level_set(DEGRADE_LEVEL_CAUTIOUS);
        assert_eq!(degrade_level(), DEGRADE_LEVEL_CAUTIOUS);

        degrade_level_set(DEGRADE_LEVEL_SLOW);
        assert_eq!(degrade_level(), DEGRADE_LEVEL_SLOW);

        degrade_level_set(DEGRADE_LEVEL_CONTAINED);
        assert_eq!(degrade_level(), DEGRADE_LEVEL_CONTAINED);

        // Restore global state for other tests.
        degrade_level_set(DEGRADE_LEVEL_FULL);
    }

    #[test]
    fn degrade_level_oob_clamps_to_contained() {
        let _serial = degrade_guard();
        // Out-of-range index (e.g. 99) must clamp to CONTAINED — fail-closed,
        // never panic.
        degrade_level_set(99);
        assert_eq!(degrade_level(), DEGRADE_LEVEL_CONTAINED);

        // Restore.
        degrade_level_set(DEGRADE_LEVEL_FULL);
    }

    #[test]
    fn degraded_set_true_maps_to_contained() {
        let _serial = degrade_guard();
        degraded_set(true);
        assert!(degraded_active());
        assert_eq!(degrade_level(), DEGRADE_LEVEL_CONTAINED);
        degraded_set(false);
    }

    #[test]
    fn degraded_set_false_maps_to_full() {
        let _serial = degrade_guard();
        // Arm first, then clear via bool shim.
        degrade_level_set(DEGRADE_LEVEL_CONTAINED);
        degraded_set(false);
        assert!(!degraded_active());
        assert_eq!(degrade_level(), DEGRADE_LEVEL_FULL);
    }

    #[test]
    fn cautious_and_slow_do_not_trip_cap_denial() {
        let _serial = degrade_guard();
        // CAUTIOUS and SLOW restrict speed only; cap-denial stays off.
        degrade_level_set(DEGRADE_LEVEL_CAUTIOUS);
        assert!(!degraded_active(), "CAUTIOUS must not arm cap-denial");

        degrade_level_set(DEGRADE_LEVEL_SLOW);
        assert!(!degraded_active(), "SLOW must not arm cap-denial");

        // Restore.
        degrade_level_set(DEGRADE_LEVEL_FULL);
    }

    #[test]
    fn null_cap_is_stale() {
        let t = CapTable::empty();
        assert_eq!(
            t.get::<Port>(Cap::NULL, CapPerms::READ),
            Err(CapError::Stale)
        );
    }

    #[test]
    fn grant_raw_refuses_null_kind() {
        // Occupancy is `kind != Null`, so a Null-kind grant would burn a
        // generation on a slot that still reads as free.
        let t = CapTable::empty();
        assert!(t.grant_raw(CapType::NULL, CapPerms::RW, 1).is_none());
        assert_eq!(t.occupied(), 0);

        // A real kind still round-trips through the same allocation path
        // `grant<T>` uses, generation included: wrap the raw handle back into
        // a typed `Cap` and dereference it through `get`, same as any other
        // caller would.
        let h = t.grant_raw(ty::SOCKET, CapPerms::READ, 7).unwrap();
        assert_ne!(h.generation(), 0);
        let cap: Cap<super::targets::Socket> = Cap::from_raw(h);
        assert_eq!(t.get(cap, CapPerms::READ), Ok(7));
    }

    #[test]
    fn holds_kind_resource_with_is_resource_specific() {
        let _serial = degrade_guard();
        let t = CapTable::empty();
        let _m0: Cap<crate::cap::targets::Socket> = t.grant(CapPerms::RW, 0).unwrap();
        // Only resource 0 is held — resource 1 must not be reported present,
        // even though the kind matches and READ/WRITE would pass on 0.
        assert!(t.holds_kind_resource_with(ty::SOCKET, 0, CapPerms::WRITE));
        assert!(!t.holds_kind_resource_with(ty::SOCKET, 1, CapPerms::WRITE));
        // Wrong kind at the same resource id must not match either.
        assert!(!t.holds_kind_resource_with(ty::IRQ, 0, CapPerms::WRITE));
    }

    #[test]
    fn holds_kind_resource_with_denies_write_when_degraded() {
        let _serial = degrade_guard();
        let t = CapTable::empty();
        let _m1: Cap<crate::cap::targets::Socket> = t.grant(CapPerms::RW, 1).unwrap();
        assert!(t.holds_kind_resource_with(ty::SOCKET, 1, CapPerms::WRITE));
        degraded_set(true);
        assert!(!t.holds_kind_resource_with(ty::SOCKET, 1, CapPerms::WRITE));
        // READ is unaffected by containment, same as `get`.
        assert!(t.holds_kind_resource_with(ty::SOCKET, 1, CapPerms::READ));
        degraded_set(false);
    }

    #[test]
    fn full_table_returns_none() {
        let t = CapTable::empty();
        for i in 0..MAX_CAPS_PER_TASK {
            let _: Cap<Port> = t.grant(CapPerms::RW, i as u32).unwrap();
        }
        let extra: Option<Cap<Port>> = t.grant(CapPerms::RW, 0);
        assert!(extra.is_none());
        assert_eq!(t.occupied(), MAX_CAPS_PER_TASK);
    }

    // ── RFC-0040 gap 1: packed resources ──────────────────────────────────

    /// Packed kinds are looked up by pool index; every other kind still
    /// matches its whole resource, and `get` returns the stored value as is.
    ///
    /// **Canary.** Compare `slot.resource` instead of its index half in
    /// `lookup`: the Shm lookup by index reads `None`.
    #[test]
    fn lookup_matches_the_index_half_of_a_packed_resource_only() {
        use super::targets::{Socket, Shm};
        let t = CapTable::empty();
        let packed = objref::SHM.pack(3, 0x00AB_CDEF);
        let shm: Cap<Shm> = t.grant(CapPerms::RW, packed).unwrap();
        let motor: Cap<Socket> = t.grant(CapPerms::RW, objref::SHM.pack(3, 1)).unwrap();
        assert_eq!(t.lookup(ty::SHM, 3), Some(shm.raw()));
        assert_eq!(t.lookup(ty::SHM, packed), None, "the query is an index");
        assert_eq!(t.lookup(ty::SHM, 4), None);
        assert_eq!(t.lookup(ty::IORING, 3), None, "another kind");
        assert_eq!(t.lookup(ty::SOCKET, 3), None, "a bare kind matches its whole resource");
        assert_eq!(t.lookup(ty::SOCKET, objref::SHM.pack(3, 1)), Some(motor.raw()));
        assert_eq!(t.get(shm, CapPerms::READ), Ok(packed));

        // Port, with its own layout.
        use super::targets::Port;
        let p: Cap<Port> = t.grant(CapPerms::RW, objref::PORT.pack(2, 9)).unwrap();
        assert_eq!(t.lookup(ty::PORT, 2), Some(p.raw()));
        assert_eq!(t.lookup(ty::PORT, objref::PORT.pack(2, 9)), None, "the query is an index");
        assert_eq!(t.lookup(ty::PORT, 9), None);
    }

    /// Both presence checks refuse `Null` and the packed kinds; only the
    /// contained one refuses a WRITE while degraded.
    ///
    /// **Canaries.** Drop `is_packed_kind` from the refusal: the Shm lines read
    /// true. Put the containment step into the uncontained variant: its
    /// degraded WRITE reads false.
    #[test]
    fn presence_checks_refuse_packed_kinds_and_only_one_is_contained() {
        use super::targets::{IoRing, Socket, Port, Shm};
        let _serial = degrade_guard();
        let t = CapTable::empty();
        let _s: Cap<Shm> = t.grant(CapPerms::RW, 5).unwrap();
        let _r: Cap<IoRing> = t.grant(CapPerms::RW, 5).unwrap();
        let _p: Cap<Port> = t.grant(CapPerms::RW, 5).unwrap();
        let _m: Cap<Socket> = t.grant(CapPerms::RW, 5).unwrap();
        for need in [CapPerms::NONE, CapPerms::READ, CapPerms::WRITE] {
            for kind in [ty::SHM, ty::IORING, ty::PORT] {
                assert!(!t.holds_kind_resource_uncontained(kind, 5, need), "{kind:?}");
                assert!(!t.holds_kind_resource_with(kind, 5, need), "{kind:?}");
            }
            assert!(!t.holds_kind_resource_uncontained(CapType::NULL, 5, need));
        }
        degraded_set(true);
        assert!(t.holds_kind_resource_uncontained(ty::SOCKET, 5, CapPerms::WRITE));
        assert!(!t.holds_kind_resource_with(ty::SOCKET, 5, CapPerms::WRITE));
        degraded_set(false);
        assert!(t.holds_kind_resource_with(ty::SOCKET, 5, CapPerms::WRITE));
        assert!(!t.holds_kind_resource_uncontained(ty::SOCKET, 6, CapPerms::NONE));
    }

    /// `holds_packed_ref` answers for the exact `(index, generation)` of one
    /// packed kind: another generation at the same index, another kind storing
    /// the same value, missing permissions and every non-packed kind are not
    /// held, and a stale capability in a lower slot does not hide a live one
    /// above it.
    ///
    /// **Canaries.** Compare the index halves instead of the whole value: the
    /// other-generation line reads `true`. Drop `s.kind == kind`: the Port line
    /// does. Drop the permission test: the WRITE line does.
    #[test]
    fn holds_packed_ref_matches_the_whole_reference_of_one_packed_kind() {
        use super::targets::{Port, Shm, Socket};
        let t = CapTable::empty();
        let _stale: Cap<Shm> = t.grant(CapPerms::RW, objref::SHM.pack(3, 1)).unwrap();
        let _live: Cap<Shm> = t.grant(CapPerms::READ, objref::SHM.pack(3, 2)).unwrap();
        let _port: Cap<Port> = t.grant(CapPerms::RW, objref::SHM.pack(4, 1)).unwrap();
        let _motor: Cap<Socket> = t.grant(CapPerms::RW, 5).unwrap();

        assert!(t.holds_packed_ref(ty::SHM, objref::SHM.pack(3, 2), CapPerms::READ), "the live cap above a stale one");
        assert!(t.holds_packed_ref(ty::SHM, objref::SHM.pack(3, 1), CapPerms::RW));
        assert!(!t.holds_packed_ref(ty::SHM, objref::SHM.pack(3, 2), CapPerms::WRITE), "a READ-only cap");
        assert!(!t.holds_packed_ref(ty::SHM, objref::SHM.pack(3, 3), CapPerms::READ), "another generation");
        assert!(!t.holds_packed_ref(ty::SHM, objref::SHM.pack(4, 1), CapPerms::READ), "a Port cap with that value");
        assert!(!t.holds_packed_ref(ty::SOCKET, 5, CapPerms::READ), "not a packed kind");
        assert!(!t.holds_packed_ref(CapType::NULL, 0, CapPerms::NONE));
    }

    /// `revoke_kind_at_index` takes every capability of one kind at one packed
    /// index and nothing else — not another index of the same kind, not
    /// another kind at the same index, not a non-packed kind — and a revoked
    /// handle stays stale after its slot is granted again.
    ///
    /// **Canary.** Drop the index compare from `revoke_kind_at_index`: the
    /// Shm-at-index-4 line reads `Stale` too.
    #[test]
    fn revoke_kind_at_index_takes_one_index_of_one_kind_and_keeps_slot_generations() {
        use super::targets::{IoRing, Socket, Shm};
        let t = CapTable::empty();
        let a: Cap<Shm> = t.grant(CapPerms::RW, objref::SHM.pack(3, 7)).unwrap();
        let elsewhere: Cap<Shm> = t.grant(CapPerms::READ, objref::SHM.pack(4, 1)).unwrap();
        let r: Cap<IoRing> = t.grant(CapPerms::RW, objref::IO_RING.pack(3, 7)).unwrap();
        let m: Cap<Socket> = t.grant(CapPerms::RW, 3).unwrap();
        assert_eq!(t.revoke_kind_at_index(ty::SHM, 3), 1);
        assert_eq!(t.get(a, CapPerms::READ), Err(CapError::Stale), "the swept index");
        assert_eq!(t.get(elsewhere, CapPerms::READ), Ok(objref::SHM.pack(4, 1)), "another index, same kind");
        assert_eq!(t.get(r, CapPerms::READ), Ok(objref::IO_RING.pack(3, 7)), "another kind, same index");
        assert_eq!(t.get(m, CapPerms::READ), Ok(3), "not a packed kind");
        assert_eq!(t.revoke_kind_at_index(ty::SHM, 3), 0, "a second pass");
        assert_eq!(t.revoke_kind_at_index(CapType::NULL, 3), 0);
        let again: Cap<Shm> = t.grant(CapPerms::RW, objref::SHM.pack(3, 7)).unwrap();
        assert_eq!(again.raw().slot(), a.raw().slot(), "precondition: the slot was reused");
        assert_eq!(t.get(a, CapPerms::READ), Err(CapError::Stale), "the old handle stays stale");
    }

    /// Wave 13 (NATFORK): a fork child's table answers to the parent's exact
    /// handles, and only through `install_at`'s rules.
    #[test]
    fn install_at_reproduces_a_handle_and_never_lowers_a_generation() {
        let parent = CapTable::empty();
        let _pad: Cap<Port> = parent.grant(CapPerms::RW, 1).unwrap();
        let h: Cap<Socket> = parent.grant(CapPerms::READ, 9).unwrap();
        let child = CapTable::empty();
        assert!(child.install_at(h.raw(), 42, &Warrant::ROOT));
        assert_eq!(child.get(h, CapPerms::READ), Ok(42), "same handle, the child's own resource");
        assert!(!child.install_at(h.raw(), 43, &Warrant::ROOT), "an occupied slot is refused");
        child.revoke(h);
        assert!(!child.install_at(h.raw(), 44, &Warrant::ROOT), "the slot's counter reached the generation: refused");
        assert!(!child.install_at(CapHandle::from_raw(0), 1, &Warrant::ROOT), "null");
        let wide = CapHandle::pack(ty::SOCKET, CapPerms::READ, 1, MAX_CAPS_PER_TASK as u16);
        assert!(!child.install_at(wide, 1, &Warrant::ROOT) || MAX_CAPS_PER_TASK >= 512, "a slot outside the table");
        // scan in chunks of one finds both parent entries, in slot order.
        let mut out = [(CapHandle::from_raw(0), 0u32); 1];
        let (n, next) = parent.scan(0, &mut out, |_| true);
        assert_eq!((n, out[0].1), (1, 1));
        let (n, _) = parent.scan(next, &mut out, |k| k == ty::SOCKET);
        assert_eq!((n, out[0].0, out[0].1), (1, h.raw(), 9));
        // clear_slot frees the slot and keeps its generation.
        child.clear_slot(h.raw().slot() as usize);
        assert_eq!(child.get(h, CapPerms::READ), Err(CapError::Stale));
        let again: Cap<Socket> = child.grant(CapPerms::READ, 1).unwrap();
        assert!(again.raw().generation() > h.raw().generation() || again.raw().slot() != h.raw().slot());
    }

    // ── RFC-0037: degrade_level_cap_pct mapping tests ─────────────────────
    //
    // These 6 tests have moved to domains/robot/degrade-policy/src/lib.rs where
    // they live next to the mapping function (level_cap_pct) and run via
    // `cargo test` from that crate's directory. The cap-tests host runner
    // no longer needs to cover them. Since wave 11 this file no longer
    // re-exports the function (the robot domain calls the leaf directly).

    /// N4: a grant takes the lowest free slot (the search starts at the
    /// free-slot hint, lowered by a revoke), a search stops past the last
    /// slot ever granted, and a wipe resets both.
    #[test]
    fn grants_take_the_lowest_free_slot_and_searches_stop_at_the_last_used() {
        let t = CapTable::empty();
        let _a: Cap<Port> = t.grant(CapPerms::RW, 1).unwrap();
        let b: Cap<Port> = t.grant(CapPerms::RW, 2).unwrap();
        let c: Cap<Port> = t.grant(CapPerms::RW, 3).unwrap();
        assert_eq!((b.raw().slot(), c.raw().slot()), (1, 2));
        t.revoke(b);
        let d: Cap<Port> = t.grant(CapPerms::RW, 4).unwrap();
        assert_eq!(d.raw().slot(), 1, "the freed slot, the lowest free one");
        let e: Cap<Port> = t.grant(CapPerms::RW, 5).unwrap();
        assert_eq!(e.raw().slot(), 3);
        assert_eq!(t.lookup(ty::PORT, 3).map(|h| h.slot()), Some(2));
        assert_eq!(t.lookup(ty::PORT, 5).map(|h| h.slot()), Some(3));
        assert_eq!(t.lookup(ty::PORT, 2), None, "revoked");
        assert_eq!(t.occupied(), 4);
        t.clear_all();
        assert_eq!(t.occupied(), 0);
        assert_eq!(t.lookup(ty::PORT, 3), None, "wiped, and not from the cache");
        let f: Cap<Port> = t.grant(CapPerms::RW, 6).unwrap();
        assert_eq!(f.raw().slot(), 0);
    }
}
