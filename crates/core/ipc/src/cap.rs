// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Typed capability wrapper — RFC-0003.
//!
//! `Cap<T>` is a `#[repr(transparent)]` newtype over the wire-format
//! `CapHandle` from [`azos_abi::cap`]. The type parameter `T` is a
//! marker carrying the kind at compile time — so `Cap<Channel>` and
//! `Cap<Sensor>` are distinct types that the type system refuses to
//! interchange.
//!
//! ## Why typed?
//!
//! Today (W1) the kernel still accepts integer handles end-to-end — see
//! [`super::handle`]. From W3 onwards new syscalls take `Cap<T>` directly:
//!
//! ```ignore
//! // The old, kind-erased shape:
//! pub fn sys_chan_send(handle: u32, data_ptr: *const u8, len: usize) -> i64;
//!
//! // The new, kind-typed shape:
//! pub fn sys_chan_send(cap: Cap<Channel>, data_ptr: *const u8, len: usize) -> Result<usize, Errno>;
//! ```
//!
//! A `Cap<Channel>` cannot be passed where `Cap<Sensor>` is expected;
//! that's a compile error, not a runtime check.
//!
//! ## Forgery resistance
//!
//! On **dereference** (`cap_table::get(&cap)`) the kernel verifies:
//!
//! 1. The slot index is in range.
//! 2. The slot is occupied (`generation > 0`).
//! 3. The handle's generation matches the slot's generation.
//! 4. The handle's kind tag matches `T::KIND`.
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

pub use azos_abi::cap::{CapHandle, CapKind, CapPerms, CAP_NULL};
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
/// `CapKind` discriminant at compile time.
///
/// New targets are added as zero-sized marker types in [`mod targets`].
pub trait CapTarget: 'static {
    /// The wire-format `CapKind` tag for this target type.
    const KIND: CapKind;
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
    use super::{CapKind, CapTarget};

    macro_rules! target {
        ($name:ident, $kind:ident, $doc:literal) => {
            #[doc = $doc]
            pub struct $name;
            impl CapTarget for $name {
                const KIND: CapKind = CapKind::$kind;
            }
        };
    }

    target!(Channel,    Channel,    "IPC channel endpoint.");
    target!(Shm,        Shm,        "Shared memory region.");
    target!(Port,       Port,       "Event port.");
    target!(Irq,        Irq,        "Hardware IRQ binding.");
    target!(MmioRegion, MmioRegion, "MMIO region.");
    target!(IoRing,     IoRing,     "IO ring.");
    target!(Sensor,     Sensor,     "Sensor descriptor.");
    target!(Gpio,       Gpio,       "GPIO pin.");
    target!(I2c,        I2c,        "I2C bus + address.");
    target!(Pwm,        Pwm,        "PWM channel.");
    target!(Motor,      Motor,      "Motor channel.");
    target!(File,       File,       "File descriptor.");
    target!(Socket,     Socket,     "Socket descriptor.");
    target!(Task,       Task,       "Process / task handle.");
    target!(AiSession,  AiSession,  "AI inference session.");
    // Added 2026-09-06 alongside the six new `CapKind` variants. A marker
    // type is inert on its own — it is what a `Cap<T>` is parameterised by,
    // not a grant — so the five without a minter below cost nothing and
    // spare the next migration a cross-crate edit.
    target!(Adc,        Adc,        "ADC channel.");
    target!(Buzzer,     Buzzer,     "The buzzer.");
    target!(Power,      Power,      "Power control (shutdown / reboot).");
    target!(Disk,       Disk,       "Raw block-device access.");
    target!(NetConfig,  NetConfig,  "Interface addressing.");
    target!(DriverRegistry, DriverRegistry,
            "The right to register as the driver for one `DRV_KIND_*`.");
    // RFC-0040 gap 2 (2026-09-19). Unlike the five above, this one is minted
    // from the start (`crate::endpoint`): an endpoint capability that nothing
    // can hold would close no hole, and a kind declared but never minted is
    // exactly the trap `CapKind::Task` fell into until wave 12 — nameable in
    // `CAPS.TOML`, silently granting nothing.
    target!(Endpoint,   Endpoint,   "Fast-IPC endpoint: the right to send a request to the service listening on it.");
    // U06-9 (2026-09-26). Singleton, like `Buzzer`: one brain-link PSK per
    // board, minted with resource `0` — see `crates/core/ipc/src/cap_seed.rs`'s
    // `CapKind::LinkKey` arm for the one target string that mints it.
    target!(LinkKey,    LinkKey,    "The brain-link PSK, in the kernel's reserved sector.");
    // Wave 9 (P9). Singleton, like `LinkKey`: one kernel entropy pool,
    // minted with resource `0` — see `crates/core/ipc/src/cap_seed.rs`'s
    // `CapKind::Entropy` arm for the one target string that mints it.
    target!(Entropy,    Entropy,    "Read access to the kernel entropy pool.");
    // Wave 9. Minted only by `SYS_IPC_LEASE_GRANT_TYPED` (never by a topology row:
    // `cap_seed` has no arm for it and the parser no name), revoked by
    // `lease::lease_free`.
    target!(Lease,      Lease,      "One lease, held by its lessor: the right to wait on it (and donate to its lessee).");
    // RFC-0055 (wave 11). Minted only by `SYS_PIPE_TYPED`, into the caller's
    // own table (never by a topology row): `crate::pipe`.
    target!(Pipe,       Pipe,       "One end of a pipe: READ for the read end, WRITE for the write end.");
    // RFC-0055 (wave 11). Seeded from the topology word `"launch"`; the
    // resource is an interned image name (`crate::launch_cap`).
    target!(Launch,     Launch,     "The right to start one image with SYS_SPAWN_EX.");
}

// ──────────────────────────────────────────────────────────────────────────
// Power / AiSession minters — RFC-0003 W5, wave 3 (2026-09-26)
// ──────────────────────────────────────────────────────────────────────────
//
// Owner decision (2026-09-26): one authority per irreversible effect.
// `crates/core/syscall/src/handlers.rs::sys_shutdown`/`sys_reboot` already gate on
// `cap_check(CapKind::Power, 0, true)`, and the console's `pm suspend` /
// `model load` (`crates/core/shell/src/authority.rs`) used `Cap<Motor>` WRITE as a
// stopgap because `targets::Power`/`targets::AiSession` existed with no
// minter — `crates/core/ipc/src/cap_seed.rs` used to list both among the kinds
// "deliberately left with no minter... giving them a mint path would open
// that door rather than close a hole." This is that minter, the same
// one-function-over-`cap_store::grant` shape every other typed kind uses
// (compare `pwm_cap::pwm_grant_cap`).
//
// **Single-resource, not pair-wide, unlike `Cap<Motor>`.** There is exactly
// one power domain and one AI-inference-session slot to name — neither has a
// second half to require — so both mint and check at `resource = 0`. That
// matches the resource `sys_shutdown`/`sys_reboot` already check against and
// `denial_target`'s mapping in `crates/core/syscall/src/handlers.rs`, which
// records `0` for `CapKind::Power` (no per-instance object to name).

/// Mint a `Cap<Power>` for `tid`. `resource` is always `0` — see the module
/// note above for why there is only one.
pub fn power_grant_cap(tid: u32, perms: CapPerms) -> Option<Cap<targets::Power>> {
    crate::cap_store::grant::<targets::Power>(tid, perms, 0)
}

/// Mint a `Cap<AiSession>` for `tid`. `resource` is always `0`, for the same
/// reason as [`power_grant_cap`].
pub fn ai_session_grant_cap(tid: u32, perms: CapPerms) -> Option<Cap<targets::AiSession>> {
    crate::cap_store::grant::<targets::AiSession>(tid, perms, 0)
}

/// Does this table hold `Cap<Power>` WRITE? The console's `pm suspend` gate
/// (`crates/core/shell/src/authority.rs::check_pm_suspend`) asks this instead of
/// going through `crates/core/syscall`'s `cap_check`, which always answers `true`
/// for a kernel task and would prove nothing for the console — the same
/// reason `crates/core/ipc/src/motor_cap.rs::table_holds_drivetrain_write` exists
/// instead of routing `flight arm` through `cap_check`.
///
/// Inherits `holds_kind_resource_with`'s RFC-0036 containment behavior: a
/// WRITE is refused while containment is armed even with the capability
/// held. See that function's doc and `table_holds_drivetrain_write`'s note
/// on the resulting denial-reason imprecision during a containment episode
/// — the same caveat applies here, unfixed, for the same reason (this
/// predicate returns `bool`, not `Result<(), CapError>`, so the caller
/// cannot distinguish "no grant" from "contained").
pub fn table_holds_power_write(table: &CapTable) -> bool {
    table.holds_kind_resource_with(CapKind::Power, 0, CapPerms::WRITE)
}

/// Does this table hold `Cap<AiSession>` WRITE? See
/// [`table_holds_power_write`] for the shape and the containment caveat;
/// identical, for the console's `model load` gate.
pub fn table_holds_ai_session_write(table: &CapTable) -> bool {
    table.holds_kind_resource_with(CapKind::AiSession, 0, CapPerms::WRITE)
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
/// **Occupancy** is tracked by `kind`: `CapKind::Null` means the slot
/// is free for reuse. **Generation** is a monotonic per-slot counter
/// that survives revoke; it is *only* reset when the slot has never
/// been granted. This separation is what makes a stale cap impossible
/// to confuse with a freshly granted cap on the same slot.
#[derive(Clone, Copy)]
pub struct CapSlot {
    /// Kind of the resource this slot points to. `CapKind::Null` ⇒ slot
    /// is empty.
    pub kind: CapKind,
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
    /// For the kinds [`objref::is_packed_kind`] names (Channel, Port, Shm,
    /// IoRing) it is a packed `(pool index, object generation)`. For every
    /// other kind it is the bare id (motor, pin, sensor type, ...).
    pub resource: u32,
}

impl CapSlot {
    /// Construct a fresh, never-granted slot.
    pub const EMPTY: Self = Self {
        kind: CapKind::Null,
        perms: CapPerms::NONE,
        generation: 0,
        resource: 0,
    };

    /// Returns `true` iff the slot currently holds a granted cap.
    #[inline]
    pub const fn is_occupied(&self) -> bool {
        !matches!(self.kind, CapKind::Null)
    }

    /// Spent: its generation has reached the field's maximum, so granting it
    /// again could only reissue a generation some previous holder still has.
    /// Never allocated again, occupied or not.
    #[inline]
    pub const fn is_retired(&self) -> bool {
        self.generation >= CapHandle::MAX_GENERATION
    }
}

/// Layout of [`CapSlot::resource`] for the kinds that carry an object
/// generation (RFC-0040 gap 1). Declared here rather than at the crate root so
/// every host crate that `#[path]`-mounts this file compiles it as well.
#[path = "objref.rs"]
pub mod objref;

/// Per-task cap table.
pub struct CapTable {
    slots: [CapSlot; MAX_CAPS_PER_TASK],
}

impl CapTable {
    /// Build a fresh empty cap table.
    pub const fn empty() -> Self {
        Self {
            slots: [CapSlot::EMPTY; MAX_CAPS_PER_TASK],
        }
    }

    /// Grant a fresh cap, returning a typed handle.
    ///
    /// Returns `None` if every slot is occupied (`EMFILE`).
    pub fn grant<T: CapTarget>(&mut self, perms: CapPerms, resource: u32) -> Option<Cap<T>> {
        // Single allocation path shared with `grant_raw` on purpose: the
        // generation invariant (never 0, always bumped on reuse) is what makes
        // a stale handle detectable, and two copies of that arithmetic is how
        // it silently drifts. `T::KIND` is never `Null`, so `grant_raw`'s
        // Null-kind refusal below can never fire on this path.
        self.grant_raw(T::KIND, perms, resource).map(Cap::from_raw)
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
    /// Refuses `CapKind::Null`: occupancy is encoded *as* `kind != Null`
    /// ([`CapSlot::is_occupied`]), so writing a Null-kind slot would produce
    /// an entry that reads as free while `bump_generation` has already moved
    /// on — a torn slot. `T::KIND` is never `Null`, so this can only fire on
    /// a caller passing runtime kind bits directly, which today is only the
    /// test in this module exercising the refusal itself.
    pub fn grant_raw(
        &mut self,
        kind: CapKind,
        perms: CapPerms,
        resource: u32,
    ) -> Option<CapHandle> {
        if matches!(kind, CapKind::Null) {
            return None;
        }
        let slot = self.allocate_slot()?;
        let slot_idx = slot as usize;
        let next_gen = self.bump_generation(slot_idx)?;
        self.slots[slot_idx] = CapSlot {
            kind,
            perms,
            generation: next_gen,
            resource,
        };
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
    /// **twenty-one — every hardware family plus Channel — had never been
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
    pub fn lookup(&self, kind: CapKind, resource: u32) -> Option<CapHandle> {
        if matches!(kind, CapKind::Null) {
            // Occupancy is encoded AS `kind != Null`, so a Null query would
            // match every free slot. Refused for the same reason `grant_raw`
            // refuses to write one.
            return None;
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.is_occupied()
                && slot.kind == kind
                && objref::resource_index(kind, slot.resource) == resource
            {
                return Some(CapHandle::pack(
                    slot.kind,
                    slot.perms,
                    slot.generation,
                    i as u16,
                ));
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
        let Some(slot) = azos_limits::nospec::get(&self.slots, slot_idx) else {
            return Err(CapError::Stale);
        };
        if !slot.is_occupied() {
            return Err(CapError::Stale);
        }
        if slot.generation != raw.generation() {
            return Err(CapError::Stale);
        }
        if slot.kind != T::KIND {
            return Err(CapError::WrongKind);
        }
        if !slot.perms.contains(need) {
            return Err(CapError::MissingPerms);
        }
        Ok(slot.resource)
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
    pub fn revoke<T: CapTarget>(&mut self, cap: Cap<T>) {
        if cap.is_null() {
            return;
        }
        let raw = cap.raw();
        let slot_idx = raw.slot() as usize;
        let Some(slot) = azos_limits::nospec::get_mut(&mut self.slots, slot_idx) else {
            return;
        };
        if slot.is_occupied() && slot.generation == raw.generation() {
            slot.kind = CapKind::Null;
            slot.perms = CapPerms::NONE;
            slot.resource = 0;
            // generation deliberately preserved; bumped on next grant.
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
    pub fn peek_raw(&self, handle: CapHandle) -> Option<(CapKind, CapPerms, u32)> {
        let slot_idx = handle.slot() as usize;
        let slot = azos_limits::nospec::get(&self.slots, slot_idx)?;
        if !slot.is_occupied() || slot.generation != handle.generation() {
            return None;
        }
        Some((slot.kind, slot.perms, slot.resource))
    }

    /// Kind-erased [`revoke`](Self::revoke), for the same reason
    /// [`peek_raw`](Self::peek_raw) is.
    ///
    /// Returns whether a slot was actually cleared, so a mover can assert that
    /// the entry it peeked is the entry it removed rather than assuming it.
    pub fn revoke_raw(&mut self, handle: CapHandle) -> bool {
        let slot_idx = handle.slot() as usize;
        let Some(slot) = azos_limits::nospec::get_mut(&mut self.slots, slot_idx) else {
            return false;
        };
        if slot.is_occupied() && slot.generation == handle.generation() {
            slot.kind = CapKind::Null;
            slot.perms = CapPerms::NONE;
            slot.resource = 0;
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
    pub fn revoke_where(&mut self, mut pred: impl FnMut(CapKind, u32) -> bool) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_occupied() && pred(slot.kind, slot.resource) {
                slot.kind = CapKind::Null;
                slot.perms = CapPerms::NONE;
                slot.resource = 0;
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
    /// Refused (`false`) for a null kind, a generation of 0 or past
    /// [`CapHandle::MAX_GENERATION`], a slot outside the table, an occupied
    /// slot, or a slot whose own counter already reached the handle's
    /// generation: a slot's generation only ever rises (the rule `grant_raw`
    /// keeps), so a stale handle this table issued earlier never validates
    /// again. A fork's child table was wiped when its slot was claimed, so
    /// every counter in it starts at 0.
    pub fn install_at(&mut self, handle: CapHandle, resource: u32) -> bool {
        let Some(kind) = CapKind::from_raw(handle.kind()) else { return false };
        let gen = handle.generation();
        if matches!(kind, CapKind::Null) || gen == 0 || gen > CapHandle::MAX_GENERATION {
            return false;
        }
        let Some(slot) = azos_limits::nospec::get_mut(&mut self.slots, handle.slot() as usize) else {
            return false;
        };
        if slot.is_occupied() || slot.generation >= gen {
            return false;
        }
        *slot = CapSlot { kind, perms: handle.perms(), generation: gen, resource };
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
        mut want: impl FnMut(CapKind) -> bool,
    ) -> (usize, usize) {
        let mut n = 0usize;
        let mut i = from;
        while i < self.slots.len() && n < out.len() {
            let s = &self.slots[i];
            if s.is_occupied() && want(s.kind) {
                out[n] = (CapHandle::pack(s.kind, s.perms, s.generation, i as u16), s.resource);
                n += 1;
            }
            i += 1;
        }
        (n, i)
    }

    /// Free slot `idx` whatever it holds, keeping its generation (so every
    /// handle on it is stale from now on). Out of range is a no-op.
    pub fn clear_slot(&mut self, idx: usize) {
        if let Some(slot) = azos_limits::nospec::get_mut(&mut self.slots, idx) {
            slot.kind = CapKind::Null;
            slot.perms = CapPerms::NONE;
            slot.resource = 0;
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

    /// Count slots retired by generation exhaustion — for diagnostics. A table
    /// whose count is climbing is a task churning capabilities; one whose count
    /// equals its size can grant nothing more.
    pub fn retired(&self) -> usize {
        self.slots.iter().filter(|s| s.is_retired()).count()
    }

    /// Count occupied slots — for diagnostics and quota enforcement.
    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|s| s.is_occupied()).count()
    }

    /// Does this table hold **any** occupied cap of `kind` whose permissions
    /// are a superset of `need`?
    ///
    /// **WHY this exists (W3-F9):** `SYS_DRV_INVOKE` needs to answer "may
    /// this client call this driver?" from `DriverManifest::required_perms`,
    /// which is a permission mask with no slot index attached — the client
    /// does not pass a cap handle, so there is nothing to dereference. This
    /// is a *presence* test over the caller's own table, not a dereference,
    /// and it is deliberately weaker than `get`: it proves the caller was
    /// granted authority over the subsystem, not over one specific resource
    /// within it. Where a syscall can take a `Cap<T>` it should, and the
    /// typed `sys_*_typed` family does.
    ///
    /// O(`MAX_CAPS_PER_TASK`) with no locking of its own (the caller holds
    /// the table lock) — one linear pass, no interrupt toggling.
    pub fn holds_kind_with(&self, kind: CapKind, need: CapPerms) -> bool {
        // A null "kind" would match empty slots; refuse it explicitly rather
        // than let a caller accidentally assert that every task is authorized.
        if matches!(kind, CapKind::Null) {
            return false;
        }
        self.slots
            .iter()
            .any(|s| s.is_occupied() && s.kind == kind && s.perms.contains(need))
    }

    /// Does this table hold an occupied cap of `kind` **for this specific
    /// `resource`** whose permissions are a superset of `need`?
    ///
    /// **WHY this exists, and how it differs from [`holds_kind_with`]
    /// (2026-08-24, `Cap<Motor>` per-motor granularity — RFC-0003 P1).**
    /// `holds_kind_with` answers "does the caller hold *any* cap of this
    /// kind", which is right for `SYS_DRV_INVOKE` (one manifest, one
    /// permission mask, no per-resource distinction). Pair-wide actuation —
    /// `motor_cap.rs`'s `require_pair_write` — needs the stronger question
    /// "does the caller hold write on resource 0 *and* on resource 1
    /// specifically", because a task holding only `Cap<Motor>(0)` must not
    /// be able to drive wheel 1 by having the presence check degrade into
    /// "some Motor cap exists". Filtering on `resource` is what makes that
    /// distinction possible.
    ///
    /// **Containment is checked here too, unlike `holds_kind_with`.** This
    /// deliberately diverges from its sibling: every caller of this method
    /// today is checking WRITE for an actuation path (the motor pair rule),
    /// so the RFC-0036 degraded-mode denial has to apply here exactly as it
    /// does inside `get()` — otherwise a task could hold two valid Motor
    /// caps and drive through containment via the "other leg" check while
    /// `get()`'s own containment correctly denies the leg it dereferences
    /// directly. `holds_kind_with`'s callers (`SYS_DRV_INVOKE`) are a
    /// pre-existing, differently-scoped presence test that this change does
    /// not touch — see the migration survey for the scope boundary.
    ///
    /// O(`MAX_CAPS_PER_TASK`), same shape as `holds_kind_with`.
    ///
    /// **Refuses the packed kinds** ([`objref::is_packed_kind`]: Channel, Port,
    /// Shm, IoRing). Their capabilities store a packed `(index, generation)`
    /// that a bare id cannot match, and answering on the index half would call
    /// a capability to a freed object "held". No caller asks about those kinds:
    /// the callers are File, Socket, Motor and the driver-bridge kinds (Gpio,
    /// I2c, Pwm, Motor).
    pub fn holds_kind_resource_with(&self, kind: CapKind, resource: u32, need: CapPerms) -> bool {
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
    pub fn holds_kind_resource_uncontained(&self, kind: CapKind, resource: u32, need: CapPerms) -> bool {
        if matches!(kind, CapKind::Null) || objref::is_packed_kind(kind) {
            return false;
        }
        self.slots.iter().any(|s| {
            s.is_occupied() && s.kind == kind && s.resource == resource && s.perms.contains(need)
        })
    }

    /// Does this table hold an occupied cap of (unpacked) `kind` with
    /// permissions a superset of `need` whose resource satisfies `pred`?
    ///
    /// For a kind whose resource is a RANGE rather than one object — a
    /// partition-scoped `Disk` capability admits every sector of its
    /// partition (RFC-0048 P3) — so the caller asks "does any capability I
    /// hold cover this", not "do I hold resource r". Same refusals and the
    /// same lack of a containment step as
    /// [`holds_kind_resource_uncontained`](Self::holds_kind_resource_uncontained).
    pub fn holds_kind_where(&self, kind: CapKind, need: CapPerms, mut pred: impl FnMut(u32) -> bool) -> bool {
        if matches!(kind, CapKind::Null) || objref::is_packed_kind(kind) {
            return false;
        }
        self.slots.iter().any(|s| {
            s.is_occupied() && s.kind == kind && s.perms.contains(need) && pred(s.resource)
        })
    }

    /// Does this table hold an occupied cap of packed `kind` whose stored
    /// reference is exactly `r` — index AND generation — with permissions a
    /// superset of `need`?
    ///
    /// **Only for the packed kinds** ([`objref::is_packed_kind`]); every other
    /// kind answers `false` (those have
    /// [`holds_kind_resource_uncontained`](Self::holds_kind_resource_uncontained)).
    /// The caller obtains `r` from the object's own pool (`shm_ref` for a
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
    pub fn holds_packed_ref(&self, kind: CapKind, r: u32, need: CapPerms) -> bool {
        if !objref::is_packed_kind(kind) {
            return false;
        }
        self.slots.iter().any(|s| {
            s.is_occupied() && s.kind == kind && s.resource == r && s.perms.contains(need)
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
    pub fn revoke_kind_at_index(&mut self, kind: CapKind, idx: u32) -> usize {
        if !objref::is_packed_kind(kind) {
            return 0;
        }
        let mut revoked = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_occupied() && slot.kind == kind && objref::idx(kind, slot.resource) == idx {
                slot.kind = CapKind::Null;
                slot.perms = CapPerms::NONE;
                slot.resource = 0;
                revoked += 1;
            }
        }
        revoked
    }

    /// Revoke every capability of `kind` and call `f(perms, resource)` for
    /// each, in slot order. Returns how many. RFC-0055: a dying task's
    /// `Cap<Pipe>` ends are dropped one by one before its table is wiped, so
    /// the pipe they name learns that an end is gone.
    pub fn drain_kind(&mut self, kind: CapKind, mut f: impl FnMut(CapPerms, u32)) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_occupied() && slot.kind == kind {
                let (perms, resource) = (slot.perms, slot.resource);
                slot.kind = CapKind::Null;
                slot.perms = CapPerms::NONE;
                slot.resource = 0;
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
    pub fn revoke_kind_resource(&mut self, kind: CapKind, resource: u32) -> usize {
        if objref::is_packed_kind(kind) || kind == CapKind::Null {
            return 0;
        }
        let mut revoked = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_occupied() && slot.kind == kind && slot.resource == resource {
                slot.kind = CapKind::Null;
                slot.perms = CapPerms::NONE;
                slot.resource = 0;
                revoked += 1;
            }
        }
        revoked
    }

    // Pick the next free slot index, or `None` if the table has no slot that
    // can still be granted. A retired slot is skipped even when free: its
    // generation cannot advance, so re-granting it would reissue one.
    fn allocate_slot(&self) -> Option<u16> {
        for (i, slot) in self.slots.iter().enumerate() {
            if !slot.is_occupied() && !slot.is_retired() {
                return Some(i as u16);
            }
        }
        None
    }

    // The slot's next generation, or `None` if it is spent. Never wraps: see
    // `CapSlot::generation`. `allocate_slot` already refuses a retired slot, so
    // `None` here is defence in depth against a second caller of this path.
    fn bump_generation(&self, slot_idx: usize) -> Option<u16> {
        let next = self.slots[slot_idx].generation.checked_add(1)?;
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
    /// The three that ARE recorded are three different events, and collapsing
    /// them would waste the one thing this path knows that the untyped one
    /// does not: `Stale` is a handle to an object that is gone or was reused —
    /// the forgery shape; `WrongKind` is a handle to a real object of another
    /// family — the confusion shape; `MissingPerms` is the right object with
    /// insufficient rights — the escalation shape.
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
    use super::targets::Channel;
    use super::*;

    /// A handle whose slot is empty must always fail with `Stale`.
    #[kani::proof]
    fn cap_forge_impossible_empty_slot() {
        let t = CapTable::empty();
        let raw_bits: u32 = kani::any();
        let forged: Cap<Channel> = Cap::from_raw(CapHandle::from_raw(raw_bits));
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
        let mut t = CapTable::empty();
        let resource: u32 = kani::any();
        let perms_bits: u8 = kani::any();
        kani::assume(perms_bits <= 0b1111);
        let perms = CapPerms::from_bits_truncate(perms_bits);
        let cap: Cap<Channel> = match t.grant(perms, resource) {
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
        let mut t = CapTable::empty();
        let resource: u32 = kani::any();
        // A cap that DOES carry WRITE, so the perms check passes and the
        // containment check is what rejects it.
        let cap: Cap<Channel> = match t.grant(CapPerms::RW, resource) {
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

    /// Granted cap with insufficient perms is rejected.
    #[kani::proof]
    fn cap_perms_required() {
        let mut t = CapTable::empty();
        let cap: Cap<Channel> = match t.grant(CapPerms::READ, 0) {
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
    use super::targets::{Channel, Sensor};
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
        let mut t = CapTable::empty();
        let c: Cap<Channel> = t.grant(CapPerms::RW, 42).unwrap();
        let resource = t.get(c, CapPerms::READ).unwrap();
        assert_eq!(resource, 42);
    }

    #[test]
    fn wrong_kind_fails() {
        let mut t = CapTable::empty();
        let c: Cap<Channel> = t.grant(CapPerms::RW, 7).unwrap();
        // Forge a Cap<Sensor> with the same raw handle bits — not a real
        // attack vector since Cap<T> is private to the kernel, but
        // verifies the runtime check.
        let forged = Cap::<Sensor>::from_raw(c.raw());
        let kind_ok = matches!(t.get(forged, CapPerms::READ), Err(CapError::WrongKind));
        assert!(kind_ok);
    }

    #[test]
    fn revoked_cap_is_stale() {
        let mut t = CapTable::empty();
        let c: Cap<Channel> = t.grant(CapPerms::RW, 1).unwrap();
        t.revoke(c);
        assert_eq!(t.get(c, CapPerms::READ), Err(CapError::Stale));
    }

    #[test]
    fn missing_perms_rejected() {
        let mut t = CapTable::empty();
        let c: Cap<Channel> = t.grant(CapPerms::READ, 9).unwrap();
        assert_eq!(t.get(c, CapPerms::WRITE), Err(CapError::MissingPerms));
    }

    #[test]
    fn generation_bump_after_reuse() {
        let mut t = CapTable::empty();
        let c1: Cap<Channel> = t.grant(CapPerms::RW, 1).unwrap();
        let g1 = c1.raw().generation();
        t.revoke(c1);
        let c2: Cap<Channel> = t.grant(CapPerms::RW, 2).unwrap();
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
        let mut t = CapTable::empty();
        // A bitmap over the generation space, not a Vec: this crate is `no_std`
        // and its test scope has no `alloc`.
        let mut seen = [0u64; (CapHandle::MAX_GENERATION as usize + 64) / 64];
        let mut count = 0usize;
        let mut last_slot = None;
        // One slot at a time: grant, record, revoke. The table keeps handing
        // back the same (lowest free) slot until that slot is spent.
        loop {
            let Some(c) = t.grant::<Channel>(CapPerms::RW, 1) else { break };
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
        let next: Cap<Channel> = t.grant(CapPerms::RW, 2).expect("other slots remain");
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
        let mut t = CapTable::empty();
        assert_eq!(t.bump_generation(0), Some(1), "a fresh slot starts at 1");
        t.slots[0].generation = CapHandle::MAX_GENERATION - 1;
        assert_eq!(
            t.bump_generation(0),
            Some(CapHandle::MAX_GENERATION),
            "the last usable generation must still be issued",
        );
        t.slots[0].generation = CapHandle::MAX_GENERATION;
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
        let mut t = CapTable::empty();
        // Retire every slot by hand — driving 512 slots x 8191 grants through
        // the real path would be 4.2M operations for the same assertion.
        for slot in t.slots.iter_mut() {
            slot.generation = CapHandle::MAX_GENERATION;
        }
        assert_eq!(t.retired(), MAX_CAPS_PER_TASK);
        assert!(t.grant::<Channel>(CapPerms::RW, 1).is_none(), "a spent table must refuse");
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
        let mut t = CapTable::empty();
        let rw: Cap<Channel> = t.grant(CapPerms::RW, 77).unwrap();
        let ro: Cap<Channel> = t.grant(CapPerms::READ, 5).unwrap();

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
        let mut t = CapTable::empty();
        let rw: Cap<Channel> = t.grant(CapPerms::RW, 77).unwrap();
        let ro: Cap<Channel> = t.grant(CapPerms::READ, 5).unwrap();
        let gone: Cap<Channel> = t.grant(CapPerms::RW, 9).unwrap();
        t.revoke(gone);
        let confused = Cap::<Sensor>::from_raw(rw.raw());

        for degraded in [false, true] {
            degraded_set(degraded);
            assert_eq!(t.get_uncontained(rw, CapPerms::WRITE), Ok(77), "degraded={degraded}");
            assert_eq!(t.get_uncontained(ro, CapPerms::READ), Ok(5), "degraded={degraded}");
            assert_eq!(t.get_uncontained(ro, CapPerms::WRITE), Err(CapError::MissingPerms), "degraded={degraded}");
            assert_eq!(t.get_uncontained(gone, CapPerms::WRITE), Err(CapError::Stale), "degraded={degraded}");
            assert_eq!(t.get_uncontained(confused, CapPerms::READ), Err(CapError::WrongKind), "degraded={degraded}");
            assert_eq!(t.get_uncontained::<Channel>(Cap::NULL, CapPerms::READ), Err(CapError::Stale), "degraded={degraded}");
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
            t.get::<Channel>(Cap::NULL, CapPerms::READ),
            Err(CapError::Stale)
        );
    }

    #[test]
    fn grant_raw_refuses_null_kind() {
        // Occupancy is `kind != Null`, so a Null-kind grant would burn a
        // generation on a slot that still reads as free.
        let mut t = CapTable::empty();
        assert!(t.grant_raw(CapKind::Null, CapPerms::RW, 1).is_none());
        assert_eq!(t.occupied(), 0);

        // A real kind still round-trips through the same allocation path
        // `grant<T>` uses, generation included: wrap the raw handle back into
        // a typed `Cap` and dereference it through `get`, same as any other
        // caller would.
        let h = t.grant_raw(CapKind::Gpio, CapPerms::READ, 7).unwrap();
        assert_ne!(h.generation(), 0);
        let cap: Cap<super::targets::Gpio> = Cap::from_raw(h);
        assert_eq!(t.get(cap, CapPerms::READ), Ok(7));
    }

    #[test]
    fn holds_kind_resource_with_is_resource_specific() {
        let _serial = degrade_guard();
        let mut t = CapTable::empty();
        let _m0: Cap<crate::cap::targets::Motor> = t.grant(CapPerms::RW, 0).unwrap();
        // Only resource 0 is held — resource 1 must not be reported present,
        // even though the kind matches and READ/WRITE would pass on 0.
        assert!(t.holds_kind_resource_with(CapKind::Motor, 0, CapPerms::WRITE));
        assert!(!t.holds_kind_resource_with(CapKind::Motor, 1, CapPerms::WRITE));
        // Wrong kind at the same resource id must not match either.
        assert!(!t.holds_kind_resource_with(CapKind::Gpio, 0, CapPerms::WRITE));
    }

    #[test]
    fn holds_kind_resource_with_denies_write_when_degraded() {
        let _serial = degrade_guard();
        let mut t = CapTable::empty();
        let _m1: Cap<crate::cap::targets::Motor> = t.grant(CapPerms::RW, 1).unwrap();
        assert!(t.holds_kind_resource_with(CapKind::Motor, 1, CapPerms::WRITE));
        degraded_set(true);
        assert!(!t.holds_kind_resource_with(CapKind::Motor, 1, CapPerms::WRITE));
        // READ is unaffected by containment, same as `get`.
        assert!(t.holds_kind_resource_with(CapKind::Motor, 1, CapPerms::READ));
        degraded_set(false);
    }

    /// `table_holds_power_write`/`table_holds_ai_session_write` — the console's
    /// `pm suspend`/`model load` gates (`crates/core/shell/src/authority.rs`) call
    /// these directly on a `CapTable`, never through `cap_store`, so this test
    /// exercises them at the same level: no grant refuses, a READ-only grant
    /// still refuses (both commands need WRITE), and a WRITE grant admits.
    #[test]
    fn power_and_ai_session_write_predicates() {
        use crate::cap::targets::{AiSession, Power};
        let mut t = CapTable::empty();
        assert!(!super::table_holds_power_write(&t));
        assert!(!super::table_holds_ai_session_write(&t));

        let _p: Cap<Power> = t.grant(CapPerms::READ, 0).unwrap();
        let _a: Cap<AiSession> = t.grant(CapPerms::READ, 0).unwrap();
        // READ alone must not satisfy a WRITE gate.
        assert!(!super::table_holds_power_write(&t));
        assert!(!super::table_holds_ai_session_write(&t));

        let mut t2 = CapTable::empty();
        let _p2: Cap<Power> = t2.grant(CapPerms::WRITE, 0).unwrap();
        let _a2: Cap<AiSession> = t2.grant(CapPerms::WRITE, 0).unwrap();
        assert!(super::table_holds_power_write(&t2));
        assert!(super::table_holds_ai_session_write(&t2));
        // The two kinds do not satisfy each other's predicate.
        let mut t3 = CapTable::empty();
        let _p3: Cap<Power> = t3.grant(CapPerms::WRITE, 0).unwrap();
        assert!(!super::table_holds_ai_session_write(&t3));
    }

    /// A capability minted for a different kind, reinterpreted as `Cap<Power>`
    /// (the same forgery `wrong_kind_still_rejected_before_pairing_logic` in
    /// `motor_cap.rs` exercises), must fail `get` with `WrongKind` — the
    /// minter existing must not weaken the kind check every other typed cap
    /// already gets for free from `Cap<T>`'s type parameter.
    #[test]
    fn forged_power_cap_from_another_kind_is_rejected() {
        use crate::cap::targets::{Gpio, Power};
        let mut t = CapTable::empty();
        let gpio: Cap<Gpio> = t.grant(CapPerms::RW, 0).unwrap();
        let forged: Cap<Power> = Cap::from_raw(gpio.raw());
        assert_eq!(t.get(forged, CapPerms::WRITE), Err(CapError::WrongKind));
        assert!(!super::table_holds_power_write(&t));
    }

    #[test]
    fn full_table_returns_none() {
        let mut t = CapTable::empty();
        for i in 0..MAX_CAPS_PER_TASK {
            let _: Cap<Channel> = t.grant(CapPerms::RW, i as u32).unwrap();
        }
        let extra: Option<Cap<Channel>> = t.grant(CapPerms::RW, 0);
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
        use super::targets::{Motor, Shm};
        let mut t = CapTable::empty();
        let packed = objref::SHM.pack(3, 0x00AB_CDEF);
        let shm: Cap<Shm> = t.grant(CapPerms::RW, packed).unwrap();
        let motor: Cap<Motor> = t.grant(CapPerms::RW, objref::SHM.pack(3, 1)).unwrap();
        assert_eq!(t.lookup(CapKind::Shm, 3), Some(shm.raw()));
        assert_eq!(t.lookup(CapKind::Shm, packed), None, "the query is an index");
        assert_eq!(t.lookup(CapKind::Shm, 4), None);
        assert_eq!(t.lookup(CapKind::IoRing, 3), None, "another kind");
        assert_eq!(t.lookup(CapKind::Motor, 3), None, "a bare kind matches its whole resource");
        assert_eq!(t.lookup(CapKind::Motor, objref::SHM.pack(3, 1)), Some(motor.raw()));
        assert_eq!(t.get(shm, CapPerms::READ), Ok(packed));

        // Channel and Port, each with its own layout.
        use super::targets::{Channel, Port};
        let ch: Cap<Channel> = t.grant(CapPerms::RW, objref::CHANNEL.pack(2, 9)).unwrap();
        let p: Cap<Port> = t.grant(CapPerms::RW, objref::PORT.pack(2, 9)).unwrap();
        assert_eq!(t.lookup(CapKind::Channel, 2), Some(ch.raw()));
        assert_eq!(t.lookup(CapKind::Port, 2), Some(p.raw()));
        assert_eq!(t.lookup(CapKind::Channel, objref::CHANNEL.pack(2, 9)), None, "the query is an index");
        assert_eq!(t.lookup(CapKind::Port, 9), None);
    }

    /// Both presence checks refuse `Null` and the packed kinds; only the
    /// contained one refuses a WRITE while degraded.
    ///
    /// **Canaries.** Drop `is_packed_kind` from the refusal: the Shm lines read
    /// true. Put the containment step into the uncontained variant: its
    /// degraded WRITE reads false.
    #[test]
    fn presence_checks_refuse_packed_kinds_and_only_one_is_contained() {
        use super::targets::{Channel, IoRing, Motor, Port, Shm};
        let _serial = degrade_guard();
        let mut t = CapTable::empty();
        let _s: Cap<Shm> = t.grant(CapPerms::RW, 5).unwrap();
        let _r: Cap<IoRing> = t.grant(CapPerms::RW, 5).unwrap();
        let _c: Cap<Channel> = t.grant(CapPerms::RW, 5).unwrap();
        let _p: Cap<Port> = t.grant(CapPerms::RW, 5).unwrap();
        let _m: Cap<Motor> = t.grant(CapPerms::RW, 5).unwrap();
        for need in [CapPerms::NONE, CapPerms::READ, CapPerms::WRITE] {
            for kind in [CapKind::Shm, CapKind::IoRing, CapKind::Channel, CapKind::Port] {
                assert!(!t.holds_kind_resource_uncontained(kind, 5, need), "{kind:?}");
                assert!(!t.holds_kind_resource_with(kind, 5, need), "{kind:?}");
            }
            assert!(!t.holds_kind_resource_uncontained(CapKind::Null, 5, need));
        }
        degraded_set(true);
        assert!(t.holds_kind_resource_uncontained(CapKind::Motor, 5, CapPerms::WRITE));
        assert!(!t.holds_kind_resource_with(CapKind::Motor, 5, CapPerms::WRITE));
        degraded_set(false);
        assert!(t.holds_kind_resource_with(CapKind::Motor, 5, CapPerms::WRITE));
        assert!(!t.holds_kind_resource_uncontained(CapKind::Motor, 6, CapPerms::NONE));
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
        use super::targets::{Motor, Port, Shm};
        let mut t = CapTable::empty();
        let _stale: Cap<Shm> = t.grant(CapPerms::RW, objref::SHM.pack(3, 1)).unwrap();
        let _live: Cap<Shm> = t.grant(CapPerms::READ, objref::SHM.pack(3, 2)).unwrap();
        let _port: Cap<Port> = t.grant(CapPerms::RW, objref::SHM.pack(4, 1)).unwrap();
        let _motor: Cap<Motor> = t.grant(CapPerms::RW, 5).unwrap();

        assert!(t.holds_packed_ref(CapKind::Shm, objref::SHM.pack(3, 2), CapPerms::READ), "the live cap above a stale one");
        assert!(t.holds_packed_ref(CapKind::Shm, objref::SHM.pack(3, 1), CapPerms::RW));
        assert!(!t.holds_packed_ref(CapKind::Shm, objref::SHM.pack(3, 2), CapPerms::WRITE), "a READ-only cap");
        assert!(!t.holds_packed_ref(CapKind::Shm, objref::SHM.pack(3, 3), CapPerms::READ), "another generation");
        assert!(!t.holds_packed_ref(CapKind::Shm, objref::SHM.pack(4, 1), CapPerms::READ), "a Port cap with that value");
        assert!(!t.holds_packed_ref(CapKind::Motor, 5, CapPerms::READ), "not a packed kind");
        assert!(!t.holds_packed_ref(CapKind::Null, 0, CapPerms::NONE));
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
        use super::targets::{IoRing, Motor, Shm};
        let mut t = CapTable::empty();
        let a: Cap<Shm> = t.grant(CapPerms::RW, objref::SHM.pack(3, 7)).unwrap();
        let elsewhere: Cap<Shm> = t.grant(CapPerms::READ, objref::SHM.pack(4, 1)).unwrap();
        let r: Cap<IoRing> = t.grant(CapPerms::RW, objref::IO_RING.pack(3, 7)).unwrap();
        let m: Cap<Motor> = t.grant(CapPerms::RW, 3).unwrap();
        assert_eq!(t.revoke_kind_at_index(CapKind::Shm, 3), 1);
        assert_eq!(t.get(a, CapPerms::READ), Err(CapError::Stale), "the swept index");
        assert_eq!(t.get(elsewhere, CapPerms::READ), Ok(objref::SHM.pack(4, 1)), "another index, same kind");
        assert_eq!(t.get(r, CapPerms::READ), Ok(objref::IO_RING.pack(3, 7)), "another kind, same index");
        assert_eq!(t.get(m, CapPerms::READ), Ok(3), "not a packed kind");
        assert_eq!(t.revoke_kind_at_index(CapKind::Shm, 3), 0, "a second pass");
        assert_eq!(t.revoke_kind_at_index(CapKind::Null, 3), 0);
        let again: Cap<Shm> = t.grant(CapPerms::RW, objref::SHM.pack(3, 7)).unwrap();
        assert_eq!(again.raw().slot(), a.raw().slot(), "precondition: the slot was reused");
        assert_eq!(t.get(a, CapPerms::READ), Err(CapError::Stale), "the old handle stays stale");
    }

    /// Wave 13 (NATFORK): a fork child's table answers to the parent's exact
    /// handles, and only through `install_at`'s rules.
    #[test]
    fn install_at_reproduces_a_handle_and_never_lowers_a_generation() {
        let mut parent = CapTable::empty();
        let _pad: Cap<Channel> = parent.grant(CapPerms::RW, 1).unwrap();
        let h: Cap<Sensor> = parent.grant(CapPerms::READ, 9).unwrap();
        let mut child = CapTable::empty();
        assert!(child.install_at(h.raw(), 42));
        assert_eq!(child.get(h, CapPerms::READ), Ok(42), "same handle, the child's own resource");
        assert!(!child.install_at(h.raw(), 43), "an occupied slot is refused");
        child.revoke(h);
        assert!(!child.install_at(h.raw(), 44), "the slot's counter reached the generation: refused");
        assert!(!child.install_at(CapHandle::from_raw(0), 1), "null");
        let wide = CapHandle::pack(CapKind::Sensor, CapPerms::READ, 1, MAX_CAPS_PER_TASK as u16);
        assert!(!child.install_at(wide, 1) || MAX_CAPS_PER_TASK >= 512, "a slot outside the table");
        // scan in chunks of one finds both parent entries, in slot order.
        let mut out = [(CapHandle::from_raw(0), 0u32); 1];
        let (n, next) = parent.scan(0, &mut out, |_| true);
        assert_eq!((n, out[0].1), (1, 1));
        let (n, _) = parent.scan(next, &mut out, |k| k == CapKind::Sensor);
        assert_eq!((n, out[0].0, out[0].1), (1, h.raw(), 9));
        // clear_slot frees the slot and keeps its generation.
        child.clear_slot(h.raw().slot() as usize);
        assert_eq!(child.get(h, CapPerms::READ), Err(CapError::Stale));
        let again: Cap<Sensor> = child.grant(CapPerms::READ, 1).unwrap();
        assert!(again.raw().generation() > h.raw().generation() || again.raw().slot() != h.raw().slot());
    }

    // ── RFC-0037: degrade_level_cap_pct mapping tests ─────────────────────
    //
    // These 6 tests have moved to domains/robot/degrade-policy/src/lib.rs where
    // they live next to the mapping function (level_cap_pct) and run via
    // `cargo test` from that crate's directory. The cap-tests host runner
    // no longer needs to cover them. Since wave 11 this file no longer
    // re-exports the function (the robot domain calls the leaf directly).
}
