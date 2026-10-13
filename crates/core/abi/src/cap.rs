// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Capability handle wire format.
//!
//! Across the syscall boundary a capability is a `u32`:
//!
//! ```text
//!   bits 31..26  → type tag      (CapType, 6 bits: kind 4 + class 2)
//!   bits 25..22  → permissions   (CapPerms bitfield, 4 bits)
//!   bits 21..9   → generation    (13 bits, monotonic per slot; a slot is
//!                                 retired at MAX_GENERATION, never wrapped)
//!   bits 8..0    → slot index    (per-task cap-table slot, 9 bits, 0..511)
//! ```
//!
//! No bits are reserved any more: see `GEN_BITS`, `SLOT_BITS` and
//! `RESERVED_BITS` below for when each field took them.
//!
//! The kernel-internal `Cap<T>` typed wrapper (`crates/core/ipc/src/cap.rs`,
//! RFC-0003) is built on top of this representation, adding compile-time
//! kind safety. Both forms encode identically; only the kernel sees the
//! typed form.
//!
//! ## Persistence and transmission (checked before widening the kind field)
//!
//! A packed `CapHandle` is **not** persisted to disk and **not** put on any
//! wire other than a syscall argument register:
//!
//! - Topology / `CAPS.TOML` (`crates/core/topology/`) stores `kind` as a text
//!   name (`"gpio"`, `"motor"`, ...) and `perms`/`target` as parsed fields;
//!   `CapSpec` never holds a packed `u32`. The handle is minted fresh from
//!   those parsed fields at admission time.
//! - OTA images (`crates/core/ota/src/pure.rs`, `OtaHeader`/`BootMeta`) carry
//!   firmware version/CRC/slot metadata, no cap fields at all.
//! - The flight recorder's `LogRecord` (`crates/core/actuation/src/logger.rs`)
//!   and the cap-denial payload (`tests/host/syscall-tests/src/cap_denial_record.rs`)
//!   record `CapKind::denial_code()` (the kind's discriminant) plus a raw
//!   resource id. Neither field is a packed `CapHandle`.
//! - The brain wire protocol (`../AzOSRobotBrain/protocol.py`) reserves a
//!   `CAPS = 0x06` packet type for a future capability-declaration payload
//!   (RFC-0039) but documents it as "not yet sent or handled on either
//!   side"; nothing there encodes `kind|perms|gen|slot` today.
//!
//! Because nothing stored or transmitted depends on the current bit
//! widths, the field boundaries below are free to move within a boot.
//!
//! ## Why 6 bits of type?
//!
//! A capability's identity is a *kind* (an endpoint, a memory object, a
//! queue, a node of the name space, a device, a log ...) and a *class* within
//! it (a file or a socket of the node kind, an interrupt line or an MMIO
//! region of the device kind). Four bits hold the kind and two the class, which
//! is the width the field has had since it was widened from 4 bits. Hardware
//! and services are not kinds: a pin, a wheel, a sensor or a partition is the
//! badge of an `Endpoint` capability and its rights are the op classes of the
//! interface behind it (`azos_devif`).
//!
//! ## Why pack into 32 bits?
//!
//! Three reasons:
//!
//! 1. Forward compatibility with userspace `int fd` ABIs. A POSIX fd is
//!    typically 32-bit signed; we use 32-bit unsigned with `0` reserved
//!    for `CAP_NULL` so that any fd > 0 is treatable as a `CapHandle`.
//! 2. Fits in a single syscall arg register on every supported arch.
//! 3. Anti-forgery: the kernel rejects a handle whose generation doesn't
//!    match the cap table; even random guesses fail with overwhelming
//!    probability.

use core::num::NonZeroU32;

/// Wire-format capability handle.
///
/// `0` is reserved for `CAP_NULL`. Any non-zero handle is a candidate; the
/// kernel verifies kind + generation on dereference.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CapHandle(pub u32);

/// Reserved null handle. Always invalid.
pub const CAP_NULL: CapHandle = CapHandle(0);

impl CapHandle {
    /// Construct from raw u32. Does not validate.
    #[inline]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Get the raw u32 representation.
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Returns `true` if this is the null handle.
    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Convert to `Option<NonZeroU32>` for ergonomic non-null usage.
    #[inline]
    pub const fn as_nonzero(self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0)
    }

    // ── Bitfield helpers ────────────────────────────────────────────────
    //
    // Each field's width is a single named `*_BITS` const; shifts and
    // masks are derived from those so the layout can only be changed in
    // one place. See the module doc for why these particular widths.

    const KIND_BITS: u32 = 6;
    const PERMS_BITS: u32 = 4;
    /// 8 → 13 on 2026-09-19, spending what was left of `RESERVED_BITS`.
    ///
    /// **Eight bits were a use-after-revoke.** `CapTable`'s per-slot counter
    /// wrapped `255 → 1` with no sweep, so the 256th grant of a slot reissued a
    /// generation a previous holder still had: its revoked handle validated
    /// again, against whatever object now sits in that slot. Thirteen bits do
    /// not fix that on their own — a wrap is a wrap — so the counter no longer
    /// wraps at all: `crates/core/ipc` retires a slot when it reaches
    /// [`MAX_GENERATION`] rather than starting over. The width is what makes
    /// retiring affordable: 8,191 grants per slot instead of 255.
    const GEN_BITS: u32 = 13;
    /// Always zero on a well-formed handle. **Exhausted on 2026-09-19**: the
    /// last five bits went to `GEN_BITS` (8 → 13). A future rebalance now has
    /// to take bits from another field, and the const-assert below is what
    /// forces that to be deliberate.
    ///
    /// **Spent one bit of it on 2026-09-18**, 6 → 5, which is precisely what
    /// the sentence above reserved it for. `config/Kconfig.limits` has declared
    /// `MAX_CAPS_PER_TASK = 512` for `PROFILE_FLEET` since that profile
    /// existed, while `SLOT_BITS` addressed only 256 — so the fleet kernel
    /// was built with `pack()` silently truncating slot indices, and slot
    /// 256 answered to the same handle as slot 0. Two different capabilities,
    /// one handle, in the profile with the largest capability pool
    /// (`MAX_CAPS_TOTAL = 65536`). It compiled in silence because the assert
    /// that should have caught it compared against `crates/core/ipc`'s own
    /// hardcoded `256` rather than the configured value; fixing that
    /// (same day) is what surfaced this.
    const RESERVED_BITS: u32 = 0;
    /// Public so `crates/core/ipc` can assert its own `MAX_CAPS_PER_TASK` fits.
    /// That crate cannot be imported here (this one is dependency-free by
    /// design), so the binding has to be made from the other side, and it
    /// cannot be made against a private constant.
    ///
    /// 8 → 9 on 2026-09-18, taking the bit from `RESERVED_BITS`: see its
    /// doc comment for the fleet-profile truncation this closes. Nine bits
    /// address 512 slots, which is the largest `MAX_CAPS_PER_TASK` any
    /// profile declares.
    pub const SLOT_BITS: u32 = 9;

    const KIND_SHIFT: u32 = 32 - Self::KIND_BITS;
    const KIND_MASK: u32 = (1 << Self::KIND_BITS) - 1;
    const PERMS_SHIFT: u32 = Self::KIND_SHIFT - Self::PERMS_BITS;
    const PERMS_MASK: u32 = (1 << Self::PERMS_BITS) - 1;
    const GEN_SHIFT: u32 = Self::PERMS_SHIFT - Self::GEN_BITS;
    const GEN_MASK: u32 = (1 << Self::GEN_BITS) - 1;
    // RESERVED occupies the bits between GEN and SLOT: no accessor, must
    // stay zero. SLOT starts at bit 0, so its shift is always 0.
    const SLOT_MASK: u32 = (1 << Self::SLOT_BITS) - 1;

    /// Mirror of `azos_ipc::cap::MAX_CAPS_PER_TASK` (256). `abi` is a
    /// dependency-free, frozen ABI crate (RFC-0008) and cannot import that
    /// constant without creating a cycle (`ipc` depends on `abi`), so this
    /// is a *third* copy of the number, alongside Kconfig's
    /// `MAX_CAPS_PER_TASK` and `crates/core/ipc/src/cap.rs`'s own hardcoded
    /// `256`. The assert below only binds this local mirror: if Kconfig's
    /// or `ipc`'s copy ever drifts from 256, nothing here catches it —
    /// that would need an analogous assert added on the `ipc` side, which
    /// is a follow-up for the owner to approve, not part of this change.
    /// 256 → 512 on 2026-09-18, alongside `SLOT_BITS` 8 → 9. This is the
    /// CEILING the handle encoding supports, not any one profile's value:
    /// `config/Kconfig.limits` sets 32 (embedded), 256 (edge) and 512 (fleet), and
    /// it is `crates/core/ipc`'s assert — now bound to the *configured* constant
    /// rather than a local copy — that checks each profile against this
    /// encoding. This mirror only keeps `abi` self-consistent.
    const MAX_CAPS_PER_TASK_MIRROR: u32 = 512;

    /// The largest generation a slot can reach. A slot at this value is spent:
    /// `crates/core/ipc` refuses to grant it again rather than wrapping the counter.
    pub const MAX_GENERATION: u16 = Self::GEN_MASK as u16;

    /// Pack type + perms + generation + slot into a wire-format handle.
    #[inline]
    pub const fn pack(ty: CapType, perms: CapPerms, generation: u16, slot: u16) -> Self {
        let v = ((ty.raw() as u32) & Self::KIND_MASK) << Self::KIND_SHIFT
            | ((perms.bits() as u32) & Self::PERMS_MASK) << Self::PERMS_SHIFT
            | ((generation as u32) & Self::GEN_MASK) << Self::GEN_SHIFT
            | (slot as u32) & Self::SLOT_MASK;
        Self(v)
    }

    /// Extract the encoded `CapType` tag (see [`CapType::raw`]).
    #[inline]
    pub const fn kind(self) -> u8 {
        ((self.0 >> Self::KIND_SHIFT) & Self::KIND_MASK) as u8
    }

    /// Extract the permission bits.
    #[inline]
    pub const fn perms(self) -> CapPerms {
        CapPerms::from_bits_truncate(((self.0 >> Self::PERMS_SHIFT) & Self::PERMS_MASK) as u8)
    }

    /// Extract the generation counter.
    #[inline]
    pub const fn generation(self) -> u16 {
        ((self.0 >> Self::GEN_SHIFT) & Self::GEN_MASK) as u16
    }

    /// Extract the per-task slot index.
    #[inline]
    pub const fn slot(self) -> u16 {
        (self.0 & Self::SLOT_MASK) as u16
    }
}

// The five fields must tile the u32 exactly, with no gap and no overlap.
const _: () = assert!(
    CapHandle::KIND_BITS
        + CapHandle::PERMS_BITS
        + CapHandle::GEN_BITS
        + CapHandle::RESERVED_BITS
        + CapHandle::SLOT_BITS
        == 32,
    "CapHandle bitfield layout must total exactly 32 bits"
);

// The slot field must be wide enough to address every valid cap-table
// slot (0..MAX_CAPS_PER_TASK_MIRROR). If this ever fires, either
// SLOT_BITS needs to grow (taking bits back from RESERVED_BITS) or
// MAX_CAPS_PER_TASK_MIRROR is stale — see its doc comment.
const _: () = assert!(
    (1u32 << CapHandle::SLOT_BITS) >= CapHandle::MAX_CAPS_PER_TASK_MIRROR,
    "CapHandle's slot field cannot address every MAX_CAPS_PER_TASK slot"
);

impl core::fmt::Debug for CapHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_null() {
            return f.write_str("Cap(null)");
        }
        write!(
            f,
            "Cap(kind={}, perms={:?}, gen={}, slot={})",
            self.kind(),
            self.perms(),
            self.generation(),
            self.slot()
        )
    }
}

/// `SYS_CAP_INFO(ty::SHM, SHM_STREAM_LIDAR)`: the handle of this
/// task's `Cap<Shm>` to the kernel's LiDAR stream (wave 11, SHMRING), when
/// its topology row declares `Shm stream.lidar` and the stream is configured
/// in. A `Shm` lookup otherwise names a region by its pool INDEX, which is
/// below the shm pool's size (16), so keys above that range can never name
/// a region; "ST" in the high half makes them recognisable in a trace.
pub const SHM_STREAM_LIDAR: u32 = 0x5354_0000;
/// [`SHM_STREAM_LIDAR`] for the camera stream (`stream.camera`).
pub const SHM_STREAM_CAMERA: u32 = 0x5354_0001;

/// Capability kinds: the generic objects a task can hold a right to. A
/// device, a file or a socket is not a kind of its own: it is a *class* of
/// one of these (`CapType`) or an interface served over an `Endpoint`
/// (`azos_devif`: a pin, a wheel, a sensor, a partition are badges of
/// endpoints, their rights the op classes).
///
/// The discriminant is the wire tag: 4 bits of the 6-bit kind field of a
/// handle (the other 2 are the class), and also the code a capability denial
/// is written under in the flight recorder. `Thread` joins in part B of D6,
/// with the call that makes one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum CapKind {
    /// Reserved for `CAP_NULL`. Should never appear on a valid handle.
    Null = 0,
    /// The right to send a request to a service: a task-hosted endpoint, or an
    /// interface the kernel hosts (`azos_devif`), whose badge names the
    /// resource and whose rights are the interface's op classes. One
    /// authority to call, nothing else (RFC-0040 gap 2).
    Endpoint = 1,
    /// A memory object: shared memory (class `SHM`, a region two tasks map) or
    /// a lease on one (class `LEASE`, held by its lessor, waited on to donate
    /// priority to the lessee).
    MemObj = 2,
    /// A queue of requests: an io_ring (class `IORING`).
    Queue = 3,
    /// An event port.
    Port = 4,
    /// A task: the right to see every task (class `TASK`, resource 0, `READ`),
    /// not authority over one.
    Domain = 5,
    /// A node of the name space: a file or a directory tree (`FILE`), a socket
    /// (`SOCKET`), one end of a pipe (`PIPE`) or the right to start one image
    /// (`LAUNCH`).
    Node = 6,
    /// A piece of hardware or its driver slot: an interrupt line (`IRQ`), an
    /// MMIO region of the board's table (`MMIO`) or the right to register as
    /// the driver for one `DRV_KIND_*` (`DRVSLOT`).
    Device = 7,
    /// A log: the kernel tracer (class `TRACE`) or the console (class `CONSOLE`).
    Log = 8,
}

impl CapKind {
    /// Try to construct from the raw 4-bit kind value.
    #[inline]
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Null),
            1 => Some(Self::Endpoint),
            2 => Some(Self::MemObj),
            3 => Some(Self::Queue),
            4 => Some(Self::Port),
            5 => Some(Self::Domain),
            6 => Some(Self::Node),
            7 => Some(Self::Device),
            8 => Some(Self::Log),
            // No catch-all beyond the named arms: an unknown tag is not a
            // kind, and `None` is what makes an unpack of a corrupt or
            // future handle fail closed instead of aliasing onto a real one.
            _ => None,
        }
    }

    /// The code this kind is written under in the flight recorder: its
    /// discriminant. A record names the generic object that was refused; the
    /// detail word carries the resource.
    #[inline]
    pub const fn denial_code(self) -> u8 {
        self as u8
    }
}

/// Kind tags set aside for later parts of D6: `Thread` is 9 (part B, with the
/// call that makes one), then these two. They are constants, not variants,
/// so [`CapKind::from_raw`] answers `None` for them and no dead variant exists.
/// (A proxy for a capability held by another node is not a kind: it is an
/// `Endpoint` the topology names `rpc-...`, which the RPC server serves.)
pub mod reserved_kind {
    /// A virtual machine.
    pub const VM: u8 = 10;
    /// A virtual CPU.
    pub const VCPU: u8 = 11;
}

/// A kind and its class: the identity a capability slot stores and a typed
/// `Cap<T>` checks. Six bits, the width of the handle's kind field: the kind
/// in the low four, the class in the high two. A kind with one class (an
/// endpoint, a port) is class 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct CapType(u8);

impl CapType {
    /// The type of an empty slot.
    pub const NULL: Self = Self(0);
    /// The most classes a kind has.
    pub const CLASSES: u8 = 4;

    /// The class `class` (below [`Self::CLASSES`]) of `kind`.
    #[inline]
    pub const fn new(kind: CapKind, class: u8) -> Self {
        assert!(class < Self::CLASSES);
        Self(kind as u8 | (class << 4))
    }

    /// From the raw 6-bit value; `None` for a kind that does not exist or bits
    /// above the field.
    #[inline]
    pub const fn from_raw(raw: u8) -> Option<Self> {
        if raw >= 64 {
            return None;
        }
        match CapKind::from_raw(raw & 0x0F) {
            Some(_) => Some(Self(raw)),
            None => None,
        }
    }

    /// The raw 6-bit value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The kind.
    #[inline]
    pub const fn kind(self) -> CapKind {
        match CapKind::from_raw(self.0 & 0x0F) {
            Some(k) => k,
            None => CapKind::Null,
        }
    }

    /// The class within the kind.
    #[inline]
    pub const fn class(self) -> u8 {
        self.0 >> 4
    }

    /// The code a denial of this type is recorded under: its kind's.
    #[inline]
    pub const fn denial_code(self) -> u8 {
        self.kind().denial_code()
    }
}

impl From<CapKind> for CapType {
    #[inline]
    fn from(k: CapKind) -> Self {
        Self::new(k, 0)
    }
}

/// The named types: every class of every kind a kernel table can hold.
pub mod ty {
    use super::{CapKind, CapType};

    /// A task-hosted or kernel-hosted endpoint.
    pub const ENDPOINT: CapType = CapType::new(CapKind::Endpoint, 0);
    /// An event port.
    pub const PORT: CapType = CapType::new(CapKind::Port, 0);
    /// A shared-memory region.
    pub const SHM: CapType = CapType::new(CapKind::MemObj, 0);
    /// One lease, held by its lessor (RFC-0031, wave 9). Minted by
    /// `MEMOBJ_LEASE_GRANT` with the lease id as its resource; `READ`
    /// is what `MEMOBJ_LEASE_WAIT` checks.
    pub const LEASE: CapType = CapType::new(CapKind::MemObj, 1);
    /// An io_ring.
    pub const IORING: CapType = CapType::new(CapKind::Queue, 0);
    /// The right to see every task: minted for one target only, `"tasks"`,
    /// `READ`, resource `0` (wave 12; `/proc/tasks` and `/proc/<tid>`).
    pub const TASK: CapType = CapType::new(CapKind::Domain, 0);
    /// A file descriptor (FAT32 / tmpfs / procfs) or a directory tree.
    pub const FILE: CapType = CapType::new(CapKind::Node, 0);
    /// The right to start one image with `SYS_SPAWN_EX` (RFC-0055, wave 11):
    /// the resource is an interned image name, `EXEC` the permission. Class 1
    /// so that its raw value stays below 32: the micro kernel (rv32) returns
    /// handles as positive results.
    pub const LAUNCH: CapType = CapType::new(CapKind::Node, 1);
    /// A socket descriptor.
    pub const SOCKET: CapType = CapType::new(CapKind::Node, 2);
    /// One end of a pipe (RFC-0055, wave 11): minted only at run time by
    /// `DOMAIN_CREATE_PIPE`, the read end `READ`, the write end `WRITE`.
    pub const PIPE: CapType = CapType::new(CapKind::Node, 3);
    /// A hardware interrupt line.
    pub const IRQ: CapType = CapType::new(CapKind::Device, 0);
    /// A device of the hardware bus (`azos_drv_bus::hwbus`) and its register
    /// window. The resource is the device's bus handle (its slot index),
    /// the value `DOMAIN_MMIO_MAP` takes and checks; its denial record carries
    /// the handle. The topology grants it by what the device is
    /// (`mmio.dt:google,goldfish-rtc`), not by where a machine listed it.
    pub const MMIO: CapType = CapType::new(CapKind::Device, 1);
    /// The right to register as the driver for one `DRV_KIND_*` (the resource).
    pub const DRIVER_REGISTRY: CapType = CapType::new(CapKind::Device, 2);
    /// The kernel tracer (wave 15, the `LOG_TRACE_*` ops): `READ` maps the
    /// per-CPU rings and reads the class mask, `WRITE` changes it.
    pub const TRACE: CapType = CapType::new(CapKind::Log, 0);
    /// The console: `WRITE` puts bytes on it, `READ` waits for input on it
    /// (`invoke` on a `Log` of this class). Seeded into every task at
    /// admission (`azos_ipc::cap_seed::seed_console`); the image's op-class
    /// mask is what withholds an op from a confined program. Class 1 so that
    /// its raw value stays below 32 (the micro kernel returns handles as
    /// positive results).
    pub const CONSOLE: CapType = CapType::new(CapKind::Log, 1);
}

/// Permission bits packed into a capability handle.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CapPerms(u8);

impl CapPerms {
    /// Read access.
    pub const READ: Self = Self(0b0001);
    /// Write access.
    pub const WRITE: Self = Self(0b0010);
    /// Execute / map-as-X access (MMIO regions).
    pub const EXEC: Self = Self(0b0100);
    /// Permission to duplicate to another task.
    pub const DUP: Self = Self(0b1000);

    /// No permissions (a stub / placeholder).
    pub const NONE: Self = Self(0);
    /// Read + Write.
    pub const RW: Self = Self(Self::READ.0 | Self::WRITE.0);
    /// Read + Write + Dup.
    pub const RW_DUP: Self = Self(Self::READ.0 | Self::WRITE.0 | Self::DUP.0);
    /// All permissions.
    pub const ALL: Self = Self(0b1111);

    /// Construct from raw bits, masking to the valid range.
    #[inline]
    pub const fn from_bits_truncate(raw: u8) -> Self {
        Self(raw & 0b1111)
    }

    /// Extract raw bits.
    #[inline]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns `true` iff `self` contains all bits of `other`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Bitwise OR.
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Bitwise AND.
    #[inline]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl core::fmt::Debug for CapPerms {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        let mut emit = |s: &str| -> core::fmt::Result {
            if !first {
                f.write_str("|")?;
            }
            first = false;
            f.write_str(s)
        };
        if self.contains(Self::READ) {
            emit("R")?;
        }
        if self.contains(Self::WRITE) {
            emit("W")?;
        }
        if self.contains(Self::EXEC) {
            emit("X")?;
        }
        if self.contains(Self::DUP) {
            emit("D")?;
        }
        if first {
            f.write_str("∅")?;
        }
        Ok(())
    }
}

/// The hot word of a capability slot: what a task's table stores for one
/// grant, in 64 bits (the first half of the 128-bit slot; the second is the
/// extension word, `ipc/src/cap.rs`). One definition, so the main kernel's
/// table and the micro kernel's decode the same word:
///
/// ```text
///   bits  0..8   type        (CapType raw; 0 = Null = the slot is free)
///   bits  8..16  permissions (CapPerms bits, 4 used)
///   bits 16..32  generation  (survives a revoke, never wraps)
///   bits 32..64  resource    (the type's own id or packed pool index)
/// ```
///
/// Bit 12 (above the four permission bits) is [`EXPIRES`](slot_word::EXPIRES):
/// the slot's warrant carries a deadline. Nothing here depends on the width
/// of a machine word.
pub mod slot_word {
    use super::{CapPerms, CapType};

    /// Bit 12: the slot's warrant carries a deadline.
    pub const EXPIRES: u64 = 1 << 12;

    /// The word of a grant.
    #[inline(always)]
    pub const fn encode(ty: CapType, perms: CapPerms, generation: u16, resource: u32) -> u64 {
        (ty.raw() as u64)
            | ((perms.bits() as u64) << 8)
            | ((generation as u64) << 16)
            | ((resource as u64) << 32)
    }

    /// The type of a word (`NULL` for a raw value that names no type).
    #[inline(always)]
    pub const fn ty(w: u64) -> CapType {
        match CapType::from_raw(w as u8) {
            Some(t) => t,
            None => CapType::NULL,
        }
    }

    /// The slot is not free.
    #[inline(always)]
    pub const fn occupied(w: u64) -> bool {
        w as u8 != CapType::NULL.raw()
    }

    /// The word's type is `t` (no decode).
    #[inline(always)]
    pub const fn ty_is(w: u64, t: CapType) -> bool {
        w as u8 == t.raw()
    }

    /// The permissions of a word.
    #[inline(always)]
    pub const fn perms(w: u64) -> CapPerms {
        CapPerms::from_bits_truncate((w >> 8) as u8)
    }

    /// The generation of a word.
    #[inline(always)]
    pub const fn generation(w: u64) -> u16 {
        (w >> 16) as u16
    }

    /// The resource of a word.
    #[inline(always)]
    pub const fn resource(w: u64) -> u32 {
        (w >> 32) as u32
    }

    /// The word has [`EXPIRES`] set.
    #[inline(always)]
    pub const fn expires(w: u64) -> bool {
        w & EXPIRES != 0
    }

    /// The word of a freed slot: the generation alone, so the next grant of
    /// the slot gets a fresh one.
    #[inline(always)]
    pub const fn cleared(w: u64) -> u64 {
        w & (0xffff << 16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_is_zero() {
        assert!(CAP_NULL.is_null());
        assert_eq!(CAP_NULL.as_raw(), 0);
    }

    #[test]
    fn pack_unpack_round_trip() {
        // Slot is 8 bits wide (0..=255); 0xAB is the largest value that
        // stays readable as hex while fitting the field.
        let h = CapHandle::pack(ty::PORT, CapPerms::RW_DUP, 0x42, 0xAB);
        assert_eq!(h.kind(), ty::PORT.raw());
        assert!(h.perms().contains(CapPerms::READ));
        assert!(h.perms().contains(CapPerms::WRITE));
        assert!(h.perms().contains(CapPerms::DUP));
        assert!(!h.perms().contains(CapPerms::EXEC));
        assert_eq!(h.generation(), 0x42);
        assert_eq!(h.slot(), 0xAB);
    }

    #[test]
    fn slot_beyond_field_width_truncates() {
        // `MAX_CAPS_PER_TASK_MIRROR - 1` (511, since SLOT_BITS went 8 → 9 on
        // 2026-09-18) is the largest legal slot; one past it must not
        // round-trip.
        //
        // The boundary is derived, not written as a literal: this test used
        // to hardcode 256, and it was one of the things that would have gone
        // quietly stale when the field width changed. The fleet profile's
        // 512-slot tables were truncating against the OLD width for as long
        // as that profile existed, and no test noticed.
        let past_end = CapHandle::MAX_CAPS_PER_TASK_MIRROR as u16;
        let h = CapHandle::pack(ty::PORT, CapPerms::NONE, 0, past_end);
        assert_ne!(h.slot(), past_end, "a slot past the field must not survive packing");
        assert_eq!(h.slot(), 0, "it wraps to 0 — the collision this width protects against");
    }

    /// The largest legal slot must survive a round trip. Pairs with the test
    /// above: that one pins where truncation starts, this one pins that the
    /// last usable slot is genuinely usable — the half of the boundary that
    /// was never asserted, and the half that the fleet profile needed.
    #[test]
    fn the_last_legal_slot_round_trips() {
        let last = (CapHandle::MAX_CAPS_PER_TASK_MIRROR - 1) as u16;
        let h = CapHandle::pack(ty::PORT, CapPerms::RW, 0x7, last);
        assert_eq!(h.slot(), last);
        assert_eq!(h.kind(), ty::PORT.raw());
        assert_eq!(h.generation(), 0x7);
        assert!(h.perms().contains(CapPerms::WRITE));
    }

    #[test]
    fn perms_contains() {
        assert!(CapPerms::ALL.contains(CapPerms::READ));
        assert!(CapPerms::ALL.contains(CapPerms::DUP));
        assert!(!CapPerms::READ.contains(CapPerms::WRITE));
        assert!(CapPerms::RW.contains(CapPerms::READ));
        assert!(CapPerms::RW.contains(CapPerms::WRITE));
        assert!(!CapPerms::RW.contains(CapPerms::DUP));
    }

    #[test]
    fn kind_from_raw() {
        assert_eq!(CapKind::from_raw(1), Some(CapKind::Endpoint));
        assert_eq!(CapKind::from_raw(2), Some(CapKind::MemObj));
        assert_eq!(CapKind::from_raw(8), Some(CapKind::Log));
        assert_eq!(CapKind::from_raw(9), None);
        assert_eq!(CapKind::from_raw(15), None);
        assert_eq!(CapKind::from_raw(0x12), None, "the class bits are not part of a kind");
    }

    /// A type is a kind and a class in six bits, and round-trips through the
    /// raw value; a raw value naming no kind or reaching past the field is not
    /// a type.
    #[test]
    fn type_round_trips_and_refuses_what_names_nothing() {
        for k in [CapKind::Endpoint, CapKind::MemObj, CapKind::Queue, CapKind::Node, CapKind::Device] {
            for c in 0..CapType::CLASSES {
                let t = CapType::new(k, c);
                assert_eq!((t.kind(), t.class()), (k, c));
                assert_eq!(CapType::from_raw(t.raw()), Some(t));
                assert!(t.raw() < 64, "a type fits the handle's kind field");
            }
        }
        assert_eq!(CapType::from(CapKind::Port), ty::PORT);
        assert_eq!(CapType::from_raw(9), None, "kind 9 does not exist");
        assert_eq!(CapType::from_raw(64), None, "past the field");
        assert_eq!(CapType::from_raw(0xFF), None);
    }

    #[test]
    fn debug_format() {
        let h = CapHandle::pack(ty::SHM, CapPerms::RW, 1, 7);
        let s = alloc_string_dbg(&h);
        assert!(s.contains("kind=2"), "{s}");
        assert!(s.contains("R|W"));
        assert!(s.contains("gen=1"));
        assert!(s.contains("slot=7"));
    }

    // Tiny helper to get a String only in tests; uses std for simplicity.
    fn alloc_string_dbg<T: core::fmt::Debug>(t: &T) -> String {
        format!("{:?}", t)
    }
}
