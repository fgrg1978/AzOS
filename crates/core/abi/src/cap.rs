// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Capability handle wire format.
//!
//! Across the syscall boundary a capability is a `u32`:
//!
//! ```text
//!   bits 31..26  → kind tag      (CapKind, 6 bits)
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
//!   record `CapKind::denial_code()` — a *different*, deliberately frozen
//!   numbering (0..13 from the retired handle table, then appended) — plus a raw
//!   resource id. Neither field is a packed `CapHandle`.
//! - The brain wire protocol (`../AzOSRobotBrain/protocol.py`) reserves a
//!   `CAPS = 0x06` packet type for a future capability-declaration payload
//!   (RFC-0039) but documents it as "not yet sent or handled on either
//!   side"; nothing there encodes `kind|perms|gen|slot` today.
//!
//! Because nothing stored or transmitted depends on the current bit
//! widths, the field boundaries below are free to move within a boot.
//!
//! ## Why 6 bits of kind? (history: the split this layout started from)
//!
//! `CapKind` originally used all 16 values a 4-bit field can hold (`Null`
//! through `AiSession`), which left no room for six pending `HandleKind`
//! counterparts (Adc, Buzzer, Power, Disk, NetConfig, DriverRegistry) that
//! block finishing the `Cap<T>` migration. The owner's fix: widen `kind`
//! by taking bits from `slot`, since `slot` never needed all 16 of its
//! bits — `MAX_CAPS_PER_TASK` is 256, so 8 bits address every slot index
//! (`0..=255`) exactly. That frees 8 bits total: 2 go to `kind` (4 → 6,
//! room for 64 kinds — the 16 in use plus the 6 pending plus headroom),
//! and 6 are left as an explicit, always-zero reserved field between
//! `generation` and `slot` rather than silently absorbed into one field.
//! Widening `kind` here only makes room for those six kinds; it does not
//! add them — that needs the minting-rule decision (mint what you create,
//! never delegate) written down first, and is deliberately out of scope
//! for this change.
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

    /// Pack kind + perms + generation + slot into a wire-format handle.
    #[inline]
    pub const fn pack(kind: CapKind, perms: CapPerms, generation: u16, slot: u16) -> Self {
        let v = ((kind as u32) & Self::KIND_MASK) << Self::KIND_SHIFT
            | ((perms.bits() as u32) & Self::PERMS_MASK) << Self::PERMS_SHIFT
            | ((generation as u32) & Self::GEN_MASK) << Self::GEN_SHIFT
            | (slot as u32) & Self::SLOT_MASK;
        Self(v)
    }

    /// Extract the encoded `CapKind` tag.
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

/// `SYS_CAP_LOOKUP(CapKind::Shm, SHM_STREAM_LIDAR)`: the handle of this
/// task's `Cap<Shm>` to the kernel's LiDAR stream (wave 11, SHMRING), when
/// its topology row declares `Shm stream.lidar` and the stream is configured
/// in. A `Shm` lookup otherwise names a region by its pool INDEX, which is
/// below the shm pool's size (16), so keys above that range can never name
/// a region; "ST" in the high half makes them recognisable in a trace.
pub const SHM_STREAM_LIDAR: u32 = 0x5354_0000;
/// [`SHM_STREAM_LIDAR`] for the camera stream (`stream.camera`).
pub const SHM_STREAM_CAMERA: u32 = 0x5354_0001;

/// Capability kinds. Each kind corresponds to a typed `Cap<T>` in the
/// kernel; the wire-format tag is the discriminant.
///
/// `repr(u8)` so that the tag fits in the 6-bit kind field of the wire-format
/// handle: 25 kinds defined today (`Null` plus 24), in a field with room for
/// 64. See the module doc for why it was widened from 4 bits. The six the
/// widening made room for were added on 2026-09-06, `Endpoint` on
/// 2026-09-19, `LinkKey` on 2026-09-26 (U06-9) and `Entropy` on 2026-09-28
/// (wave 9, P9); `ALL_KINDS` in
/// `tests/host/abi-tests` pins the count and the order, so a variant added here
/// without its two other arms does not compile and a variant added without
/// updating that array does not pass.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum CapKind {
    /// Reserved for `CAP_NULL`. Should never appear on a valid handle.
    Null = 0,
    /// IPC channel endpoint.
    Channel = 1,
    /// Shared memory region.
    Shm = 2,
    /// Event port.
    Port = 3,
    /// Hardware IRQ binding.
    Irq = 4,
    /// MMIO region. A capability's resource is an index into the board's MMIO
    /// region table (`azos_drv_base::platform::hw::MMIO_REGIONS`, RFC-0043),
    /// the value `SYS_MMIO_MAP` takes and checks; the table fixes the range and
    /// whether it may be written. Its denial record carries the region's base.
    MmioRegion = 5,
    /// IO ring (io_ring submission/completion queues).
    IoRing = 6,
    /// Sensor descriptor.
    Sensor = 7,
    /// GPIO pin.
    Gpio = 8,
    /// I2C bus + address.
    I2c = 9,
    /// PWM channel.
    Pwm = 10,
    /// Motor channel.
    Motor = 11,
    /// File descriptor (FAT32 / tmpfs / procfs).
    File = 12,
    /// Socket descriptor.
    Socket = 13,
    /// Process / task handle. Minted since wave 12 for one target only:
    /// `"tasks"`, `READ`, resource `0` — the right to see EVERY task in
    /// `/proc/tasks` and by `/proc/<tid>`. Without it an image sees only
    /// itself and its descendants (Linux `hidepid=2`, owner round 48).
    Task = 14,
    /// AI inference session.
    AiSession = 15,
    // ── Added 2026-09-06, once `CapHandle`'s kind field was widened from 4
    // bits to 6. Each of the six below mirrors a kind the untyped `cap_check`
    // path gates (from the caller's capability table since RFC-0040 gap 1),
    // so none of them closes a hole by existing: they exist so
    // those families have a typed name to migrate ONTO, one at a time.
    //
    // Only `DriverRegistry` has a minter, a topology name and typed syscalls
    // today — see `crates/core/ipc/src/cap_seed.rs`, which names the other five as
    // open gaps rather than leaving them to be discovered. A variant with no
    // minter cannot be granted, so adding it grants nothing.
    /// ADC channel.
    Adc = 16,
    /// The buzzer — one instance, no sub-resource.
    Buzzer = 17,
    /// Power control: shutdown and reboot.
    Power = 18,
    /// Raw block-device access, below the filesystem.
    Disk = 19,
    /// Interface addressing.
    NetConfig = 20,
    /// The right to register as the driver for one `DRV_KIND_*`.
    ///
    /// The resource index is the `DRV_KIND_*` value, so holding this for
    /// GPIO is not holding it for the motor, rather than being blanket.
    DriverRegistry = 21,
    /// A fast-IPC **endpoint**: the right to send a request to the service
    /// listening on it, and nothing else (RFC-0040 gap 2, added 2026-09-19).
    ///
    /// # Why this is not one of the three kinds that already look like it
    ///
    /// * `Channel` (1) is a message RING. It has no task binding at all —
    ///   `channel_recv_cap` resolves purely through the holder's table — and no
    ///   per-exchange identity, so it cannot express "this reply answers that
    ///   request".
    /// * `Port` (3) is an event QUEUE: `bind(source_kind, user_key)` then
    ///   `queue_event`/`poll`. One direction, no reply channel.
    /// * `Task` (14) is authority over a TASK. "May send this service a
    ///   request" and "may act on this task" are different authorities, and a
    ///   service should be addressable without its TID being the name of it —
    ///   one task may listen on several endpoints, and an endpoint may outlive
    ///   the task that first served it.
    ///
    /// The gap this closes: fast IPC is addressed by TID, and while
    /// `fast_ipc_reply` checks that the replier is the server the exchange was
    /// addressed to, `fast_ipc_call` checks only that the destination is a live
    /// TID. Any task granted `SYS_IPC_FAST_CALL` can call any task. Holding a
    /// capability to an endpoint is what that call will require instead.
    Endpoint = 22,
    /// The brain-link PSK, held in a reserved sector no USB host can address
    /// (U06-9, RFC ownership decision 2026-09-26). A singleton, like
    /// `Buzzer`: one key per board, so the resource a slot carries is always
    /// `0`. `READ` is the only permission `SYS_LINK_KEY_READ_TYPED` checks —
    /// there is no write path, the key is provisioned at image-build time.
    LinkKey = 23,
    /// Read access to the kernel entropy pool (`SYS_ENTROPY_READ_TYPED`,
    /// wave 9 P9). A singleton, like `LinkKey`: one pool per kernel, so the
    /// resource a slot carries is always `0`. `READ` is the only permission
    /// the call checks.
    ///
    /// Its own kind rather than a reuse of `LinkKey`: a task that needs
    /// random bytes (nonces, ephemeral keys) must not have to hold the
    /// brain-link PSK to get them, and a task that holds the PSK gains
    /// nothing it did not already have from this one.
    Entropy = 24,
    /// One lease of the lease table (RFC-0031), held by its LESSOR (wave 9).
    /// Minted by `SYS_IPC_LEASE_GRANT_TYPED` (603) for a ring-3 lessor, with the lease id
    /// as its resource, and revoked when the lease is freed. `READ` is what
    /// `SYS_IPC_LEASE_WAIT` checks: waiting on a lease donates the waiter's
    /// priority to its lessee, so only the task the lease was granted by may.
    Lease = 25,
    /// One end of a pipe (RFC-0055, wave 11). Minted only at run time, into
    /// the caller's own table, by `SYS_PIPE_TYPED` (607): the read end
    /// carries `READ`, the write end `WRITE`, both naming one pool slot and
    /// its generation. Read, write and close are the file calls 564/565/566.
    /// The topology word `"pipe"` exists and is refused: a pipe end is never
    /// granted by a row. Ends reach another task only through the
    /// `SYS_SPAWN_EX` move list.
    Pipe = 26,
    /// The right to start one image with `SYS_SPAWN_EX` (608, RFC-0055,
    /// wave 11). Seeded from the topology word `"launch"`; the target is an
    /// image name (`"TOOLBOX.ELF"`), interned by `crates/core/ipc/src/launch_cap.rs`,
    /// and `EXEC` is the permission the call checks against the image the
    /// file's digest resolves to (not the path typed).
    Launch = 27,
}

impl CapKind {
    /// Try to construct from the raw 6-bit tag value.
    #[inline]
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Null),
            1 => Some(Self::Channel),
            2 => Some(Self::Shm),
            3 => Some(Self::Port),
            4 => Some(Self::Irq),
            5 => Some(Self::MmioRegion),
            6 => Some(Self::IoRing),
            7 => Some(Self::Sensor),
            8 => Some(Self::Gpio),
            9 => Some(Self::I2c),
            10 => Some(Self::Pwm),
            11 => Some(Self::Motor),
            12 => Some(Self::File),
            13 => Some(Self::Socket),
            14 => Some(Self::Task),
            15 => Some(Self::AiSession),
            16 => Some(Self::Adc),
            17 => Some(Self::Buzzer),
            18 => Some(Self::Power),
            19 => Some(Self::Disk),
            20 => Some(Self::NetConfig),
            21 => Some(Self::DriverRegistry),
            22 => Some(Self::Endpoint),
            23 => Some(Self::LinkKey),
            24 => Some(Self::Entropy),
            25 => Some(Self::Lease),
            26 => Some(Self::Pipe),
            27 => Some(Self::Launch),
            // No catch-all beyond the named arms: an unknown tag is not a
            // kind, and `None` is what makes an unpack of a corrupt or
            // future handle fail closed instead of aliasing onto a real one.
            _ => None,
        }
    }

    /// The code this kind is written under in the flight recorder.
    ///
    /// **Frozen, and NOT the discriminant.** The first fourteen are the numbers
    /// the retired handle table's `code()` wrote, which the black box has been
    /// using since capability denials started being recorded: a recording made
    /// by an older build must still decode. `CapKind::Gpio` is discriminant 8
    /// and code **2**, because the handle table's GPIO code was 2 — writing the
    /// discriminant instead would make every typed GPIO denial decode as an
    /// ADC one, silently, in a file whose whole purpose is to be read after the
    /// fact.
    ///
    /// The first fourteen are pinned as literals in `tests/host/syscall-tests/src/cap_denial_record.rs`. The eight that
    /// exist only as `Cap<T>` (`Channel`, `Shm`, `Port`, `IoRing`, `File`,
    /// `Socket`, `Task`, `AiSession`) are appended from 14. `Null` is 0, "no object".
    ///
    /// **Append, never renumber**, and never add a `_ =>` arm — this match is
    /// exhaustive because it lives in the same crate as the enum, which is the
    /// only place `#[non_exhaustive]` permits that. A variant added without an
    /// arm here is a compile error; a wildcard would make it a silently wrong
    /// recording instead.
    pub const fn denial_code(self) -> u8 {
        match self {
            // The retired handle table's codes — same object, same number.
            Self::Null => 0,
            Self::Sensor => 1,
            Self::Gpio => 2,
            Self::I2c => 3,
            Self::Pwm => 4,
            Self::Motor => 5,
            Self::Irq => 6,
            Self::MmioRegion => 7,
            Self::Adc => 8,
            Self::Buzzer => 9,
            Self::Power => 10,
            Self::Disk => 11,
            Self::NetConfig => 12,
            Self::DriverRegistry => 13,
            // Only ever typed.
            Self::Channel => 14,
            Self::Shm => 15,
            Self::Port => 16,
            Self::IoRing => 17,
            Self::File => 18,
            Self::Socket => 19,
            Self::Task => 20,
            Self::AiSession => 21,
            Self::Endpoint => 22,
            Self::LinkKey => 23,
            Self::Entropy => 24,
            Self::Lease => 25,
            Self::Pipe => 26,
            Self::Launch => 27,
        }
    }
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
        let h = CapHandle::pack(CapKind::Channel, CapPerms::RW_DUP, 0x42, 0xAB);
        assert_eq!(h.kind(), CapKind::Channel as u8);
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
        let h = CapHandle::pack(CapKind::Channel, CapPerms::NONE, 0, past_end);
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
        let h = CapHandle::pack(CapKind::Channel, CapPerms::RW, 0x7, last);
        assert_eq!(h.slot(), last);
        assert_eq!(h.kind(), CapKind::Channel as u8);
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
        assert_eq!(CapKind::from_raw(1), Some(CapKind::Channel));
        assert_eq!(CapKind::from_raw(15), Some(CapKind::AiSession));
        assert_eq!(CapKind::from_raw(16), Some(CapKind::Adc));
        assert_eq!(CapKind::from_raw(21), Some(CapKind::DriverRegistry));
        assert_eq!(CapKind::from_raw(22), None);
    }

    #[test]
    fn debug_format() {
        let h = CapHandle::pack(CapKind::Shm, CapPerms::RW, 1, 7);
        let s = alloc_string_dbg(&h);
        assert!(s.contains("kind=2"));
        assert!(s.contains("R|W"));
        assert!(s.contains("gen=1"));
        assert!(s.contains("slot=7"));
    }

    // Tiny helper to get a String only in tests; uses std for simplicity.
    fn alloc_string_dbg<T: core::fmt::Debug>(t: &T) -> String {
        format!("{:?}", t)
    }
}
