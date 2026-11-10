// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Capability handle wire format.
//!
//! Across the syscall boundary a capability is a `u32`:
//!
//! ```text
//!   bits 31..26  → type tag      (CapType, 6 bits: kind 4 + class 2)
//!   bits 25..10  → generation    (16 bits, as the slot word stores it)
//!   bits 9..0    → slot index    (per-task cap-table slot, 10 bits)
//! ```
//!
//! Every bit is checked: no value names a slot through a bit the check
//! ignores. The rights are not here, they are the slot's; a holder asks with
//! `CAP_INFO_QUERY`.
//!
//! The kernel-internal `Cap<T>` typed wrapper (`crates/core/ipc/src/cap.rs`,
//! capability IPC) is built on top of this representation, adding compile-time
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
//! - The robot extension's wire protocol
//!   (`crates/domains/robot/behavior/src/companion_protocol.rs`) reserves a
//!   `PKT_CAPS = 0x06` packet type for a future capability-declaration payload
//!   that is not sent or handled yet; nothing there encodes
//!   `kind|perms|gen|slot` today.
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
//! 3. A use after close is refused: the kernel rejects a handle whose
//!    generation doesn't match the cap table. A guess reaches only what the
//!    guesser's own table holds.
//!
//! ## Generation recurrence
//!
//! The generation is the only defence for the copies of a handle in user
//! memory, which nothing can sweep. Rights gave up their bits for it: 65,535
//! grants of one slot before a stale handle can name that slot's occupant again.
//! `crates/core/ipc` restarts a slot only after a sweep has cleared every
//! warrant reference to it, so what can recur is a domain's private name for
//! something it holds, never a reference between domains.

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
    const GEN_BITS: u32 = 16;
    /// Public so `crates/core/ipc` can assert its own `MAX_CAPS_PER_TASK` fits.
    /// That crate cannot be imported here (this one is dependency-free by
    /// design), so the binding has to be made from the other side, and it
    /// cannot be made against a private constant.
    pub const SLOT_BITS: u32 = 10;

    const KIND_SHIFT: u32 = 32 - Self::KIND_BITS;
    const KIND_MASK: u32 = (1 << Self::KIND_BITS) - 1;
    const GEN_SHIFT: u32 = Self::KIND_SHIFT - Self::GEN_BITS;
    const GEN_MASK: u32 = (1 << Self::GEN_BITS) - 1;
    const SLOT_MASK: u32 = (1 << Self::SLOT_BITS) - 1;

    /// Mirror of `azos_ipc::cap::MAX_CAPS_PER_TASK` (256). `abi` is a
    /// dependency-free, frozen ABI crate and cannot import that
    /// constant without creating a cycle (`ipc` depends on `abi`), so this
    /// is a *third* copy of the number, alongside Kconfig's
    /// `MAX_CAPS_PER_TASK` and `crates/core/ipc/src/cap.rs`'s own hardcoded
    /// `256`. The assert below only binds this local mirror: if Kconfig's
    /// or `ipc`'s copy ever drifts from 256, nothing here catches it —
    /// that would need an analogous assert added on the `ipc` side, which
    /// is a follow-up for the owner to approve, not part of this change.
    /// 256 → 512, alongside `SLOT_BITS` 8 → 9. This is the
    /// CEILING the handle encoding supports, not any one profile's value:
    /// `config/limits/Kconfig.limits` sets 32 (embedded), 256 (edge) and 512 (fleet), and
    /// it is `crates/core/ipc`'s assert — now bound to the *configured* constant
    /// rather than a local copy — that checks each profile against this
    /// encoding. This mirror only keeps `abi` self-consistent.
    const MAX_CAPS_PER_TASK_MIRROR: u32 = 512;

    // REQ-001
    /// The largest generation a slot can reach. A slot freed at this value
    /// waits for a sweep before it restarts (`CapTable::unpark`).
    pub const MAX_GENERATION: u16 = Self::GEN_MASK as u16;

    /// Pack type + generation + slot into a wire-format handle.
    #[inline]
    pub const fn pack(ty: CapType, generation: u16, slot: u16) -> Self {
        let v = ((ty.raw() as u32) & Self::KIND_MASK) << Self::KIND_SHIFT
            | ((generation as u32) & Self::GEN_MASK) << Self::GEN_SHIFT
            | (slot as u32) & Self::SLOT_MASK;
        Self(v)
    }

    /// Extract the encoded `CapType` tag (see [`CapType::raw`]).
    #[inline]
    pub const fn kind(self) -> u8 {
        ((self.0 >> Self::KIND_SHIFT) & Self::KIND_MASK) as u8
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

// The fields must tile the u32 exactly, with no gap and no overlap.
const _: () = assert!(
    CapHandle::KIND_BITS + CapHandle::GEN_BITS + CapHandle::SLOT_BITS == 32,
    "CapHandle bitfield layout must total exactly 32 bits"
);

// A handle's generation is the whole of the slot word's: a wider one could not
// be checked in the one load a resolve makes.
const _: () = assert!(CapHandle::MAX_GENERATION == u16::MAX, "the slot word stores 16 bits of generation");

// The slot field must be wide enough to address every valid cap-table
// slot (0..MAX_CAPS_PER_TASK_MIRROR). If this ever fires, either
// SLOT_BITS needs to grow or
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
            "Cap(kind={}, gen={}, slot={})",
            self.kind(),
            self.generation(),
            self.slot()
        )
    }
}

/// `SYS_CAP_INFO(ty::SHM, SHM_INSPECT_PUBLIC)`: the handle of this task's
/// `Cap<Shm>` to the kernel's public introspection region (Kconfig INSPECT),
/// when its topology row declares `MemObj inspect.public`. A `Shm` lookup
/// otherwise names a region by its pool INDEX, which is below the shm pool's
/// size, so keys above that range can never name a region; "ST" in the high
/// half makes them recognisable in a trace.
pub const SHM_INSPECT_PUBLIC: u32 = 0x5354_0002;
/// [`SHM_INSPECT_PUBLIC`] for the admin region (`inspect.admin`), granted
/// only to a task that holds the full task view.
pub const SHM_INSPECT_ADMIN: u32 = 0x5354_0003;
/// `SYS_CAP_INFO(ty::SHM, SHM_INPUT_EVENTS)`: the handle of this task's
/// `Cap<Shm>` to the kernel's input event ring (`MemObj input.events`), the
/// ring the input drivers publish into and the terminal server drains.
pub const SHM_INPUT_EVENTS: u32 = 0x5354_0004;
/// [`SHM_INPUT_EVENTS`] for the console screen region (`MemObj
/// console.screen`, Kconfig FB_CONSOLE): the text on the screen, the
/// scrollback and the overlay the terminal server asks the renderer to draw.
pub const SHM_CONSOLE_SCREEN: u32 = 0x5354_0005;
/// [`SHM_INPUT_EVENTS`] for the structured kernel log's ring (`MemObj
/// klog.ring`, Kconfig KLOG), granted `READ|MAP`: the records
/// `{ts, level, module, msg}` of every kernel log line, which `logd` drains
/// into its files. `logd` is the only task granted it.
pub const SHM_KLOG_RING: u32 = 0x5354_0006;
/// [`SHM_INPUT_EVENTS`] for the input focus word (`MemObj input.focus`, Kconfig
/// INPUTD), granted `READ|WRITE|MAP` to the input server alone: who the
/// keyboard and the pointer belong to, which the input drivers read for every
/// event. A page of its own, so no other holder of the input regions can write
/// it.
pub const SHM_INPUT_FOCUS: u32 = 0x5354_000D;
/// [`SHM_INPUT_EVENTS`] for the region the kernel shares with a ring-3 file
/// server (`MemObj fs.share`, Kconfig FS_EXT4_RING3), granted
/// `READ|WRITE|MAP` to that server's row alone: the names the kernel asks
/// about and the data the server answers with (`azos_devif::fs::Extent`).
pub const SHM_FS_SHARE: u32 = 0x5354_000E;
/// [`SHM_KLOG_RING`]'s sink page: where `logd` says which security records it
/// lost (`MemObj klog.ack`, Kconfig `SEC_LOG`, `logd`'s row alone).
pub const SHM_KLOG_ACK: u32 = 0x5354_000F;

/// `SYS_CAP_INFO(ty::SHM, SHM_INSPECT_NAMES)`: the handle of this task's
/// `Cap<Shm>` to the name server's view of the topology (`MemObj
/// inspect.names`), an introspection tree only a row that declares it holds.
pub const SHM_INSPECT_NAMES: u32 = 0x5354_0007;
/// [`SHM_INSPECT_NAMES`] for the RPC server's view (`inspect.rpc`).
pub const SHM_INSPECT_RPC: u32 = 0x5354_0008;
/// [`SHM_INSPECT_NAMES`] for the MCP bridge's view (`inspect.mcp`).
pub const SHM_INSPECT_MCP: u32 = 0x5354_0009;
/// [`SHM_INSPECT_NAMES`] for the component manager's plan (`inspect.components`).
pub const SHM_INSPECT_COMPONENTS: u32 = 0x5354_000A;
/// [`SHM_INSPECT_NAMES`] for the logins of the topology (`inspect.logins`).
pub const SHM_INSPECT_LOGINS: u32 = 0x5354_000B;
/// [`SHM_INSPECT_NAMES`] for the topology's clock row (`inspect.clock`).
pub const SHM_INSPECT_CLOCK: u32 = 0x5354_000C;

// Every kernel-owned region key names one region: a key two regions share
// makes `SYS_CAP_INFO` answer for whichever the kernel translates first (the
// focus word once shared 0x5354_0007 with the name server's view, and the
// input server found no focus word).
const _: () = {
    let keys = [
        SHM_INSPECT_PUBLIC, SHM_INSPECT_ADMIN, SHM_INPUT_EVENTS, SHM_CONSOLE_SCREEN, SHM_KLOG_RING,
        SHM_INPUT_FOCUS, SHM_KLOG_ACK, SHM_INSPECT_NAMES, SHM_INSPECT_RPC, SHM_INSPECT_MCP, SHM_INSPECT_COMPONENTS,
        SHM_INSPECT_LOGINS, SHM_INSPECT_CLOCK, SHM_FS_SHARE,
    ];
    let mut i = 0;
    while i < keys.len() {
        let mut j = i + 1;
        while j < keys.len() {
            assert!(keys[i] != keys[j], "two kernel-owned regions share a SYS_CAP_INFO key");
            j += 1;
        }
        i += 1;
    }
};

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
    /// authority to call, nothing else.
    Endpoint = 1,
    /// A memory object: shared memory (class `SHM`, a region two tasks map).
    MemObj = 2,
    /// A queue: an io_ring (class `IORING`), or a queue of a NIC the kernel
    /// drives, taken to run from ring 3 (class `NIC_QUEUE`).
    Queue = 3,
    /// An event port.
    Port = 4,
    /// A task: the right to see every task (class `TASK`, resource 0, `READ`),
    /// not authority over one.
    Domain = 5,
    /// A node of the name space: a file or a directory tree (`FILE`), a socket
    /// (`SOCKET`) or the right to start one image (`LAUNCH`).
    Node = 6,
    /// A piece of hardware: an interrupt line (`IRQ`), an MMIO region of the
    /// board's table (`MMIO`) or a range of I/O ports (`IOPORT`).
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

/// Set in the resource of an `Irq` capability that names a message-signalled
/// slot (`msi.<k>`, `IRQ_MSI_LINE | k`) rather than a controller input.
pub const IRQ_MSI_LINE: u32 = 1 << 31;

/// The named types: every class of every kind a kernel table can hold.
pub mod ty {
    use super::{CapKind, CapType};

    /// A task-hosted or kernel-hosted endpoint.
    pub const ENDPOINT: CapType = CapType::new(CapKind::Endpoint, 0);
    /// An event port.
    pub const PORT: CapType = CapType::new(CapKind::Port, 0);
    /// A shared-memory region.
    pub const SHM: CapType = CapType::new(CapKind::MemObj, 0);
    /// An io_ring.
    pub const IORING: CapType = CapType::new(CapKind::Queue, 0);
    /// The right to see every task: minted for one target only, `"tasks"`,
    /// `READ`, resource `0`: the warrant of the admin introspection
    /// region.
    pub const TASK: CapType = CapType::new(CapKind::Domain, 0);
    /// A file descriptor (FAT32 / tmpfs / azvol) or a directory tree.
    pub const FILE: CapType = CapType::new(CapKind::Node, 0);
    /// The right to start one image with `SYS_SPAWN_EX`:
    /// the resource is an interned image name, `EXEC` the permission. Class 1
    /// so that its raw value stays below 32: the micro kernel (rv32) returns
    /// handles as positive results.
    pub const LAUNCH: CapType = CapType::new(CapKind::Node, 1);
    /// A socket descriptor.
    pub const SOCKET: CapType = CapType::new(CapKind::Node, 2);
    /// A hardware interrupt line.
    pub const IRQ: CapType = CapType::new(CapKind::Device, 0);
    /// A device of the hardware bus (`azos_drv_bus::hwbus`) and its register
    /// window. The resource is the device's bus handle (its slot index),
    /// the value `DOMAIN_MMIO_MAP` takes and checks; its denial record carries
    /// the handle. The topology grants it by what the device is
    /// (`mmio.dt:google,goldfish-rtc`), not by where a machine listed it.
    pub const MMIO: CapType = CapType::new(CapKind::Device, 1);
    /// A range of I/O ports (x86_64's port space), opened to the calling
    /// thread by `DEVICE_IOPORT_ENABLE`. The resource is the range,
    /// [`super::ioport_range`] packs it. Granted by a topology row
    /// `ioport.<first>.<count>` (decimal), `READ|WRITE` only: the CPU's
    /// permission bitmap cannot open a port for `in` and not for `out`.
    pub const IOPORT: CapType = CapType::new(CapKind::Device, 3);
    /// Types of retired capabilities: never given to another type (`Device`
    /// class 2 was the driver-server registry right).
    pub const RETIRED: [CapType; 1] = [CapType::new(CapKind::Device, 2)];
    /// One receive/transmit queue of a NIC the kernel drives: the right to take
    /// it from the kernel's stack and run it from ring 3 over a pair of rings
    /// (the `QUEUE_NICQ_*` ops, [`crate::nic_queue`]). The resource is
    /// [`crate::nic_queue::resource`]; the topology grants it by interface
    /// name and queue (`nicq.eth1.0`).
    pub const NIC_QUEUE: CapType = CapType::new(CapKind::Queue, 1);
    /// The kernel tracer (the `LOG_TRACE_*` ops): `READ` maps the
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

/// The resource of a [`ty::IOPORT`] capability: the first port in bits 0..16,
/// the last (inclusive) in bits 16..32. `None` for an empty range or one
/// that runs past port 0xFFFF.
pub const fn ioport_range(first: u32, count: u32) -> Option<u32> {
    if count == 0 || first > 0xFFFF || count > 0x1_0000 - first {
        return None;
    }
    Some(first | ((first + count - 1) << 16))
}

/// The `(first, last)` ports (inclusive) of an [`ioport_range`] resource;
/// `None` for a word no range packs to (last below first).
pub const fn ioport_bounds(resource: u32) -> Option<(u16, u16)> {
    let (first, last) = ((resource & 0xFFFF) as u16, (resource >> 16) as u16);
    if last < first {
        return None;
    }
    Some((first, last))
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
    /// Permission to make a copy: derive an attenuated child capability, mint
    /// a badged one, or send a DUP entry. Copying inside the holder's own
    /// table needs this alone; handing the copy to another Domain also needs
    /// [`TRANSFER`](Self::TRANSFER).
    pub const DUP: Self = Self(0b1000);
    /// Permission to move the capability to another Domain over IPC (a MOVE
    /// entry of a message, a spawn's move list), or to send a copy of it
    /// there (a DUP entry also needs [`DUP`](Self::DUP)). Separate from `DUP`:
    /// a holder may derive for itself without being able to give authority
    /// away, and a capability meant to travel need not be copyable.
    pub const TRANSFER: Self = Self(0b01_0000);
    /// Permission to map a memory object into an address space
    /// (`SYS_MO_MAP`). Separate from `READ`: reading a region through the
    /// kernel (acquire, clone, release) does not give it a window in ring 3.
    pub const MAP: Self = Self(0b10_0000);

    /// No permissions (a stub / placeholder).
    pub const NONE: Self = Self(0);
    /// Read + Write.
    pub const RW: Self = Self(Self::READ.0 | Self::WRITE.0);
    /// `DUP` + `TRANSFER`: the holder may copy the capability and hand a copy,
    /// or the capability itself, to another Domain. What a task gets over an
    /// object it created itself, and what a topology grant with
    /// `transfer = true` carries.
    pub const DELEGATE: Self = Self(Self::DUP.0 | Self::TRANSFER.0);
    /// Read + Write + [`DELEGATE`](Self::DELEGATE).
    pub const RW_DELEGATE: Self = Self(Self::RW.0 | Self::DELEGATE.0);
    /// All permissions.
    pub const ALL: Self = Self(0b11_1111);

    /// Construct from raw bits, masking to the valid range.
    #[inline]
    pub const fn from_bits_truncate(raw: u8) -> Self {
        Self(raw & Self::ALL.0)
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
        if self.contains(Self::TRANSFER) {
            emit("T")?;
        }
        if self.contains(Self::MAP) {
            emit("M")?;
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
///   bits  8..16  permissions (CapPerms bits, 6 used: 8..14; 14 and 15 are the flags)
///   bits 16..32  generation  (survives a revoke, never wraps)
///   bits 32..64  resource    (the type's own id or packed pool index)
/// ```
///
/// Bit 14 (above the six permission bits) is [`EXPIRES`](slot_word::EXPIRES):
/// the slot's warrant carries a deadline. Bit 15 is [`WEAK`](slot_word::WEAK):
/// the slot's warrant is weak, and [`perms`](slot_word::perms) reads a weak
/// word as `READ` and `MAP` only (a read-only view, window included), whatever
/// bits are stored. Nothing here depends on the width of a machine word.
pub mod slot_word {
    use super::{CapPerms, CapType};

    /// Bit 14: the slot's warrant carries a deadline.
    pub const EXPIRES: u64 = 1 << 14;

    /// Bit 15: the slot's warrant is weak (transitively read-only). A weak
    /// slot resolves with its permissions masked to [`WEAK_KEEPS`]; the stored
    /// bits stay as granted so a refusal the mask caused can be told from one
    /// the holder would have had anyway ([`perms_raw`]).
    pub const WEAK: u64 = 1 << 15;

    /// The rights a weak word keeps: `READ`, and `MAP` because mapping is how a
    /// region is read (a weak holder's mapping is read-only, `WRITE` being
    /// masked). Everything that gives authority away or changes the object
    /// (`WRITE`, `EXEC`, `DUP`, `TRANSFER`) is masked.
    pub const WEAK_KEEPS: CapPerms = CapPerms::READ.union(CapPerms::MAP);

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

    /// The permissions a word grants: the stored ones, only [`WEAK_KEEPS`] when
    /// the word is [`WEAK`]. The only reader of the permission byte that decides a
    /// use, so a weak slot cannot be resolved with more than `READ` by any
    /// path. One flag test, branch-free.
    #[inline(always)]
    pub const fn perms(w: u64) -> CapPerms {
        let keep = if w & WEAK != 0 { WEAK_KEEPS.bits() } else { CapPerms::ALL.bits() };
        CapPerms::from_bits_truncate(((w >> 8) as u8) & keep)
    }

    /// The permission byte as stored, before the weak mask.
    #[inline(always)]
    pub const fn perms_raw(w: u64) -> CapPerms {
        CapPerms::from_bits_truncate((w >> 8) as u8)
    }

    /// The word has [`WEAK`] set.
    #[inline(always)]
    pub const fn weak(w: u64) -> bool {
        w & WEAK != 0
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

    /// Why a slot's word refuses a handle.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Refusal {
        /// The slot is free, or holds another generation.
        Stale,
        /// The slot holds another kind.
        WrongKind,
        /// The slot lacks a right asked for.
        MissingPerms,
    }

    /// The checks every capability table makes of a handle of `generation`
    /// against its slot's word `w`, in this order: occupied and of that
    /// generation, of `kind` (`None`: any kind), with the rights `need`.
    #[inline(always)]
    pub const fn check(w: u64, generation: u16, kind: Option<CapType>, need: CapPerms) -> Result<(), Refusal> {
        if !occupied(w) || self::generation(w) != generation {
            return Err(Refusal::Stale);
        }
        if let Some(k) = kind {
            if !ty_is(w, k) {
                return Err(Refusal::WrongKind);
            }
        }
        if !perms(w).contains(need) {
            return Err(Refusal::MissingPerms);
        }
        Ok(())
    }

    /// The generation the next grant of the free slot `w` takes; `None` when
    /// the slot is parked at the last one, which restarts (at 0, so the next
    /// grant takes 1) only when nothing names its old generations.
    #[inline(always)]
    pub const fn next_generation(w: u64) -> Option<u16> {
        self::generation(w).checked_add(1)
    }

    /// May a grant take the slot whose word is `w`: free and not parked.
    #[inline(always)]
    pub const fn grantable(w: u64) -> bool {
        !occupied(w) && next_generation(w).is_some()
    }
}

/// What a launch capability targets (`ty::LAUNCH`): an image name, an 8.3 name
/// of upper-case letters, digits, `_` and `-`, ending in `.ELF`, or a signed
/// package ([`launch_name::parse`]). Every kernel that grants or spawns on a
/// launch capability checks it here.
pub mod launch_name {
    /// Longest image name.
    pub const MAX: usize = 12;

    /// Is `name` an image name a launch grant may target?
    pub fn is_valid(name: &[u8]) -> bool {
        if name.len() <= 4 || name.len() > MAX || !name.ends_with(b".ELF") {
            return false;
        }
        let base = &name[..name.len() - 4];
        base.len() <= 8 && base.iter().all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    }

    /// Spelling of a package grant's target: `pkg.` and the 64 lower-case hex
    /// digits of the package's id.
    pub const PACKAGE_PREFIX: &[u8] = b"pkg.";

    /// What a launch grant's target names: one image, or every image of one
    /// signed package.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Target<'a> {
        /// An image, by its name ([`is_valid`]).
        Image(&'a [u8]),
        /// A package, by its id (`azos_pkg`'s `Verified::id`).
        Package([u8; 32]),
    }

    /// The grant `target` names, or `None` for a spelling that is neither.
    pub fn parse(target: &[u8]) -> Option<Target<'_>> {
        let Some(hex) = target.strip_prefix(PACKAGE_PREFIX) else {
            return is_valid(target).then_some(Target::Image(target));
        };
        if hex.len() != 64 {
            return None;
        }
        let mut id = [0u8; 32];
        for (i, pair) in hex.chunks_exact(2).enumerate() {
            let nibble = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            id[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
        }
        Some(Target::Package(id))
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
        let h = CapHandle::pack(ty::PORT, 0x42, 0xAB);
        assert_eq!(h.kind(), ty::PORT.raw());
        assert_eq!(h.generation(), 0x42);
        assert_eq!(h.slot(), 0xAB);
    }

    #[test]
    fn slot_beyond_field_width_truncates() {
        // The first value past the slot field must not round-trip.
        //
        // The boundary is derived, not written as a literal: this test used
        // to hardcode 256, and it was one of the things that would have gone
        // quietly stale when the field width changed. The fleet profile's
        // 512-slot tables were truncating against the OLD width for as long
        // as that profile existed, and no test noticed.
        let past_end = 1u16 << CapHandle::SLOT_BITS;
        let h = CapHandle::pack(ty::PORT, 0, past_end);
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
        let h = CapHandle::pack(ty::PORT, 0x7, last);
        assert_eq!(h.slot(), last);
        assert_eq!(h.kind(), ty::PORT.raw());
        assert_eq!(h.generation(), 0x7);
    }

    /// The six rights, the two flags above them and the generation do not
    /// overlap in the hot word.
    #[test]
    fn six_rights_fit_the_hot_word() {
        assert_eq!(CapPerms::ALL.bits(), 0b11_1111);
        assert_eq!(CapPerms::from_bits_truncate(0xff), CapPerms::ALL, "bits past the sixth are not rights");
        assert_eq!(CapPerms::ALL.bits() as u64, 0x3f);
        assert_eq!(slot_word::EXPIRES & (0x3f << 8), 0, "the deadline flag is not a right");
        assert_eq!(slot_word::WEAK & (0x3f << 8), 0, "the weak flag is not a right");
        assert_eq!(slot_word::EXPIRES & slot_word::WEAK, 0);
        assert_eq!(slot_word::EXPIRES | slot_word::WEAK | (0x3f << 8), 0xff00, "the byte is full");
        let w = slot_word::encode(ty::PORT, CapPerms::ALL, 5, 7) | slot_word::EXPIRES;
        assert_eq!(slot_word::perms(w), CapPerms::ALL, "a flag leaks into no right");
        let h = CapHandle::pack(ty::SHM, CapHandle::MAX_GENERATION, 511);
        assert_eq!(h.generation(), CapHandle::MAX_GENERATION);
        assert_eq!(h.slot(), 511);
        assert_eq!(h.kind(), ty::SHM.raw());
    }

    #[test]
    fn perms_contains() {
        assert!(CapPerms::ALL.contains(CapPerms::READ));
        assert!(CapPerms::ALL.contains(CapPerms::DUP));
        assert!(!CapPerms::READ.contains(CapPerms::WRITE));
        assert!(CapPerms::RW.contains(CapPerms::READ));
        assert!(CapPerms::RW.contains(CapPerms::WRITE));
        assert!(!CapPerms::RW.contains(CapPerms::DUP));
        assert!(CapPerms::ALL.contains(CapPerms::TRANSFER) && CapPerms::ALL.contains(CapPerms::MAP));
        assert!(!CapPerms::RW.union(CapPerms::DUP).contains(CapPerms::TRANSFER), "DUP does not imply TRANSFER");
        assert!(!CapPerms::READ.contains(CapPerms::MAP), "READ does not imply MAP");
        assert!(CapPerms::DELEGATE.contains(CapPerms::DUP) && CapPerms::DELEGATE.contains(CapPerms::TRANSFER));
        assert!(!CapPerms::DELEGATE.contains(CapPerms::MAP));
    }

    /// A weak word reads as `READ` and `MAP` alone, whatever it stores; the
    /// stored byte stays reachable for the refusal record; a strong word is
    /// untouched.
    /// Canary: drop the `keep` mask in `slot_word::perms` and the weak
    /// assertions go red.
    #[test]
    fn a_weak_word_reads_as_read_only() {
        let strong = slot_word::encode(ty::PORT, CapPerms::ALL, 3, 9);
        let weak = strong | slot_word::WEAK;
        assert_eq!(slot_word::perms(strong), CapPerms::ALL);
        assert!(!slot_word::weak(strong));
        assert_eq!(slot_word::perms(weak), CapPerms::READ.union(CapPerms::MAP));
        assert_eq!(slot_word::perms_raw(weak), CapPerms::ALL);
        assert!(slot_word::weak(weak));
        let no_read = slot_word::encode(ty::PORT, CapPerms::WRITE, 3, 9) | slot_word::WEAK;
        assert_eq!(slot_word::perms(no_read), CapPerms::NONE, "the mask never adds a right");
        assert_eq!(slot_word::cleared(weak), 3 << 16, "a freed slot keeps its generation and no flag");
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
        let h = CapHandle::pack(ty::SHM, 1, 7);
        let s = alloc_string_dbg(&h);
        assert!(s.contains("kind=2"), "{s}");
        assert!(s.contains("gen=1"));
        assert!(s.contains("slot=7"));
    }

    // Tiny helper to get a String only in tests; uses std for simplicity.
    fn alloc_string_dbg<T: core::fmt::Debug>(t: &T) -> String {
        format!("{:?}", t)
    }
}

/// Error returned by `CapTable::get`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapError {
    /// The handle's generation is stale (slot empty or reused).
    Stale,
    /// The handle's kind does not match the expected `T`.
    WrongKind,
    /// The slot does not have the required permission bits.
    MissingPerms,
    /// Degraded mode is armed and this is a write/actuation: the
    /// capability is valid but its use is contained until degraded mode clears.
    Contained,
    /// The RECEIVING table of a capability move has no free slot.
    ///
    /// It is its own variant rather than being folded
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
