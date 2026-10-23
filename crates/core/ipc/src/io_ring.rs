// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IO Ring — shared-memory submission/completion queues (AQ1).
//!
//! Inspired by Linux io_uring: userspace writes requests into a shared page
//! and the kernel writes completions back.
//!
//! **Execution.** An entry executes through [`IoRingOps`], which
//! the kernel installs at boot with [`io_ring_register_ops`]
//! (`azos_syscall::ioring_ops`); each entry calls what the matching typed
//! syscall calls. Before it runs, every entry passes, in order, the submitter's
//! seccomp profile for the syscall the opcode stands for ([`opcode_gate`]), the
//! owner's Domain pledge mask for the same call (`DOMAIN_PLEDGE`: the ring is
//! one trap, but a narrowed Domain narrowed what its entries do as well), the
//! capability its owner must hold, and, for a write, containment.
//! A refused entry completes with [`CQE_F_REFUSED`] and a negative errno. At
//! most [`RING_SQ_SIZE`] entries run per submit, and never one whose completion
//! the CQ has no room for.
//!
//! Layout (fits in one 4 KiB page):
//!   SQ (Submission Queue): userspace writes requests, kernel reads
//!   CQ (Completion Queue): kernel writes results, userspace reads
//!   Data buffer: large results (LiDAR scans, camera frames)

use crate::cap::ty;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use azos_sync::SpinLock;

use crate::cap::objref;
use crate::cap::{CapError, CapPerms, CapType};
use crate::port_link::{LinkSet, PortLink};

/// How a `Cap<IoRing>` packs `(index, generation)`: 8 + 24 bits
/// (`objref::IO_RING`).
const LAYOUT: objref::Layout = objref::IO_RING;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of entries in each queue.
pub const RING_SQ_SIZE: usize = 32;
pub const RING_CQ_SIZE: usize = 32;

/// Maximum data per slot in the data buffer.
pub const RING_DATA_SLOT_SIZE: usize = 64;

/// Total data buffer size.
pub const RING_DATA_BUF_SIZE: usize = 2048;

/// Maximum number of io_rings system-wide. Kconfig `MAX_IO_RINGS`
/// (default 16; at most 256, the assertion below).
pub const MAX_IO_RINGS: usize = azos_limits::MAX_IO_RINGS;

/// A `Cap<IoRing>` stores a packed `(index, generation)` with
/// `LAYOUT.idx_bits()` of index, so every ring index must fit them.
const _: () = assert!(MAX_IO_RINGS <= 1 << LAYOUT.idx_bits());

// ---------------------------------------------------------------------------
// Ring opcodes
// ---------------------------------------------------------------------------

pub const OP_NOP: u16 = 0;
pub const OP_READ_SENSOR: u16 = 1;
pub const OP_WRITE_GPIO: u16 = 2;
pub const OP_READ_GPIO: u16 = 3;
pub const OP_I2C_READ: u16 = 4;
pub const OP_I2C_WRITE: u16 = 5;
pub const OP_PWM_SET: u16 = 6;
pub const OP_MOTOR_SPEED: u16 = 7;
pub const OP_NET_SEND: u16 = 8;
/// `NODE_RECV` on a ring: `param0` a `Cap<Socket>` handle of the ring's owner
/// (`READ`), `param1`/`param2` the window the bytes land in (a `data_buf`
/// window, or a registered buffer with [`SQE_F_FIXED`]). Never waits.
pub const OP_NET_RECV: u16 = 9;
/// Register a buffer: pin a range of a `MemObj` the ring's owner already maps
/// and name it by slot, so that entries with [`SQE_F_FIXED`] reach it without
/// a user range validated or copied per operation. `param0` a `Cap<Shm>` handle
/// of the owner (`READ | WRITE | MAP`), `param1` the byte offset of the range
/// in the object, `param2` its length, `reg` the slot to fill (below
/// [`RING_MAX_REGBUFS`], free). Completes with `0`. Takes no `MemObj` table
/// slot: the object is the one the owner holds.
pub const OP_BUF_REGISTER: u16 = 10;
/// Give back the buffer in slot `reg` ([`OP_BUF_REGISTER`]); `-EINVAL` for a
/// slot that holds none. Completes with `0`.
pub const OP_BUF_UNREGISTER: u16 = 11;
/// `NODE_READ` on a ring: `param0` a `Cap<File>` handle of the
/// ring's owner (`READ`), `param1`/`param2` the `data_buf` window to read into.
pub const OP_FILE_READ: u16 = 12;
/// `NODE_WRITE` on a ring: `param0` a `Cap<File>` handle (`WRITE`,
/// refused while contained), `param1`/`param2` the `data_buf` window to write.
pub const OP_FILE_WRITE: u16 = 13;
/// A completion at a deadline (`SYS_SLEEP_UNTIL`'s twin): `param0 | param1 <<
/// 32` is the deadline in nanoseconds on the time counter. Completes with `1`
/// in the pass that sees it when the deadline had already passed, otherwise
/// the entry is PARKED and completes with `0` in the first pass at or after
/// the deadline. Without an SQ poller a pass is a submit, so a parked timer
/// completes on the owner's next `SYS_RING_ENTER` after its deadline
/// (a submit with an empty SQ only reaps).
pub const OP_TIMER: u16 = 16;
/// A completion when a futex word of a shm region changes: `param0` a `Cap<Shm>` handle of
/// the owner (`READ`), `param1` the byte offset of a 4-aligned `u32` in the
/// region, `param2` the expected value. Completes with `1` when the word
/// already differs, else parks and completes with `0` in the first pass that
/// sees it differ; a capability revoked while parked completes the entry as a
/// refusal. Checked against `SYS_FUTEX_WAIT`'s row, as the call is.
pub const OP_NOTIFY_WAIT: u16 = 17;

/// Start an SQ poller for this ring: a kernel task that consumes the SQ
/// without a syscall (Linux's `IORING_SETUP_SQPOLL`, asked for in-band).
/// Allowed only when the owner's topology row declares `sqpoll_idle_ms`
/// (off by default); refused with `-EPERM` otherwise. Completes with 0 once
/// the poller exists; the entries queued behind it are the poller's. Every
/// entry the poller runs is authorized exactly as a submitted one: the
/// owner's seccomp profile, the owner's capabilities, containment, and the
/// op table's own rules (the motor layer's halt rule among them).
pub const OP_SQPOLL_START: u16 = 18;

/// Make every write queued before this entry durable (twin of
/// `NODE_FSYNC`: `param0` is a `Cap<File>`, any permission). Never waits
/// in the submit: the entry asks the filesystem's flusher for a flush
/// ([`IoRingOps::file_fsync`] answers a ticket) and parks; it completes with
/// [`CQE_F_DURABLE`] once that flush is done ([`IoRingOps::fsync_done`]), from
/// the flush path ([`io_ring_flush_posted`]) or the ring's next pass,
/// whichever claims the ring first. A real-time submitter only enqueues.
pub const OP_FSYNC: u16 = 19;

/// Read sectors of a partition into the data buffer: `param0` is the `block`
/// endpoint's badge (partition `n` is badge `n + 1`), `param1` the buffer
/// offset, `param2` the length in bytes (a multiple of 512), and the entry's
/// `addr` (low half) and `reg` (high half) the first sector, relative to the
/// partition. Needs `READ`, and `ImageProfile::ifaces` listing `block`.
pub const OP_BLOCK_READ: u16 = 20;
/// Write sectors of a partition from the data buffer, as [`OP_BLOCK_READ`].
/// Needs `WRITE`, and is refused while contained.
pub const OP_BLOCK_WRITE: u16 = 21;

/// [`SqEntry::flags`] bit: the next entry runs only after this one completed
/// in its pass with a non-negative result. A failed or refused linked entry
/// completes the next one with `-ECANCELED` and [`CQE_F_REFUSED`] without
/// running it (and so on down the chain). A linked entry that PARKS (an
/// `OP_FSYNC`, a timer) is a barrier: the pass stops consuming the SQ until
/// it completes; if it then fails, the next entry is canceled. The chain is
/// the run of LINK entries in SQ order; writes before an `OP_FSYNC` are in
/// its flush by SQ order alone, the link adds "do not run the fsync if the
/// write failed" and, the other way, "nothing after the fsync before it".
pub const SQE_F_LINK: u16 = 1 << 0;

/// [`SqEntry::flags`] bit: the entry's buffer is a registered one
/// ([`OP_BUF_REGISTER`]): `reg` is its slot, `param1` the byte offset inside it
/// and `param2` the length, in place of a window of `data_buf`. The data-moving
/// opcodes take it ([`OP_NET_SEND`], [`OP_NET_RECV`], [`OP_FILE_READ`],
/// [`OP_FILE_WRITE`]); any other opcode refuses it with `-EINVAL`
/// ([`IO_ERR_INVALID_PARAM`]), the block opcodes included (their `reg` is half
/// of a sector number).
pub const SQE_F_FIXED: u16 = 1 << 1;

/// [`IoRing::sq_flags`] bit: an SQ poller runs this ring.
pub const SQ_F_SQPOLL: u32 = 1 << 0;
/// [`IoRing::sq_flags`] bit: the poller has parked; ring 3 must call
/// `SYS_RING_ENTER` once after publishing `sq_tail` to wake it. Read
/// it only after a full fence following the `sq_tail` store: the poller sets
/// it, fences, and re-reads `sq_tail` before parking, so one side always sees
/// the other.
pub const SQ_F_NEED_WAKEUP: u32 = 1 << 1;

/// Most entries (timers, waits and fsyncs) one ring holds parked at once
/// (Kconfig `IORING_MAX_PARKED`, default 8). Each parked
/// entry holds one reserved completion slot, so a parked entry can always
/// complete; the reservation counts against the CQ's back-pressure.
pub const RING_MAX_PARKED: usize = azos_limits::IORING_MAX_PARKED;
const _: () = assert!(RING_MAX_PARKED >= 1 && RING_MAX_PARKED <= RING_CQ_SIZE);

/// Registered buffers one ring holds (Kconfig `IORING_MAX_REGBUFS`, default 4).
/// A slot is named by an SQE's `reg`.
pub const RING_MAX_REGBUFS: usize = azos_limits::IORING_MAX_REGBUFS;
const _: () = assert!(RING_MAX_REGBUFS >= 1 && RING_MAX_REGBUFS <= u16::MAX as usize);
/// A parked block window is `(offset, length)` in two `u16`s.
const _: () = assert!(RING_DATA_BUF_SIZE <= u16::MAX as usize);

// ---------------------------------------------------------------------------
// Shared structures (mapped in both kernel and userspace)
// ---------------------------------------------------------------------------

/// Submission queue entry — written by userspace, read by kernel.
///
/// # WHY `addr` and `reg` are their own fields (the `param1` split)
///
/// The previous layout had three generic `paramN` words and told I2C to pack
/// *both* the device address and the register into `param1`. Two things went
/// wrong with that, and only one of them was documented:
///
///  * **The capability could not be reconstructed.** The I2C capability
///    `(bus, addr)` — what the I2C read and write calls checked — needs the
///    address on its own. With addr and reg fused there is no faithful way to
///    rebuild it, so [`dispatch_sqe`] denied both I2C opcodes outright to
///    unprivileged rings rather than enforce something weaker than the
///    syscall path.
///  * **`param1` was already taken.** The I2C arms *also* read `param1` as
///    the offset into `data_buf`, in the same expression that passed it as
///    `addr_reg` to the driver. One field, two mutually exclusive meanings:
///    any ring submitting a working I2C read addressed a device number equal
///    to its own buffer offset. Inert only because `OPS` is never registered.
///
/// Splitting them costs 8 bytes per SQE (24 → 32). The ring still fits one
/// 4 KiB page with room to spare: 4 queue indices (16 B) + 32 × 32 B SQ
/// (1024) + 32 × 16 B CQ (512) + 2048 B data = 3600 B.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SqEntry {
    pub opcode: u16,
    pub flags: u16,
    /// Bus / device selector: I2C bus, GPIO pin, sensor type, PWM channel,
    /// socket fd, left motor speed.
    pub param0: u32,
    /// Offset into `data_buf` for the buffer opcodes; a scalar (GPIO level,
    /// PWM duty, right motor speed) for the register opcodes.
    pub param1: u32,
    /// Length in bytes for the buffer opcodes.
    pub param2: u32,
    /// Device address on the bus named by `param0`. **I2C only.** Kept
    /// separate from `param1` so `dispatch_sqe` can check the exact
    /// (bus, addr) resource a the `i2c` endpoint names.
    pub addr: u16,
    /// Device register. **`OP_I2C_READ` only** — `OP_I2C_WRITE` takes the
    /// register as the first byte of its payload, exactly as `sys_i2c_write`
    /// defines it, and ignores this field.
    pub reg: u16,
    /// Opaque tag for correlation.
    pub user_data: u64,
}

/// Completion queue entry — written by kernel, read by userspace.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CqEntry {
    pub user_data: u64,    // copied from SqEntry
    pub result: i32,       // bytes read, or negative error
    pub flags: u32,        // `CQE_F_*`
}

/// [`CqEntry::flags`] bit: the kernel refused the entry, and `result` is a
/// negative errno (`azos_abi::error::Errno`). Clear when the operation ran:
/// `result` is then the operation's own answer, negative driver codes included,
/// so a refusal can never be mistaken for one.
///
/// The refusals, in the order they are checked: `-ENOSYS` for an opcode this
/// kernel does not execute; `-EPERM` for the submitter's seccomp profile;
/// `-EINVAL` for an argument rejected before the capability check reads it;
/// `-ECAPPERMS` for a capability the ring's owner does not hold; `-EAGAIN` for
/// a write refused by containment, or a motor command refused by the halt rule
/// (a latched e-stop or containment); and the typed call's own code where an
/// op-table entry refuses as that call does (a motor-bound PWM channel or GPIO
/// pin).
pub const CQE_F_REFUSED: u32 = 1 << 0;

/// [`CqEntry::flags`] bit: the operation was ACCEPTED ONTO A QUEUE and is not
/// yet durable or on the wire: an `OP_FILE_WRITE` is in the FAT32 write-back
/// cache (`FS_WRITEBACK`) or written through without a device flush, an
/// `OP_NET_SEND` is on the NIC's TX queue. An `OP_FSYNC` makes the writes
/// durable. Set only with a positive result (bytes queued).
pub const CQE_F_QUEUED: u32 = 1 << 1;

/// [`CqEntry::flags`] bit: an `OP_FSYNC` completed at a flush point: every
/// write queued before it was written back and the device flushed. Set only
/// with result 0; a failed flush completes with `-EIO` and no flag.
pub const CQE_F_DURABLE: u32 = 1 << 2;

// The ring page is ABI: ring 3 reads and writes it at the address
// `SYS_RING_SETUP` returns. These pin the offsets it relies on.
const _: () = {
    assert!(core::mem::size_of::<SqEntry>() == 32);
    assert!(core::mem::size_of::<CqEntry>() == 16);
    assert!(core::mem::offset_of!(IoRing, sq_head) == azos_abi::io_ring::SQ_HEAD);
    assert!(core::mem::offset_of!(IoRing, sq_tail) == azos_abi::io_ring::SQ_TAIL);
    assert!(core::mem::offset_of!(IoRing, sq_entries) == azos_abi::io_ring::SQ_ENTRIES);
    assert!(core::mem::offset_of!(IoRing, cq_head) == azos_abi::io_ring::CQ_HEAD);
    assert!(core::mem::offset_of!(IoRing, cq_tail) == azos_abi::io_ring::CQ_TAIL);
    assert!(core::mem::offset_of!(IoRing, cq_entries) == azos_abi::io_ring::CQ_ENTRIES);
    assert!(core::mem::offset_of!(IoRing, data_buf) == azos_abi::io_ring::DATA);
    assert!(core::mem::offset_of!(IoRing, sq_flags) == azos_abi::io_ring::SQ_FLAGS);
    assert!(core::mem::offset_of!(IoRing, version) == azos_abi::io_ring::VERSION);
    // The version word is the structure's last field and fills its tail: no
    // hidden padding after it.
    assert!(core::mem::size_of::<IoRing>() == azos_abi::io_ring::VERSION + 4);
    // Opcodes, flags and sizes ring 3 compiles against (`azos_abi::io_ring`).
    assert!(OP_NOP == azos_abi::io_ring::OP_NOP);
    assert!(OP_READ_SENSOR == azos_abi::io_ring::OP_READ_SENSOR);
    assert!(OP_WRITE_GPIO == azos_abi::io_ring::OP_WRITE_GPIO);
    assert!(OP_READ_GPIO == azos_abi::io_ring::OP_READ_GPIO);
    assert!(OP_I2C_READ == azos_abi::io_ring::OP_I2C_READ);
    assert!(OP_I2C_WRITE == azos_abi::io_ring::OP_I2C_WRITE);
    assert!(OP_PWM_SET == azos_abi::io_ring::OP_PWM_SET);
    assert!(OP_MOTOR_SPEED == azos_abi::io_ring::OP_MOTOR_SPEED);
    assert!(OP_NET_SEND == azos_abi::io_ring::OP_NET_SEND);
    assert!(OP_NET_RECV == azos_abi::io_ring::OP_NET_RECV);
    assert!(OP_BUF_REGISTER == azos_abi::io_ring::OP_BUF_REGISTER);
    assert!(OP_BUF_UNREGISTER == azos_abi::io_ring::OP_BUF_UNREGISTER);
    assert!(SQE_F_FIXED == azos_abi::io_ring::SQE_F_FIXED);
    assert!(OP_FILE_READ == azos_abi::io_ring::OP_FILE_READ);
    assert!(OP_FILE_WRITE == azos_abi::io_ring::OP_FILE_WRITE);
    assert!(OP_TIMER == azos_abi::io_ring::OP_TIMER);
    assert!(OP_NOTIFY_WAIT == azos_abi::io_ring::OP_NOTIFY_WAIT);
    assert!(OP_SQPOLL_START == azos_abi::io_ring::OP_SQPOLL_START);
    assert!(OP_FSYNC == azos_abi::io_ring::OP_FSYNC);
    assert!(OP_BLOCK_READ == azos_abi::io_ring::OP_BLOCK_READ);
    assert!(OP_BLOCK_WRITE == azos_abi::io_ring::OP_BLOCK_WRITE);
    assert!(SQE_F_LINK == azos_abi::io_ring::SQE_F_LINK);
    assert!(CQE_F_QUEUED == azos_abi::io_ring::CQE_F_QUEUED);
    assert!(CQE_F_DURABLE == azos_abi::io_ring::CQE_F_DURABLE);
    assert!(SQ_F_SQPOLL == azos_abi::io_ring::SQ_F_SQPOLL);
    assert!(SQ_F_NEED_WAKEUP == azos_abi::io_ring::SQ_F_NEED_WAKEUP);
    assert!(CQE_F_REFUSED == azos_abi::io_ring::CQE_F_REFUSED);
    assert!(RING_SQ_SIZE == azos_abi::io_ring::SQ_SIZE as usize);
    assert!(RING_CQ_SIZE == azos_abi::io_ring::CQ_SIZE as usize);
    assert!(RING_DATA_BUF_SIZE == azos_abi::io_ring::DATA_SIZE);
    assert!(core::mem::size_of::<IoRing>() <= 4096);
};

/// The shared ring structure (fits in ~4 KiB page).
#[repr(C)]
pub struct IoRing {
    // Submission queue
    pub sq_head: AtomicU32,          // kernel consumes from here
    pub sq_tail: AtomicU32,          // userspace produces to here
    pub sq_entries: [SqEntry; RING_SQ_SIZE],

    // Completion queue
    pub cq_head: AtomicU32,          // userspace consumes from here
    pub cq_tail: AtomicU32,          // kernel produces to here
    pub cq_entries: [CqEntry; RING_CQ_SIZE],

    // Shared data buffer for large results
    pub data_buf: [u8; RING_DATA_BUF_SIZE],

    /// `SQ_F_*`: [`SQ_F_SQPOLL`] once an SQ poller runs this ring,
    /// [`SQ_F_NEED_WAKEUP`] while that poller is parked. Written by the
    /// kernel only; ring 3 reads it after publishing `sq_tail`.
    pub sq_flags: AtomicU32,

    /// `azos_abi::io_ring::IO_RING_VERSION`, written by the kernel at setup
    /// and never again. It occupies what was the page structure's tail
    /// padding, so the size is unchanged.
    pub version: AtomicU32,
}

// ---------------------------------------------------------------------------
// Kernel-side ring management
// ---------------------------------------------------------------------------

/// Kernel state for one io_ring instance.
pub struct IoRingState {
    /// Physical address of the shared page (0 = unused slot).
    pub phys_addr: usize,
    /// Owning task TID (as `usize`). Read by [`io_ring_owner`] and by the
    /// per-opcode capability check in [`dispatch_sqe`].
    pub owner_task: usize,
    /// Ring ID (index in global array).
    pub ring_id: u32,
    /// Whether this ring is active.
    pub active: bool,
    /// `true` iff the ring was created by a kernel task (`user_pt == 0`).
    ///
    /// **WHY it is captured at create time (W3-F3):** a pass that runs in
    /// kernel context — as the deleted M05 worker drained every ring — sees
    /// "the current task" as privileged, so a capability check written
    /// against it would be unconditionally satisfied there and enforce
    /// nothing. Recording the creator's privilege — and its TID — makes the
    /// check a property of the ring, whoever runs the pass.
    pub owner_privileged: bool,
    /// `true` while a submit pass is dereferencing `phys_addr` outside the
    /// table lock.
    ///
    /// **WHY (W3-F3):** `dispatch_sqe` calls into drivers (I2C transfers,
    /// motor writes); holding an IRQ-saving spinlock across that would pin
    /// interrupts off for milliseconds and is a control-loop jitter source in
    /// its own right. So the submit path copies `phys_addr` out and drops the
    /// lock — which reopens `io_ring_destroy` freeing the page under it. This
    /// flag closes that window: destroy refuses while a pass is in flight.
    pub in_flight: bool,
    /// `true` when the owning task died while a submit pass held an in-flight
    /// claim: the slot is already `active = false` (so no *new* claim can
    /// start) but its page is still being dereferenced and must not be freed
    /// until [`release_ring`] closes the claim.
    ///
    /// **WHY (IPC-3):** the task-exit hook must not spin waiting for the
    /// submit pass, and it must not free the page under it either — that is
    /// precisely the use-after-free `in_flight` was introduced to prevent.
    /// Deferring the free to the claim's own exit point is the only place
    /// where "the pass is definitely finished" is known, and `release_ring`
    /// already holds the table lock there.
    ///
    /// **Verified true (2026-09-06 audit), not just asserted.** Every
    /// transition of `active`/`in_flight`/`orphaned` runs under
    /// `IO_RINGS.lock_irqsave()`, and there are exactly four call sites:
    /// `claim_ring`'s `if !state.active || state.in_flight { return None; }`
    /// refuses to hand out `phys_addr` a second time; `io_ring_destroy` and
    /// `io_ring_release_all` both re-check `state.in_flight` under the same
    /// lock before touching `phys_addr`, and the latter *defers* — setting
    /// `orphaned` instead of freeing — exactly when it finds the flag set;
    /// `release_ring` is the only place that clears `in_flight` and the only
    /// place that acts on `orphaned`, and it does both under the lock too.
    /// `io_ring_create` reads `orphaned` under the same lock and takes a slot
    /// only when it is neither `active` nor `orphaned`, so an orphan's slot
    /// and page are not handed to a new ring before `release_ring` has run.
    /// Because all four are mutually exclusive on the same lock, "no *new*
    /// claim can start" and "the page is freed at most once, by whichever
    /// call observes the pass ending" both hold by construction, not by
    /// convention. `io_ring_submit` is the only kernel caller of
    /// `claim_ring`, and it pairs it with `release_ring` on every exit path
    /// (the `#[test] a_ring_orphaned_mid_pass_accepts_no_new_claim` test below
    /// exercises the deferred-free arm directly).
    pub orphaned: bool,
    /// Generation of the ring in this slot: stamped by
    /// `io_ring_create`, 0 once the slot is reusable.
    ///
    /// A `Cap<IoRing>` stores `(slot, generation)` and resolves only while the
    /// slot is active and carries that generation, so a capability to a
    /// destroyed ring never reaches the next ring at its index, in any task's
    /// table. Cleared with the slot by `IoRingState::empty()` in
    /// `io_ring_destroy`, `io_ring_release_all` and, for an orphan, in
    /// `release_ring` when its pass ends: an orphaned slot keeps its generation
    /// while it is not reusable, and resolves nothing because it is not active.
    pub generation: u32,
    /// The user virtual address the page is mapped at in its owner's address
    /// space, 0 when it is mapped nowhere (a kernel-created ring, or a ring 3
    /// ring before `SYS_RING_SETUP` recorded its mapping).
    ///
    /// **A mapped ring is freed only after it is unmapped.** Freeing the page
    /// while a user PTE still names it hands ring 3 a frame the allocator gives
    /// to someone else, so [`destroy_locked`] refuses a mapped ring and only
    /// [`io_ring_destroy_mapped_ref`] takes one, calling its unmap before the
    /// free. The exit path ([`io_ring_release_all`]) frees without unmapping:
    /// the dead task's address space never runs again, and its teardown
    /// (`process::destroy_user_address_space`) spares every leaf in the window
    /// the address was reserved from, so the frame is not freed twice.
    pub user_va: usize,
    /// TID of this ring's SQ poller, 0 when it has none. Set once, by the pass
    /// that ran the ring's [`OP_SQPOLL_START`]; the ring keeps its poller until
    /// it is destroyed, and every destroy wakes it so it can see the ring gone
    /// and exit.
    pub poller_tid: u32,
    /// The poller's idle time before it parks, from the owner's topology row.
    pub sqpoll_idle_ms: u32,
    /// The page was charged to `owner_task`'s budget at create.
    pub charged: bool,
    /// The event port this ring is bound to as a source (`PORT_BIND`,
    /// type 1), or `PortLink::NONE`. A pass that wrote at least one completion
    /// reads it when its claim is released and signals that port after the
    /// table lock is dropped ([`release_ring_with`]).
    pub link: PortLink,
    /// [`io_ring_flush_posted`] found the ring in flight: the pass holding
    /// the claim may have reaped before the flush ended, so the claim's
    /// release reaps once more ([`release_ring_with`]).
    pub reap_again: bool,
    /// [`io_ring_worker_pass`] found the ring in flight: the claim's release
    /// wakes the worker again.
    pub kick_on_release: bool,
}

impl IoRingState {
    pub const fn empty() -> Self {
        Self {
            phys_addr: 0,
            owner_task: usize::MAX,
            ring_id: 0,
            active: false,
            owner_privileged: false,
            in_flight: false,
            orphaned: false,
            generation: 0,
            user_va: 0,
            poller_tid: 0,
            sqpoll_idle_ms: 0,
            charged: false,
            link: PortLink::NONE,
            reap_again: false,
            kick_on_release: false,
        }
    }
}

/// Global array of io_ring instances.
///
/// Protected by a single `SpinLock` covering the whole table, the same shape
/// as `port.rs`'s `PORTS`, `memobj.rs`'s
/// `MEMOBJS` and `irq_bind.rs`'s `IRQ_BINDINGS`.
///
/// **WHY (W3-F3):** this was the one table in the crate still declared
/// `static mut`, with every accessor touching it in a bare `unsafe` block and
/// no synchronization at all, while `SYS_IO_SETUP` / `SYS_IO_SUBMIT` /
/// `SYS_IO_WAIT` reach it from ring 3 on any hart. Two harts could both
/// observe `!IO_RINGS[i].active` and both claim slot `i` — one page leaked
/// and two tasks sharing a ring id — and `io_ring_destroy` racing
/// `io_ring_submit` freed the page while the other hart was still writing
/// completions into it. `lock_irqsave()` throughout, matching its five
/// siblings, so an IRQ-context caller can be added later without silently
/// reintroducing a same-hart deadlock.
const EMPTY_RING: IoRingState = IoRingState::empty();

/// The ring table plus its per-slot generation sources,
/// under the same lock. `Deref`/
/// `DerefMut` to the ring array so every existing `rings[i]` / `rings.iter()`
/// accessor below is unchanged; only `create_core` reads `next_gen`.
struct IoRingTable {
    rings: [IoRingState; MAX_IO_RINGS],
    /// Entry `i` is the generation index `i`'s *next* create will stamp.
    /// Starts at 1 (`0` doubles as the mid-sweep marker), never reset by an
    /// ordinary release — only by that slot's own targeted wrap sweep. See
    /// `objref`'s module doc ("Per-slot generations...").
    next_gen: [u32; MAX_IO_RINGS],
}

impl core::ops::Deref for IoRingTable {
    type Target = [IoRingState; MAX_IO_RINGS];
    fn deref(&self) -> &Self::Target {
        &self.rings
    }
}

impl core::ops::DerefMut for IoRingTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rings
    }
}

static IO_RINGS: SpinLock<IoRingTable> = SpinLock::new(IoRingTable {
    rings: [EMPTY_RING; MAX_IO_RINGS],
    next_gen: [1u32; MAX_IO_RINGS],
});

/// What a parked entry waits for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ParkedOn {
    Free,
    /// [`OP_TIMER`]: the deadline in nanoseconds.
    Timer(u64),
    /// [`OP_NOTIFY_WAIT`]: `(Cap<Shm> handle, offset, expected)`.
    Word(u32, u32, u32),
    /// [`OP_FSYNC`]: the flush ticket [`IoRingOps::file_fsync`] answered.
    Flush(u64),
    /// [`OP_BLOCK_READ`] / [`OP_BLOCK_WRITE`] queued on the block request
    /// layer: the token [`IoRingOps::block_start`] answered, the data-buffer
    /// offset and byte length of the window, and whether it is a write.
    Block(u32, u16, u16, bool),
}

/// One parked entry: what it waits for and the tag its completion carries.
#[derive(Clone, Copy)]
struct Parked {
    on: ParkedOn,
    user_data: u64,
    /// The entry carried [`SQE_F_LINK`]: it is the ring's barrier.
    link: bool,
}

/// The entries one ring holds parked, kernel-side (never on the shared page,
/// which ring 3 can rewrite).
#[derive(Clone, Copy)]
struct ParkedSet {
    e: [Parked; RING_MAX_PARKED],
    /// Occupied entries; each holds one reserved completion slot.
    n: u32,
    /// A linked entry is parked: the SQ is not consumed until it completes.
    barrier: bool,
    /// The barrier completed with a failure: cancel the next SQ entry.
    cancel_next: bool,
}

impl ParkedSet {
    const EMPTY: Self = Self {
        e: [Parked { on: ParkedOn::Free, user_data: 0, link: false }; RING_MAX_PARKED],
        n: 0,
        barrier: false,
        cancel_next: false,
    };
}

/// Per-slot parked sets.
///
/// **Guarded by the in-flight claim, not by a lock**, exactly as the ring page
/// is: set `i` is read and written only by the pass holding slot `i`'s claim
/// (`claim_locked` hands out at most one), and reset by `create_core` under
/// the table lock while slot `i` is neither active nor orphaned, so no pass
/// can hold it. A set left behind by a destroyed ring is never read before
/// that reset.
struct ParkedTable(core::cell::UnsafeCell<[ParkedSet; MAX_IO_RINGS]>);
// SAFETY: see the type's doc — every access is serialised by the claim
// protocol or the table lock.
unsafe impl Sync for ParkedTable {}
static PARKED: ParkedTable = ParkedTable(core::cell::UnsafeCell::new([ParkedSet::EMPTY; MAX_IO_RINGS]));

/// Slot `i` may hold a parked [`OP_FSYNC`]: set by the pass that parks one,
/// cleared by [`io_ring_flush_posted`] before it claims the ring. A hint only
/// (a stale `true` costs one claim); the parked set is the truth.
static FLUSH_PARKED: [AtomicBool; MAX_IO_RINGS] = [const { AtomicBool::new(false) }; MAX_IO_RINGS];

/// Slot `i` may hold a parked block entry: set by the pass that parks one,
/// kept by the worker while the entry stays parked, cleared when it posts the
/// last one. A hint only, as [`FLUSH_PARKED`] is; the parked set is the truth.
static BLOCK_PARKED: [AtomicBool; MAX_IO_RINGS] = [const { AtomicBool::new(false) }; MAX_IO_RINGS];

/// Slot `i` was handed off: a pass that may not block stopped at a file entry
/// and the worker owes the ring a pass ([`io_ring_worker_pass`]).
static HANDOFF: [AtomicBool; MAX_IO_RINGS] = [const { AtomicBool::new(false) }; MAX_IO_RINGS];
/// The `sq_tail` the handing-off pass saw: the worker runs up to it and no
/// further, so it executes only what ring 3 SUBMITTED (running published but
/// unsubmitted entries is the SQ poller's privilege, which topology gates).
static HANDOFF_TAIL: [AtomicU32; MAX_IO_RINGS] = [const { AtomicU32::new(0) }; MAX_IO_RINGS];

/// Slot `i`'s parked set.
///
/// # Safety
/// The caller holds slot `i`'s in-flight claim, or the table lock with slot
/// `i` neither active nor orphaned.
#[allow(clippy::mut_from_ref)]
unsafe fn parked_of(i: usize) -> &'static mut ParkedSet {
    &mut (*PARKED.0.get())[i]
}

/// One registered buffer ([`OP_BUF_REGISTER`]).
#[derive(Clone, Copy)]
struct RegBuf {
    /// The pinned object's packed reference; 0 for a free slot.
    r: u32,
    /// Length of the registered range in bytes.
    len: u32,
    /// Kernel address of byte 0 of the range: the pin keeps the frames, and
    /// the run was physically contiguous when it was registered.
    kva: usize,
}

/// The buffers one ring has registered, kernel-side (never on the shared page).
#[derive(Clone, Copy)]
struct RegBufSet {
    e: [RegBuf; RING_MAX_REGBUFS],
}

impl RegBufSet {
    const EMPTY: Self = Self { e: [RegBuf { r: 0, len: 0, kva: 0 }; RING_MAX_REGBUFS] };
}

/// Per-slot registered buffers. **Guarded exactly as [`PARKED`] is**: slot `i`
/// is read and written only by the pass holding its in-flight claim, and
/// emptied (its pins handed to a [`Drain`]) by whoever vacates the slot under
/// the table lock, when no pass holds the claim or the pass whose claim is
/// ending ([`release_ring_with`]) does.
struct RegBufTable(core::cell::UnsafeCell<[RegBufSet; MAX_IO_RINGS]>);
// SAFETY: see the type's doc.
unsafe impl Sync for RegBufTable {}
static REGBUFS: RegBufTable = RegBufTable(core::cell::UnsafeCell::new([RegBufSet::EMPTY; MAX_IO_RINGS]));

/// Slot `i`'s registered buffers.
///
/// # Safety
/// As [`parked_of`].
#[allow(clippy::mut_from_ref)]
unsafe fn regbufs_of(i: usize) -> &'static mut RegBufSet {
    &mut (*REGBUFS.0.get())[i]
}

/// What a vacated slot leaves for after the table lock is dropped: the worker
/// has block requests to drain, and the objects its registered buffers pinned
/// to give back. The pins cannot be given back under the table lock: that
/// takes the object table's lock, whose holders may be waiting on an interrupt
/// (a revoke that unmaps on every hart) this hart, with interrupts off, would
/// never take.
struct Drain {
    blocks: bool,
    pins: [u32; RING_MAX_REGBUFS],
}

impl Drain {
    const NONE: Self = Self { blocks: false, pins: [0; RING_MAX_REGBUFS] };

    /// Give the pins back and wake the worker if it has requests to drain.
    /// No table lock held.
    fn finish(self) {
        // SAFETY: a copy-out read of `OPS`, which is not written while tasks run.
        let ops = unsafe { OPS };
        if let Some(ops) = ops {
            for r in self.pins {
                if r != 0 {
                    (ops.buf_unpin)(r);
                }
            }
            if self.blocks {
                kick_worker(ops);
            }
        }
    }
}

/// Slot `i` is being vacated: its parked block entries will never be asked for
/// their answer, so the requests they name go to the worker to drain
/// ([`IoRingOps::block_orphan`]) and the set is emptied; its registered buffers
/// are emptied too, their pins left in the result for [`Drain::finish`].
///
/// A request that is queued or in the device keeps a slot of the block request
/// layer until somebody collects it; a ring that dies with one would hold it
/// for good.
///
/// # Safety
/// The table lock is held and no pass holds slot `i`'s claim, or the caller is
/// the pass whose claim is ending ([`release_ring_with`]).
unsafe fn vacate_resources(i: usize) -> Drain {
    BLOCK_PARKED[i].store(false, Ordering::SeqCst);
    let mut out = Drain::NONE;
    let regs = regbufs_of(i);
    // Canary `ioring-regbuf-leak-canary`: the pins are forgotten with the slot.
    if !cfg!(feature = "ioring-regbuf-leak-canary") {
        for (pin, b) in out.pins.iter_mut().zip(regs.e.iter()) {
            *pin = b.r;
        }
    }
    *regs = RegBufSet::EMPTY;
    let parked = parked_of(i);
    if parked.n == 0 {
        return out;
    }
    if let Some(ops) = OPS {
        for p in parked.e.iter() {
            if let ParkedOn::Block(token, ..) = p.on {
                (ops.block_orphan)(token);
                out.blocks = true;
            }
        }
    }
    *parked = ParkedSet::EMPTY;
    out
}

/// Most io-rings ONE task may hold at once.
///
/// **The obligation the minting rule creates.** The capability design states it
/// plainly: a task may be handed a capability over an object it just created,
/// and *minting without a per-task quota is exhaustion*. `MAX_IO_RINGS` bounds
/// the pool for the WHOLE MACHINE, so before this a single ring-3 program
/// calling `io_ring_create` in a loop took every slot and denied io-rings to
/// everyone — the kernel's own users included.
///
/// Half the pool, mirroring `MAX_SOCKETS_PER_TASK` and `MAX_FDS_PER_TASK`:
/// enough for a program doing ordinary work, never enough for one task to lock
/// the machine out.
pub const MAX_IO_RINGS_PER_TASK: usize = MAX_IO_RINGS / 2;

/// Allocate a new io_ring. Returns (ring_id, phys_addr) or None.
///
/// A slot that [`io_ring_release_all`] left `orphaned` is not free. A task that
/// dies with N rings in flight keeps those N slots out of the `MAX_IO_RINGS`
/// pool until their submit passes end, when [`release_ring`] frees each slot
/// and its page. Such slots count against no task's `MAX_IO_RINGS_PER_TASK`.
pub fn io_ring_create(owner_task: usize) -> Option<(u32, usize)> {
    create_core(owner_task).map(|(r, phys)| (LAYOUT.idx(r), phys))
}

/// [`io_ring_create`], answering the packed `(index, generation)` reference of
/// the new ring (the value a `Cap<IoRing>` stores) and its page.
pub fn io_ring_create_ref(owner_task: usize) -> Option<(u32, usize)> {
    create_core(owner_task)
}

/// The create body: `(packed reference, phys)`.
///
/// **Per-slot generation, swept only at its own index.**
/// Each slot's generation is its own
/// (`IoRingTable::next_gen`); when slot `i`'s reaches `LAYOUT.gen_max()`, this
/// marks it mid-sweep (`next_gen[i] = 0`, which the free-slot scan already
/// treats as unavailable), releases the table lock, runs
/// `objref::sweep_index(ty::IORING, i)` — which revokes only the stale
/// `Cap<IoRing>`s left over at index `i`, nothing live — resets `next_gen[i]`
/// to `1`, and retries; a create during the brief sweep window that lands on
/// a DIFFERENT free slot is unaffected. Must not be called with a cap-table
/// lock held.
fn create_core(owner_task: usize) -> Option<(u32, usize)> {
    // The ring's page counts against its creator's budget when
    // the creator is the calling process; freeing it gives the charge back
    // (`uncharge_owner`).
    let charged = azos_sched::current_proc_tid() as usize == owner_task;
    if charged && !azos_sched::mm_charge(1) {
        return None;
    }
    // Allocate a physical page for the shared ring
    let page = match azos_mm::pmm::alloc_page_zone(azos_mm::zone::Zone::Ring) {
        Ok(p) => p,
        Err(_) => {
            if charged { azos_sched::mm_discharge(1); }
            return None;
        }
    };
    let phys = page.as_usize();

    // Snapshot the creator's privilege *before* taking the table lock —
    // `current_user_pt()` reads scheduler state and we want the critical
    // section to stay short and free of foreign locks.
    let privileged = azos_sched::current_user_pt() == 0;

    // Two passes at most: the second runs only after this call's own
    // per-slot wrap sweep finishes.
    'pass: for _ in 0..2 {
        let mut rings = IO_RINGS.lock_irqsave();
        // Counted under the SAME lock that allocates. Checking the quota and then
        // taking the lock would let two of a task's own threads both pass the
        // check and both allocate, which is the bug one level down. Same rule and
        // same reasoning as `socket_create`'s quota.
        //
        // A refusal leaves the loop instead of returning from it, so the page
        // allocated above goes back below, with the no-free-slot case.
        let held = rings.iter().filter(|r| r.active && r.owner_task == owner_task).count();
        if held >= MAX_IO_RINGS_PER_TASK {
            break 'pass;
        }
        for i in 0..MAX_IO_RINGS {
            // Free means neither active nor orphaned, and not this call's own
            // slot mid-sweep (`next_gen[i] != 0`). An orphaned slot's
            // owner died while a submit pass held it: that pass is still
            // writing into its page, and `release_ring` frees the page and
            // clears `in_flight` for whatever the slot holds when the pass
            // ends. Taking the slot here would lose the orphan's page and
            // let that pass clear the new ring's `in_flight`, reopening
            // `io_ring_destroy` on a ring still in flight. A task that dies
            // with rings in flight therefore keeps those slots out of the
            // pool until their passes end.
            if !rings[i].active && !rings[i].orphaned && rings.next_gen[i] != 0 {
                // The generation is taken once a free slot is known, so a full
                // table or a quota refusal consumes none.
                let gen = match objref::take_slot_gen(rings.next_gen[i], LAYOUT) {
                    objref::SlotGen::Gen(g) => g,
                    objref::SlotGen::Wrap => {
                        rings.next_gen[i] = 0;
                        drop(rings);
                        objref::sweep_index(ty::IORING, i as u32);
                        rings = IO_RINGS.lock_irqsave();
                        rings.next_gen[i] = 1;
                        continue 'pass;
                    }
                };
                rings.next_gen[i] = gen + 1;
                rings[i] = IoRingState {
                    phys_addr: phys,
                    owner_task,
                    ring_id: i as u32,
                    active: true,
                    owner_privileged: privileged,
                    in_flight: false,
                    orphaned: false,
                    generation: gen,
                    user_va: 0,
                    poller_tid: 0,
                    charged,
                    sqpoll_idle_ms: 0,
                    link: PortLink::NONE,
                    reap_again: false,
                    kick_on_release: false,
                };
                // A new ring starts with nothing parked. Slot `i` was neither
                // active nor orphaned under this lock, so no pass holds it.
                // SAFETY: that is `parked_of`'s second condition.
                unsafe { *parked_of(i) = ParkedSet::EMPTY; }
                // Zero-init the ring (alloc_page already zeroes, but be explicit).
                // SAFETY: `phys` is a freshly allocated PMM page, exclusively
                // owned by this slot, which we hold the table lock over.
                unsafe {
                    // `phys` is PHYSICAL; the kernel writes the ring through its own
                    // view of that page — identity on riscv64, upper half on aarch64.
                    let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
                    (*ring).sq_head.store(0, Ordering::Relaxed);
                    (*ring).sq_tail.store(0, Ordering::Relaxed);
                    (*ring).cq_head.store(0, Ordering::Relaxed);
                    (*ring).cq_tail.store(0, Ordering::Relaxed);
                    (*ring).sq_flags.store(0, Ordering::Relaxed);
                    // The layout word.
                    (*ring).version.store(azos_abi::io_ring::IO_RING_VERSION, Ordering::Release);
                }
                return Some((LAYOUT.pack(i as u32, gen), phys));
            }
        }
        break 'pass;
    }
    // Quota reached, no free slot, or refused during a sweep: the page goes back.
    let _ = azos_mm::pmm::free_page(page);
    if charged { azos_sched::mm_discharge(1); }
    None
}

/// A ring's page was freed; give the charge back to its creator
/// if it was charged. Any task's context: the discharge is posted to the
/// creator (`mm_discharge_tid`), which folds it in at its next charge.
fn uncharge_owner(state: &IoRingState) {
    if state.charged {
        azos_sched::mm_discharge_tid(state.owner_task as u32, 1);
    }
}

/// Table slot of a ring id that has passed `ring_id < MAX_IO_RINGS`, masked
/// against Spectre v1 (`azos_limits::nospec`): the ids reach here from ring 3
/// (the raw `SYS_RING_*` ids and the index half of a packed reference), and the
/// plain branch alone can be speculated past.
#[inline(always)]
fn ring_slot(ring_id: u32) -> usize {
    azos_limits::nospec::array_index_nospec(ring_id as usize, MAX_IO_RINGS)
}

/// TID of the task that created `ring_id`, or `None` if the slot is inactive.
///
/// **WHY this is public (W3-F3):** `owner_task` was written by
/// `io_ring_create` and read nowhere, so the field advertised an ownership
/// model no code applied. The legacy `SYS_IO_SUBMIT` / `SYS_IO_WAIT` arms (retired
/// with the move to generation-stamped handles) took a raw userspace ring id
/// bounded only by `MAX_IO_RINGS` (16), so without an owner check any task could drive
/// or observe any other task's ring.
pub fn io_ring_owner(ring_id: u32) -> Option<usize> {
    if ring_id as usize >= MAX_IO_RINGS { return None; }
    let rings = IO_RINGS.lock_irqsave();
    let state = &rings[ring_slot(ring_id)];
    if state.active { Some(state.owner_task) } else { None }
}

/// The packed reference of live ring `ring_id`, or `None` if its slot is not
/// active: for a caller holding a validated index that needs the value a
/// `Cap<IoRing>` stores.
pub fn io_ring_ref(ring_id: u32) -> Option<u32> {
    if ring_id as usize >= MAX_IO_RINGS { return None; }
    let rings = IO_RINGS.lock_irqsave();
    let state = &rings[ring_slot(ring_id)];
    if state.active { Some(LAYOUT.pack(ring_id, state.generation)) } else { None }
}

/// Resolve a packed reference to its slot, with the table lock held by the
/// caller.
///
/// `Stale` unless the slot is active and carries the reference's generation: a
/// vacated slot (generation 0), a slot reused by another ring, a bare index
/// (generation 0) and an orphaned slot (not active) all answer `Stale`.
fn live_index(rings: &[IoRingState; MAX_IO_RINGS], r: u32) -> Result<usize, IoRingCapError> {
    let i = LAYOUT.idx(r) as usize;
    let g = LAYOUT.gen(r);
    if g == 0 || i >= MAX_IO_RINGS {
        return Err(IoRingCapError::Cap(CapError::Stale));
    }
    // The index is the reference's, i.e. ring 3's: masked after the check.
    let i = azos_limits::nospec::array_index_nospec(i, MAX_IO_RINGS);
    if !rings[i].active || rings[i].generation != g {
        return Err(IoRingCapError::Cap(CapError::Stale));
    }
    Ok(i)
}

/// Destroy an io_ring and free its page.
///
/// Returns `false` if the ring is not active, or if a submit pass is
/// currently in flight on it — freeing the page under a live pass is exactly
/// the use-after-free `in_flight` exists to prevent. Callers that get `false`
/// on a busy ring may retry; the pass is bounded by `RING_SQ_SIZE`.
pub fn io_ring_destroy(ring_id: u32) -> bool {
    if ring_id as usize >= MAX_IO_RINGS { return false; }
    let mut poller = 0;
    let mut drain = Drain::NONE;
    let (done, gone) = {
        let mut rings = IO_RINGS.lock_irqsave();
        let state = &mut rings[ring_slot(ring_id)];
        let gone = (state.link, LAYOUT.pack(ring_id, state.generation));
        (destroy_locked(state, &mut poller, &mut drain), gone)
    };
    sqpoll_wake(poller);
    drain.finish();
    if done {
        post_gone(gone, CODE_REVOKED);
    }
    done
}

/// `EREVOKED` / `EPEERDIED`, the codes of a gone ring's port event.
const CODE_REVOKED: u16 = azos_abi::error::Errno::EREVOKED as u16;
const CODE_PEER_DIED: u16 = azos_abi::error::Errno::EPEERDIED as u16;

/// Ring `r` (its packed reference), bound to a port through `link`, is gone:
/// the port's source reports `PORT_EVENT_SOURCE_GONE` with `code` (wave 15
/// N5b). No lock of this module held.
fn post_gone((link, r): (PortLink, u32), code: u16) {
    if !link.is_none() {
        let _ = crate::port::port_source_gone(link, crate::port::PortSourceKind::Ring(r), code);
    }
}

/// [`io_ring_destroy`] through a packed reference: `Stale` if the ring at its
/// index is not the one it names, `Closed` while a submit pass is in flight on
/// it (retry).
pub fn io_ring_destroy_ref(r: u32) -> Result<(), IoRingCapError> {
    let mut poller = 0;
    let mut drain = Drain::NONE;
    let (done, link) = {
        let mut rings = IO_RINGS.lock_irqsave();
        let i = live_index(&rings, r)?;
        let link = rings[i].link;
        (destroy_locked(&mut rings[i], &mut poller, &mut drain), link)
    };
    sqpoll_wake(poller);
    drain.finish();
    if done {
        post_gone((link, r), CODE_REVOKED);
        Ok(())
    } else {
        Err(IoRingCapError::Closed)
    }
}

/// Record that live ring `r`'s page is mapped at `va` in `tid`'s address space.
///
/// `Stale` for a reference to another ring; `Closed` when `tid` does not own
/// the ring or a mapping is already recorded (one mapping per ring, by its
/// owner). Called by `SYS_RING_SETUP` once the PTE is installed.
pub fn io_ring_record_user_va(r: u32, tid: u32, va: usize) -> Result<(), IoRingCapError> {
    let mut rings = IO_RINGS.lock_irqsave();
    let i = live_index(&rings, r)?;
    let state = &mut rings[i];
    if va == 0 || state.owner_task != tid as usize || state.user_va != 0 {
        return Err(IoRingCapError::Closed);
    }
    state.user_va = va;
    Ok(())
}

/// The user address recorded for live ring `r`, 0 when none.
pub fn io_ring_user_va(r: u32) -> Result<usize, IoRingCapError> {
    let rings = IO_RINGS.lock_irqsave();
    let i = live_index(&rings, r)?;
    Ok(rings[i].user_va)
}

/// Destroy live ring `r` on behalf of `tid`, unmapping its page first when it
/// is mapped: `unmap(va)` runs after the slot is vacated and before the page
/// is freed, with no lock of this module held.
///
/// `Stale` for a reference to another ring; `Closed` while a submit pass is in
/// flight (retry), or when the page is mapped and `tid` is not the owner — the
/// PTE is in the owner's address space, which `unmap` cannot reach from
/// another task, and freeing the page under it is the use-after-free
/// [`IoRingState::user_va`] exists to prevent.
///
/// The slot is emptied under the lock before `unmap` runs, so no new claim can
/// start on it and the page belongs to this call alone until it is freed.
pub fn io_ring_destroy_mapped_ref(
    r: u32,
    tid: u32,
    unmap: fn(va: usize),
) -> Result<(), IoRingCapError> {
    let (phys, va, poller, link, drain) = {
        let mut rings = IO_RINGS.lock_irqsave();
        let i = live_index(&rings, r)?;
        let state = &mut rings[i];
        if state.in_flight || (state.user_va != 0 && state.owner_task != tid as usize) {
            return Err(IoRingCapError::Closed);
        }
        let taken = (state.phys_addr, state.user_va, state.poller_tid, state.link);
        uncharge_owner(state);
        // SAFETY: live, not in flight, under the table lock.
        let drain = unsafe { vacate_resources(i) };
        *state = IoRingState::empty();
        (taken.0, taken.1, taken.2, taken.3, drain)
    };
    drain.finish();
    if va != 0 {
        unmap(va);
    }
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(phys));
    sqpoll_wake(poller);
    post_gone((link, r), CODE_REVOKED);
    Ok(())
}

/// The destroy body, table lock held. `empty()` clears the generation.
///
/// Refuses a ring whose page is mapped in user space (`user_va != 0`): see
/// [`IoRingState::user_va`]. [`io_ring_destroy_mapped_ref`] is the one destroy
/// that takes such a ring.
fn destroy_locked(state: &mut IoRingState, poller: &mut u32, drain: &mut Drain) -> bool {
    if !state.active || state.in_flight || state.user_va != 0 { return false; }
    let _ = azos_mm::pmm::free_page(
        azos_mm::addr::PhysAddr::new(state.phys_addr)
    );
    uncharge_owner(state);
    *poller = state.poller_tid;
    // SAFETY: the slot is active and not in flight, under the table lock.
    *drain = unsafe { vacate_resources(state.ring_id as usize) };
    *state = IoRingState::empty();
    true
}

/// Claim a ring for a submit pass: validates it, marks `in_flight`, and
/// returns `(phys_addr, owner_tid, owner_privileged)`.
///
/// Returns `None` when the ring is inactive or already in flight. The caller
/// **must** pair this with [`release_ring`] on every exit path.
fn claim_ring(ring_id: u32) -> Option<(usize, u32, bool)> {
    if ring_id as usize >= MAX_IO_RINGS { return None; }
    let mut rings = IO_RINGS.lock_irqsave();
    claim_locked(&mut rings[ring_slot(ring_id)])
}

/// [`claim_ring`] through a packed reference: the generation is compared inside
/// the lock the claim takes. Answers the slot index with the claim; `Stale` for
/// a reference to another ring, `SubmitError(IO_ERR_INVALID_PARAM)` (what
/// `io_ring_submit` answers) for a ring already in flight.
fn claim_ring_ref(r: u32) -> Result<RefClaim, IoRingCapError> {
    let mut rings = IO_RINGS.lock_irqsave();
    let i = live_index(&rings, r)?;
    let st = &mut rings[i];
    // In the same hold as the claim, so a submit costs one lock round trip.
    if st.poller_tid != 0 {
        return Ok(RefClaim::Polled { poller: st.poller_tid, owner: st.owner_task });
    }
    claim_locked(st)
        .map(|claim| RefClaim::Claimed(i as u32, claim))
        .ok_or(IoRingCapError::SubmitError(IO_ERR_INVALID_PARAM))
}

/// What [`claim_ring_ref`] found.
enum RefClaim {
    /// `(slot, (phys, owner TID, owner privileged))`, claim taken.
    Claimed(u32, (usize, u32, bool)),
    /// An SQ poller runs the ring; nothing was claimed.
    Polled { poller: u32, owner: usize },
}

/// The claim body, table lock held.
fn claim_locked(state: &mut IoRingState) -> Option<(usize, u32, bool)> {
    if !state.active || state.in_flight { return None; }
    state.in_flight = true;
    Some((
        state.phys_addr,
        // `owner_task` is a TID stored widened to usize; narrow it back for
        // the handle table, saturating rather than truncating so a sentinel
        // `usize::MAX` can never alias a real TID.
        state.owner_task.min(u32::MAX as usize) as u32,
        state.owner_privileged,
    ))
}

/// Release a claim taken by [`claim_ring`].
///
/// Also completes a **deferred destroy**: if the owning task died mid-pass,
/// [`io_ring_release_all`] left the slot `active = false, orphaned = true`
/// with its page intact, because freeing it there would have pulled the page
/// out from under the very pass this call is ending. This is the exactly-once
/// exit point of every claim, so it is the one place where the page is
/// provably no longer referenced.
///
/// Hot-path cost: one bool read inside a lock this function already takes —
/// no extra acquisition, no extra branch on the submit fast path beyond a
/// predictable not-taken test.
fn release_ring(ring_id: u32) {
    release_ring_with(ring_id, None, false);
}

/// [`release_ring`], recording the SQ poller the pass started, if it did.
///
/// A poller started by a pass whose ring was orphaned meanwhile (its owner
/// died mid-pass) is woken instead: its first pass finds the ring gone and it
/// exits.
///
/// `completed`: the pass wrote at least one completion. The ring's port link
/// is read in this same hold and that port is signalled after it
/// (`port::port_signal_ring`); a link the port no longer answers to is
/// cleared. A ring with no link pays one branch.
fn release_ring_with(ring_id: u32, started: Option<(u32, u32)>, completed: bool) {
    if ring_id as usize >= MAX_IO_RINGS { return; }
    let mut orphan_poller = 0;
    let mut signal: Option<(PortLink, u32)> = None;
    let reap_again;
    let kick;
    // Only an orphaned ring has anything to drain: the hot path of every pass's
    // release carries a tag, not the pin list.
    let mut drain: Option<Drain> = None;
    {
        let mut rings = IO_RINGS.lock_irqsave();
        let state = &mut rings[ring_id as usize];
        state.in_flight = false;
        reap_again = core::mem::take(&mut state.reap_again) && !state.orphaned;
        kick = core::mem::take(&mut state.kick_on_release) && !state.orphaned;
        if state.orphaned {
            let phys = state.phys_addr;
            uncharge_owner(state);
            // SAFETY: the pass whose claim this is has ended, under the lock.
            drain = Some(unsafe { vacate_resources(ring_id as usize) });
            // The slot becomes reusable here, so this is where its generation is
            // cleared (`empty()`), not at the owner's exit.
            *state = IoRingState::empty();
            let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(phys));
            orphan_poller = started.map_or(0, |(t, _)| t);
        } else {
            if let Some((tid, idle_ms)) = started {
                state.poller_tid = tid;
                state.sqpoll_idle_ms = idle_ms;
            }
            if completed && !state.link.is_none() {
                signal = Some((state.link, LAYOUT.pack(ring_id, state.generation)));
            }
        }
    }
    sqpoll_wake(orphan_poller);
    if let Some(d) = drain {
        d.finish();
    }
    if let Some((link, r)) = signal {
        if !crate::port::port_signal_ring(link, r) {
            io_ring_clear_link(r, link);
        }
    }
    if reap_again {
        // A flush ended while this claim was held (`io_ring_flush_posted`).
        post_parked(ring_id as usize);
    }
    if kick {
        // The worker found this ring in flight: it owes it a pass still.
        // SAFETY: a copy-out read of `OPS`, which is not written while tasks run.
        if let Some(ops) = unsafe { OPS } {
            kick_worker(ops);
        }
    }
}

fn kick_worker(ops: &IoRingOps) {
    if let Some(k) = ops.handoff_kick {
        k();
    }
}

/// The io_ring worker's pass (a kernel task outside the RT band, Kconfig
/// `IORING_WORKER`). Two jobs.
///
/// **Handed-off rings.** For every ring a pass handed off, claim it and run
/// the same pass (the owner's seccomp profile, capabilities, containment and
/// SQ order) from the entry the hand-off stopped at up to the `sq_tail` it saw,
/// with the block layer allowed: the file entries of every submitter under
/// Kconfig `IORING_ASYNC`, an RT task's block and fsync entries, a block entry
/// the request layer could not take. Completions go through the CQ and the
/// ring's port as any pass's do. A ring a pass holds is marked, and that
/// claim's release wakes the worker again.
///
/// **Queued block requests** (`IORING_ASYNC`). Nobody else drives them: a
/// submit only queues. The worker starts what is queued, sleeps until the
/// oldest request is over ([`IoRingOps::block_service`]), and posts the
/// completions of the rings that parked one, from here, so a completion does
/// not wait for the ring's next submit. Hand-offs that arrive meanwhile run
/// between two requests.
///
/// Answers the rings it ran or posted.
pub fn io_ring_worker_pass() -> u32 {
    // SAFETY: a copy-out read of `OPS`, which is not written while tasks run.
    let Some(ops) = (unsafe { OPS }) else { return 0 };
    let mut ran = 0;
    loop {
        ran += handoff_sweep(ops);
        let more = (ops.block_service)();
        ran += block_sweep();
        if !more {
            return ran;
        }
    }
}

/// The hand-off half of [`io_ring_worker_pass`].
fn handoff_sweep(ops: &IoRingOps) -> u32 {
    let mut ran = 0;
    for i in 0..MAX_IO_RINGS {
        if !HANDOFF[i].swap(false, Ordering::SeqCst) {
            continue;
        }
        let claim = {
            let mut rings = IO_RINGS.lock_irqsave();
            let st = &mut rings[i];
            if st.active && st.in_flight {
                HANDOFF[i].store(true, Ordering::SeqCst);
                st.kick_on_release = true;
            }
            claim_locked(st)
        };
        let Some((phys, owner_tid, owner_priv)) = claim else { continue };
        let upto = HANDOFF_TAIL[i].load(Ordering::SeqCst);
        // SAFETY: the claim was taken just above and is released below.
        let out = unsafe { run_pass(i as u32, None, phys, owner_tid, owner_priv, ops, false, true, Some(upto)) };
        release_ring_with(i as u32, None, out.n > 0);
        ran += 1;
    }
    ran
}

/// The completion half of [`io_ring_worker_pass`]: post the parked block
/// entries whose request is over.
fn block_sweep() -> u32 {
    let mut ran = 0;
    for i in 0..MAX_IO_RINGS {
        if BLOCK_PARKED[i].swap(false, Ordering::SeqCst) {
            post_parked(i);
            ran += 1;
        }
    }
    ran
}

/// The filesystem's flusher finished a flush: post every parked [`OP_FSYNC`]
/// it made durable, from here, so the completion does not wait for the ring's
/// next submit. Called by the kernel's `fs-wb` task (never RT) with no lock
/// held. A ring a pass holds is marked, and that claim's release posts.
pub fn io_ring_flush_posted() {
    for i in 0..MAX_IO_RINGS {
        if FLUSH_PARKED[i].swap(false, Ordering::SeqCst) {
            post_parked(i);
        }
    }
}

/// Claim slot `i` and complete its parked entries that are ready (a flush
/// that ended, a block request that is over); when a pass holds the claim,
/// leave the reap to that claim's release.
fn post_parked(i: usize) {
    // SAFETY: a copy-out read of `OPS`, which is not written while tasks run.
    let Some(ops) = (unsafe { OPS }) else { return };
    let claim = {
        let mut rings = IO_RINGS.lock_irqsave();
        let st = &mut rings[i];
        if st.active && st.in_flight {
            st.reap_again = true;
        }
        claim_locked(st)
    };
    let Some((phys, owner_tid, _)) = claim else { return };
    // SAFETY: the claim keeps the page alive and makes this the only user of
    // slot `i`'s parked set until the release below.
    let done = unsafe {
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        let parked = parked_of(i);
        let n = reap_parked(ring, parked, ops, owner_tid);
        if parked.e.iter().any(|p| matches!(p.on, ParkedOn::Flush(_))) {
            FLUSH_PARKED[i].store(true, Ordering::Release);
        }
        if parked.e.iter().any(|p| matches!(p.on, ParkedOn::Block(..))) {
            BLOCK_PARKED[i].store(true, Ordering::Release);
        }
        n
    };
    release_ring_with(i as u32, None, done > 0);
}

/// Store `link` as the port ring `r` reports completions to
/// (`PORT_BIND`): the rule of `channel::channel_set_link`. Stored
/// when the ring has no link, its link names the same port, or its link
/// equals `replace` (one the binder found dead); `Busy(current)` otherwise.
/// `Stored { ready }`: the CQ held an unread completion (`cq_tail != cq_head`
/// on the page) in the same table hold.
pub fn io_ring_set_link(r: u32, link: PortLink, replace: PortLink) -> Result<LinkSet, IoRingCapError> {
    let mut rings = IO_RINGS.lock_irqsave();
    let i = live_index(&rings, r)?;
    let st = &mut rings[i];
    let cur = st.link;
    if cur.is_none() || cur.port == link.port || cur == replace {
        st.link = link;
        // SAFETY: an active slot's page stays allocated while the table lock
        // is held (every free runs under it); the two words are atomics.
        let ready = unsafe {
            let ring = azos_mm::addr::phys_to_virt(st.phys_addr) as *const IoRing;
            (*ring).cq_tail.load(Ordering::Acquire) != (*ring).cq_head.load(Ordering::Acquire)
        };
        return Ok(LinkSet::Stored { ready });
    }
    Ok(LinkSet::Busy(cur))
}

/// Clear ring `r`'s port link if it is still `link`. Nothing for a stale `r`.
pub fn io_ring_clear_link(r: u32, link: PortLink) {
    let mut rings = IO_RINGS.lock_irqsave();
    if let Ok(i) = live_index(&rings, r) {
        if rings[i].link == link {
            rings[i].link = PortLink::NONE;
        }
    }
}

/// Destroy every io_ring owned by `tid` — task-exit hook (IPC-3).
///
/// **WHY this exists (IPC-3):** `IO_RINGS` is a fixed 16-entry BSS table and
/// each live entry pins one 4 KiB PMM page. Nothing reclaimed either:
/// `task_release_all` called only `handle_revoke_all`, `cap_store::reset` and
/// `memobj_release_all`, so a task that died holding a ring leaked both the slot
/// and its page permanently. Sixteen deaths and `SYS_IO_SETUP` fails forever.
/// It also bounds an inheritance hazard, as `port_release_all` does:
/// `io_ring_owner(id)` holds a TID, and a
/// TID is reissued only after `NEXT_TID` wraps at 2^32 (TIDs are monotone, see
/// `cap_store.rs`'s module doc), so a ring left active — its `owner_privileged`
/// bit included — would be inherited by the task that draws that TID after the
/// wrap.
///
/// **The submit-pass race, and why this does not reintroduce it.**
/// `io_ring_submit` copies `phys_addr` out and drops the table lock before
/// calling `dispatch_sqe` (it must: it calls into I2C/motor drivers, and
/// holding an IRQ-saving spinlock across that is a control-loop jitter
/// source). `in_flight` is what stops `io_ring_destroy` freeing the page
/// inside that window. A task-exit hook has neither option available to
/// `io_ring_destroy`'s callers: it cannot return `false` and ask to be
/// retried, and it must not block waiting for the pass — the caller
/// is `scheduler::task_exit`, mid-teardown, on its way to `do_schedule`.
///
/// So the free is **deferred, never waited on**: an in-flight ring is marked
/// `active = false, orphaned = true` and its page left mapped. `claim_ring`
/// requires `active`, so no *new* pass can start; the one pass already
/// running keeps dereferencing a page that is still live and valid, and
/// [`release_ring`] frees it when that pass ends. The window is unobservable
/// from every other accessor — `io_ring_owner` and `io_ring_destroy` both
/// test `active` before touching `phys_addr`, and
/// `io_ring_create` does not count the slot as free until that pass ends.
///
/// Cost: exit path only, one table hold per slot.
pub fn io_ring_release_all(tid: u32) {
    // SQ pollers of the dying task's rings, woken once the lock is dropped so
    // each sees its ring gone and exits (a parked one would otherwise sleep
    // forever on a ring that no longer exists).
    let mut pollers = [0u32; MAX_IO_RINGS];
    // First, each bound ring's port hears that it is gone (wave 15 N5b), one
    // ring a hold so nothing is buffered per ring (an orphaned ring too, at
    // its owner's exit rather than when its last pass ends). A pass still in
    // flight that completes later finds its port source gone and signals
    // nothing.
    let mut from = 0usize;
    while from < MAX_IO_RINGS {
        let mut gone = None;
        {
            let rings = IO_RINGS.lock_irqsave();
            while from < MAX_IO_RINGS && gone.is_none() {
                let st = &rings[from];
                if st.active && st.owner_task == tid as usize && !st.link.is_none() {
                    gone = Some((st.link, LAYOUT.pack(from as u32, st.generation)));
                }
                from += 1;
            }
        }
        if let Some(g) = gone {
            post_gone(g, CODE_PEER_DIED);
        }
    }
    // One hold per slot: the pins a vacated ring leaves are given back after its
    // hold ends ([`Drain::finish`]), and a list of them for every slot at once
    // would not fit a kernel stack at `MAX_IO_RINGS` 256.
    for i in 0..MAX_IO_RINGS {
        let drain = {
            let mut rings = IO_RINGS.lock_irqsave();
            let state = &mut rings[i];
            // `owner_task` is a TID widened to `usize` at both create sites
            // (`io_ring_create_cap`). Compare in
            // `usize` so the `usize::MAX` sentinel cannot alias a real TID.
            if !state.active || state.owner_task != tid as usize {
                continue;
            }
            pollers[i] = state.poller_tid;
            if state.in_flight {
                // Deferred: hand the free to `release_ring`. Clearing `active`
                // first is what makes this safe — `claim_ring` will refuse from
                // here on, so exactly one pass remains and it owns the free.
                state.active = false;
                state.orphaned = true;
                None
            } else {
                let phys = state.phys_addr;
                // SAFETY: active, not in flight, under the table lock.
                let drain = unsafe { vacate_resources(i) };
                *state = IoRingState::empty();
                let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(phys));
                Some(drain)
            }
        };
        if let Some(d) = drain {
            d.finish();
        }
    }
    for p in pollers {
        sqpoll_wake(p);
    }
    sqpoll_revoke_permit(tid);
}

// ---------------------------------------------------------------------------
// IO Ring dispatch table — avoids circular dependencies (F00.1)
// ---------------------------------------------------------------------------

/// Codes for IO ring operations. The `IO_ERR_*` values that complete an entry
/// are negative errnos and always travel with [`CQE_F_REFUSED`]; `IO_ERR_NO_OPS`
/// and `IO_ERR_CQ_FULL` are answers of the submit itself, never a completion.
pub const IO_OK: i32 = 0;
pub const IO_ERR_INVALID_OP: i32 = azos_abi::error::Errno::ENOSYS.to_syscall_ret() as i32;
pub const IO_ERR_INVALID_PARAM: i32 = azos_abi::error::Errno::EINVAL.to_syscall_ret() as i32;
pub const IO_ERR_NO_OPS: i32 = -3;
/// The submit executed nothing because the completion queue was full.
pub const IO_ERR_CQ_FULL: i32 = azos_abi::error::Errno::EBUSY.to_syscall_ret() as i32;
/// The submitter's seccomp profile does not list the opcode's syscall.
pub const IO_ERR_SECCOMP: i32 = azos_abi::error::Errno::EPERM.to_syscall_ret() as i32;
/// An entry the owner's Domain pledge mask refuses: what the trap answers for
/// the typed call the entry stands for.
pub const IO_ERR_PLEDGE: i32 = azos_abi::error::Errno::EACCES.to_syscall_ret() as i32;
/// A write refused by containment: the typed calls' `Contained` code.
pub const IO_ERR_CONTAINED: i32 = azos_abi::error::Errno::EAGAIN.to_syscall_ret() as i32;

/// What an op-table entry answers: `Ok` with the operation's own result, or
/// `Err` with a negative errno when the entry refused before acting (the
/// completion then carries [`CQE_F_REFUSED`]).
pub type OpResult = Result<i32, i32>;

/// Dispatch table for IO ring operations.
///
/// **Registered by the kernel at boot** (`azos_syscall::ioring_ops`), whose
/// entries call what the typed syscalls call. Until a table is registered,
/// [`io_ring_submit`] answers [`IO_ERR_NO_OPS`].
pub struct IoRingOps {
    /// The submitter's seccomp verdict for syscall `nr`, the number the opcode
    /// stands for ([`opcode_gate`]): `true` for an allowed or audited call (the
    /// audit recorded), `false` for a denied one. `owner_tid` is the ring's
    /// owner; the kernel's entry refuses when the task submitting is not it,
    /// so the profile consulted is the one of the task whose capabilities
    /// authorize the entry.
    ///
    /// Linux seccomp sees `io_uring_enter` once and none of the operations in
    /// the ring; this is asked once per entry.
    pub syscall_allowed: fn(owner_tid: u32, nr: u64) -> bool,
    /// The submitter's seccomp verdict for the kernel-hosted interface with
    /// host key `key` (`ImageProfile::ifaces`), asked for the opcodes that
    /// stand for an interface op ([`opcode_gate`]) in place of a syscall:
    /// `true` for an allowed or audited interface, `false` for an unlisted one.
    pub iface_allowed: fn(owner_tid: u32, key: u16) -> bool,
    /// The submitter's seccomp verdict for the class of the `invoke` op
    /// `op` (`azos_abi::invoke`), asked for the opcodes that stand for an op
    /// of a handle ([`opcode_gate`]): `true` for a listed or audited class,
    /// `false` for an unlisted one.
    pub op_allowed: fn(owner_tid: u32, op: u16) -> bool,
    /// The owner's Domain pledge mask (`azos_sched::domain::admit`) for the call
    /// an entry stands for: `nr` the syscall number of it, `bit` its bit of the
    /// mask ([`OpGate::pledge`]). `false`: the mask refuses it and the receipt is
    /// written. The ring is one `SYS_RING_ENTER` to the trap's prologue, which
    /// judged only that; each entry would otherwise be the same operation done
    /// outside the mask. Asked after the seccomp question, per entry, with the
    /// owner's Domain (not the task submitting: the SQ poller is a kernel task).
    pub pledge_allowed: fn(owner_tid: u32, nr: u64, bit: u8) -> bool,
    /// Is degraded-mode containment armed? A write entry of a ring-3 ring is refused
    /// with [`IO_ERR_CONTAINED`] while it answers `true`, as the typed call's
    /// `CapTable::get` refuses it. A hook rather than a direct
    /// `cap::degraded_active` call so the host suite, whose capability tests
    /// toggle the degrade level on their own lock, has a deterministic answer.
    pub write_contained: fn() -> bool,
    pub read_sensor:   fn(sensor_type: u32, buf: *mut u8, buf_len: usize) -> OpResult,
    pub write_gpio:    fn(pin: u32, value: u32) -> OpResult,
    pub read_gpio:     fn(pin: u32) -> OpResult,
    /// Mirrors `sys_i2c_read(bus, addr, reg, buf, len)`. `addr_reg` used to be
    /// one packed word; see [`SqEntry`] for why it had to be split.
    pub i2c_read:      fn(bus: u32, addr: u32, reg: u32, buf: *mut u8, len: usize) -> OpResult,
    /// Mirrors `sys_i2c_write(bus, addr, data, len)`: `data[0]` is the
    /// register, so there is no separate `reg` argument.
    pub i2c_write:     fn(bus: u32, addr: u32, data: *const u8, len: usize) -> OpResult,
    /// Duty in percent, `SYS_PWM_SET_DUTY_PCT_TYPED`'s argument.
    pub pwm_set:       fn(channel: u32, duty_pct: u32) -> OpResult,
    /// ONE wheel, as the `Motor` interface's `speed` commands one: 0 stops (coast),
    /// anything else drives forward at that percentage. `OP_MOTOR_SPEED` calls
    /// it once per wheel, so the halt rule and the envelope apply to each. The
    /// command is `owner_tid`'s: the effect gate records it as that task's,
    /// and that task's exit stops the wheel.
    pub motor_wheel:   fn(owner_tid: u32, id: u32, speed_pct: u32) -> OpResult,
    /// `NODE_SEND` below the trap: resolve the `Cap<Socket>` handle `cap`
    /// in `owner_tid`'s table (`WRITE`, with containment) as the typed call
    /// does, record a refusal as it does, and queue at most `len` bytes on the
    /// socket WITHOUT waiting (no ARP or window wait): `Ok(bytes queued)`,
    /// `Ok(0)` for a closed window, `Err` for a refusal.
    pub net_send:      fn(owner_tid: u32, cap: u32, data: *const u8, len: usize) -> OpResult,
    /// `NODE_RECV` below the trap: resolve the `Cap<Socket>` handle `cap` in
    /// `owner_tid`'s table (`READ`) as the typed call does, record a refusal as
    /// it does, check the socket's owner stamp as `socket_access_ok` does, and
    /// take at most `len` bytes off the socket straight into `buf` WITHOUT
    /// waiting: `Ok(bytes)`, `Ok(0)` for nothing queued, `Ok(-1)` for a socket
    /// that cannot receive, `Ok(-EEOF)` once a stream has ended, `Err` for a
    /// refusal. `buf` is a window `dispatch_sqe` bounded, in the ring's data
    /// buffer or in a registered buffer (kernel memory either way, so there is
    /// no user copy to validate or to lose the bytes to).
    pub net_recv:      fn(owner_tid: u32, cap: u32, buf: *mut u8, len: usize) -> OpResult,
    /// Record a device-capability refusal of the ring's owner (`kind`, reason
    /// `MissingPerms`) the way a typed call records its own refusals
    /// (`handlers::note_typed_denial`), charged to `owner_tid`'s bound. Called
    /// once per refused entry, before it completes with [`IO_ERR_PERM`].
    ///
    /// Until this hook a refused ring entry was recorded nowhere, the hole the
    /// typed recorder was built to close for the syscalls.
    pub note_denial:   fn(owner_tid: u32, kind: CapType),
    /// `NODE_READ` / `NODE_WRITE` below the trap: resolve
    /// the `Cap<File>` handle `cap` in `owner_tid`'s table as the typed call
    /// does (`READ`, or `WRITE` with containment), record a refusal as it does,
    /// and move at most `len` bytes between the descriptor and `buf`. `Err` for
    /// a refusal, `Ok` with the byte count or the typed call's own code.
    pub file_io:       fn(owner_tid: u32, cap: u32, write: bool, buf: *mut u8, len: usize) -> OpResult,
    /// Sectors of partition `badge - 1` (`OP_BLOCK_READ` / `OP_BLOCK_WRITE`),
    /// the capability and containment already checked: resolve `sector`
    /// (relative to the partition, `len / 512` of them) to the device, refuse
    /// and record a run outside the partition, and move `len` bytes between
    /// the device and `buf`. `Ok(len)` for the run done, `Err` for a refusal.
    pub block_io:      fn(badge: u32, write: bool, sector: u64, buf: *mut u8, len: usize) -> OpResult,
    /// [`OP_BLOCK_READ`] / [`OP_BLOCK_WRITE`] as a QUEUED request (Kconfig
    /// `IORING_ASYNC`), the capability, containment and window already
    /// checked: resolve the run as `block_io` does (a run outside the
    /// partition is refused and recorded: [`BlockStart::Refused`]) and put it
    /// on the block request layer WITHOUT starting the device and without
    /// sleeping. The kernel owns the request's bounce buffer (a write's `len`
    /// bytes are copied out of `buf` now), so the ring page is never lent to
    /// the device and a ring destroyed meanwhile cannot hand it a freed frame.
    /// [`BlockStart::Unqueueable`] when the layer cannot take it now (no
    /// queue on this board, the queue is full, a run longer than one device
    /// command): the entry then takes `block_io`'s synchronous path.
    /// [`BlockStart::Dirty`] for a READ whose range the filesystem's
    /// write-back cache holds unwritten: queueing it would start a read of
    /// stale sectors, and writing them first waits for the device, so a pass
    /// that is not the worker's hands the entry over and the worker's
    /// `block_io` writes them back, then reads.
    pub block_start:   fn(owner_tid: u32, badge: u32, write: bool, sector: u64, buf: *const u8, len: usize) -> BlockStart,
    /// Has the request `token` ended? `None` while it is queued or in the
    /// device. Otherwise the request is collected (its slot freed), a read's
    /// `len` bytes are copied to `out`, and the entry's result is answered:
    /// `len`, or a negative errno when the device failed it. Never waits.
    pub block_poll:    fn(token: u32, out: *mut u8, len: usize) -> Option<i32>,
    /// The ring that parked `token` is gone: nobody will ask for its answer.
    /// Takes no lock a caller may not hold and frees nothing (the table lock
    /// of the ring table is held, interrupts off): the worker drains it
    /// ([`IoRingOps::block_service`]).
    pub block_orphan:  fn(token: u32),
    /// The io_ring worker's turn at the queued block requests, a task that may
    /// sleep: start what is queued, sleep until the oldest request is over and
    /// collect it. Frees what orphaned requests held. Answers whether any
    /// request is still queued or in the device. With nothing queued it is a
    /// load and returns `false`.
    pub block_service: fn() -> bool,
    /// Has the time counter reached `deadline_ns`, rounded up to a tick as
    /// `SYS_SLEEP_UNTIL` rounds it? [`OP_TIMER`]'s clock.
    pub deadline_reached: fn(deadline_ns: u64) -> bool,
    /// Read the `u32` at byte `offset` of the region the `Cap<Shm>` handle
    /// `shm_cap` names in `owner_tid`'s table (`READ`): `Ok(value)`, or `Err`
    /// with the typed call's errno for a refused handle or an offset outside
    /// the region or not 4-aligned. Re-resolved on every look, so a revoked
    /// capability ends a parked wait.
    pub notify_word:   fn(owner_tid: u32, shm_cap: u32, offset: u32) -> Result<u32, i32>,
    /// [`OP_FSYNC`] below the trap: resolve the `Cap<File>` handle `cap` in
    /// `owner_tid`'s table as `NODE_FSYNC` does (any permission), and
    /// ASK the filesystem's flusher for a flush of every write queued so far.
    /// Never waits on the device. `Ok(ticket)` to wait for with
    /// [`IoRingOps::fsync_done`], `Err` for a refusal.
    pub file_fsync:    fn(owner_tid: u32, cap: u32) -> OpResult64,
    /// Has the flush `ticket` names completed? `None` while it runs, `Some(0)`
    /// once durable, `Some(-errno)` when it failed.
    pub fsync_done:    fn(ticket: u64) -> Option<i32>,
    /// May the running task enter the block layer? `false` for a real-time
    /// task (owner rule: RT only enqueues). Asked once per submit or poller
    /// pass; with Kconfig `IORING_ASYNC` the file entries of a task that may
    /// block still go to the worker ([`IoRingOps::file_inline`]) and its block
    /// entries are queued, so this decides only the entries the queue cannot
    /// take.
    pub may_block:     fn() -> bool,
    /// May the running task, which [`IoRingOps::may_block`] allows, run a FILE
    /// entry (`OP_FILE_READ` / `OP_FILE_WRITE`) in its own pass? `false` sends
    /// every submitter's file entries to the worker (Kconfig `IORING_ASYNC`: the
    /// file seam is synchronous, so the worker is its queue). Asked only for a
    /// file entry, by a pass that is not the worker's.
    pub file_inline:   fn() -> bool,
    /// Wake the io_ring worker, which runs a handed-off ring's pass
    /// ([`io_ring_worker_pass`]); `None` when the kernel has no worker
    /// (Kconfig `IORING_WORKER` off): a pass that may not block then refuses
    /// its file entries with `-EAGAIN` instead of running them.
    pub handoff_kick:  Option<fn()>,
    /// [`OP_BUF_REGISTER`]: resolve the `Cap<Shm>` handle `shm_cap` in
    /// `owner_tid`'s table (`READ | WRITE | MAP`) as a map does and record a
    /// refusal as it does; require that the owner maps the object, that it is
    /// an anonymous or contiguous read-write object the kernel can reach, not
    /// purged, with no frame a clone shares, and that `[offset, offset + len)`
    /// lies in one physically contiguous run of it; then pin the object (a
    /// kernel reference, not a `MemObj` slot) and answer its packed reference
    /// and the kernel address of byte `offset`. `Err` is the entry's refusal.
    pub buf_pin:       fn(owner_tid: u32, shm_cap: u32, offset: u32, len: u32) -> Result<PinnedBuf, i32>,
    /// Give back the pin [`IoRingOps::buf_pin`] took on `r`. Takes the object
    /// table's lock: never called with the ring table's lock held.
    pub buf_unpin:     fn(r: u32),
    /// May the kernel reach the registered buffer pinned on `r` for
    /// `owner_tid`'s entry right now? The pin outlives what it was granted
    /// for: the owner can release the object or MOVE it to another task, and
    /// the frames then belong to someone else, so every use asks that the
    /// owner still MAPS the object (a read would otherwise disclose the
    /// receiver's memory to the owner's socket) and the object is not purged.
    /// `sink`: the kernel WRITES through it (an entry that fills the buffer:
    /// [`OP_NET_RECV`], [`OP_FILE_READ`]), so the object must also still be
    /// read-write and no clone may share a frame of it (a write would show in
    /// the clone).
    pub buf_usable:    fn(owner_tid: u32, r: u32, sink: bool) -> bool,
}

/// What [`IoRingOps::buf_pin`] answers: the pinned object's packed reference
/// (non-zero) and the kernel (direct-map) address of the registered range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedBuf {
    pub r: u32,
    pub kva: usize,
}

/// What [`IoRingOps::block_start`] answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStart {
    /// Queued; the token [`IoRingOps::block_poll`] and
    /// [`IoRingOps::block_orphan`] take.
    Queued(u32),
    /// Refused before anything was queued: the negative errno the entry
    /// completes with, [`CQE_F_REFUSED`].
    Refused(i32),
    /// The request layer cannot take it now.
    Unqueueable,
    /// A read of sectors a write-back cache still holds: the worker's.
    Dirty,
}

/// What [`IoRingOps::file_fsync`] answers: a flush ticket, or a refusal.
pub type OpResult64 = Result<u64, i32>;

/// Global dispatch table, `None` until [`io_ring_register_ops`] runs.
///
/// Written by `io_ring_register_ops` once at boot, before any task runs (and
/// by host tests under the crate-wide serial lock); every later access copies
/// the pointer-sized `Option<&'static _>` out, so no read races a write.
static mut OPS: Option<&'static IoRingOps> = None;

/// Register the IO ring dispatch table. The kernel calls it once at boot,
/// before any task runs; until then [`io_ring_submit`] returns
/// [`IO_ERR_NO_OPS`].
pub fn io_ring_register_ops(ops: &'static IoRingOps) {
    // SAFETY: boot-time registration, before any task runs; no reader exists yet.
    unsafe { OPS = Some(ops); }
}

/// Process all pending SQ entries for a ring. Returns number of completions,
/// or a negative error code: [`IO_ERR_INVALID_PARAM`] for an out-of-range
/// ring id, then [`IO_ERR_NO_OPS`] for every in-range id, active or not, while
/// no table is registered (see [`io_ring_register_ops`]). Only with a table
/// registered does an inactive ring get [`IO_ERR_INVALID_PARAM`], and a ring
/// whose CQ is full with an entry pending [`IO_ERR_CQ_FULL`].
///
/// This runs inline in the submitting syscall (`SYS_RING_ENTER`) — no separate kernel thread.
/// Processes all entries from sq_head to sq_tail in batch.
pub fn io_ring_submit(ring_id: u32) -> i32 {
    if ring_id as usize >= MAX_IO_RINGS {
        return IO_ERR_INVALID_PARAM;
    }

    // SAFETY: a copy-out read of `OPS`, which is not written while tasks run.
    let ops = unsafe { match OPS {
        Some(o) => o,
        None => return IO_ERR_NO_OPS,
    }};

    // Take an exclusive in-flight claim, then drop the table lock before
    // dispatching: `dispatch_sqe` calls into drivers and must not run with
    // interrupts disabled. `release_ring` below closes the claim.
    let (phys, owner_tid, owner_privileged) = match claim_ring(ring_id) {
        Some(v) => v,
        None => return IO_ERR_INVALID_PARAM,
    };
    submit_claimed(ring_id, None, phys, owner_tid, owner_privileged, ops)
}

/// [`io_ring_submit`] through a packed reference; the generation is compared
/// inside the lock the claim takes. `CqFull` when the pass executed nothing
/// because the completion queue had no room.
///
/// With no op table registered nothing executes and no claim is taken, so the
/// compare takes the table lock once on its own: a stale reference answers
/// `Stale` and a live one `SubmitError(IO_ERR_NO_OPS)`. That one extra hold on
/// a path that executes nothing is accepted (owner decision 2026-09-14,
/// Q4): answering `IO_ERR_NO_OPS` for any capability would let
/// a stale one read as live.
///
/// # `caller_tid` (2026-09-23)
///
/// Every device-capability check inside a submit pass is resolved on the
/// ring's **owner** — `state.owner_task`, stamped once by [`create_core`] and
/// never touched again ([`ring_dev_ok`], `dispatch_sqe`'s I2C/GPIO/PWM/motor
/// arms). That was sound under decision 3 ("a capability may never be handed
/// to another task"): the only task that could ever present a live
/// `Cap<IoRing>` for this ring **was** its owner, so "the owner's table" and
/// "the caller's table" were the same table by construction.
///
/// Decision 38 amended that: a
/// capability MOVE can hand a live `Cap<IoRing>` to a task that never created
/// the ring and holds no device capability of its own. `cap_store::move_cap`
/// is kind-erased — nothing about it is specific to `Cap<Socket>`, the kind
/// the gap-2 ring-3 exercise happened to use — and `SYS_IPC_FAST_CALL_EP`
/// (582) is the one live syscall that reaches it. Without this check, a task
/// that received a moved `Cap<IoRing>` this way could submit I2C, GPIO, PWM
/// or motor operations that `ring_dev_ok` would authorize against the
/// **original owner's** table: a confused deputy that runs hardware
/// operations under a different task's authority than the one that actually
/// called this syscall, entirely without that task presenting any device
/// capability of its own.
///
/// `caller_tid` is the task that resolved `r` through its own capability
/// table (`sys_ioring_submit_typed` already computes it) — the only party a
/// syscall can honestly attribute the call to. Refusing before
/// [`submit_claimed`] runs preserves the kernel-context batch path
/// ([`io_ring_submit`], which has no ring-3 caller and is why `ring_dev_ok`
/// is keyed on the owner in the first place, not on `current_task_tid()`: see
/// its doc) — this only closes the one entry point where a real caller
/// exists and can be compared against the owner it will be authorized as.
pub fn io_ring_submit_ref(caller_tid: u32, r: u32) -> Result<u32, IoRingCapError> {
    // SAFETY: a copy-out read of `OPS`, which is not written while tasks run.
    let registered = unsafe { OPS };
    let Some(ops) = registered else {
        let rings = IO_RINGS.lock_irqsave();
        live_index(&rings, r)?;
        return Err(IoRingCapError::SubmitError(IO_ERR_NO_OPS));
    };
    // A ring an SQ poller runs is not claimed here: the poller holds the
    // claim whenever it is mid-pass, and taking it inline would race that
    // pass. The submit is the wake-up ring 3 sends when the poller has
    // parked (`SQ_F_NEED_WAKEUP`), and answers 0 completions.
    let (ring_id, (phys, owner_tid, owner_privileged)) = match claim_ring_ref(r)? {
        RefClaim::Claimed(i, c) => (i, c),
        RefClaim::Polled { poller, owner } => {
            if owner != caller_tid as usize {
                return Err(IoRingCapError::Cap(crate::cap::CapError::MissingPerms));
            }
            sqpoll_wake(poller);
            return Ok(0);
        }
    };
    if caller_tid != owner_tid {
        // Release the in-flight claim before refusing: `claim_ring_ref`
        // already marked it, and every other exit from this function either
        // runs `submit_claimed` (which releases) or returns before claiming.
        release_ring(ring_id);
        // `MissingPerms`, not a new variant: "the right object, insufficient
        // rights" is exactly this shape (`cap.rs`'s `CapError::code` doc) —
        // the caller holds a real, live capability to a real ring, and what
        // it lacks is the authority the ring's device checks are keyed on.
        // Reusing it means this refusal is recorded through the same
        // `note_typed_denial(ty::IORING, ...)` choke point every other
        // IoRing denial already goes through, with no new match arm needed
        // at the call site.
        return Err(IoRingCapError::Cap(crate::cap::CapError::MissingPerms));
    }
    let n = submit_claimed(ring_id, Some(r), phys, owner_tid, owner_privileged, ops);
    if n >= 0 {
        Ok(n as u32)
    } else if n == IO_ERR_CQ_FULL {
        Err(IoRingCapError::CqFull)
    } else {
        Err(IoRingCapError::SubmitError(n))
    }
}

/// One submit pass over a ring claimed by [`claim_ring`] or `claim_ring_ref`,
/// ending with [`release_ring_with`]. Returns the number of completions, or
/// [`IO_ERR_CQ_FULL`] when an entry was pending and none could run.
///
/// `r` is the ring's packed reference, which an [`OP_SQPOLL_START`] hands to
/// the poller it spawns; `None` on the untyped kernel path, which cannot start
/// one.
fn submit_claimed(
    ring_id: u32,
    r: Option<u32>,
    phys: usize,
    owner_tid: u32,
    owner_privileged: bool,
    ops: &IoRingOps,
) -> i32 {
    // SAFETY: the claim was taken by the caller and is released just below.
    let may_block = (ops.may_block)();
    let out = unsafe { run_pass(ring_id, r, phys, owner_tid, owner_privileged, ops, false, may_block, None) };
    release_ring_with(ring_id, out.started, out.n > 0);
    if out.handoff || out.blocks {
        kick_worker(ops);
    }
    out.n
}

/// What a pass did, for its caller.
struct PassOut {
    /// Completions written, or [`IO_ERR_CQ_FULL`].
    n: i32,
    /// `(poller TID, idle ms)` when this pass started an SQ poller.
    started: Option<(u32, u32)>,
    /// Earliest deadline of a parked timer, `u64::MAX` for none.
    next_deadline_ns: u64,
    /// Is a notify wait parked (which only a later look can complete)?
    words: bool,
    /// The pass stopped at a file entry it may not run: kick the worker.
    handoff: bool,
    /// The pass queued a block request ([`ParkedOn::Block`]): kick the worker,
    /// which starts it and posts its completion.
    blocks: bool,
}

/// The body of a pass over a claimed ring. Does not release the claim.
///
/// # Safety
/// The caller holds slot `ring_id`'s in-flight claim and `phys` is its page.
/// The one read of SQ entry `idx` a pass makes (OVSwrap review F4): a volatile
/// copy of the 32-byte entry out of the ring page, which ring 3 maps RW and may
/// rewrite during the pass. Everything after works on this copy — the opcode,
/// the handle, the offsets `window_ok` bounds, the selectors `narrow_u8!`
/// checks — so the value checked is the value used.
///
/// `#[inline(never)]` and volatile on purpose. A plain `(*ring).sq_entries[i]`
/// copy is an ordinary load the compiler may split, sink or re-materialise
/// next to each use, which would be a re-read of ring memory after the check;
/// the code argued against that from how the copy escapes, which is not a
/// guarantee. A volatile read is one access the compiler may not repeat, and a
/// function of its own makes "the entry is copied exactly once per entry" a
/// property the gate checks in the disassembly (`ioring_sqe_once_row`: this
/// symbol exists, loads its 32 bytes, and has exactly one call site).
///
/// # Safety
/// `ring` points to a live ring page and `idx < RING_SQ_SIZE`.
///
/// Read as four `u64` words, not as the struct: a volatile read of the struct
/// is one load (and one store) per field and per padding hole, ten of each,
/// measured at ~12 instructions per entry on the vsbench ring lanes; the four
/// words carry the same 32 bytes in four loads. `SqEntry` is `repr(C)`, 32
/// bytes, 8-aligned, every field an integer, so any 32 bytes are a valid one.
#[inline(never)]
unsafe fn sqe_snapshot(ring: *const IoRing, idx: usize) -> SqEntry {
    const _: () = assert!(core::mem::size_of::<SqEntry>() == 32 && core::mem::align_of::<SqEntry>() == 8);
    let words = core::ptr::read_volatile(
        core::ptr::addr_of!((*ring).sq_entries[idx]) as *const [u64; 4]);
    core::mem::transmute::<[u64; 4], SqEntry>(words)
}

/// One pass over ring `ring_id`'s SQ: run its pending entries (up to `upto`
/// for the worker's pass) and answer what it did.
///
/// # Safety
///
/// The caller holds `ring_id`'s in-flight claim and releases it after the
/// pass; `phys` is that slot's page, which the claim keeps allocated.
//
// Not `inline(always)`: tried, and it cut ~33 instructions from each submit
// but added ~20 to every entry of the loop (vsbench, both ISAs), so a batch of
// two or more paid more.
#[allow(clippy::too_many_arguments)]
unsafe fn run_pass(
    ring_id: u32,
    r: Option<u32>,
    phys: usize,
    owner_tid: u32,
    owner_privileged: bool,
    ops: &IoRingOps,
    via_poller: bool,
    may_block: bool,
    upto: Option<u32>,
) -> PassOut {
    let mut started: Option<(u32, u32)> = None;
    let mut handoff = false;
    let mut blocks = false;
    // Only the io_ring worker's pass is bounded by `upto`: it is the pass the
    // others hand off to, so it runs every entry itself.
    let worker = upto.is_some();
    // SAFETY: the in-flight claim keeps `io_ring_destroy` from freeing the
    // page for the duration of this block.
    let completions = {
        // `phys` is PHYSICAL; the kernel writes the ring through its own
        // view of that page — identity on riscv64, upper half on aarch64.
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        if via_poller {
            // The poller is awake and polling: ring 3 need not wake it.
            (*ring).sq_flags.fetch_and(!SQ_F_NEED_WAKEUP, Ordering::SeqCst);
        }

        let mut head = (*ring).sq_head.load(Ordering::Acquire);
        let tail = (*ring).sq_tail.load(Ordering::Acquire);
        let mut completions: i32 = 0;

        // W2-C4: `sq_tail` lives on the page mapped into userspace and is not
        // validated on write — a producer bug (or hostile userspace) can set it
        // arbitrarily far from `sq_head`. `head != tail` alone is unbounded:
        // with wrapping u32 arithmetic this can take up to 2^32 iterations to
        // converge, hanging this hart (this runs inline in SYS_IO_SUBMIT) and
        // re-dispatching real actuator ops (motor/gpio/i2c) every iteration
        // until the watchdog resets the board. Bound the work done per call to
        // the ring's actual physical capacity — a well-behaved producer never
        // lets more than RING_SQ_SIZE entries be outstanding at once.
        let mut pending = tail.wrapping_sub(head).min(RING_SQ_SIZE as u32);
        if let Some(t) = upto {
            // The worker runs what the handing-off pass saw submitted, no more.
            pending = pending.min(t.wrapping_sub(head));
        }
        let mut cq_full = false;

        // SAFETY: this pass holds slot `ring_id`'s in-flight claim.
        let parked = parked_of(ring_id as usize);
        // SAFETY: the same claim.
        let bufs = regbufs_of(ring_id as usize);
        // Parked entries first: they were submitted before anything now in
        // the SQ, and each already holds its completion slot.
        if parked.n != 0 {
            completions += reap_parked(ring, parked, ops, owner_tid);
        }

        // The CQ slots new entries may use: those the parked entries hold are
        // not theirs. Kept in a local, and moved with every park below.
        let mut room = RING_CQ_SIZE as u32 - parked.n;
        // A parked linked entry is a barrier: nothing behind it runs yet.
        let pending = if parked.barrier { 0 } else { pending };
        // `SQE_F_LINK`: the previous entry was linked and did not succeed.
        let mut cancel = pending != 0 && core::mem::take(&mut parked.cancel_next);
        let mut flush_parked = false;
        for _ in 0..pending {
            // **Back-pressure: an entry runs only if its completion can be
            // recorded.** The CQ is written at `cq_tail % RING_CQ_SIZE`, and
            // nothing here used to read `cq_head`: a second submit before the
            // consumer drained overwrote completions it had not read, while the
            // actuator entries behind them still executed. So the pass stops
            // at a full CQ and `sq_head` stays on the first entry not run; the
            // next submit, after a drain, runs it. Nothing is buffered on the
            // kernel side. A `cq_head` ahead of `cq_tail` (a consumer bug, or a
            // hostile one on its own ring) wraps to a huge count and reads as
            // full: the pass fails closed. Every parked entry holds one slot,
            // so "full" is reached `parked.n` completions early.
            let cq_head = (*ring).cq_head.load(Ordering::Acquire);
            let cq_tail = (*ring).cq_tail.load(Ordering::Acquire);
            if cq_tail.wrapping_sub(cq_head) >= room {
                cq_full = true;
                break;
            }

            let sq_idx = (head as usize) % RING_SQ_SIZE;
            let sqe = sqe_snapshot(ring, sq_idx);
            // Owner rule: a pass that may not do this entry's work (an RT
            // task's; every task's file entry under Kconfig `IORING_ASYNC`)
            // hands the rest of the pass, from this entry on, to the worker.
            // A canceled entry runs nothing, so it never needs the worker.
            macro_rules! hand_off {
                () => {{
                    if ops.handoff_kick.is_some() {
                        HANDOFF_TAIL[ring_id as usize].store(tail, Ordering::SeqCst);
                        HANDOFF[ring_id as usize].store(true, Ordering::SeqCst);
                        handoff = true;
                        break;
                    }
                    // No worker: refused, never run inline.
                    push_cqe(ring, cq_tail, sqe.user_data, IO_ERR_WOULD_BLOCK, CQE_F_REFUSED);
                    completions += 1;
                    head = head.wrapping_add(1);
                    cancel = sqe.flags & SQE_F_LINK != 0;
                    continue;
                }};
            }
            if !cancel && needs_worker(ops, sqe.opcode, may_block, worker) {
                hand_off!();
            }
            let linked = sqe.flags & SQE_F_LINK != 0;
            if cancel {
                // Not run: the entry it is linked to failed. The chain goes
                // on while the canceled entries are linked too.
                push_cqe(ring, cq_tail, sqe.user_data, IO_ERR_CANCELED, CQE_F_REFUSED);
                completions += 1;
                head = head.wrapping_add(1);
                cancel = linked;
                continue;
            }

            let r_entry = match dispatch_entry(
                &sqe, &mut (*ring).data_buf, bufs, ops, owner_tid, owner_privileged,
                may_block, worker, parked.n < RING_MAX_PARKED as u32,
            ) {
                Step::Done(res) => res,
                // A block entry the request layer could not take, from a pass
                // that may not wait for the device.
                Step::Handoff => hand_off!(),
                // Rare paths, out of line so they do not weigh on the loop.
                Step::Durable(res) => {
                    push_cqe(ring, cq_tail, sqe.user_data, res, if res == 0 { CQE_F_DURABLE } else { 0 });
                    completions += 1;
                    head = head.wrapping_add(1);
                    cancel = linked && res != 0;
                    continue;
                }
                Step::Park(on) => {
                    if park_entry(parked, on, sqe.user_data, linked) {
                        if matches!(on, ParkedOn::Flush(_)) {
                            FLUSH_PARKED[ring_id as usize].store(true, Ordering::SeqCst);
                            flush_parked = true;
                        }
                        if matches!(on, ParkedOn::Block(..)) {
                            BLOCK_PARKED[ring_id as usize].store(true, Ordering::SeqCst);
                            blocks = true;
                        }
                        room -= 1;
                        head = head.wrapping_add(1);
                        if linked {
                            // The barrier: the rest waits for its completion.
                            break;
                        }
                        continue;
                    }
                    // Every parked slot is taken: refused, and completed now
                    // with the slot the check above guaranteed.
                    Err(IO_ERR_PARKED_FULL)
                }
                Step::StartSqpoll => {
                    let res = if via_poller || started.is_some() {
                        // Already polled: nothing to start.
                        Ok(0)
                    } else {
                        start_sqpoll(ring, r, owner_tid, owner_privileged).map(|p| {
                            started = Some(p);
                            0
                        })
                    };
                    if res.is_ok() {
                        // Once a poller runs the ring, the entries behind this
                        // one are the poller's to run.
                        push_cqe(ring, cq_tail, sqe.user_data, 0, 0);
                        completions += 1;
                        head = head.wrapping_add(1);
                        break;
                    }
                    res
                }
            };
            let (result, flags) = match r_entry {
                // A write or a send that succeeded is QUEUED, not durable.
                Ok(v) if v > 0 && (sqe.opcode == OP_FILE_WRITE || sqe.opcode == OP_NET_SEND) => {
                    (v, CQE_F_QUEUED)
                }
                Ok(v) => (v, 0),
                Err(errno) => (errno, CQE_F_REFUSED),
            };
            push_cqe(ring, cq_tail, sqe.user_data, result, flags);
            completions += 1;
            head = head.wrapping_add(1);
            if linked {
                cancel = result < 0 || flags & CQE_F_REFUSED != 0;
            }
        }

        if flush_parked {
            // A flush that ended between the entry's look and its hint above
            // found no hint to post by: look once more, after the hint.
            completions += reap_parked(ring, parked, ops, owner_tid);
        }

        // Advance SQ head
        (*ring).sq_head.store(head, Ordering::Release);
        if completions == 0 && cq_full { IO_ERR_CQ_FULL } else { completions }
    };

    // What is left parked, for a poller deciding how long it may sleep. A
    // submit has no use for it, and does not pay for the scan.
    // SAFETY: still under the claim.
    let parked = parked_of(ring_id as usize);
    let mut next_deadline_ns = u64::MAX;
    let mut words = false;
    if via_poller && parked.n != 0 {
        for p in parked.e.iter() {
            match p.on {
                ParkedOn::Timer(d) => next_deadline_ns = next_deadline_ns.min(d),
                ParkedOn::Word(..) => words = true,
                // Posted by the flush path (`io_ring_flush_posted`) and the
                // worker (`io_ring_worker_pass`).
                ParkedOn::Flush(_) | ParkedOn::Block(..) | ParkedOn::Free => {}
            }
        }
    }
    PassOut { n: completions, started, next_deadline_ns, words, handoff, blocks }
}

/// Park an entry in a free slot of `parked`; `false` when every slot is taken.
#[inline(never)]
fn park_entry(parked: &mut ParkedSet, on: ParkedOn, user_data: u64, link: bool) -> bool {
    match parked.e.iter_mut().find(|p| p.on == ParkedOn::Free) {
        Some(slot) => {
            *slot = Parked { on, user_data, link };
            parked.n += 1;
            parked.barrier |= link;
            true
        }
        None => false,
    }
}

/// A parking entry ([`OP_TIMER`], [`OP_NOTIFY_WAIT`]) refused because the ring
/// already holds [`RING_MAX_PARKED`] parked entries: `-EBUSY`, with
/// [`CQE_F_REFUSED`]. Drain a parked entry (let it complete) and resubmit.
pub const IO_ERR_PARKED_FULL: i32 = azos_abi::error::Errno::EBUSY.to_syscall_ret() as i32;

/// An entry not run because the [`SQE_F_LINK`] entry before it failed, was
/// refused, or (a parked barrier) completed with a failure: `-ECANCELED`, with
/// [`CQE_F_REFUSED`].
pub const IO_ERR_CANCELED: i32 = azos_abi::error::Errno::ECANCELED.to_syscall_ret() as i32;

/// A file or fsync entry from a task that may not block (a real-time task)
/// on a kernel with no io_ring worker to hand it to (Kconfig `IORING_WORKER`
/// off): `-EAGAIN`, with [`CQE_F_REFUSED`]. Never run inline.
pub const IO_ERR_WOULD_BLOCK: i32 = azos_abi::error::Errno::EAGAIN.to_syscall_ret() as i32;

/// Write one completion at `cq_tail` — the value the caller's room check just
/// read, which only this pass moves — and publish it.
///
/// # Safety
/// `ring` is the claimed ring's page, and the caller checked there is room.
unsafe fn push_cqe(ring: *mut IoRing, cq_tail: u32, user_data: u64, result: i32, flags: u32) {
    let cq_idx = (cq_tail as usize) % RING_CQ_SIZE;
    (*ring).cq_entries[cq_idx] = CqEntry { user_data, result, flags };
    (*ring).cq_tail.store(cq_tail.wrapping_add(1), Ordering::Release);
}

/// Complete every parked entry whose condition now holds; answers how many.
///
/// Each completes into the slot it reserved when it parked, so room is there
/// unless the consumer moved `cq_head` backwards on its own ring; then the
/// pass stops, as the SQ loop does, and the entries stay parked.
///
/// # Safety
/// `ring` is the claimed ring's page and `parked` its parked set.
#[inline(never)]
unsafe fn reap_parked(ring: *mut IoRing, parked: &mut ParkedSet, ops: &IoRingOps, owner_tid: u32) -> i32 {
    let mut done = 0;
    for p in parked.e.iter_mut() {
        if p.on == ParkedOn::Free {
            continue;
        }
        // Room first: a block entry's poll collects its request, so it may
        // only be asked when the completion can be written.
        let cq_head = (*ring).cq_head.load(Ordering::Acquire);
        let cq_tail = (*ring).cq_tail.load(Ordering::Acquire);
        if cq_tail.wrapping_sub(cq_head) >= RING_CQ_SIZE as u32 {
            break;
        }
        let r = match p.on {
            ParkedOn::Free => continue,
            ParkedOn::Timer(deadline) => {
                if !(ops.deadline_reached)(deadline) {
                    continue;
                }
                Ok(0)
            }
            ParkedOn::Word(cap, offset, expected) => match (ops.notify_word)(owner_tid, cap, offset) {
                Ok(v) if v == expected => continue,
                Ok(_) => Ok(0),
                Err(e) => Err(e),
            },
            ParkedOn::Flush(ticket) => match (ops.fsync_done)(ticket) {
                None => continue,
                Some(r) => Ok(r),
            },
            // The window was bounded when the entry parked; a read's bytes
            // land in it now, in the ring page this claim keeps alive.
            ParkedOn::Block(token, offset, len, _) => {
                let window = (*ring).data_buf.as_mut_ptr().add(offset as usize);
                match (ops.block_poll)(token, window, len as usize) {
                    None => continue,
                    Some(r) => Ok(r),
                }
            }
        };
        let (result, flags) = match r {
            Ok(0) if matches!(p.on, ParkedOn::Flush(_)) => (0, CQE_F_DURABLE),
            // A block write the device completed is on the device, not yet
            // durable: `OP_FSYNC` is the flush point.
            Ok(v) if v > 0 && matches!(p.on, ParkedOn::Block(_, _, _, true)) => (v, CQE_F_QUEUED),
            Ok(v) => (v, 0),
            Err(e) => (e, CQE_F_REFUSED),
        };
        push_cqe(ring, cq_tail, p.user_data, result, flags);
        if p.link {
            // The barrier is down; a failure cancels what it guarded.
            parked.barrier = false;
            parked.cancel_next = result < 0;
        }
        *p = Parked { on: ParkedOn::Free, user_data: 0, link: false };
        parked.n -= 1;
        done += 1;
    }
    done
}

/// What one SQ entry does in a pass: completes now, or parks.
enum Step {
    Done(OpResult),
    /// An [`OP_FSYNC`] whose flush was already done: completes now, durable.
    Durable(i32),
    Park(ParkedOn),
    /// A block entry this pass may not wait for the device on, and the request
    /// layer could not take (or, a read, [`BlockStart::Dirty`]): the worker
    /// runs it ([`io_ring_worker_pass`]).
    Handoff,
    /// [`OP_SQPOLL_START`], admitted by seccomp; the pass decides the rest.
    StartSqpoll,
}

/// Must the worker run entry `opcode`, not this pass? `may_block`: the pass is
/// a task that may wait for the device (not a real-time one). `worker`: this
/// pass is the worker's own, which runs everything.
///
/// A file entry goes to the worker under Kconfig `IORING_ASYNC` whoever
/// submits it ([`IoRingOps::file_inline`]: no file system work in a submit, the
/// file seam is synchronous so the worker is its queue), else only from a task
/// that may not block. An fsync only asks the flusher but still is file system
/// work: a real-time task leaves it to the worker. A block entry is queued by any
/// task when `IORING_ASYNC` is on (a copy and a queue slot), and decided entry
/// by entry ([`Step::Handoff`]) when the request layer cannot take it or, for a
/// read, the write-back cache must first write its range out
/// ([`BlockStart::Dirty`]); without `IORING_ASYNC` a task that may not block
/// leaves it to the worker.
#[inline(always)]
fn needs_worker(ops: &IoRingOps, opcode: u16, may_block: bool, worker: bool) -> bool {
    match opcode {
        OP_FILE_READ | OP_FILE_WRITE => !may_block || (!worker && !(ops.file_inline)()),
        OP_FSYNC => !may_block,
        OP_BLOCK_READ | OP_BLOCK_WRITE => !may_block && !azos_limits::IORING_ASYNC,
        _ => false,
    }
}

/// [`dispatch_sqe`], plus the two opcodes that may complete later.
///
/// `OP_TIMER` and `OP_NOTIFY_WAIT` ask the same seccomp question first, as
/// every other entry does; a wait resolves its capability on every look (in
/// [`IoRingOps::notify_word`]), a timer names no object. Whatever is decided
/// when an entry parks — the profile, the argument — is decided then, as a
/// blocking syscall decides at entry.
#[inline(always)]
fn dispatch_entry(
    sqe: &SqEntry,
    data_buf: &mut [u8; RING_DATA_BUF_SIZE],
    bufs: &mut RegBufSet,
    ops: &IoRingOps,
    owner_tid: u32,
    owner_priv: bool,
    may_block: bool,
    worker: bool,
    parked_free: bool,
) -> Step {
    // A registered buffer is named only by the data-moving opcodes: on any other
    // `reg` means something else or nothing, and the entry is refused unread.
    if sqe.flags & SQE_F_FIXED != 0 && !takes_fixed(sqe.opcode) {
        return Step::Done(Err(IO_ERR_INVALID_PARAM));
    }
    // Every opcode below `OP_TIMER` completes now: one compare, not a chain,
    // on the path every ring entry takes.
    if sqe.opcode < OP_TIMER {
        return Step::Done(dispatch_sqe(sqe, data_buf, bufs, ops, owner_tid, owner_priv));
    }
    match sqe.opcode {
        OP_TIMER => {
            if let Err(e) = admit(ops, owner_tid, OpGate::Syscall(azos_abi::syscall_nr::SYS_SLEEP_UNTIL)) {
                return Step::Done(Err(e));
            }
            let deadline = sqe.param0 as u64 | (sqe.param1 as u64) << 32;
            if (ops.deadline_reached)(deadline) {
                Step::Done(Ok(1))
            } else {
                Step::Park(ParkedOn::Timer(deadline))
            }
        }
        OP_NOTIFY_WAIT => {
            if let Err(e) = admit(ops, owner_tid, OpGate::Syscall(azos_abi::syscall_nr::SYS_FUTEX_WAIT)) {
                return Step::Done(Err(e));
            }
            match (ops.notify_word)(owner_tid, sqe.param0, sqe.param1) {
                Err(e) => Step::Done(Err(e)),
                Ok(v) if v != sqe.param2 => Step::Done(Ok(1)),
                Ok(_) => Step::Park(ParkedOn::Word(sqe.param0, sqe.param1, sqe.param2)),
            }
        }
        OP_SQPOLL_START => {
            if let Err(e) = admit(ops, owner_tid, OpGate::Syscall(azos_abi::syscall_nr::SYS_RING_ENTER)) {
                return Step::Done(Err(e));
            }
            Step::StartSqpoll
        }
        OP_BLOCK_READ | OP_BLOCK_WRITE => dispatch_block(sqe, data_buf, ops, owner_tid, owner_priv, may_block, worker, parked_free),
        OP_FSYNC => {
            if let Err(e) = admit(ops, owner_tid, OpGate::Op(azos_abi::invoke::NODE_FSYNC)) {
                return Step::Done(Err(e));
            }
            let ticket = match (ops.file_fsync)(owner_tid, sqe.param0) {
                Ok(t) => t,
                Err(e) => return Step::Done(Err(e)),
            };
            // The canary restores the synchronous answer: the entry completes
            // in the submit, durable or not.
            if cfg!(feature = "ioring-sync-fsync-canary") {
                return Step::Durable(0);
            }
            match (ops.fsync_done)(ticket) {
                Some(r) => Step::Durable(r),
                None => Step::Park(ParkedOn::Flush(ticket)),
            }
        }
        _ => Step::Done(dispatch_sqe(sqe, data_buf, bufs, ops, owner_tid, owner_priv)),
    }
}

/// Does opcode `op` take [`SQE_F_FIXED`]: the ones that move bytes between a
/// kernel object and a window of ring 3 memory, and whose `reg` is free.
#[inline(always)]
const fn takes_fixed(op: u16) -> bool {
    matches!(op, OP_NET_SEND | OP_NET_RECV | OP_FILE_READ | OP_FILE_WRITE)
}

/// Permission denied for a ring op whose owner lacks the capability:
/// `-ECAPPERMS`, what a typed call answers for a capability without the
/// permission it needs.
///
/// A completion carrying it also carries [`CQE_F_REFUSED`]. The flag, not the
/// value, is what tells a refusal from a driver's own negative return: this
/// was `-4`, which a reader could not tell apart from a driver that returned
/// `-4`.
pub const IO_ERR_PERM: i32 = azos_abi::error::Errno::ECAPPERMS.to_syscall_ret() as i32;

/// The syscall number an opcode stands for, whose seccomp verdict decides
/// whether the entry may run; `None` for an opcode this kernel does not
/// execute (`OP_NOP` is answered before the question is asked).
///
/// Each is the interface or the typed call whose function the kernel's
/// op-table entry calls: the `sensor`, `gpio`, `i2c`, `pwm` and `motor`
/// interfaces (the motor speed asked once for the pair) and the socket send
/// and receive (569, 570).
pub const fn opcode_gate(opcode: u16) -> Option<OpGate> {
    use azos_abi::invoke as inv;
    use azos_abi::syscall_nr as nr;
    use azos_devif::key;
    match opcode {
        OP_READ_SENSOR => Some(OpGate::Iface(key::SENSOR)),
        OP_WRITE_GPIO | OP_READ_GPIO => Some(OpGate::Iface(key::GPIO)),
        OP_I2C_READ | OP_I2C_WRITE => Some(OpGate::Iface(key::I2C)),
        OP_PWM_SET => Some(OpGate::Iface(key::PWM)),
        OP_MOTOR_SPEED => Some(OpGate::Iface(key::MOTOR)),
        OP_NET_SEND => Some(OpGate::Op(inv::NODE_SEND)),
        OP_NET_RECV => Some(OpGate::Op(inv::NODE_RECV)),
        // A pinned reference to an object the task holds: the op `MEMOBJ_ACQUIRE`.
        OP_BUF_REGISTER | OP_BUF_UNREGISTER => Some(OpGate::Op(inv::MEMOBJ_ACQUIRE)),
        OP_FILE_READ => Some(OpGate::Op(inv::NODE_READ)),
        OP_FILE_WRITE => Some(OpGate::Op(inv::NODE_WRITE)),
        OP_TIMER => Some(OpGate::Syscall(nr::SYS_SLEEP_UNTIL)),
        OP_SQPOLL_START => Some(OpGate::Syscall(nr::SYS_RING_ENTER)),
        OP_FSYNC => Some(OpGate::Op(inv::NODE_FSYNC)),
        OP_BLOCK_READ | OP_BLOCK_WRITE => Some(OpGate::Iface(key::BLOCK)),
        OP_NOTIFY_WAIT => Some(OpGate::Syscall(nr::SYS_FUTEX_WAIT)),
        _ => None,
    }
}

/// What the submitter's seccomp profile is asked about an opcode: the typed
/// syscall it stands for, or the kernel-hosted interface (host key) whose op
/// it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpGate {
    /// The syscall number the opcode stands for.
    Syscall(u64),
    /// The host key of the interface the opcode drives.
    Iface(u16),
    /// The `invoke` op the opcode stands for: the owner's profile must list
    /// its class on its kind.
    Op(u16),
}

impl OpGate {
    /// The call this gate stands for as the pledge mask judges it: the syscall
    /// number and its bit of the mask (`azos_abi::invoke::pledge_bit`). An op of
    /// a handle is a `SYS_INVOKE` judged by its class; an interface op is an
    /// IPC call (the audit record of [`IoRingOps::iface_allowed`] says the same),
    /// judged by its case; a syscall by its case.
    pub const fn pledge(self) -> (u64, u8) {
        use azos_abi::invoke::pledge_bit;
        use azos_abi::syscall_nr::{SYS_INVOKE, SYS_IPC_CALL_V2};
        match self {
            OpGate::Syscall(nr) => (nr, pledge_bit(nr, 0, false)),
            OpGate::Iface(_) => (SYS_IPC_CALL_V2, pledge_bit(SYS_IPC_CALL_V2, 0, false)),
            OpGate::Op(op) => (SYS_INVOKE, pledge_bit(SYS_INVOKE, op as u64, false)),
        }
    }
}

/// Both filters of what a task may call, asked of one entry: the owner's
/// seccomp profile ([`IO_ERR_SECCOMP`]), then its Domain's pledge mask
/// ([`IO_ERR_PLEDGE`]). The refusal answers before anything else of the entry
/// is read.
fn admit(ops: &IoRingOps, owner_tid: u32, gate: OpGate) -> Result<(), i32> {
    let allowed = match gate {
        OpGate::Syscall(nr) => (ops.syscall_allowed)(owner_tid, nr),
        OpGate::Iface(key) => (ops.iface_allowed)(owner_tid, key),
        OpGate::Op(op) => (ops.op_allowed)(owner_tid, op),
    };
    if !allowed {
        return Err(IO_ERR_SECCOMP);
    }
    let (nr, bit) = gate.pledge();
    if !(ops.pledge_allowed)(owner_tid, nr, bit) {
        return Err(IO_ERR_PLEDGE);
    }
    Ok(())
}

/// Does the ring's owner hold an endpoint of the kernel-hosted interface `key`
/// carrying `badge` with the op class the entry needs? The badge is the
/// resource (a pin, a bus and an address, a channel, a sensor type), the rights
/// the op class: `READ` for a read (a WRITE-only grant must not read through the
/// ring), `WRITE` for an act. No containment step here (a write is refused after
/// the capability, so a task that does not hold the device learns nothing from
/// the degrade level).
fn ring_dev_ok(owner_tid: u32, owner_privileged: bool, key: u16, badge: u32, need_write: bool) -> bool {
    if owner_privileged {
        return true;
    }
    let need = if need_write { CapPerms::WRITE } else { CapPerms::READ };
    crate::cap_store::with_table(owner_tid, |t| {
        crate::endpoint::table_holds_host_badge_right_uncontained(t, key, badge, need)
    })
    .unwrap_or(false)
}

/// Bounds a `data_buf` window. `checked_add` rather than `offset + len`:
/// the kernel builds with `overflow-checks = true` and `panic = "abort"`,
/// so on a 32-bit target a wrapping sum here would be a board reset driven
/// from ring 3. On RV64 the sum cannot overflow, but the check is free and
/// the property should not depend on the pointer width.
#[inline(always)]
const fn window_ok(offset: usize, len: usize) -> bool {
    matches!(offset.checked_add(len), Some(end) if end <= RING_DATA_BUF_SIZE)
}

/// The start of a window [`window_ok`] passed, masked against Spectre v1
/// (`azos_limits::nospec`): `offset` is ring 3's word, and `offset == size`
/// is a legal empty window, so the mask's bound is one past the buffer.
#[inline(always)]
fn window_start(offset: usize) -> usize {
    azos_limits::nospec::array_index_nospec(offset, RING_DATA_BUF_SIZE + 1)
}

/// The registered-buffer slot an SQE's `reg` names, masked against Spectre v1
/// (`reg` is ring 3's word).
#[inline(always)]
fn reg_slot(reg: u16) -> Result<usize, i32> {
    let slot = reg as usize;
    if slot >= RING_MAX_REGBUFS {
        return Err(IO_ERR_INVALID_PARAM);
    }
    Ok(azos_limits::nospec::array_index_nospec(slot, RING_MAX_REGBUFS))
}

/// A use of a registered buffer the kernel may no longer make (the owner no
/// longer maps the object, or a clone shares a frame a write would reach):
/// `-EBUSY`.
pub const IO_ERR_BUF_GONE: i32 = azos_abi::error::Errno::EBUSY.to_syscall_ret() as i32;

/// The memory an entry's `param1`/`param2` name, as a kernel pointer to the
/// first byte and bounded to `param2` bytes: a window of `data_buf`, or, with
/// [`SQE_F_FIXED`], a range of the registered buffer in slot `reg`. The entry
/// never sees an unbounded pointer: the offset and length are checked here,
/// once, with `checked_add`, and the offset is masked against Spectre v1.
/// `sink`: the kernel writes into it. A registered buffer must still be one the
/// kernel may reach for `owner_tid` ([`IoRingOps::buf_usable`]).
///
/// A registered buffer costs one slot read and the sink test: no user range is
/// validated, no page of ring 3 walked and no bytes bounced, which is what the
/// registration paid for once.
#[inline(always)]
fn sqe_window(
    owner_tid: u32,
    sqe: &SqEntry,
    data_buf: &mut [u8; RING_DATA_BUF_SIZE],
    bufs: &RegBufSet,
    ops: &IoRingOps,
    sink: bool,
) -> Result<*mut u8, i32> {
    let offset = sqe.param1 as usize;
    let len = sqe.param2 as usize;
    if sqe.flags & SQE_F_FIXED == 0 {
        if !window_ok(offset, len) {
            return Err(IO_ERR_INVALID_PARAM);
        }
        return Ok(data_buf[window_start(offset)..].as_mut_ptr());
    }
    fixed_window(owner_tid, sqe.reg, offset, len, bufs, ops, sink)
}

/// [`sqe_window`] for a registered buffer.
#[inline(never)]
fn fixed_window(owner_tid: u32, reg: u16, offset: usize, len: usize, bufs: &RegBufSet, ops: &IoRingOps, sink: bool) -> Result<*mut u8, i32> {
    let b = bufs.e[reg_slot(reg)?];
    if b.r == 0 {
        return Err(IO_ERR_INVALID_PARAM);
    }
    match offset.checked_add(len) {
        Some(end) if end <= b.len as usize => {}
        _ => return Err(IO_ERR_INVALID_PARAM),
    }
    if !(ops.buf_usable)(owner_tid, b.r, sink) {
        return Err(IO_ERR_BUF_GONE);
    }
    // `offset == len` of the buffer is a legal empty window: the mask's bound
    // is one past the buffer.
    let at = azos_limits::nospec::array_index_nospec(offset, b.len as usize + 1);
    Ok((b.kva + at) as *mut u8)
}

/// `OP_BLOCK_READ` / `OP_BLOCK_WRITE`: the checks of every device entry, in the
/// order of [`dispatch_sqe`] (seccomp and pledge, the capability, containment
/// for a write, the window), then the run.
///
/// A partition is named by the `block` endpoint's badge, as a pin or a wheel
/// is. The capability and containment come first; then the run must be whole
/// sectors inside the data window. The first sector is the entry's `addr` (low
/// half) and `reg` (high half), relative to the partition: the op-table entry
/// adds the partition's start and refuses a run past its end.
///
/// The run is then QUEUED ([`IoRingOps::block_start`], Kconfig `IORING_ASYNC`)
/// and the entry PARKS: no device work and no sleep in this pass, the worker
/// starts the request and posts the completion. Only an entry the request
/// layer cannot take (and a ring with no free parked slot) takes the
/// synchronous [`IoRingOps::block_io`], in a pass that may wait for the device,
/// else [`Step::Handoff`] to one. A hand-off decided here asks the seccomp
/// question a second time in the worker, so an audited profile records it
/// twice; it is the rare path.
fn dispatch_block(
    sqe: &SqEntry,
    data_buf: &mut [u8; RING_DATA_BUF_SIZE],
    ops: &IoRingOps,
    owner_tid: u32,
    owner_priv: bool,
    may_block: bool,
    worker: bool,
    parked_free: bool,
) -> Step {
    let write = sqe.opcode == OP_BLOCK_WRITE;
    if let Err(e) = admit(ops, owner_tid, OpGate::Iface(azos_devif::key::BLOCK)) {
        return Step::Done(Err(e));
    }
    let badge = sqe.param0;
    if !ring_dev_ok(owner_tid, owner_priv, azos_devif::key::BLOCK, badge, write) {
        (ops.note_denial)(owner_tid, ty::ENDPOINT);
        return Step::Done(Err(IO_ERR_PERM));
    }
    if write && !owner_priv && (ops.write_contained)() {
        return Step::Done(Err(IO_ERR_CONTAINED));
    }
    let offset = sqe.param1 as usize;
    let len = sqe.param2 as usize;
    if len == 0 || len % azos_devif::block::SECTOR_BYTES != 0 || !window_ok(offset, len) {
        return Step::Done(Err(IO_ERR_INVALID_PARAM));
    }
    let sector = sqe.addr as u64 | ((sqe.reg as u64) << 16);
    let ptr = data_buf[window_start(offset)..].as_mut_ptr();
    if azos_limits::IORING_ASYNC && parked_free {
        match (ops.block_start)(owner_tid, badge, write, sector, ptr, len) {
            // The window is at most the data buffer, which a `u16` holds.
            BlockStart::Queued(token) => return Step::Park(ParkedOn::Block(token, offset as u16, len as u16, write)),
            BlockStart::Refused(e) => return Step::Done(Err(e)),
            BlockStart::Unqueueable => {}
            // The write-back it needs waits for the device: not in a submit.
            BlockStart::Dirty if !worker => return Step::Handoff,
            BlockStart::Dirty => {}
        }
    }
    if !may_block {
        return Step::Handoff;
    }
    Step::Done((ops.block_io)(badge, write, sector, ptr, len))
}

/// Dispatch a single SQ entry to the appropriate hardware operation.
///
/// **WHY every actuator arm is capability-checked (W3-F3):** this function
/// used to execute `OP_MOTOR_SPEED`, `OP_WRITE_GPIO`, `OP_PWM_SET` and
/// `OP_I2C_WRITE` with no `cap_check` whatsoever. It was inert only because
/// `io_ring_register_ops` has no callers, so `OPS` is `None` — the day a
/// board registers the dispatch table, an io_ring becomes a complete bypass
/// of the capability system that every equivalent syscall
/// (`sys_motor_set_target`, `sys_gpio_write`, …) does enforce. The checks
/// mirror those syscalls' `cap_check` calls exactly, kind for kind.
///
/// **What this batch changed.** Every opcode is now checked against the same
/// authority its syscall counterpart uses, and no opcode is denied for want
/// of a check that could not be expressed:
///
///  * **I2C** — was a blanket deny for unprivileged rings, because the ABI
///    fused address and register (and the buffer offset) into `param1`.
///    Splitting them (see [`SqEntry`]) makes the I2C capability `(bus, addr)`
///    reconstructible, so the check is the I2C read call's.
///  * **Sockets** — were a blanket deny, then an owner-stamp lookup on a bare
///    descriptor. Both net opcodes now name a `Cap<Socket>` handle in the
///    owner's table, which the op-table entry resolves as the typed call does.
///  * **Narrowed parameters** — `Sensor`, `Pwm` and the I2C bus/address are
///    `u8` in the capability resource but arrive as `u32`/`u16`. They are rejected out
///    of range rather than truncated; see `narrow_u8!` below for why that was
///    a live bypass and not a tidiness issue.
///
/// **The order of the checks.** An opcode this kernel does not
/// execute is refused first; then the submitter's seccomp profile for the
/// syscall the opcode stands for; then the capability, with the narrowing of
/// its parameters; then containment, for a write; then the op-table entry,
/// which calls what the typed call calls. A refusal at any step completes the
/// entry with a negative errno and [`CQE_F_REFUSED`].
fn dispatch_sqe(
    sqe: &SqEntry,
    data_buf: &mut [u8; RING_DATA_BUF_SIZE],
    bufs: &mut RegBufSet,
    ops: &IoRingOps,
    owner_tid: u32,
    owner_priv: bool,
) -> OpResult {
    let p0 = sqe.param0;
    let p1 = sqe.param1;
    let p2 = sqe.param2;

    let gate = match sqe.opcode {
        OP_NOP => return Ok(IO_OK),
        op => match opcode_gate(op) {
            Some(g) => g,
            None => return Err(IO_ERR_INVALID_OP),
        },
    };
    // Seccomp per operation, before anything about the entry is read further:
    // a profile that does not list the typed call (or the interface) refuses
    // its ring twin the same way, capability or not.
    // The Domain's pledge mask next, for the same call: a Domain that gave up
    // the net class does not send through its ring either.
    admit(ops, owner_tid, gate)?;

    // Local shorthand so each arm reads like its call counterpart: the
    // owner's table must hold an endpoint of interface `$key` carrying `$badge`, with the
    // op class the entry needs. A refusal is recorded under the endpoint.
    macro_rules! need_dev {
        ($key:expr, $badge:expr, $write:expr) => {
            if !ring_dev_ok(owner_tid, owner_priv, $key, $badge, $write) {
                (ops.note_denial)(owner_tid, ty::ENDPOINT);
                return Err(IO_ERR_PERM);
            }
        };
    }

    // Containment for a write, after the capability: a task that
    // does not hold the device still gets `-ECAPPERMS` and learns nothing from
    // the degrade level, as `CapTable::get` orders its checks. A kernel-created
    // ring is not contained, as a kernel caller of the untyped writes is not
    // (`untyped_write_contained`). The motor opcode does not use this: its
    // typed call resolves without containment and the halt rule refuses in
    // the motor layer, which the op-table entry reaches.
    macro_rules! not_contained {
        () => {
            if !owner_priv && (ops.write_contained)() {
                return Err(IO_ERR_CONTAINED);
            }
        };
    }

    // **WHY every narrowed parameter is range-checked first (found in
    // passing, same class as W3-F3).** The capability resources store sensor
    // type, PWM channel and I2C bus/address as `u8`, while the ring ABI delivers them
    // as `u32`/`u16`. The pre-existing arms wrote `HandleKind::Sensor(p0 as
    // u8)` and then handed the *un-narrowed* `p0` to the driver, so
    // `p0 = 256` passed the capability check for `Sensor(0)` and drove
    // sensor 256. That is a live capability bypass by aliasing: a task
    // granted one device can reach every 256th device above it. Rejecting
    // out-of-range values — rather than truncating — is what makes the value
    // checked and the value used the same value.
    macro_rules! narrow_u8 {
        ($v:expr) => {{
            let v = $v;
            if v > u8::MAX as u32 { return Err(IO_ERR_INVALID_PARAM); }
            v as u8
        }};
    }

    match sqe.opcode {
        OP_READ_SENSOR => {
            need_dev!(azos_devif::key::SENSOR, narrow_u8!(p0) as u32, false);
            let offset = p1 as usize;
            let len = p2 as usize;
            if !window_ok(offset, len) {
                return Err(IO_ERR_INVALID_PARAM);
            }
            let buf_ptr = data_buf[window_start(offset)..].as_mut_ptr();
            (ops.read_sensor)(p0, buf_ptr, len)
        }

        OP_WRITE_GPIO => {
            need_dev!(azos_devif::key::GPIO, p0, true);
            not_contained!();
            (ops.write_gpio)(p0, p1)
        }

        OP_READ_GPIO => {
            need_dev!(azos_devif::key::GPIO, p0, false);
            (ops.read_gpio)(p0)
        }

        // I2C now carries bus in `param0` and the device address in its own
        // `addr` field, so the check below names the same (bus, addr) a
        // the `i2c` endpoint names, READ for a read. Before the split, addr and reg shared
        // `param1` with the `data_buf` offset and the handle could not be
        // rebuilt, so both opcodes were denied to every unprivileged ring —
        // a whole class of legitimate work the capability system was
        // supposed to permit.
        OP_I2C_READ => {
            let bus  = narrow_u8!(p0);
            let addr = narrow_u8!(sqe.addr as u32);
            // `reg` is not part of the capability, but it is narrowed to u8
            // by the driver: a silently truncated register writes/reads the
            // wrong register on a live actuator bus. Reject instead.
            let reg  = narrow_u8!(sqe.reg as u32);
            need_dev!(azos_devif::key::I2C, azos_devif::i2c::badge(bus, addr), false);
            let offset = p1 as usize;
            let len = p2 as usize;
            if !window_ok(offset, len) {
                return Err(IO_ERR_INVALID_PARAM);
            }
            let buf_ptr = data_buf[window_start(offset)..].as_mut_ptr();
            (ops.i2c_read)(bus as u32, addr as u32, reg as u32, buf_ptr, len)
        }

        // Write is the actuator direction — this is how the PWM/motor
        // expanders are driven — so it demands `write` on the same handle,
        // matching `sys_i2c_write`'s `cap_check(…, true)`.
        OP_I2C_WRITE => {
            let bus  = narrow_u8!(p0);
            let addr = narrow_u8!(sqe.addr as u32);
            need_dev!(azos_devif::key::I2C, azos_devif::i2c::badge(bus, addr), true);
            not_contained!();
            let offset = p1 as usize;
            let len = p2 as usize;
            if !window_ok(offset, len) {
                return Err(IO_ERR_INVALID_PARAM);
            }
            let data_ptr = data_buf[window_start(offset)..].as_ptr();
            (ops.i2c_write)(bus as u32, addr as u32, data_ptr, len)
        }

        OP_PWM_SET => {
            need_dev!(azos_devif::key::PWM, narrow_u8!(p0) as u32, true);
            not_contained!();
            (ops.pwm_set)(p0, p1)
        }

        // `param0`/`param1` are the left and right wheel speeds in percent,
        // each commanded through its own `motor_wheel` call. The SQE carries
        // no motor id, so the equivalent of a per-wheel `motor.N` WRITE
        // check is to require write on both ids. The topology seeds exactly
        // `motor.0` and `motor.1` RW for the drivetrain
        // (`crates/core/topology/src/builder.rs`), so a task legitimately allowed
        // to drive holds both; requiring only one would let a task granted a
        // single wheel command the pair. Most safety-relevant opcode in the
        // table — deny on any doubt.
        //
        // **A speed above 100 is refused, not clamped.** The typed call clamps
        // (`gate_speed` takes `min(100)`), which on a ring would turn a
        // negative speed written as `u32` — a reverse, to its author — into
        // full speed forward.
        //
        // **Both wheels are always commanded, and a refusal of either refuses
        // the entry.** The halt rule reads one query per command, so under a
        // latched e-stop both answer `MOTOR_REFUSED_HALTED` and both write duty
        // 0; stopping at the first refusal would leave the second wheel's last
        // duty on its channel. The completion reports the first refusal, else
        // the first negative code, else the right wheel's result. A halt that
        // latches between the two calls leaves the left wheel driven and the
        // entry refused, exactly as two typed calls would.
        OP_MOTOR_SPEED => {
            need_dev!(azos_devif::key::MOTOR, 0, true);
            need_dev!(azos_devif::key::MOTOR, 1, true);
            if p0 > 100 || p1 > 100 {
                return Err(IO_ERR_INVALID_PARAM);
            }
            let left = (ops.motor_wheel)(owner_tid, 0, p0);
            let right = (ops.motor_wheel)(owner_tid, 1, p1);
            match (left, right) {
                (Err(e), _) | (_, Err(e)) => Err(e),
                (Ok(l), _) if l < 0 => Ok(l),
                (_, Ok(r)) => Ok(r),
            }
        }

        // `param0` is a `Cap<Socket>` handle in the owner's table, as the
        // typed socket calls take it; the op-table entry resolves it (WRITE,
        // containment) and records a refusal as `NODE_SEND` does, then
        // queues the bytes without waiting. A send that queued completes
        // `CQE_F_QUEUED`. The window is bounded first, in the data buffer or
        // (`SQE_F_FIXED`) in a registered buffer.
        OP_NET_SEND => {
            let data_ptr = sqe_window(owner_tid, sqe, data_buf, bufs, ops, false)?;
            (ops.net_send)(owner_tid, p0, data_ptr, p2 as usize)
        }

        // The receive twin: `READ` on the same kind of handle, the bytes taken
        // off the socket straight into the window (it is the sink, so a
        // registered buffer must still be one the kernel may write).
        OP_NET_RECV => {
            let buf_ptr = sqe_window(owner_tid, sqe, data_buf, bufs, ops, true)?;
            (ops.net_recv)(owner_tid, p0, buf_ptr, p2 as usize)
        }

        OP_BUF_REGISTER => {
            let slot = reg_slot(sqe.reg)?;
            if bufs.e[slot].r != 0 {
                return Err(IO_ERR_INVALID_PARAM);
            }
            let pin = (ops.buf_pin)(owner_tid, p0, p1, p2)?;
            bufs.e[slot] = RegBuf { r: pin.r, len: p2, kva: pin.kva };
            Ok(IO_OK)
        }

        OP_BUF_UNREGISTER => {
            let slot = reg_slot(sqe.reg)?;
            let b = core::mem::replace(&mut bufs.e[slot], RegBuf { r: 0, len: 0, kva: 0 });
            if b.r == 0 {
                return Err(IO_ERR_INVALID_PARAM);
            }
            (ops.buf_unpin)(b.r);
            Ok(IO_OK)
        }

        // A file and a channel are named by a capability HANDLE in the owner's
        // table, not by a resource number, so the op-table entry resolves it
        // (and records a refusal) exactly as the typed call does; containment
        // of a file write is `CapTable::get`'s, as in `NODE_WRITE`.
        // The window is bounded first: the entry must never see an unbounded
        // pointer, whatever its handle turns out to be.
        OP_FILE_READ | OP_FILE_WRITE => {
            let write = sqe.opcode == OP_FILE_WRITE;
            let ptr = sqe_window(owner_tid, sqe, data_buf, bufs, ops, !write)?;
            (ops.file_io)(owner_tid, p0, write, ptr, p2 as usize)
        }

        // `OP_TIMER`, `OP_NOTIFY_WAIT` and the block opcodes complete
        // asynchronously or by the worker and are decided by `dispatch_entry`
        // (`dispatch_block`); reached here directly they refuse like any
        // opcode this function does not execute.

        // Any other opcode, the unassigned 22 and up included, executes
        // nothing and says so: a completion of `IO_OK` for work not done is
        // indistinguishable, for the client, from the work done.
        _ => Err(IO_ERR_INVALID_OP),
    }
}

// ──────────────────────────────────────────────────────────────────────────
// SQ polling (SQPOLL)
// ──────────────────────────────────────────────────────────────────────────
//
// A kernel task per ring runs passes over the ring's SQ without a syscall.
// Off unless the signed topology gives the owner's row an idle time
// (`TaskSpec::sqpoll_idle_ms`), which the kernel records here with
// `io_ring_permit_sqpoll` when it seeds the task; the owner then asks for a
// poller in-band with `OP_SQPOLL_START`.
//
// **Zero syscalls is not zero checks.** A poller pass is the same `run_pass`
// a submit runs: every entry asks the owner's seccomp profile (read from the
// owner's slot, `IoRingOps::syscall_allowed`), the owner's capabilities
// (`ring_dev_ok`, keyed on the owner since W3-F3), containment, and reaches
// the same op-table entry, so the motor layer's halt rule applies per entry.
// A refusal is recorded against the owner, as the typed call records it.
//
// The poller is spawned and woken through `SqpollHooks`, which the kernel
// registers (`azos_syscall::ioring_sqpoll`): this crate does not create
// tasks.

/// Most tasks the topology may permit an SQ poller.
pub const MAX_SQPOLL_PERMITS: usize = 8;

/// `(tid, idle_ms)` of every task permitted an SQ poller; `tid == 0` is free.
static SQPOLL_PERMITS: SpinLock<[(u32, u32); MAX_SQPOLL_PERMITS]> =
    SpinLock::new([(0, 0); MAX_SQPOLL_PERMITS]);

/// Permit task `tid` to start SQ pollers that park after `idle_ms` of an
/// empty queue; `idle_ms == 0` withdraws the permit. The kernel calls it from
/// the task's topology row (`sqpoll_idle_ms`). `false` when the table is full
/// or `tid` is 0. Withdrawn by [`io_ring_release_all`] when the task exits.
pub fn io_ring_permit_sqpoll(tid: u32, idle_ms: u32) -> bool {
    if tid == 0 {
        return false;
    }
    let mut t = SQPOLL_PERMITS.lock_irqsave();
    if let Some(e) = t.iter_mut().find(|e| e.0 == tid) {
        *e = if idle_ms == 0 { (0, 0) } else { (tid, idle_ms) };
        return true;
    }
    if idle_ms == 0 {
        return true;
    }
    match t.iter_mut().find(|e| e.0 == 0) {
        Some(e) => {
            *e = (tid, idle_ms);
            true
        }
        None => false,
    }
}

/// The idle time task `tid` is permitted, 0 for none.
fn sqpoll_permit(tid: u32) -> u32 {
    if tid == 0 {
        return 0;
    }
    SQPOLL_PERMITS.lock_irqsave().iter().find(|e| e.0 == tid).map_or(0, |e| e.1)
}

fn sqpoll_revoke_permit(tid: u32) {
    let _ = io_ring_permit_sqpoll(tid, 0);
}

/// How the kernel starts and wakes an SQ poller.
pub struct SqpollHooks {
    /// Create the poller task for the ring whose packed reference is `r`, at
    /// no higher a priority than `owner_tid`'s; its TID, or `None` if no task
    /// could be created.
    pub spawn: fn(r: u32, owner_tid: u32) -> Option<u32>,
    /// Wake poller `poller_tid` from its park, or make its next park return
    /// at once. Callable with no lock of this module held.
    pub wake: fn(poller_tid: u32),
}

/// The SQ poller hooks. Written by `io_ring_register_sqpoll` once at boot,
/// before any task runs (and by host tests under the crate-wide serial lock);
/// every later access copies the `Option<&'static _>` out.
static mut SQPOLL: Option<&'static SqpollHooks> = None;

/// Register the SQ poller hooks. The kernel calls it once at boot; until
/// then `OP_SQPOLL_START` answers `-ENOSYS`.
pub fn io_ring_register_sqpoll(h: &'static SqpollHooks) {
    // SAFETY: boot-time registration, before any task runs; no reader exists yet.
    unsafe { SQPOLL = Some(h); }
}

fn sqpoll_wake(poller_tid: u32) {
    if poller_tid == 0 {
        return;
    }
    // SAFETY: a copy-out read of `SQPOLL`, which is not written while tasks run.
    if let Some(h) = unsafe { SQPOLL } {
        (h.wake)(poller_tid);
    }
}

/// `-EPERM`: the owner's topology row does not permit an SQ poller.
pub const IO_ERR_SQPOLL_DENIED: i32 = azos_abi::error::Errno::EPERM.to_syscall_ret() as i32;
/// `-ENOMEM`: no poller task could be created.
pub const IO_ERR_SQPOLL_NO_TASK: i32 = azos_abi::error::Errno::ENOMEM.to_syscall_ret() as i32;

/// [`OP_SQPOLL_START`] in a submit pass: `(poller TID, idle ms)` once the
/// poller exists and the page says so.
///
/// # Safety
/// `ring` is the claimed ring's page.
#[inline(never)]
unsafe fn start_sqpoll(
    ring: *mut IoRing,
    r: Option<u32>,
    owner_tid: u32,
    owner_priv: bool,
) -> Result<(u32, u32), i32> {
    let (Some(r), Some(h)) = (r, SQPOLL) else { return Err(IO_ERR_INVALID_OP) };
    // A kernel-created ring has no topology row; neither does a stranger.
    let idle_ms = if owner_priv { 0 } else { sqpoll_permit(owner_tid) };
    if idle_ms == 0 {
        return Err(IO_ERR_SQPOLL_DENIED);
    }
    let tid = (h.spawn)(r, owner_tid).ok_or(IO_ERR_SQPOLL_NO_TASK)?;
    (*ring).sq_flags.fetch_or(SQ_F_SQPOLL, Ordering::SeqCst);
    Ok((tid, idle_ms))
}

/// What one poller pass found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SqpollPass {
    /// The ring is destroyed (or its owner died): the poller exits.
    Gone,
    /// Another pass holds the ring, or the pass that started this poller has
    /// not yet recorded it: try again.
    Busy,
    /// A pass ran.
    Done {
        /// Completions written (0 also for a pass that met a full CQ).
        ran: u32,
        /// The ring's idle time before its poller parks.
        idle_ms: u32,
        /// Earliest parked timer deadline, `u64::MAX` for none.
        next_deadline_ns: u64,
        /// A notify wait is parked, which only a later look completes.
        words: bool,
    },
}

/// Claim live ring `r` for its poller: `(slot, claim, idle_ms)`.
fn poller_claim(r: u32) -> Result<(u32, (usize, u32, bool), u32), SqpollPass> {
    let mut rings = IO_RINGS.lock_irqsave();
    let Ok(i) = live_index(&rings, r) else { return Err(SqpollPass::Gone) };
    let st = &mut rings[i];
    if st.poller_tid == 0 {
        return Err(SqpollPass::Busy);
    }
    let idle_ms = st.sqpoll_idle_ms;
    match claim_locked(st) {
        Some(c) => Ok((i as u32, c, idle_ms)),
        None => Err(SqpollPass::Busy),
    }
}

/// One pass of ring `r`'s SQ poller: the submit pass, run from the poller.
pub fn io_ring_sqpoll_pass(r: u32) -> SqpollPass {
    // SAFETY: a copy-out read of `OPS`, which is not written while tasks run.
    let Some(ops) = (unsafe { OPS }) else { return SqpollPass::Gone };
    let (i, (phys, owner_tid, owner_priv), idle_ms) = match poller_claim(r) {
        Ok(c) => c,
        Err(e) => return e,
    };
    // SAFETY: `poller_claim` took the claim; released just below.
    let may_block = (ops.may_block)();
    let out = unsafe { run_pass(i, Some(r), phys, owner_tid, owner_priv, ops, true, may_block, None) };
    release_ring_with(i, None, out.n > 0);
    if out.handoff || out.blocks {
        kick_worker(ops);
    }
    SqpollPass::Done {
        ran: out.n.max(0) as u32,
        idle_ms,
        next_deadline_ns: out.next_deadline_ns,
        words: out.words,
    }
}

/// What a poller about to park found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SqpollPark {
    Gone,
    Busy,
    /// An entry arrived after all: do not park.
    NotIdle,
    /// [`SQ_F_NEED_WAKEUP`] is set and the SQ was empty after it was: park.
    /// A submit from here on wakes the poller, or stamps the wake so its park
    /// returns at once.
    Parked,
}

/// The poller's half of the park handshake: set [`SQ_F_NEED_WAKEUP`], fence,
/// and re-read `sq_tail`. Ring 3's half is the mirror image (publish
/// `sq_tail`, fence, read the flag); with both fences one side always sees the
/// other's store, so an entry published during the park is either seen here
/// or answered by ring 3's wake-up submit.
pub fn io_ring_sqpoll_prepare_park(r: u32) -> SqpollPark {
    let (i, (phys, _, _), _) = match poller_claim(r) {
        Ok(c) => c,
        Err(SqpollPass::Gone) => return SqpollPark::Gone,
        Err(_) => return SqpollPark::Busy,
    };
    // SAFETY: the claim keeps the page alive until `release_ring` below.
    let pending = unsafe {
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        (*ring).sq_flags.fetch_or(SQ_F_NEED_WAKEUP, Ordering::SeqCst);
        core::sync::atomic::fence(Ordering::SeqCst);
        let pending = (*ring).sq_tail.load(Ordering::SeqCst) != (*ring).sq_head.load(Ordering::Relaxed);
        if pending {
            (*ring).sq_flags.fetch_and(!SQ_F_NEED_WAKEUP, Ordering::SeqCst);
        }
        pending
    };
    release_ring(i);
    if pending { SqpollPark::NotIdle } else { SqpollPark::Parked }
}

// ──────────────────────────────────────────────────────────────────────────
// Cap<IoRing> typed wrappers
// ──────────────────────────────────────────────────────────────────────────
//
// Same mechanical pattern as the Port and Shm batches: the typed
// entry validates the cap against the caller's `CapTable`, then
// delegates to the existing integer-handle logic. `io_ring_create_cap`
// follows the Shm "creates + grants atomically" shape — on
// cap-table exhaustion the ring is rolled back so callers never
// observe a half-created state.

/// Errors returned by the typed `io_ring_*_cap` functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoRingCapError {
    /// Capability dereference failed (stale / wrong kind / missing perms).
    Cap(crate::cap::CapError),
    /// Out of memory or no free ring slot.
    NoMem,
    /// Ring doesn't exist or has been destroyed.
    Closed,
    /// Cap-table slot table is full — the ring was rolled back.
    Full,
    /// Underlying `io_ring_submit` returned a negative status; see
    /// [`IO_ERR_INVALID_PARAM`] / [`IO_ERR_NO_OPS`].
    SubmitError(i32),
    /// The submit executed nothing: an entry was pending and the completion
    /// queue had no room for its completion. Drain the CQ and submit again.
    CqFull,
}

impl From<crate::cap::CapError> for IoRingCapError {
    fn from(e: crate::cap::CapError) -> Self {
        Self::Cap(e)
    }
}

/// Typed `io_ring_create`: allocates a ring and mints a `Cap<IoRing>`
/// into `tid`'s cap-table. Returns the cap and the physical address
/// of the ring page. On cap-table exhaustion the ring is rolled back.
pub fn io_ring_create_cap(
    tid: u32,
) -> Result<(crate::cap::Cap<crate::cap::targets::IoRing>, u64), IoRingCapError> {
    io_ring_create_cap_ref(tid).map(|(cap, _, phys)| (cap, phys))
}

/// [`io_ring_create_cap`], also answering the packed reference the capability
/// stores, which [`io_ring_record_user_va`] and
/// [`io_ring_destroy_mapped_ref`] take.
pub fn io_ring_create_cap_ref(
    tid: u32,
) -> Result<(crate::cap::Cap<crate::cap::targets::IoRing>, u32, u64), IoRingCapError> {
    let (r, phys_addr) = create_core(tid as usize).ok_or(IoRingCapError::NoMem)?;
    // The capability stores the packed `(index, generation)`. `RW_DELEGATE`
    // (owner decision 2026-09-26, O3.4): the creator may copy and gift its own
    // ring.
    match objref::grant_packed::<crate::cap::targets::IoRing>(tid, crate::cap::CapPerms::RW_DELEGATE, r) {
        Some(cap) => Ok((cap, r, phys_addr as u64)),
        None => {
            // Roll back the ring so cap-table exhaustion is not a leak. The
            // ring was created microseconds ago and has never been
            // submitted, so the `in_flight` refusal cannot fire here.
            let _ = io_ring_destroy_ref(r);
            Err(IoRingCapError::Full)
        }
    }
}

// **There is no typed submit that takes a `&CapTable`.** `io_ring_submit_cap`
// resolved the capability and ran the pass with the caller's table borrowed,
// which means inside `cap_store::with_table`; with an op table registered,
// each entry's capability check (`ring_dev_ok`) takes that same table's lock,
// so the pass deadlocked on its first entry. `SYS_RING_ENTER` resolves
// the reference in a hold of its own — WRITE, without the containment step,
// which is applied per write entry in `dispatch_sqe` —
// and calls [`io_ring_submit_ref`] after the hold.

/// Typed `io_ring_destroy`: validates the cap (requires `WRITE`), frees the
/// ring + its backing page, **and revokes the cap**.
///
/// **WHY the revoke is here (W3-F5):** ring ids are allocated first-free-slot
/// and destroying a ring does not touch the cap-table slot's generation —
/// the only thing `CapTable::get` validates. A cap left live after its ring
/// is gone therefore keeps resolving to the same id, and the next
/// `io_ring_create` hands that id to whoever asks next: task A destroys ring
/// 0, task B creates and receives ring 0, and A's stale cap now submits into
/// B's ring. The previous doc told callers to revoke separately; no caller
/// did.
///
/// Returns `Closed` if the ring could not be destroyed because a submit pass
/// is in flight — the cap is left intact so the caller can retry.
///
/// **Not contained.** Destroying is a release, so it resolves through
/// `CapTable::get_uncontained`: it still needs `WRITE`, and it stays live
/// while degraded-mode containment is armed, the way closing a socket does (owner
/// decision 2026-09-13). Submitting — which executes the ring's queued writes —
/// stays contained. There is no untyped destroy.
pub fn io_ring_destroy_cap(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::IoRing>,
) -> Result<(), IoRingCapError> {
    let r = table.get_uncontained(cap, crate::cap::CapPerms::WRITE)?;
    io_ring_destroy_ref(r)?;
    table.delete(cap);
    Ok(())
}

/// Wipe the ring table **without** returning pages to the allocator. Host-test
/// hygiene only — the suite shares one static `IO_RINGS`, and going through
/// `free_page` here would corrupt the free-counting the orphan test relies on
/// (the test allocator is reset separately). Never built into the kernel: a
/// reachable "destroy every ring on the board" entry point is precisely what
/// a ring's capability exists to prevent.
#[cfg(test)]
pub fn __io_ring_reset_for_tests() {
    let mut rings = IO_RINGS.lock_irqsave();
    for i in 0..MAX_IO_RINGS {
        rings[i] = IoRingState::empty();
        rings.next_gen[i] = 1;
        // SAFETY: the table lock is held and every slot was just emptied.
        unsafe {
            *parked_of(i) = ParkedSet::EMPTY;
            *regbufs_of(i) = RegBufSet::EMPTY;
        }
    }
}

/// How many entries slot `i` holds parked (host tests).
#[cfg(test)]
pub fn __io_ring_parked_for_tests(i: usize) -> u32 {
    let _rings = IO_RINGS.lock_irqsave();
    // SAFETY: host tests read this between passes, never during one.
    unsafe { parked_of(i).n }
}

/// Fast-forward slot `i`'s own generation source, so a host test reaches its
/// wrap without `LAYOUT.gen_max()` create/destroy cycles at that index.
#[cfg(test)]
pub fn __io_ring_set_next_gen_for_tests(i: usize, next_gen: u32) {
    IO_RINGS.lock_irqsave().next_gen[i] = next_gen;
}

/// The generation stamped in slot `ring_id` (host tests).
#[cfg(test)]
pub fn __io_ring_generation_for_tests(ring_id: u32) -> u32 {
    IO_RINGS.lock_irqsave()[ring_id as usize].generation
}

/// Unregister the op table, as the kernel runs. Host tests only: every test
/// that submits registers `TEST_OPS` itself, under the crate-wide serial lock.
#[cfg(test)]
pub fn __io_ring_unregister_ops_for_tests() {
    // SAFETY: host tests only, under the crate-wide serial lock; no pass is running.
    unsafe { OPS = None; }
}

/// Unregister the SQ poller hooks and forget every permit (host tests).
#[cfg(test)]
pub fn __io_ring_sqpoll_reset_for_tests() {
    // SAFETY: host tests only, under the crate-wide serial lock; no pass is running.
    unsafe { SQPOLL = None; }
    *SQPOLL_PERMITS.lock_irqsave() = [(0, 0); MAX_SQPOLL_PERMITS];
}

/// `(poller_tid, sqpoll_idle_ms)` of a slot (host tests).
#[cfg(test)]
pub fn __io_ring_poller_for_tests(ring_id: u32) -> (u32, u32) {
    let rings = IO_RINGS.lock_irqsave();
    (rings[ring_id as usize].poller_tid, rings[ring_id as usize].sqpoll_idle_ms)
}

/// `(active, in_flight, orphaned, phys_addr)` for a slot (host tests).
#[cfg(test)]
pub fn __io_ring_slot_for_tests(ring_id: u32) -> (bool, bool, bool, usize) {
    if ring_id as usize >= MAX_IO_RINGS { return (false, false, false, 0); }
    let rings = IO_RINGS.lock_irqsave();
    let s = &rings[ring_id as usize];
    (s.active, s.in_flight, s.orphaned, s.phys_addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering as AOrd};
    use std::sync::Mutex;

    const OWNER: u32 = 1;
    const OTHER: u32 = 2;

    /// `crate::harness::serial()` serialises this suite with the port
    /// and irq_bind suites, which share the scheduler shim, and resets both
    /// shims.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        __io_ring_reset_for_tests();
        reset_hooks();
        // Kernel-mode creator → `owner_privileged`, so `dispatch_sqe`'s
        // capability checks pass and the submit path is drivable.
        azos_sched::shim_set_current(OWNER, 0);
        g
    }

    // ── The orphan window ──────────────────────────────────────────────────
    //
    // Reproduces "the owning task dies while a submit pass is in flight"
    // deterministically and single-threaded: `dispatch_sqe` runs with the
    // table lock dropped, so an opcode handler that calls
    // `io_ring_release_all` re-enters the table from exactly the window the
    // `in_flight` flag exists to protect.

    static ORPHAN_ARMED: AtomicBool = AtomicBool::new(false);
    static ORPHAN_TID: AtomicU32 = AtomicU32::new(0);
    static ORPHAN_PHYS: AtomicUsize = AtomicUsize::new(0);
    static ORPHAN_RING: AtomicU32 = AtomicU32::new(0);
    /// Frees observed on the ring's page *while the pass was still running*.
    static FREES_DURING_PASS: AtomicU32 = AtomicU32::new(u32::MAX);
    /// Owner reported by `io_ring_owner` during the pass.
    static OWNER_DURING_PASS: AtomicUsize = AtomicUsize::new(0);
    /// When non-zero, the hook also creates a ring for this TID inside the
    /// window and starts a pass on it, standing for another hart.
    static CREATE_IN_WINDOW_FOR: AtomicU32 = AtomicU32::new(0);
    /// `(ring_id, phys_addr, claimed)` of the ring created inside the window.
    static CREATED_IN_WINDOW: Mutex<Option<(u32, usize, bool)>> = Mutex::new(None);
    /// The orphan's slot, as `__io_ring_slot_for_tests` saw it right after
    /// that create.
    static ORPHAN_SLOT_IN_WINDOW: Mutex<Option<(bool, bool, bool, usize)>> = Mutex::new(None);

    /// Calls that reached `read_sensor`, so a refusal can be shown to have
    /// executed nothing.
    static SENSOR_CALLS: AtomicU32 = AtomicU32::new(0);

    fn hook_read_sensor(_ty: u32, _buf: *mut u8, _len: usize) -> OpResult {
        SENSOR_CALLS.fetch_add(1, AOrd::SeqCst);
        if ORPHAN_ARMED.swap(false, AOrd::SeqCst) {
            io_ring_release_all(ORPHAN_TID.load(AOrd::SeqCst));
            FREES_DURING_PASS.store(
                azos_mm::shim_free_count(ORPHAN_PHYS.load(AOrd::SeqCst)),
                AOrd::SeqCst,
            );
            OWNER_DURING_PASS.store(
                io_ring_owner(ORPHAN_RING.load(AOrd::SeqCst)).unwrap_or(usize::MAX),
                AOrd::SeqCst,
            );
            let creator = CREATE_IN_WINDOW_FOR.swap(0, AOrd::SeqCst);
            if creator != 0 {
                let made = io_ring_create(creator as usize)
                    .map(|(id, phys)| (id, phys, claim_ring(id).is_some()));
                *CREATED_IN_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = made;
                *ORPHAN_SLOT_IN_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(__io_ring_slot_for_tests(ORPHAN_RING.load(AOrd::SeqCst)));
            }
        }
        Ok(7)
    }

    /// Last `(bus, addr, reg, len)` seen by the I2C hooks, so a test can prove
    /// the driver got the *same* address the capability was checked against.
    static I2C_SEEN: Mutex<Option<(u32, u32, u32, usize)>> = Mutex::new(None);
    fn i2c_seen() -> Option<(u32, u32, u32, usize)> {
        *I2C_SEEN.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn i2c_seen_clear() {
        *I2C_SEEN.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn nop_wg(_p: u32, _v: u32) -> OpResult { Ok(0) }
    fn nop_rg(_p: u32) -> OpResult { Ok(0) }
    fn hook_i2c_r(b: u32, a: u32, r: u32, _buf: *mut u8, l: usize) -> OpResult {
        *I2C_SEEN.lock().unwrap_or_else(|e| e.into_inner()) = Some((b, a, r, l));
        Ok(0)
    }
    fn hook_i2c_w(b: u32, a: u32, _d: *const u8, l: usize) -> OpResult {
        *I2C_SEEN.lock().unwrap_or_else(|e| e.into_inner()) = Some((b, a, u32::MAX, l));
        Ok(0)
    }
    fn nop_pwm(_c: u32, _d: u32) -> OpResult { Ok(0) }
    /// `(owner, cap, len)` of every send that reached the socket.
    static NET_SEEN: Mutex<Vec<(u32, u32, usize)>> = Mutex::new(Vec::new());
    fn hook_net_send(owner: u32, cap: u32, _d: *const u8, l: usize) -> OpResult {
        if CONTAINED.load(AOrd::SeqCst) {
            return Err(-11);
        }
        if cap == BAD_CAP {
            return Err(E_STALE);
        }
        NET_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((owner, cap, l));
        Ok(l as i32)
    }
    /// `(owner, cap, len, buffer address)` of every receive that reached the
    /// socket.
    static RECV_SEEN: Mutex<Vec<(u32, u32, usize, usize)>> = Mutex::new(Vec::new());
    /// What a receive on the test socket delivers.
    const RECV_BYTES: &[u8; 4] = b"RECV";
    fn hook_net_recv(owner: u32, cap: u32, buf: *mut u8, len: usize) -> OpResult {
        if cap == BAD_CAP {
            return Err(E_STALE);
        }
        RECV_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((owner, cap, len, buf as usize));
        let n = len.min(RECV_BYTES.len());
        // SAFETY: `dispatch_sqe` bounded `buf..buf + len` inside the ring's data
        // buffer or the registered buffer's arena.
        unsafe { core::ptr::copy_nonoverlapping(RECV_BYTES.as_ptr(), buf, n) };
        Ok(n as i32)
    }

    /// The arena the test "pins": registered buffers live in it, as the kernel's
    /// do in the direct map of the frames it pinned.
    const ARENA_LEN: usize = 8192;
    fn arena() -> usize {
        static BASE: AtomicUsize = AtomicUsize::new(0);
        let b = BASE.load(AOrd::SeqCst);
        if b != 0 {
            return b;
        }
        let fresh = Box::leak(vec![0u8; ARENA_LEN].into_boxed_slice()).as_ptr() as usize;
        match BASE.compare_exchange(0, fresh, AOrd::SeqCst, AOrd::SeqCst) {
            Ok(_) => fresh,
            Err(won) => won,
        }
    }
    fn arena_byte(i: usize) -> u8 {
        // SAFETY: inside the leaked arena.
        unsafe { *((arena() + i) as *const u8) }
    }
    /// The objects the test hooks hold a pin on, and the order they were taken.
    static BUF_PINS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static BUF_NEXT: AtomicU32 = AtomicU32::new(1);
    /// `(owner, cap, offset, len)` of every registration that reached the pin hook.
    static BUF_PIN_SEEN: Mutex<Vec<(u32, u32, u32, u32)>> = Mutex::new(Vec::new());
    /// A clone shares a frame of every pinned object: the kernel may not write.
    static BUF_SHARED: AtomicBool = AtomicBool::new(false);
    fn pins() -> Vec<u32> {
        BUF_PINS.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn hook_buf_pin(owner: u32, cap: u32, offset: u32, len: u32) -> Result<PinnedBuf, i32> {
        if cap == BAD_CAP {
            return Err(E_STALE);
        }
        BUF_PIN_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((owner, cap, offset, len));
        match (offset as usize).checked_add(len as usize) {
            Some(end) if len != 0 && end <= ARENA_LEN => {}
            _ => return Err(IO_ERR_INVALID_PARAM),
        }
        let r = BUF_NEXT.fetch_add(1, AOrd::SeqCst);
        BUF_PINS.lock().unwrap_or_else(|e| e.into_inner()).push(r);
        Ok(PinnedBuf { r, kva: arena() + offset as usize })
    }
    fn hook_buf_unpin(r: u32) {
        let mut v = BUF_PINS.lock().unwrap_or_else(|e| e.into_inner());
        let at = v.iter().position(|&x| x == r).expect("a pin given back twice, or never taken");
        v.remove(at);
    }
    /// The owner released or moved the object: no use of any pin is allowed.
    static BUF_UNMAPPED: AtomicBool = AtomicBool::new(false);
    fn hook_buf_usable(_owner: u32, _r: u32, sink: bool) -> bool {
        !BUF_UNMAPPED.load(AOrd::SeqCst) && !(sink && BUF_SHARED.load(AOrd::SeqCst))
    }

    /// `(id, speed_pct)` of every `motor_wheel` call, in order.
    static MOTOR_SEEN: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());
    /// The wheel whose `motor_wheel` call refuses with `-EAGAIN`, as the
    /// kernel's entry does under the halt rule; `u32::MAX` for none.
    static MOTOR_REFUSES: AtomicU32 = AtomicU32::new(u32::MAX);
    fn hook_motor_wheel(_owner: u32, id: u32, pct: u32) -> OpResult {
        MOTOR_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((id, pct));
        if MOTOR_REFUSES.load(AOrd::SeqCst) == id { Err(IO_ERR_CONTAINED) } else { Ok(0) }
    }
    fn motor_seen() -> Vec<(u32, u32)> {
        MOTOR_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The one syscall number the test profile denies; 0 for none.
    static SECCOMP_DENIES: AtomicU64 = AtomicU64::new(0);
    fn hook_syscall_allowed(_owner: u32, nr: u64) -> bool {
        SECCOMP_DENIES.load(AOrd::SeqCst) != nr
    }
    /// The one interface host key the test profile denies; 0 for none.
    static IFACE_DENIES: AtomicU32 = AtomicU32::new(0);
    fn hook_iface_allowed(_owner: u32, key: u16) -> bool {
        IFACE_DENIES.load(AOrd::SeqCst) != key as u32
    }
    /// The one op the test profile denies; 0 for none.
    static OP_DENIES: AtomicU32 = AtomicU32::new(0);
    fn hook_op_allowed(_owner: u32, op: u16) -> bool {
        OP_DENIES.load(AOrd::SeqCst) != op as u32
    }
    /// The one pledge mask bit the test Domain has given up; 255 for none.
    static PLEDGE_DROPPED: AtomicU32 = AtomicU32::new(255);
    fn hook_pledge_allowed(_owner: u32, _nr: u64, bit: u8) -> bool {
        PLEDGE_DROPPED.load(AOrd::SeqCst) != bit as u32
    }
    /// What `write_contained` answers.
    static CONTAINED: AtomicBool = AtomicBool::new(false);
    fn hook_write_contained() -> bool {
        CONTAINED.load(AOrd::SeqCst)
    }

    /// `(owner, kind)` of every refusal `note_denial` was asked to record.
    static DENIALS: Mutex<Vec<(u32, CapType)>> = Mutex::new(Vec::new());
    fn hook_note_denial(owner: u32, kind: CapType) {
        DENIALS.lock().unwrap_or_else(|e| e.into_inner()).push((owner, kind));
    }
    fn denials() -> Vec<(u32, CapType)> {
        DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    /// The handle the file and channel hooks refuse, as a stale one.
    const BAD_CAP: u32 = 0xDEAD;
    const E_STALE: i32 = azos_abi::error::Errno::ECAPSTALE.to_syscall_ret() as i32;
    /// `(owner, cap, write, len)` of every call that reached a file or
    /// channel hook (`write` is `true` for a channel send).
    static IO_SEEN: Mutex<Vec<(u32, u32, bool, usize)>> = Mutex::new(Vec::new());
    fn io_seen() -> Vec<(u32, u32, bool, usize)> {
        IO_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn io_hook(owner: u32, cap: u32, write: bool, len: usize) -> OpResult {
        if cap == BAD_CAP {
            return Err(E_STALE);
        }
        IO_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((owner, cap, write, len));
        Ok(len as i32)
    }
    fn hook_file_io(owner: u32, cap: u32, write: bool, _b: *mut u8, len: usize) -> OpResult {
        io_hook(owner, cap, write, len)
    }
    /// `(badge, write, sector, len)` of every block entry that reached the
    /// op table.
    static BLOCK_SEEN: Mutex<Vec<(u32, bool, u64, usize)>> = Mutex::new(Vec::new());
    /// Block entries that ran on the synchronous path (`block_io`).
    static BLOCK_INLINE: AtomicU32 = AtomicU32::new(0);
    fn hook_block_io(badge: u32, write: bool, sector: u64, _b: *mut u8, len: usize) -> OpResult {
        BLOCK_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((badge, write, sector, len));
        BLOCK_INLINE.fetch_add(1, AOrd::SeqCst);
        Ok(len as i32)
    }

    /// What the test's block request layer does with a run: 0 queues it, 1
    /// cannot take it ([`BlockStart::Unqueueable`]), 2 refuses it, 3 answers a
    /// READ [`BlockStart::Dirty`] (the write-back cache holds its range).
    static BLOCK_MODE: AtomicU32 = AtomicU32::new(0);
    /// The device fails every request it completes.
    static BLOCK_FAILS: AtomicBool = AtomicBool::new(false);
    /// The device holds every request: `block_service` completes none.
    static BLOCK_HOLD: AtomicBool = AtomicBool::new(false);
    static BLOCK_NEXT: AtomicU32 = AtomicU32::new(1);
    static BLOCK_SERVICED: AtomicU32 = AtomicU32::new(0);
    /// One queued request: its token, whether it writes, its length, its state
    /// (`Q` queued, `OK` / `BAD` over, `GONE` orphaned) and what a write
    /// carried when it was queued.
    #[derive(Clone, Debug, PartialEq)]
    struct Req { token: u32, write: bool, len: usize, state: u8, data: Vec<u8> }
    const Q: u8 = 0;
    const OK: u8 = 1;
    const BAD: u8 = 2;
    const GONE: u8 = 3;
    static BLOCK_REQS: Mutex<Vec<Req>> = Mutex::new(Vec::new());
    static BLOCK_ORPHANS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    fn block_reqs() -> Vec<Req> {
        BLOCK_REQS.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn block_orphans() -> Vec<u32> {
        BLOCK_ORPHANS.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    /// The byte a completed read of token `t` leaves in the window.
    fn pattern(t: u32) -> u8 {
        0xA0 | (t as u8 & 0x0F)
    }
    fn hook_block_start(_owner: u32, badge: u32, write: bool, sector: u64, buf: *const u8, len: usize) -> BlockStart {
        match BLOCK_MODE.load(AOrd::SeqCst) {
            1 => return BlockStart::Unqueueable,
            2 => return BlockStart::Refused(IO_ERR_PERM),
            3 if !write => return BlockStart::Dirty,
            _ => {}
        }
        BLOCK_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((badge, write, sector, len));
        let token = BLOCK_NEXT.fetch_add(1, AOrd::SeqCst);
        // A write's bytes are taken NOW, as the kernel's entry takes them.
        // SAFETY: `dispatch_sqe` bounded `[buf, buf + len)` inside the ring's
        // data buffer.
        let data = if write { unsafe { core::slice::from_raw_parts(buf, len) }.to_vec() } else { Vec::new() };
        BLOCK_REQS.lock().unwrap_or_else(|e| e.into_inner()).push(Req { token, write, len, state: Q, data });
        BlockStart::Queued(token)
    }
    fn hook_block_poll(token: u32, out: *mut u8, len: usize) -> Option<i32> {
        let mut q = BLOCK_REQS.lock().unwrap_or_else(|e| e.into_inner());
        let i = q.iter().position(|r| r.token == token)?;
        match q[i].state {
            Q => None,
            OK => {
                let r = q.remove(i);
                if !r.write {
                    // SAFETY: `block_poll` is handed a window `[out, out + len)` inside the
                    // ring's data buffer.
                    unsafe { core::ptr::write_bytes(out, pattern(token), len) };
                }
                Some(r.len as i32)
            }
            _ => {
                q.remove(i);
                Some(azos_abi::error::Errno::EIO.to_syscall_ret() as i32)
            }
        }
    }
    fn hook_block_orphan(token: u32) {
        BLOCK_ORPHANS.lock().unwrap_or_else(|e| e.into_inner()).push(token);
        if let Some(r) = BLOCK_REQS.lock().unwrap_or_else(|e| e.into_inner()).iter_mut().find(|r| r.token == token) {
            r.state = GONE;
        }
    }
    /// The worker's turn: the oldest queued request ends (or none, with the
    /// device held), and what orphaned requests held is freed.
    fn hook_block_service() -> bool {
        BLOCK_SERVICED.fetch_add(1, AOrd::SeqCst);
        let mut q = BLOCK_REQS.lock().unwrap_or_else(|e| e.into_inner());
        q.retain(|r| r.state != GONE);
        // The real service sleeps until one request ends, so "more" always
        // follows progress; a held device is the test's way to have none, and
        // answers "nothing to wait for" so the pass returns.
        if BLOCK_HOLD.load(AOrd::SeqCst) {
            return false;
        }
        if let Some(r) = q.iter_mut().find(|r| r.state == Q) {
            r.state = if BLOCK_FAILS.load(AOrd::SeqCst) { BAD } else { OK };
        }
        q.iter().any(|r| r.state == Q)
    }
    fn block_seen() -> Vec<(u32, bool, u64, usize)> {
        BLOCK_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    /// The time counter, in nanoseconds, as `deadline_reached` reads it.
    static NOW_NS: AtomicU64 = AtomicU64::new(0);
    fn hook_deadline_reached(deadline: u64) -> bool {
        NOW_NS.load(AOrd::SeqCst) >= deadline
    }
    /// Flush tickets: the last one asked for, and the last one done (the
    /// test plays the flusher). `FLUSH_FAILS`: the done flush failed.
    static FLUSH_ASKED: AtomicU64 = AtomicU64::new(0);
    static FLUSH_DONE: AtomicU64 = AtomicU64::new(0);
    static FLUSH_FAILS: AtomicBool = AtomicBool::new(false);
    fn hook_file_fsync(owner: u32, cap: u32) -> OpResult64 {
        if cap == BAD_CAP {
            return Err(E_STALE);
        }
        IO_SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((owner, cap, false, 0));
        Ok(FLUSH_ASKED.fetch_add(1, AOrd::SeqCst) + 1)
    }
    fn hook_fsync_done(ticket: u64) -> Option<i32> {
        if FLUSH_DONE.load(AOrd::SeqCst) < ticket {
            None
        } else if FLUSH_FAILS.load(AOrd::SeqCst) {
            Some(azos_abi::error::Errno::EIO.to_syscall_ret() as i32)
        } else {
            Some(0)
        }
    }
    /// The flusher finishes every flush asked so far, and posts.
    fn flush_now(fail: bool) {
        FLUSH_FAILS.store(fail, AOrd::SeqCst);
        FLUSH_DONE.store(FLUSH_ASKED.load(AOrd::SeqCst), AOrd::SeqCst);
        io_ring_flush_posted();
    }
    /// `false`: the submitting task is real-time (owner rule: no block I/O).
    static MAY_BLOCK: AtomicBool = AtomicBool::new(true);
    fn hook_may_block() -> bool { MAY_BLOCK.load(AOrd::SeqCst) }
    /// `false`: a task that may block still hands its file entries to the
    /// worker (Kconfig `IORING_ASYNC`); a test sets it to put the canary back.
    static FILE_INLINE: AtomicBool = AtomicBool::new(!azos_limits::IORING_ASYNC);
    fn hook_file_inline() -> bool { FILE_INLINE.load(AOrd::SeqCst) }
    /// Worker wake-ups asked for.
    static KICKS: AtomicU32 = AtomicU32::new(0);
    fn hook_kick() { KICKS.fetch_add(1, AOrd::SeqCst); }
    /// The notify word every `notify_word` look reads.
    static WORD: AtomicU32 = AtomicU32::new(0);
    /// Every `notify_word` look refuses, as for a revoked capability.
    static REVOKED: AtomicBool = AtomicBool::new(false);
    fn hook_notify_word(_owner: u32, cap: u32, _offset: u32) -> Result<u32, i32> {
        if cap == BAD_CAP || REVOKED.load(AOrd::SeqCst) { Err(E_STALE) } else { Ok(WORD.load(AOrd::SeqCst)) }
    }

    static TEST_OPS: IoRingOps = IoRingOps {
        syscall_allowed: hook_syscall_allowed,
        iface_allowed: hook_iface_allowed,
        op_allowed: hook_op_allowed,
        pledge_allowed: hook_pledge_allowed,
        write_contained: hook_write_contained,
        read_sensor: hook_read_sensor,
        write_gpio:  nop_wg,
        read_gpio:   nop_rg,
        i2c_read:    hook_i2c_r,
        i2c_write:   hook_i2c_w,
        pwm_set:     nop_pwm,
        motor_wheel: hook_motor_wheel,
        net_send:    hook_net_send,
        net_recv:    hook_net_recv,
        note_denial: hook_note_denial,
        file_io:     hook_file_io,
        block_io:    hook_block_io,
        block_start: hook_block_start,
        block_poll:  hook_block_poll,
        block_orphan: hook_block_orphan,
        block_service: hook_block_service,
        deadline_reached: hook_deadline_reached,
        notify_word: hook_notify_word,
        file_fsync:  hook_file_fsync,
        fsync_done:  hook_fsync_done,
        may_block:   hook_may_block,
        file_inline: hook_file_inline,
        handoff_kick: Some(hook_kick),
        buf_pin:     hook_buf_pin,
        buf_unpin:   hook_buf_unpin,
        buf_usable:  hook_buf_usable,
    };

    /// Put the test table's hooks back to "allow, not contained, nothing seen".
    fn reset_hooks() {
        SENSOR_CALLS.store(0, AOrd::SeqCst);
        BLOCK_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        BLOCK_INLINE.store(0, AOrd::SeqCst);
        BLOCK_MODE.store(0, AOrd::SeqCst);
        BLOCK_FAILS.store(false, AOrd::SeqCst);
        BLOCK_HOLD.store(false, AOrd::SeqCst);
        BLOCK_NEXT.store(1, AOrd::SeqCst);
        BLOCK_SERVICED.store(0, AOrd::SeqCst);
        BLOCK_REQS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        BLOCK_ORPHANS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        for f in BLOCK_PARKED.iter() { f.store(false, AOrd::SeqCst); }
        SECCOMP_DENIES.store(0, AOrd::SeqCst);
        IFACE_DENIES.store(0, AOrd::SeqCst);
        OP_DENIES.store(0, AOrd::SeqCst);
        PLEDGE_DROPPED.store(255, AOrd::SeqCst);
        CONTAINED.store(false, AOrd::SeqCst);
        MOTOR_REFUSES.store(u32::MAX, AOrd::SeqCst);
        MOTOR_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        IO_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        NOW_NS.store(0, AOrd::SeqCst);
        WORD.store(0, AOrd::SeqCst);
        REVOKED.store(false, AOrd::SeqCst);
        FLUSH_ASKED.store(0, AOrd::SeqCst);
        FLUSH_DONE.store(0, AOrd::SeqCst);
        FLUSH_FAILS.store(false, AOrd::SeqCst);
        for f in FLUSH_PARKED.iter() { f.store(false, AOrd::SeqCst); }
        for f in HANDOFF.iter() { f.store(false, AOrd::SeqCst); }
        MAY_BLOCK.store(true, AOrd::SeqCst);
        FILE_INLINE.store(!azos_limits::IORING_ASYNC, AOrd::SeqCst);
        KICKS.store(0, AOrd::SeqCst);
        NET_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        RECV_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        BUF_PINS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        BUF_PIN_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        BUF_SHARED.store(false, AOrd::SeqCst);
        BUF_UNMAPPED.store(false, AOrd::SeqCst);
        // SAFETY: inside the leaked arena; no pass runs between tests.
        unsafe { core::ptr::write_bytes(arena() as *mut u8, 0, ARENA_LEN) };
    }

    /// An unassigned opcode must REFUSE, not report success: from the
    /// submitter's side an `IO_OK` for work not done is indistinguishable
    /// from work done. 10 and 11 once named camera capture and IRQ wait,
    /// which answered `IO_OK` without doing either; they are the buffer
    /// opcodes now, and 22 and 23 are the unassigned ones.
    ///
    /// **The positive control is what gives this teeth.** Asserting only that
    /// two opcodes fail passes against a `dispatch_sqe` that fails on
    /// everything, which would be a far worse regression than the one being
    /// fixed. `OP_NOP` must still succeed.
    ///
    /// **Canary.** Make the `_` arm answer `IO_OK`: this must go red while the
    /// `OP_NOP` assertion stays green.
    #[test]
    fn an_unimplemented_opcode_refuses_instead_of_reporting_success() {
        let mut buf = [0u8; RING_DATA_BUF_SIZE];
        let mut bufs = RegBufSet::EMPTY;
        let sqe_for = |op: u16| SqEntry {
            opcode: op,
            flags: 0,
            param0: 0,
            param1: 0,
            param2: 0,
            addr: 0,
            reg: 0,
            user_data: 0,
        };
        for op in [22u16, 23] {
            assert_eq!(
                dispatch_sqe(&sqe_for(op), &mut buf, &mut bufs, &TEST_OPS, 1, false),
                Err(IO_ERR_INVALID_OP),
                "opcode {op} is not implemented and must not answer IO_OK"
            );
        }
        // Positive control: the dispatch still works.
        assert_eq!(
            dispatch_sqe(&sqe_for(OP_NOP), &mut buf, &mut bufs, &TEST_OPS, 1, false),
            Ok(IO_OK),
            "OP_NOP must still succeed — otherwise this test passes against a \
             dispatch that refuses everything"
        );
    }

    /// Queue one `OP_READ_SENSOR` on the ring page.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test, and nothing else touches that ring meanwhile.
    unsafe fn queue_sensor_sqe(phys: usize) {
        // `phys` is PHYSICAL; the kernel writes the ring through its own
        // view of that page — identity on riscv64, upper half on aarch64.
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        (*ring).sq_entries[0] = SqEntry {
            opcode: OP_READ_SENSOR,
            flags: 0,
            param0: 0,
            param1: 0,
            param2: 0,
            addr: 0,
            reg: 0,
            user_data: 0xABCD_1234,
        };
        (*ring).sq_tail.store(1, Ordering::Release);
    }

    /// Submit exactly one SQE and return its completion `result`.
    ///
    /// Goes through the real `io_ring_submit`, so the claim/release discipline
    /// and the owner/privilege plumbing are exercised too — a test that called
    /// `dispatch_sqe` directly would prove nothing about what ring 3 reaches.
    /// Submit ring `id`, then (when the kernel hands every file entry and queues
    /// every block entry to the worker, Kconfig `IORING_ASYNC`, and the
    /// submitter may block) the worker's turn, the way the kernel's worker task
    /// takes it after the wake-up. Answers the completions written in all, or
    /// the submit's error. An RT submitter's hand-off is the test's to run.
    fn submit_settled(id: u32) -> i32 {
        let ring = azos_mm::addr::phys_to_virt(IO_RINGS.lock_irqsave()[ring_slot(id)].phys_addr) as *mut IoRing;
        // SAFETY: a live ring of this test; the page is only read.
        let before = unsafe { (*ring).cq_tail.load(Ordering::Acquire) };
        let n = io_ring_submit(id);
        if n < 0 {
            return n;
        }
        if azos_limits::IORING_ASYNC && MAY_BLOCK.load(AOrd::SeqCst) {
            io_ring_worker_pass();
        }
        // SAFETY: `ring` is this test's live ring page; this is an atomic access.
        unsafe { (*ring).cq_tail.load(Ordering::Acquire) }.wrapping_sub(before) as i32
    }

    /// Queue `sqe`, submit ring `id` through [`submit_settled`] and consume
    /// its one completion, answering that completion's `result`.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test as ring `id`, and nothing else touches that ring meanwhile.
    unsafe fn submit_one(id: u32, phys: usize, sqe: SqEntry) -> i32 {
        // `phys` is PHYSICAL; the kernel writes the ring through its own
        // view of that page — identity on riscv64, upper half on aarch64.
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        let head = (*ring).sq_head.load(Ordering::Acquire);
        let tail = (*ring).sq_tail.load(Ordering::Acquire);
        (*ring).sq_entries[(tail as usize) % RING_SQ_SIZE] = sqe;
        (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
        let cq_before = (*ring).cq_tail.load(Ordering::Acquire);
        assert_eq!(submit_settled(id), 1, "submit did not produce one completion");
        let _ = head;
        // Consume it, as a ring client does: an undrained CQ stops the ring
        // after `RING_CQ_SIZE` completions.
        (*ring).cq_head.store(cq_before.wrapping_add(1), Ordering::Release);
        (*ring).cq_entries[(cq_before as usize) % RING_CQ_SIZE].result
    }

    fn sqe(opcode: u16, param0: u32, param1: u32, param2: u32, addr: u16, reg: u16) -> SqEntry {
        SqEntry { opcode, flags: 0, param0, param1, param2, addr, reg, user_data: 0 }
    }

    #[test]
    fn owner_death_mid_pass_defers_the_page_free_to_release_ring() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);

        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        ORPHAN_ARMED.store(true, AOrd::SeqCst);
        ORPHAN_TID.store(OWNER, AOrd::SeqCst);
        ORPHAN_PHYS.store(phys, AOrd::SeqCst);
        ORPHAN_RING.store(id, AOrd::SeqCst);
        FREES_DURING_PASS.store(u32::MAX, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `queue_sensor_sqe`).
        unsafe { queue_sensor_sqe(phys) };

        let completions = io_ring_submit(id);

        // The handler ran, so the task really did "die" mid-pass.
        assert_eq!(completions, 1);
        assert_ne!(FREES_DURING_PASS.load(AOrd::SeqCst), u32::MAX, "hook never ran");

        // THE PROPERTY: the exit hook must NOT free the page under a live
        // pass — that is the use-after-free `in_flight` exists to prevent.
        assert_eq!(
            FREES_DURING_PASS.load(AOrd::SeqCst), 0,
            "page was freed while a submit pass was still writing to it"
        );
        // ...but the slot is already closed to new claims.
        assert_eq!(OWNER_DURING_PASS.load(AOrd::SeqCst), usize::MAX);

        // And once the claim is released, the page is freed exactly once.
        assert_eq!(azos_mm::shim_free_count(phys), 1);
        let (active, in_flight, orphaned, _) = __io_ring_slot_for_tests(id);
        assert!(!active && !in_flight && !orphaned);
        assert_eq!(azos_mm::shim_pages_in_use(), 0);

        // The completion the dying task's pass produced is still coherent —
        // it was written into a page that stayed valid throughout.
        // (Read before reuse; the slot is reusable immediately after.)
        let (id2, _phys2) = io_ring_create(OTHER as usize).unwrap();
        assert_eq!(id2, id);
    }

    #[test]
    fn a_ring_orphaned_mid_pass_accepts_no_new_claim() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        ORPHAN_ARMED.store(true, AOrd::SeqCst);
        ORPHAN_TID.store(OWNER, AOrd::SeqCst);
        ORPHAN_PHYS.store(phys, AOrd::SeqCst);
        ORPHAN_RING.store(id, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `queue_sensor_sqe`).
        unsafe { queue_sensor_sqe(phys) };
        io_ring_submit(id);

        // After the deferred free the slot is empty, so every accessor that
        // could dereference `phys_addr` refuses first.
        assert!(io_ring_owner(id).is_none());
        assert!(!io_ring_destroy(id));
        assert_eq!(azos_mm::shim_free_count(phys), 1);
    }

    /// A slot whose owner died mid-pass is not free until that pass ends.
    ///
    /// `io_ring_create` took any `!active` slot, and `io_ring_release_all`
    /// leaves exactly that shape (`active = false, orphaned = true`) while a
    /// pass is in flight. A create in that window overwrote the record: the
    /// orphan's page was never freed, and the pass's `release_ring` then
    /// cleared `in_flight` on the NEW ring, opening `io_ring_destroy` on a ring
    /// still being submitted on another hart.
    ///
    /// Driven from inside the pass, like the orphan test above. The second
    /// ring's own pass is a direct `claim_ring`, standing for another hart.
    ///
    /// **Canary.** Make the free-slot test in `io_ring_create` `!active` again:
    /// the first assertion goes red.
    #[test]
    fn a_create_while_an_orphan_is_in_flight_does_not_take_its_slot() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        *CREATED_IN_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *ORPHAN_SLOT_IN_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = None;

        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        ORPHAN_ARMED.store(true, AOrd::SeqCst);
        ORPHAN_TID.store(OWNER, AOrd::SeqCst);
        ORPHAN_PHYS.store(phys, AOrd::SeqCst);
        ORPHAN_RING.store(id, AOrd::SeqCst);
        CREATE_IN_WINDOW_FOR.store(OTHER, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `queue_sensor_sqe`).
        unsafe { queue_sensor_sqe(phys) };

        assert_eq!(io_ring_submit(id), 1);
        let (new_id, new_phys, claimed) = CREATED_IN_WINDOW
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("the hook did not create a ring inside the window");

        assert_ne!(new_id, id, "a create during the orphan's pass took the orphan's slot");
        assert_eq!(
            *ORPHAN_SLOT_IN_WINDOW.lock().unwrap_or_else(|e| e.into_inner()),
            Some((false, true, true, phys)),
            "the create overwrote the orphan's slot record while its pass was running"
        );
        assert!(claimed, "the second ring's pass could not start");
        // The orphan's page came back exactly once, when its pass ended.
        assert_eq!(azos_mm::shim_free_count(phys), 1, "the orphan's page was never freed");
        // The ending pass left the second ring, its page and its claim alone.
        assert_eq!(
            __io_ring_slot_for_tests(new_id),
            (true, true, false, new_phys),
            "the orphan's pass ending touched the new ring"
        );
        assert_eq!(azos_mm::shim_free_count(new_phys), 0);

        release_ring(new_id);
        assert!(io_ring_destroy(new_id));
        assert_eq!(azos_mm::shim_pages_in_use(), 0);
    }

    // ── The ordinary (not in flight) path ──────────────────────────────────

    #[test]
    fn release_all_frees_only_the_dying_tasks_rings_and_their_pages() {
        let _g = setup();
        let (a, pa) = io_ring_create(OWNER as usize).unwrap();
        let (b, pb) = io_ring_create(OTHER as usize).unwrap();
        let (c, pc) = io_ring_create(OWNER as usize).unwrap();
        assert_eq!(azos_mm::shim_pages_in_use(), 3);

        io_ring_release_all(OWNER);

        assert!(io_ring_owner(a).is_none());
        assert!(io_ring_owner(c).is_none());
        assert_eq!(azos_mm::shim_free_count(pa), 1);
        assert_eq!(azos_mm::shim_free_count(pc), 1);
        // The other task's ring and page are untouched.
        assert_eq!(io_ring_owner(b), Some(OTHER as usize));
        assert_eq!(azos_mm::shim_free_count(pb), 0);
        assert_eq!(azos_mm::shim_pages_in_use(), 1);
    }

    #[test]
    fn release_all_is_idempotent_and_never_double_frees() {
        let _g = setup();
        let (_a, pa) = io_ring_create(OWNER as usize).unwrap();
        io_ring_release_all(OWNER);
        io_ring_release_all(OWNER);
        io_ring_release_all(OWNER);
        assert_eq!(azos_mm::shim_free_count(pa), 1);
    }

    #[test]
    fn exhausting_the_table_then_killing_an_owner_restores_capacity() {
        let _g = setup();
        // TWO owners: one can no longer fill the table, because the per-task
        // quota landed with the rule that minting without one is
        // exhaustion. The property under test is unchanged — reclaiming a dead
        // task's rings returns both the slots and the PAGES.
        const THIRD: u32 = 4242;
        for i in 0..MAX_IO_RINGS_PER_TASK {
            assert!(io_ring_create(OWNER as usize).is_some(), "owner, slot {i}");
        }
        for i in 0..MAX_IO_RINGS_PER_TASK {
            assert!(io_ring_create(OTHER as usize).is_some(), "other, slot {i}");
        }
        // The permanent-failure state before IPC-3: enough dead tasks and
        // SYS_IO_SETUP never succeeds again, with every page gone for good.
        assert!(io_ring_create(THIRD as usize).is_none(), "the table is full");

        io_ring_release_all(OWNER);

        // Only the dead owner's pages come back; the other owner still holds
        // its own, so this is no longer 0 — asserting 0 here would be
        // asserting that a live task's memory was freed underneath it.
        assert!(io_ring_create(THIRD as usize).is_some());
    }

    #[test]
    fn one_task_cannot_take_every_io_ring_on_the_machine() {
        let _g = setup();
        for i in 0..MAX_IO_RINGS_PER_TASK {
            assert!(io_ring_create(OWNER as usize).is_some(), "slot {i}");
        }
        assert!(io_ring_create(OWNER as usize).is_none(), "took more than its share");
        // The negative half: the refusal is the quota, not an empty pool.
        assert!(io_ring_create(OTHER as usize).is_some(), "another task has room");
    }

    /// A quota refusal gives back the page `io_ring_create` allocated before
    /// it took the lock. The refusal returned from inside the lock block and
    /// kept the page: one PMM page per refused call, from ring 3.
    ///
    /// **Canary.** Return `None` from the quota check again: the page count
    /// goes red.
    #[test]
    fn a_quota_refusal_gives_its_page_back() {
        let _g = setup();
        for i in 0..MAX_IO_RINGS_PER_TASK {
            assert!(io_ring_create(OWNER as usize).is_some(), "slot {i}");
        }
        assert_eq!(azos_mm::shim_pages_in_use(), MAX_IO_RINGS_PER_TASK);

        for _ in 0..3 {
            assert!(io_ring_create(OWNER as usize).is_none(), "took more than its share");
        }
        assert_eq!(
            azos_mm::shim_pages_in_use(),
            MAX_IO_RINGS_PER_TASK,
            "a quota refusal kept the page it allocated"
        );

        // Positive control: a create that is admitted still holds its page.
        assert!(io_ring_create(OTHER as usize).is_some());
        assert_eq!(azos_mm::shim_pages_in_use(), MAX_IO_RINGS_PER_TASK + 1);
    }

    #[test]
    fn release_all_ignores_uninvolved_tasks() {
        let _g = setup();
        let (a, pa) = io_ring_create(OWNER as usize).unwrap();
        io_ring_release_all(999);
        assert_eq!(io_ring_owner(a), Some(OWNER as usize));
        // `owner_task` holds `usize::MAX` when unowned; a u32 TID can never
        // equal it, so an absurd TID must not sweep inactive slots.
        io_ring_release_all(u32::MAX);
        assert_eq!(io_ring_owner(a), Some(OWNER as usize));
        assert_eq!(azos_mm::shim_free_count(pa), 0);
    }

    // ── The per-opcode capability matrix (the `param1` split) ──────────────
    //
    // Every test here drives a **ring-3-owned** ring (`user_pt != 0`), which
    // is the only configuration where `dispatch_sqe`'s checks do anything.
    // Both halves are asserted each time: the holder of the exact handle gets
    // through, and every other identity/handle in the space is refused.

    // `IoRing` in this module is the shared ring page; the capability target
    // goes by another name here.
    use crate::cap::targets::IoRing as RingTarget;
    use crate::cap::Cap;
    use crate::cap_store;

    /// Grant `tid` an endpoint capability to the kernel-hosted interface `key`
    /// for the resource `badge`, with `perms` as its op classes.
    fn grant_dev(tid: u32, key: u16, badge: u32, perms: CapPerms) {
        crate::endpoint::kernel_endpoint_cap(tid, perms, key, badge).expect("cap table full");
    }

    /// The badge of the I2C device at `addr` on `bus`.
    fn i2c_badge(bus: u8, addr: u8) -> u32 {
        azos_devif::i2c::badge(bus, addr)
    }

    /// A ring owned by an unprivileged task, with both tasks' capability
    /// tables wiped.
    fn setup_unpriv() -> (std::sync::MutexGuard<'static, ()>, u32, usize) {
        let g = crate::harness::serial();
        __io_ring_reset_for_tests();
        reset_hooks();
        cap_store::reset(OWNER);
        cap_store::reset(OTHER);
        crate::endpoint::__endpoint_reset_for_tests();
        ORPHAN_ARMED.store(false, AOrd::SeqCst);
        i2c_seen_clear();
        io_ring_register_ops(&TEST_OPS);
        // Non-zero user page table = ring 3 ⇒ `owner_privileged == false`.
        azos_sched::shim_set_current(OWNER, 0x1000);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        (g, id, phys)
    }

    #[test]
    fn i2c_read_needs_the_same_handle_the_syscall_needs() {
        let (_g, id, phys) = setup_unpriv();
        // A the `i2c` endpoint names (bus, addr) as `bus << 8 | addr`; READ for a read.
        grant_dev(OWNER, azos_devif::key::I2C, i2c_badge(1, 0x68), CapPerms::READ);

        // The legitimate call goes through...
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        let r = unsafe { submit_one(id, phys, sqe(OP_I2C_READ, 1, 0, 4, 0x68, 0x3B)) };
        assert_eq!(r, 0, "the holder of I2c(1,0x68) was refused its own device");
        // ...and the driver saw exactly the bus/addr/reg that were checked.
        assert_eq!(i2c_seen(), Some((1, 0x68, 0x3B, 4)));

        // ...but nothing else on the bus, and no other bus, is reachable.
        for addr in 0u16..=0xFF {
            if addr == 0x68 { continue; }
            i2c_seen_clear();
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            let r = unsafe { submit_one(id, phys, sqe(OP_I2C_READ, 1, 0, 4, addr, 0)) };
            assert_eq!(r, IO_ERR_PERM, "addr 0x{addr:02x} on bus 1 was not refused");
            assert_eq!(i2c_seen(), None, "a refused op still reached the driver");
        }
        for bus in 0u32..=0xFF {
            if bus == 1 { continue; }
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            let r = unsafe { submit_one(id, phys, sqe(OP_I2C_READ, bus, 0, 4, 0x68, 0)) };
            assert_eq!(r, IO_ERR_PERM, "bus {bus} was not refused");
        }
    }

    #[test]
    fn i2c_write_needs_write_perms_read_only_is_not_enough() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::I2C, i2c_badge(0, 0x40), CapPerms::READ);
        // Read is allowed by an RO handle...
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_I2C_READ, 0, 0, 1, 0x40, 0)) },
            0
        );
        // ...the actuator direction is not. This is the half that matters:
        // an I2C write is how the PWM/motor expanders are driven.
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_I2C_WRITE, 0, 0, 2, 0x40, 0)) },
            IO_ERR_PERM
        );
        // With RW it is.
        cap_store::reset(OWNER);
        grant_dev(OWNER, azos_devif::key::I2C, i2c_badge(0, 0x40), CapPerms::RW);
        i2c_seen_clear();
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_I2C_WRITE, 0, 0, 2, 0x40, 0)) },
            0
        );
        // `sys_i2c_write` takes the register as data[0], so no reg is passed.
        assert_eq!(i2c_seen(), Some((0, 0x40, u32::MAX, 2)));
    }

    #[test]
    fn another_tasks_i2c_handle_does_not_authorize_this_ring() {
        let (_g, id, phys) = setup_unpriv();
        // The device exists and somebody holds it — just not the ring's owner.
        grant_dev(OTHER, azos_devif::key::I2C, i2c_badge(1, 0x68), CapPerms::RW);
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_I2C_READ, 1, 0, 4, 0x68, 0)) },
            IO_ERR_PERM
        );
        assert_eq!(i2c_seen(), None);
    }

    /// **The aliasing hole this batch closed.** The capability resources store
    /// these as `u8`; the ring delivers `u32`/`u16`. Truncating meant `p0 = 256` was
    /// checked as device 0 and then executed as device 256.
    #[test]
    fn a_parameter_that_does_not_fit_its_handle_width_is_rejected_not_truncated() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::RW);
        grant_dev(OWNER, azos_devif::key::PWM, 0, CapPerms::RW);
        grant_dev(OWNER, azos_devif::key::I2C, i2c_badge(0, 0), CapPerms::RW);

        // Baseline: device 0 works for each.
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_READ_SENSOR, 0, 0, 8, 0, 0)) }, 7);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_PWM_SET, 0, 50, 0, 0, 0)) }, 0);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_I2C_READ, 0, 0, 1, 0, 0)) }, 0);

        // Every alias of device 0 is refused, on every narrowed parameter.
        for k in 1u32..=4 {
            let alias = k * 256;
            assert_eq!(
                // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
                unsafe { submit_one(id, phys, sqe(OP_READ_SENSOR, alias, 0, 8, 0, 0)) },
                IO_ERR_INVALID_PARAM, "sensor {alias} aliased sensor 0"
            );
            assert_eq!(
                // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
                unsafe { submit_one(id, phys, sqe(OP_PWM_SET, alias, 50, 0, 0, 0)) },
                IO_ERR_INVALID_PARAM, "pwm {alias} aliased pwm 0"
            );
            assert_eq!(
                // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
                unsafe { submit_one(id, phys, sqe(OP_I2C_READ, alias, 0, 1, 0, 0)) },
                IO_ERR_INVALID_PARAM, "i2c bus {alias} aliased bus 0"
            );
            i2c_seen_clear();
            assert_eq!(
                // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
                unsafe { submit_one(id, phys, sqe(OP_I2C_READ, 0, 0, 1, alias as u16, 0)) },
                IO_ERR_INVALID_PARAM, "i2c addr {alias} aliased addr 0"
            );
            assert_eq!(i2c_seen(), None);
        }
        // And the largest values the fields can hold do not panic either.
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_READ_SENSOR, u32::MAX, 0, 8, 0, 0)) },
            IO_ERR_INVALID_PARAM
        );
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_I2C_READ, u32::MAX, 0, 1, u16::MAX, u16::MAX)) },
            IO_ERR_INVALID_PARAM
        );
    }

    /// A truncated I2C register silently talks to the wrong register on a live
    /// actuator bus, so it is refused even though it is not part of the cap.
    #[test]
    fn an_out_of_range_i2c_register_is_refused() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::I2C, i2c_badge(0, 0x40), CapPerms::RW);
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_I2C_READ, 0, 0, 1, 0x40, 0x100)) },
            IO_ERR_INVALID_PARAM
        );
        assert_eq!(i2c_seen(), None);
    }

    /// `OP_NET_SEND` and `OP_NET_RECV` name a `Cap<Socket>`: the op-table entry
    /// resolves it in the OWNER's table, so the dispatcher hands it the owner
    /// and the handle, a refusal it answers completes flagged, and the bytes
    /// land in the window the entry named.
    ///
    #[test]
    fn net_opcodes_hand_the_owner_and_the_socket_cap_to_the_op_table() {
        let (_g, id, phys) = setup_unpriv();
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_NET_SEND, 0x77, 0, 4, 0, 0)) }, 4);
        assert_eq!(*NET_SEEN.lock().unwrap(), vec![(OWNER, 0x77, 4)], "the send reached the socket with the owner and handle");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_NET_SEND, BAD_CAP, 0, 4, 0, 0)) }, E_STALE);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_NET_RECV, 0x78, 16, 4, 0, 0)) };
        assert_eq!(done(c), (4, 0), "a receive that delivered completes unflagged");
        let seen = RECV_SEEN.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, OWNER, "the receive resolves the handle in the ring's owner's table");
        assert_eq!(seen[0].1, 0x78);
        assert_eq!(seen[0].2, 4);
        assert_eq!(ring_data(phys)[16..20], RECV_BYTES[..], "the bytes land at the data-buffer offset the entry named");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_NET_RECV, BAD_CAP, 0, 4, 0, 0)) };
        assert_eq!(done(c), (E_STALE, CQE_F_REFUSED));
        // An unbounded window never reaches the socket.
        let before = RECV_SEEN.lock().unwrap().len();
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_NET_RECV, 0x78, RING_DATA_BUF_SIZE as u32 - 2, 4, 0, 0)) };
        assert_eq!(done(c), (IO_ERR_INVALID_PARAM, CQE_F_REFUSED));
        assert_eq!(RECV_SEEN.lock().unwrap().len(), before);
    }

    /// A ring owned by a *different* unprivileged task resolves the socket in
    /// that task's OWN table: the dispatcher hands the op table the owner of
    /// the ring, never the task that happens to run the pass.
    #[test]
    fn net_opcodes_resolve_the_handle_for_the_rings_owner() {
        let _g = crate::harness::serial();
        __io_ring_reset_for_tests();
        reset_hooks();
        io_ring_register_ops(&TEST_OPS);
        azos_sched::shim_set_current(OTHER, 0x2000);
        let (id, phys) = io_ring_create(OTHER as usize).unwrap();
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        let _ = unsafe { submit_one(id, phys, sqe(OP_NET_SEND, 0x77, 0, 4, 0, 0)) };
        assert_eq!(*NET_SEEN.lock().unwrap(), vec![(OTHER, 0x77, 4)]);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        let _ = unsafe { submit_one(id, phys, sqe(OP_NET_RECV, 0x77, 0, 4, 0, 0)) };
        assert_eq!(RECV_SEEN.lock().unwrap()[0].0, OTHER);
    }

    /// A copy of ring page `phys`'s data buffer.
    fn ring_data(phys: usize) -> Vec<u8> {
        let ring = azos_mm::addr::phys_to_virt(phys) as *const IoRing;
        // SAFETY: `phys` is a live ring page of the calling test, no pass running.
        unsafe { (&(*ring).data_buf)[..].to_vec() }
    }

    /// An entry as the SQ holds it with `SQE_F_FIXED` set.
    fn fixed(opcode: u16, p0: u32, off: u32, len: u32, slot: u16) -> SqEntry {
        SqEntry { flags: SQE_F_FIXED, ..sqe(opcode, p0, off, len, 0, slot) }
    }

    /// Register `len` bytes at `offset` of the object `cap` names into `slot`.
    fn register(id: u32, phys: usize, cap: u32, offset: u32, len: u32, slot: u16) -> (i32, u32) {
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        done(unsafe { submit_one_cqe(id, phys, sqe(OP_BUF_REGISTER, cap, offset, len, 0, slot)) })
    }

    /// **A registered buffer is named once and reached by slot.** The pin hook
    /// sees the owner, the handle and the range exactly as the entry gave them;
    /// a receive with `SQE_F_FIXED` lands in the pinned range at the entry's
    /// offset and nowhere in the data buffer; a send reads from it.
    ///
    /// **Canary.** Ignore `SQE_F_FIXED` in `sqe_window`: the bytes land in
    /// `data_buf`.
    #[test]
    fn a_registered_buffer_is_reached_by_slot_and_offset() {
        let (_g, id, phys) = setup_unpriv();
        assert_eq!(register(id, phys, 0x31, 100, 512, 1), (0, 0));
        assert_eq!(*BUF_PIN_SEEN.lock().unwrap(), vec![(OWNER, 0x31, 100, 512)]);
        assert_eq!(pins().len(), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, fixed(OP_NET_RECV, 0x78, 8, 4, 1)) };
        assert_eq!(done(c), (4, 0));
        let seen = RECV_SEEN.lock().unwrap().clone();
        assert_eq!(seen[0].3, arena() + 100 + 8, "the window starts at the buffer plus the entry's offset");
        for k in 0..4 {
            assert_eq!(arena_byte(108 + k), RECV_BYTES[k]);
        }
        assert!(ring_data(phys).iter().all(|&b| b == 0), "a fixed receive wrote the data buffer");
        // A send names it too, and the file opcodes.
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, fixed(OP_NET_SEND, 0x77, 0, 512, 1)) };
        assert_eq!(done(c), (512, CQE_F_QUEUED));
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, fixed(OP_FILE_READ, 0x55, 0, 512, 1)) };
        assert_eq!(done(c), (512, 0));
        assert!(io_seen().contains(&(OWNER, 0x55, false, 512)));
    }

    /// The window of a fixed entry is bounded by the BUFFER, not by the data
    /// buffer: the last byte works, one past it is refused, a length that would
    /// wrap does not panic, a slot beyond the table or an empty one is refused,
    /// and none of them reaches the socket.
    ///
    /// **Canary.** Bound the window by `RING_DATA_BUF_SIZE`: the last four
    /// bytes of the 4 KiB buffer are refused.
    #[test]
    fn a_fixed_window_is_bounded_by_its_buffer() {
        let (_g, id, phys) = setup_unpriv();
        assert_eq!(register(id, phys, 0x31, 0, 4096, 0), (0, 0));
        let run = |e: SqEntry| {
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            done(unsafe { submit_one_cqe(id, phys, e) })
        };
        let inval = (IO_ERR_INVALID_PARAM, CQE_F_REFUSED);
        assert_eq!(run(fixed(OP_NET_RECV, 0x78, 4092, 4, 0)), (4, 0), "the last four bytes");
        assert_eq!(run(fixed(OP_NET_RECV, 0x78, 4096, 0, 0)), (0, 0), "the empty window at the end");
        assert_eq!(run(fixed(OP_NET_RECV, 0x78, 4093, 4, 0)), inval, "one past the end");
        assert_eq!(run(fixed(OP_NET_RECV, 0x78, u32::MAX, u32::MAX, 0)), inval, "a wrapping window");
        assert_eq!(run(fixed(OP_NET_RECV, 0x78, 0, 4, 1)), inval, "a slot holding nothing");
        assert_eq!(run(fixed(OP_NET_RECV, 0x78, 0, 4, RING_MAX_REGBUFS as u16)), inval, "a slot past the table");
        assert_eq!(run(fixed(OP_NET_RECV, 0x78, 0, 4, u16::MAX)), inval, "the largest slot");
        assert_eq!(RECV_SEEN.lock().unwrap().len(), 2, "only the two legal windows reached the socket");
        assert_eq!(run(fixed(OP_NET_SEND, 0x77, 4093, 4, 0)), inval);
        assert_eq!(run(fixed(OP_FILE_WRITE, 0x55, 4093, 4, 0)), inval);
        assert!(NET_SEEN.lock().unwrap().is_empty() && io_seen().is_empty());
    }

    /// `SQE_F_FIXED` is refused on every opcode that does not move bytes to a
    /// window of ring 3 memory, before the entry is read: the block opcodes
    /// (their `reg` is half a sector number), the register opcodes, a timer, and
    /// an opcode no kernel knows.
    #[test]
    fn the_fixed_flag_is_refused_where_reg_means_something_else() {
        let (_g, id, phys) = setup_unpriv();
        for op in [OP_NOP, OP_READ_SENSOR, OP_I2C_READ, OP_I2C_WRITE, OP_PWM_SET, OP_BLOCK_READ, OP_BLOCK_WRITE,
                   OP_TIMER, OP_FSYNC, OP_BUF_REGISTER, OP_BUF_UNREGISTER, 77] {
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            let c = unsafe { submit_one_cqe(id, phys, SqEntry { flags: SQE_F_FIXED, ..sqe(op, 0, 0, 512, 0, 0) }) };
            assert_eq!(done(c), (IO_ERR_INVALID_PARAM, CQE_F_REFUSED), "opcode {op}");
        }
        assert!(block_seen().is_empty() && pins().is_empty());
    }

    /// The slot table: a slot is filled once, freed by an unregister, and a
    /// table-full or double-use is refused without pinning anything more. The
    /// refusals of the pin hook come back as the entry's.
    #[test]
    fn registering_fills_slots_once_and_unregistering_gives_the_pin_back() {
        let (_g, id, phys) = setup_unpriv();
        let inval = (IO_ERR_INVALID_PARAM, CQE_F_REFUSED);
        for slot in 0..RING_MAX_REGBUFS as u16 {
            assert_eq!(register(id, phys, 0x31, 64 * slot as u32, 64, slot), (0, 0), "slot {slot}");
        }
        assert_eq!(pins().len(), RING_MAX_REGBUFS);
        assert_eq!(register(id, phys, 0x31, 0, 64, 0), inval, "a slot in use");
        assert_eq!(register(id, phys, 0x31, 0, 64, RING_MAX_REGBUFS as u16), inval, "past the table");
        assert_eq!(pins().len(), RING_MAX_REGBUFS, "a refused registration pinned something");
        assert_eq!(register(id, phys, BAD_CAP, 0, 64, 0), inval, "a busy slot is refused before the capability is asked");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_BUF_UNREGISTER, 0, 0, 0, 0, 2)) };
        assert_eq!(done(c), (0, 0));
        assert_eq!(pins().len(), RING_MAX_REGBUFS - 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_BUF_UNREGISTER, 0, 0, 0, 0, 2)) };
        assert_eq!(done(c), (IO_ERR_INVALID_PARAM, CQE_F_REFUSED), "an empty slot");
        // The freed slot takes a new buffer; a stale handle comes back as the hook's refusal.
        assert_eq!(register(id, phys, BAD_CAP, 0, 64, 2), (E_STALE, CQE_F_REFUSED));
        assert_eq!(register(id, phys, 0x31, 0, 0, 2), inval, "an empty range");
        assert_eq!(register(id, phys, 0x31, 0, 64, 2), (0, 0));
        assert_eq!(pins().len(), RING_MAX_REGBUFS);
    }

    /// Every pin a ring holds is given back when the ring goes, by each of the
    /// ways it can: destroyed, its owner exiting, and its owner exiting under a
    /// pass in flight (the pass's release frees the slot). A pin left behind is
    /// an object the kernel keeps for good.
    ///
    /// **Canary** `ioring-regbuf-leak-canary` (skip the pin list in
    /// `vacate_resources`): every line goes red.
    #[test]
    fn a_vacated_ring_gives_every_pin_back() {
        // Destroyed.
        let (_g, id, phys) = setup_unpriv();
        assert_eq!(register(id, phys, 0x31, 0, 64, 0), (0, 0));
        assert_eq!(register(id, phys, 0x31, 64, 64, 1), (0, 0));
        assert_eq!(pins().len(), 2);
        assert!(io_ring_destroy(id));
        assert!(pins().is_empty(), "destroy left a pin");

        // The owner exits.
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        assert_eq!(register(id, phys, 0x31, 0, 64, 3), (0, 0));
        assert_eq!(pins().len(), 1);
        io_ring_release_all(OWNER);
        assert!(pins().is_empty(), "the owner's exit left a pin");

        // The owner exits while a pass holds the ring: the claim's release frees it.
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        assert_eq!(register(id, phys, 0x31, 0, 64, 0), (0, 0));
        let claim = claim_ring(id).expect("a free ring");
        io_ring_release_all(OWNER);
        assert_eq!(pins().len(), 1, "a pin was given back under a pass that still uses it");
        release_ring(id);
        assert!(pins().is_empty(), "the orphaned ring's release left a pin");
        let _ = (claim, phys);

        // A slot of a destroyed ring starts empty for the ring that takes its place.
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, fixed(OP_NET_RECV, 0x78, 0, 4, 0)) };
        assert_eq!(done(c), (IO_ERR_INVALID_PARAM, CQE_F_REFUSED), "a new ring inherited a buffer");
    }

    /// A buffer the kernel may no longer write is refused to a SINK and still
    /// read from: a clone sharing a frame of the pinned object makes a receive
    /// or a file read into it a write into the clone's memory, not a send.
    ///
    /// **Canary.** Ask `buf_usable` with `sink` false for every use: the
    /// receive completes.
    #[test]
    fn a_shared_buffer_is_refused_as_a_sink_and_read_as_a_source() {
        let (_g, id, phys) = setup_unpriv();
        assert_eq!(register(id, phys, 0x31, 0, 64, 0), (0, 0));
        BUF_SHARED.store(true, AOrd::SeqCst);
        let run = |e: SqEntry| {
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            done(unsafe { submit_one_cqe(id, phys, e) })
        };
        assert_eq!(run(fixed(OP_NET_RECV, 0x78, 0, 4, 0)), (IO_ERR_BUF_GONE, CQE_F_REFUSED));
        assert_eq!(run(fixed(OP_FILE_READ, 0x55, 0, 4, 0)), (IO_ERR_BUF_GONE, CQE_F_REFUSED));
        assert!(RECV_SEEN.lock().unwrap().is_empty() && io_seen().is_empty());
        assert_eq!(run(fixed(OP_NET_SEND, 0x77, 0, 4, 0)), (4, CQE_F_QUEUED));
        assert_eq!(run(fixed(OP_FILE_WRITE, 0x55, 0, 4, 0)), (4, CQE_F_QUEUED));
    }

    /// A pin outlives what it was granted for: once the owner no longer maps
    /// the object (released, or MOVEd to a task that maps the same frames) NO
    /// use of the slot is allowed, a send included: it would read the new
    /// holder's memory into the owner's socket.
    ///
    /// **Canary.** Ask `buf_usable` only for a sink: the send completes.
    #[test]
    fn a_pin_the_owner_no_longer_maps_is_refused_for_every_use() {
        let (_g, id, phys) = setup_unpriv();
        assert_eq!(register(id, phys, 0x31, 0, 64, 0), (0, 0));
        BUF_UNMAPPED.store(true, AOrd::SeqCst);
        let run = |e: SqEntry| {
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            done(unsafe { submit_one_cqe(id, phys, e) })
        };
        for e in [fixed(OP_NET_RECV, 0x78, 0, 4, 0), fixed(OP_NET_SEND, 0x77, 0, 4, 0),
                  fixed(OP_FILE_READ, 0x55, 0, 4, 0), fixed(OP_FILE_WRITE, 0x55, 0, 4, 0)] {
            assert_eq!(run(e), (IO_ERR_BUF_GONE, CQE_F_REFUSED), "opcode {}", e.opcode);
        }
        assert!(RECV_SEEN.lock().unwrap().is_empty() && NET_SEEN.lock().unwrap().is_empty() && io_seen().is_empty());
        // The slot can still be given back.
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_BUF_UNREGISTER, 0, 0, 0, 0, 0)) };
        assert_eq!(done(c), (0, 0));
        assert!(pins().is_empty());
    }

    /// `data_buf` windows: the last legal byte works, one past it is refused,
    /// and a length that would wrap `usize` does not panic (the kernel builds
    /// with `overflow-checks = true` and `panic = "abort"`).
    #[test]
    fn data_buffer_windows_are_bounded_without_panicking() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::RW);
        let last = RING_DATA_BUF_SIZE as u32;
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_READ_SENSOR, 0, last - 1, 1, 0, 0)) }, 7);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_READ_SENSOR, 0, last, 0, 0, 0)) }, 7);
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_READ_SENSOR, 0, last, 1, 0, 0)) },
            IO_ERR_INVALID_PARAM
        );
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_READ_SENSOR, 0, u32::MAX, u32::MAX, 0, 0)) },
            IO_ERR_INVALID_PARAM
        );
    }

    /// Motor is the most safety-relevant opcode: it drives both wheels in one
    /// call and carries no motor id, so it requires write on *both*.
    #[test]
    fn motor_speed_requires_write_on_both_wheels() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::MOTOR, 0, CapPerms::RW);
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_MOTOR_SPEED, 100, 100, 0, 0, 0)) },
            IO_ERR_PERM, "one wheel's handle commanded the pair"
        );
        grant_dev(OWNER, azos_devif::key::MOTOR, 1, CapPerms::RW);
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
            unsafe { submit_one(id, phys, sqe(OP_MOTOR_SPEED, 100, 100, 0, 0, 0)) },
            0
        );
    }

    /// The whole matrix is inert for a kernel-created ring, by design: a ring
    /// a kernel task created keeps the kernel's full access
    /// (`owner_privileged`).
    #[test]
    fn a_kernel_owned_ring_keeps_its_bypass() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        // No handles granted at all, yet every opcode runs.
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_I2C_READ, 1, 0, 4, 0x68, 0)) }, 0);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_MOTOR_SPEED, 0, 0, 0, 0, 0)) }, 0);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one`).
        assert_eq!(unsafe { submit_one(id, phys, sqe(OP_NET_SEND, 999, 0, 4, 0, 0)) }, 4);
    }

    #[test]
    fn out_of_range_and_boundary_ring_ids_never_panic() {
        let _g = setup();
        for id in [MAX_IO_RINGS as u32, MAX_IO_RINGS as u32 + 1, u32::MAX, u32::MAX - 1] {
            assert!(io_ring_owner(id).is_none());
            assert!(!io_ring_destroy(id));
            assert_eq!(io_ring_submit(id), IO_ERR_INVALID_PARAM);
        }
        let last = MAX_IO_RINGS as u32 - 1;
        assert!(io_ring_owner(last).is_none());
        assert!(!io_ring_destroy(last));
    }

    /// Spectre v1: a ring id that passed its bound reaches the table through
    /// `ring_slot`, which keeps an in-range id and sends any other to slot 0
    /// (branch-free, so also under speculation). The mask is compiled out when
    /// `MITIGATION_SPECTRE_V1_INDEX` is off, so the out-of-range half is
    /// asserted only with it on.
    ///
    /// **Canary.** Make `ring_slot` return `ring_id as usize`: the second half
    /// goes red (with the mitigation on).
    #[test]
    fn a_ring_id_reaches_the_table_through_the_index_mask() {
        for id in 0..MAX_IO_RINGS as u32 {
            assert_eq!(ring_slot(id), id as usize, "an in-range id is kept");
        }
        if azos_limits::nospec::ENABLED {
            for id in [MAX_IO_RINGS as u32, MAX_IO_RINGS as u32 + 1, u32::MAX] {
                assert_eq!(ring_slot(id), 0, "id {id} is masked to slot 0");
            }
        }
    }

    // ── Generation ─────────────────────────────────────────────────────────
    //
    // Destroys here go through `io_ring_destroy_cap`, which resolves without
    // containment, so no assertion depends on the degrade level another suite
    // in this binary may be holding.

    const THIRD: u32 = 3;
    const STALE: IoRingCapError = IoRingCapError::Cap(CapError::Stale);

    fn setup_gen() -> std::sync::MutexGuard<'static, ()> {
        let g = setup();
        for tid in [OWNER, OTHER, THIRD] {
            cap_store::reset(tid);
        }
        g
    }

    /// A ring created by `tid` through the typed path: its capability and the
    /// packed reference the capability stores.
    fn create_for(tid: u32) -> (Cap<RingTarget>, u32) {
        let (cap, _) = io_ring_create_cap(tid).expect("create");
        (cap, cap_store::get(tid, cap, CapPerms::READ).expect("a fresh capability resolves"))
    }

    /// Another table's capability for `r`, minted the way every packed
    /// capability is.
    fn mint(tid: u32, r: u32) -> Cap<RingTarget> {
        objref::grant_packed::<RingTarget>(tid, CapPerms::RW, r).expect("mint")
    }

    fn destroy(tid: u32, cap: Cap<RingTarget>) -> Result<(), IoRingCapError> {
        cap_store::with_table(tid, |t| io_ring_destroy_cap(t, cap)).expect("a live tid")
    }

    /// (1) A ring destroyed and recreated at the same index is another object:
    /// the old capability is `Stale` in the creator's table and in a second
    /// table, and the new ring survives. The destroy is the untyped one, which
    /// revokes nothing, so only the generation can refuse.
    ///
    /// **Canary.** Drop `rings[i].generation != g` from `live_index`: A's old
    /// capability destroys the new ring.
    #[test]
    fn a_recreated_ring_index_is_stale_in_every_table_that_named_the_old_ring() {
        let _g = setup_gen();
        io_ring_register_ops(&TEST_OPS);
        let (cap_a, old) = create_for(OWNER);
        let in_b = mint(OTHER, old);
        assert!(io_ring_destroy(LAYOUT.idx(old)));
        let (cap_c, new) = create_for(THIRD);
        assert_eq!(LAYOUT.idx(new), LAYOUT.idx(old), "precondition: the index was reused");
        assert_ne!(LAYOUT.gen(new), LAYOUT.gen(old), "precondition: another generation");

        assert_eq!(destroy(OWNER, cap_a), Err(STALE), "the creator's table");
        assert_eq!(destroy(OTHER, in_b), Err(STALE), "a second table");
        assert_eq!(io_ring_submit_ref(OWNER, old), Err(STALE), "submit");
        assert_eq!(io_ring_owner(LAYOUT.idx(new)), Some(THIRD as usize), "the new ring survived");
        assert_eq!(destroy(THIRD, cap_c), Ok(()));
    }

    /// (2) A kernel-context destroy of a ring-3 task's ring, with no recreate,
    /// stales that task's capability; the vacated slot's generation is 0.
    ///
    /// **Canary.** Keep the generation across `*state = IoRingState::empty()`
    /// in `destroy_locked`: the slot's generation reads non-zero.
    #[test]
    fn a_kernel_destroy_stales_a_ring3_holder() {
        let _g = setup_gen();
        azos_sched::shim_set_current(OWNER, 0x1000);
        let (cap, r) = create_for(OWNER);
        azos_sched::shim_set_current(0, 0);
        assert!(io_ring_destroy(LAYOUT.idx(r)), "the kernel destroys it");
        assert_eq!(__io_ring_generation_for_tests(LAYOUT.idx(r)), 0);
        assert_eq!(destroy(OWNER, cap), Err(STALE));
    }

    /// (3) The owner's exit (`io_ring_release_all`) stales the capabilities
    /// naming its rings in other tables.
    ///
    /// **Canary.** `continue` in `io_ring_release_all` for a ring not in
    /// flight: the ring stays live and the second table's destroy succeeds.
    #[test]
    fn the_owners_exit_stales_the_other_tables() {
        let _g = setup_gen();
        let (_cap, r) = create_for(OWNER);
        let in_b = mint(OTHER, r);
        io_ring_release_all(OWNER);
        assert_eq!(__io_ring_generation_for_tests(LAYOUT.idx(r)), 0);
        assert_eq!(destroy(OTHER, in_b), Err(STALE));
    }

    /// (5) An orphaned slot (owner died mid-pass) is not reusable and keeps its
    /// generation, but nothing resolves through it. When the pass ends the slot
    /// is freed with its generation, and the next ring there carries another.
    ///
    /// **Canaries.** Drop `!rings[i].orphaned` from `create_core`'s free test:
    /// the create during the pass takes the orphan's index. Drop
    /// `!rings[i].active` from `live_index`: the orphan's capability reads
    /// `Closed` instead of `Stale`.
    #[test]
    fn an_orphaned_slot_is_not_reused_until_its_pass_ends_and_then_changes_generation() {
        let _g = setup_gen();
        let (cap, r) = create_for(OWNER);
        let in_b = mint(OTHER, r);
        let idx = LAYOUT.idx(r);
        assert!(claim_ring(idx).is_some(), "a pass in flight, standing for another hart");
        io_ring_release_all(OWNER);
        assert!(__io_ring_slot_for_tests(idx).2, "precondition: orphaned");
        assert_eq!(__io_ring_generation_for_tests(idx), LAYOUT.gen(r), "the orphan keeps it");
        assert_eq!(destroy(OTHER, in_b), Err(STALE), "nothing resolves through an orphan");

        let (_during, r_during) = create_for(THIRD);
        assert_ne!(LAYOUT.idx(r_during), idx, "the orphan's slot is not free");

        release_ring(idx);
        assert_eq!(__io_ring_generation_for_tests(idx), 0, "freed with its generation");
        let (_after, r_after) = create_for(THIRD);
        assert_eq!(LAYOUT.idx(r_after), idx, "precondition: the freed slot was reused");
        assert_ne!(LAYOUT.gen(r_after), LAYOUT.gen(r), "another generation");
        assert_eq!(destroy(OWNER, cap), Err(STALE));
        assert_eq!(destroy(OTHER, in_b), Err(STALE));
    }

    /// (6) U03-1 / U04-1's fix, owner decision 2026-09-26: a slot that reaches
    /// `LAYOUT.gen_max()` is swept **at its own index only**
    /// (`objref::sweep_index`) and reused from generation 1 — instead of the
    /// old design's pool-wide counter, whose exhaustion swept every
    /// `Cap<IoRing>` in every table, live or not. OWNER's ring (slot 0) and an
    /// unrelated `Cap<Shm>` read exactly as before A's churn on slot 1 crosses
    /// the same ceiling. THIRD's stale capability on slot 1's previous
    /// incarnation — the targeted sweep's one job — is gone afterward, and
    /// slot 1 itself comes back, not lost.
    ///
    /// **Canary.** Drop the `rings.next_gen[i] != 0` guard from
    /// `create_core`'s free-slot scan: a concurrent create could select slot 1
    /// while it is mid-sweep.
    #[test]
    fn a_slots_own_wrap_sweeps_only_that_index_and_the_slot_still_comes_back() {
        let _g = setup_gen();

        // OWNER's ring: the "other task's live capability" the old sweep
        // revoked. Created first so it lands on slot 0.
        let (cap_owner, r_owner) = create_for(OWNER);
        assert_eq!(LAYOUT.idx(r_owner), 0, "precondition: OWNER's ring is slot 0");
        let shm: Cap<crate::cap::targets::Shm> =
            cap_store::grant(OWNER, CapPerms::RW, objref::SHM.pack(2, 9)).unwrap();

        // OTHER churns slot 1 right up to and past its own generation
        // ceiling.
        let (cap1, r1) = create_for(OTHER);
        assert_eq!(LAYOUT.idx(r1), 1, "precondition: OTHER's churn lands on slot 1");
        assert_eq!(destroy(OTHER, cap1), Ok(()));
        __io_ring_set_next_gen_for_tests(1, LAYOUT.gen_max() - 1);

        let (cap1, r1) = create_for(OTHER);
        assert_eq!(LAYOUT.idx(r1), 1);
        assert_eq!(LAYOUT.gen(r1), LAYOUT.gen_max() - 1);
        assert_eq!(destroy(OTHER, cap1), Ok(()));

        let (cap1, r1) = create_for(OTHER);
        assert_eq!(LAYOUT.idx(r1), 1);
        assert_eq!(LAYOUT.gen(r1), LAYOUT.gen_max(), "the last generation slot 1 can carry");
        // THIRD holds a capability on THIS incarnation, already unreachable
        // through the generation compare the moment it is destroyed below.
        let in_third = mint(THIRD, r1);
        assert_eq!(destroy(OTHER, cap1), Ok(()));

        // The next create on slot 1 wraps: swept at index 1 only, then reused.
        let (_cap_new, r_new) = create_for(OTHER);
        assert_eq!(LAYOUT.idx(r_new), 1, "the slot comes back — no permanent loss");
        assert_eq!(LAYOUT.gen(r_new), 1, "reused from generation 1 after its own wrap");

        assert_eq!(cap_store::get(OWNER, cap_owner, CapPerms::READ), Ok(r_owner), "OWNER's capability");
        assert_eq!(cap_store::get(OWNER, shm, CapPerms::READ), Ok(objref::SHM.pack(2, 9)), "another kind");
        assert_eq!(io_ring_ref(0), Some(r_owner), "OWNER's ring is still live");
        assert_eq!(
            cap_store::get(THIRD, in_third, CapPerms::READ),
            Err(CapError::Stale),
            "THIRD's stale capability, swept"
        );
        assert_eq!(io_ring_ref(1), Some(r_new), "slot 1 now answers for the new incarnation");
    }

    /// (7) A bare index (generation 0) resolves to nothing — live ring or free
    /// slot, with or without an op table. With no table (the kernel today) a
    /// live reference answers `IO_ERR_NO_OPS` and executes nothing.
    ///
    /// **Canary.** Drop `g == 0` and the generation compare from `live_index`:
    /// the bare capability destroys the live ring.
    #[test]
    fn a_bare_ring_index_never_resolves() {
        let _g = setup_gen();
        let (_cap, r) = create_for(OWNER);
        let idx = LAYOUT.idx(r);
        let bare: Cap<RingTarget> = cap_store::grant(OTHER, CapPerms::RW, idx).unwrap();
        let bare_free: Cap<RingTarget> = cap_store::grant(OTHER, CapPerms::RW, idx + 1).unwrap();

        __io_ring_unregister_ops_for_tests();
        assert_eq!(io_ring_submit_ref(OWNER, idx), Err(STALE), "no op table, bare index");
        assert_eq!(
            io_ring_submit_ref(OWNER, r),
            Err(IoRingCapError::SubmitError(IO_ERR_NO_OPS)),
            "no op table, live reference"
        );
        io_ring_register_ops(&TEST_OPS);
        assert_eq!(io_ring_submit_ref(OWNER, idx), Err(STALE), "with a table");
        assert_eq!(destroy(OTHER, bare), Err(STALE), "a live ring");
        assert_eq!(destroy(OTHER, bare_free), Err(STALE), "a free slot");
        assert_eq!(io_ring_owner(idx), Some(OWNER as usize), "the ring survived");
    }

    /// A task that receives a MOVED `Cap<IoRing>` (decision
    /// 38, `cap_store::move_cap`, kind-erased — this needs no `Cap<Socket>`
    /// dressing, only a capability a task did not create) must not borrow the
    /// ring's ORIGINAL creator's device authority. `ring_dev_ok` resolves I2C
    /// / GPIO / PWM / motor checks against `state.owner_task`, stamped once at
    /// create and never updated by a move — so before this fix, `OTHER`
    /// submitting through a capability it received from `OWNER` executed with
    /// `OWNER`'s sensor endpoint, which `OTHER` never held.
    ///
    /// `mint` stands in for the far side of a completed move: after
    /// `cap_store::move_cap`, the receiver holds exactly this — a live,
    /// correctly-generationed capability in its own table, naming an object it
    /// did not create.
    ///
    /// **Canary.** Delete the `caller_tid != owner_tid` check from
    /// `io_ring_submit_ref`: `OTHER`'s submit succeeds, `SENSOR_CALLS` reads 1
    /// instead of 0, and the final assertion (`OWNER` submitting its own entry)
    /// finds nothing queued.
    #[test]
    fn a_moved_capability_does_not_borrow_the_creators_device_authority() {
        let (_g, id, phys) = setup_unpriv();
        // OWNER — and only OWNER — holds the Sensor capability the queued op
        // needs.
        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::READ);
        let r = io_ring_ref(id).expect("live");

        // OTHER now holds a live Cap<IoRing> to a ring it did not create and
        // no sensor endpoint at all — exactly what a completed move leaves behind.
        let _in_other: Cap<RingTarget> = mint(OTHER, r);

        // SAFETY: `phys` is this test's live ring page, no other user (see `queue_sensor_reads`).
        unsafe { queue_sensor_reads(phys, 1); }
        assert_eq!(
            io_ring_submit_ref(OTHER, r),
            Err(IoRingCapError::Cap(CapError::MissingPerms)),
            "a task holding a moved Cap<IoRing> ran a device op under its \
             creator's authority",
        );
        assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 0, "nothing ran under borrowed authority");

        // The queued entry is untouched: OWNER, the actual owner, still
        // submits it successfully.
        assert_eq!(io_ring_submit_ref(OWNER, r), Ok(1));
        assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 1);
    }

    // ── Completion-queue back-pressure ─────────────────────────────────────

    /// Queue `n` sensor reads at the ring's `sq_tail`, each tagged with
    /// `0x100 + ` its SQ position.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test, and nothing else touches that ring meanwhile.
    unsafe fn queue_sensor_reads(phys: usize, n: u32) {
        let ring = phys as *mut IoRing;
        for _ in 0..n {
            let tail = (*ring).sq_tail.load(Ordering::Acquire);
            (*ring).sq_entries[(tail as usize) % RING_SQ_SIZE] =
                SqEntry { user_data: 0x100 + tail as u64, ..sqe(OP_READ_SENSOR, 0, 0, 8, 0, 0) };
            (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
        }
    }

    /// **A full CQ executes nothing more.** Thirty-two completions nobody has
    /// read fill the queue; the thirty-third entry does not run, `sq_head`
    /// stays on it, the oldest unread completion is intact, and the submit
    /// answers `IO_ERR_CQ_FULL` (`CqFull` on the typed path). Once the consumer
    /// reads one, exactly one more runs, into the slot it freed.
    ///
    /// **Canaries.** Delete the `break`: the thirty-third read runs and
    /// overwrites CQE 0. Make the test `>` instead of `>=`: the same.
    #[test]
    fn a_full_cq_executes_nothing_more() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::READ);
        let ring = phys as *mut IoRing;
        let r = io_ring_ref(id).expect("live");
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue_sensor_reads(phys, RING_SQ_SIZE as u32);
            assert_eq!(io_ring_submit(id), RING_SQ_SIZE as i32);
            assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 32);

            queue_sensor_reads(phys, 1);
            assert_eq!(io_ring_submit(id), IO_ERR_CQ_FULL, "a full CQ answered as a submit that ran");
            assert_eq!(io_ring_submit_ref(OWNER, r), Err(IoRingCapError::CqFull), "the typed path");
            assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 32, "an entry ran with no room for its completion");
            assert_eq!((*ring).sq_head.load(Ordering::Acquire), 32, "sq_head passed an entry that did not run");
            assert_eq!((*ring).cq_tail.load(Ordering::Acquire), 32);
            assert_eq!((*ring).cq_entries[0].user_data, 0x100, "an unread completion was overwritten");

            (*ring).cq_head.store(1, Ordering::Release);
            assert_eq!(io_ring_submit(id), 1, "one slot drained, one entry runs");
            assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 33);
            assert_eq!((*ring).sq_head.load(Ordering::Acquire), 33);
            assert_eq!((*ring).cq_entries[0].user_data, 0x100 + 32, "written into the slot the consumer freed");
            assert_eq!(io_ring_submit(id), 0, "nothing pending");
        }
    }

    /// A pass that meets a full CQ part-way runs what fits, stops, and the
    /// rest waits for the next submit.
    ///
    /// **Canary.** Check the CQ once before the loop instead of per entry: the
    /// second submit runs all three.
    #[test]
    fn a_pass_stops_where_the_cq_fills() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::READ);
        let ring = phys as *mut IoRing;
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue_sensor_reads(phys, 30);
            assert_eq!(io_ring_submit(id), 30);
            queue_sensor_reads(phys, 3);
            assert_eq!(io_ring_submit(id), 2, "two completions fit");
            assert_eq!((*ring).sq_head.load(Ordering::Acquire), 32);
            assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 32);
            assert_eq!(io_ring_submit(id), IO_ERR_CQ_FULL);
            assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 32);
        }
    }

    /// A `cq_head` ahead of `cq_tail` is not an empty queue: it reads full,
    /// and nothing runs.
    ///
    /// **Canary.** `saturating_sub` for `wrapping_sub` in the CQ test: the
    /// hostile head reads as 0 outstanding and the read runs.
    #[test]
    fn a_cq_head_ahead_of_its_tail_reads_full() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::READ);
        let ring = phys as *mut IoRing;
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            (*ring).cq_head.store(1, Ordering::Release);
            queue_sensor_reads(phys, 1);
            assert_eq!(io_ring_submit(id), IO_ERR_CQ_FULL);
            assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 0);
            assert_eq!((*ring).cq_tail.load(Ordering::Acquire), 0);
            assert_eq!((*ring).sq_head.load(Ordering::Acquire), 0);
        }
    }

    // ── Refusals in the completion ─────────────────────────────────────────

    /// Submit one entry and return its whole completion.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test as ring `id`, and nothing else touches that ring meanwhile.
    unsafe fn submit_one_cqe(id: u32, phys: usize, e: SqEntry) -> CqEntry {
        let ring = phys as *mut IoRing;
        let cq_before = (*ring).cq_tail.load(Ordering::Acquire);
        let _ = submit_one(id, phys, e);
        (*ring).cq_entries[(cq_before as usize) % RING_CQ_SIZE]
    }

    fn done(c: CqEntry) -> (i32, u32) {
        (c.result, c.flags)
    }

    /// **A missing capability completes refused, with `-ECAPPERMS`, and the
    /// operation does not run.** With the capability the same entry runs and
    /// completes without the flag.
    ///
    /// **Canaries.** Drop `need_dev!` from the `OP_READ_SENSOR` arm: the first
    /// completion is the hook's 7. Complete a refusal with `flags: 0`: the flag
    /// assertion goes red.
    #[test]
    fn a_missing_capability_completes_refused_with_ecapperms_and_runs_nothing() {
        let (_g, id, phys) = setup_unpriv();
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_READ_SENSOR, 0, 0, 8, 0, 0)) };
        assert_eq!(done(c), (-201, CQE_F_REFUSED));
        assert_eq!(IO_ERR_PERM, -201);
        assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 0, "a refused entry reached the sensor");

        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::READ);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_READ_SENSOR, 0, 0, 8, 0, 0)) };
        assert_eq!(done(c), (7, 0), "the holder's read runs and is not flagged");
        assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 1);
    }

    /// **Seccomp per entry.** A profile that does not list the `sensor`
    /// interface refuses the ring's sensor read with `-EPERM` whether or
    /// not the capability is held — the profile is asked first — and the sensor is not read. An
    /// opcode the profile lists still runs on the same ring.
    ///
    /// **Canary.** Delete the `iface_allowed` check from `dispatch_sqe`: the
    /// held read completes 7 and the hook count is 1.
    #[test]
    fn a_seccomp_denial_refuses_the_entry_before_its_capability_and_runs_nothing() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::READ);
        grant_dev(OWNER, azos_devif::key::GPIO, 5, CapPerms::READ);
        IFACE_DENIES.store(azos_devif::key::SENSOR as u32, AOrd::SeqCst);

        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let held = unsafe { submit_one_cqe(id, phys, sqe(OP_READ_SENSOR, 0, 0, 8, 0, 0)) };
        assert_eq!(done(held), (-1, CQE_F_REFUSED), "a held sensor, denied by the profile");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let unheld = unsafe { submit_one_cqe(id, phys, sqe(OP_READ_SENSOR, 1, 0, 8, 0, 0)) };
        assert_eq!(done(unheld), (-1, CQE_F_REFUSED), "the profile answers before the capability");
        assert_eq!(SENSOR_CALLS.load(AOrd::SeqCst), 0, "a denied entry reached the sensor");

        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let gpio = unsafe { submit_one_cqe(id, phys, sqe(OP_READ_GPIO, 5, 0, 0, 0, 0)) };
        assert_eq!(done(gpio), (0, 0), "a listed opcode still runs");
        IFACE_DENIES.store(0, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_READ_SENSOR, 0, 0, 8, 0, 0)) };
        assert_eq!(done(c), (7, 0));
    }

    /// **A block entry needs the partition's endpoint with the op class, whole
    /// sectors inside the data window, and (a write) no containment; the first
    /// sector is the entry's `addr` and `reg`, low half first.**
    ///
    /// **Canaries.** Drop `ring_dev_ok` from `dispatch_block`: the unheld entry
    /// reaches the op table. Drop the containment test from it: the contained
    /// write reaches it. Take the sector from `addr` alone: the sector line
    /// reads 2.
    #[test]
    fn a_block_entry_needs_its_partition_the_class_and_whole_sectors_in_the_window() {
        let (_g, id, phys) = setup_unpriv();
        let blk = azos_devif::key::BLOCK;
        let run = |op, badge, off, len, addr, reg| {
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            let c = unsafe { submit_one_cqe(id, phys, sqe(op, badge, off, len, addr, reg)) };
            done(c)
        };

        // Not held: refused, and the op table is not reached.
        assert_eq!(run(OP_BLOCK_READ, 1, 0, 512, 0, 0), (IO_ERR_PERM, CQE_F_REFUSED));
        assert!(block_seen().is_empty());

        // READ on partition 0 (badge 1): reads of it run, with the sector the
        // entry's two halves spell; a write and another partition do not.
        grant_dev(OWNER, blk, 1, CapPerms::READ);
        assert_eq!(run(OP_BLOCK_READ, 1, 512, 1024, 2, 1), (1024, 0));
        assert_eq!(block_seen(), vec![(1, false, 0x0001_0002, 1024)]);
        assert_eq!(run(OP_BLOCK_WRITE, 1, 0, 512, 0, 0), (IO_ERR_PERM, CQE_F_REFUSED), "READ is not WRITE");
        assert_eq!(run(OP_BLOCK_READ, 2, 0, 512, 0, 0), (IO_ERR_PERM, CQE_F_REFUSED), "another partition");
        assert_eq!(block_seen().len(), 1);

        // The run is whole sectors inside the 2 KiB window.
        for (off, len) in [(0u32, 0u32), (0, 100), (0, 513), (1536, 1024), (u32::MAX, 512), (0, 2560)] {
            assert_eq!(
                run(OP_BLOCK_READ, 1, off, len, 0, 0),
                (IO_ERR_INVALID_PARAM, CQE_F_REFUSED),
                "offset {off} len {len}"
            );
        }
        assert_eq!(run(OP_BLOCK_READ, 1, 1536, 512, 0, 0), (512, 0), "the last sector of the window");
        assert_eq!(block_seen().len(), 2);

        // WRITE: runs with the class, and containment refuses it.
        grant_dev(OWNER, blk, 1, CapPerms::RW);
        // A write the device completed is on the device, not durable.
        let queued = if azos_limits::IORING_ASYNC { CQE_F_QUEUED } else { 0 };
        assert_eq!(run(OP_BLOCK_WRITE, 1, 0, 512, 7, 0), (512, queued));
        assert_eq!(block_seen().last(), Some(&(1, true, 7, 512)));
        CONTAINED.store(true, AOrd::SeqCst);
        let before = block_seen().len();
        assert_eq!(run(OP_BLOCK_WRITE, 1, 0, 512, 7, 0), (IO_ERR_CONTAINED, CQE_F_REFUSED));
        assert_eq!(run(OP_BLOCK_READ, 1, 0, 512, 7, 0), (512, 0), "a read is not contained");
        assert_eq!(block_seen().len(), before + 1);
    }

    /// Every executable opcode asks the profile for its own gate (the typed
    /// syscall it stands for, or the kernel-hosted interface whose op it is),
    /// on a kernel ring where no capability can refuse first.
    ///
    /// **Canaries.** Swap two entries of `opcode_gate`: the literal pins go
    /// red. Map an opcode to `None`: its entry reads `-ENOSYS`, not `-EPERM`.
    /// Ask the syscall verdict for a device opcode instead of the interface's:
    /// the opcode runs past a profile that does not list the interface.
    #[test]
    fn every_executable_opcode_asks_seccomp_for_its_own_gate() {
        use azos_devif::key;
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        let dev = OpGate::Iface;
        let opg = OpGate::Op;
        let table = [
            (OP_READ_SENSOR, dev(key::SENSOR), 12),
            (OP_WRITE_GPIO, dev(key::GPIO), 8),
            (OP_READ_GPIO, dev(key::GPIO), 8),
            (OP_I2C_READ, dev(key::I2C), 9),
            (OP_I2C_WRITE, dev(key::I2C), 9),
            (OP_PWM_SET, dev(key::PWM), 10),
            (OP_MOTOR_SPEED, dev(key::MOTOR), 11),
            (OP_NET_SEND, opg(azos_abi::invoke::NODE_SEND), 0x6806),
            (OP_NET_RECV, opg(azos_abi::invoke::NODE_RECV), 0x6807),
            (OP_FILE_READ, opg(azos_abi::invoke::NODE_READ), 0x6001),
            (OP_FILE_WRITE, opg(azos_abi::invoke::NODE_WRITE), 0x6102),
            (OP_FSYNC, opg(azos_abi::invoke::NODE_FSYNC), 0x6103),
            (OP_NOTIFY_WAIT, OpGate::Syscall(azos_abi::syscall_nr::SYS_FUTEX_WAIT), 28),
            (OP_BLOCK_READ, dev(key::BLOCK), 14),
            (OP_BLOCK_WRITE, dev(key::BLOCK), 14),
            (OP_BUF_REGISTER, opg(azos_abi::invoke::MEMOBJ_ACQUIRE), 0x2301),
            (OP_BUF_UNREGISTER, opg(azos_abi::invoke::MEMOBJ_ACQUIRE), 0x2301),
        ];
        for (op, gate, literal) in table {
            assert_eq!(opcode_gate(op), Some(gate), "opcode {op}");
            SECCOMP_DENIES.store(0, AOrd::SeqCst);
            IFACE_DENIES.store(0, AOrd::SeqCst);
            OP_DENIES.store(0, AOrd::SeqCst);
            match gate {
                OpGate::Op(o) => {
                    assert_eq!(o as u64, literal, "opcode {op}");
                    OP_DENIES.store(o as u32, AOrd::SeqCst);
                }
                OpGate::Syscall(nr) => {
                    assert_eq!(nr, literal, "opcode {op}");
                    SECCOMP_DENIES.store(nr, AOrd::SeqCst);
                }
                OpGate::Iface(k) => {
                    assert_eq!(k as u64, literal, "opcode {op}");
                    IFACE_DENIES.store(k as u32, AOrd::SeqCst);
                }
            }
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            let c = unsafe { submit_one_cqe(id, phys, sqe(op, 0, 0, 1, 0, 0)) };
            assert_eq!(done(c), (-1, CQE_F_REFUSED), "opcode {op} ran past a profile denying {gate:?}");
        }
        assert!(motor_seen().is_empty() && SENSOR_CALLS.load(AOrd::SeqCst) == 0);
        assert!(io_seen().is_empty(), "a denied file or channel entry reached its hook");
        for op in [OP_NOP, 22, u16::MAX] {
            assert_eq!(opcode_gate(op), None, "opcode {op}");
        }
    }

    /// Every executable opcode asks the owner's Domain pledge mask for the bit
    /// of the call it stands for, after seccomp and before anything else of the
    /// entry: the ring is one trap of case block/wake, so a Domain that gave up
    /// the net, read or write class (or the block/wake case) would otherwise
    /// still do the same work as ring entries. The refusal is `-EACCES`, what
    /// the trap answers, flagged refused, and no hook runs.
    ///
    /// **Canaries.** Delete the `pledge_allowed` question from `admit`: every
    /// line goes red. Ask the bit of the wrong gate (the case of a `Op` gate):
    /// the net and file lines go red.
    #[test]
    fn every_executable_opcode_asks_the_pledge_mask_for_its_own_bit() {
        use azos_abi::invoke::{pledge_case, pledge_class, CLASS_CTL, CLASS_NET, CLASS_READ, CLASS_WRITE};
        use azos_abi::syscall_nr::CASE_BLOCK_WAKE;
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        let bw = pledge_case(CASE_BLOCK_WAKE);
        let table = [
            (OP_READ_SENSOR, bw),
            (OP_WRITE_GPIO, bw),
            (OP_READ_GPIO, bw),
            (OP_I2C_READ, bw),
            (OP_I2C_WRITE, bw),
            (OP_PWM_SET, bw),
            (OP_MOTOR_SPEED, bw),
            (OP_BLOCK_READ, bw),
            (OP_BLOCK_WRITE, bw),
            (OP_TIMER, bw),
            (OP_NOTIFY_WAIT, bw),
            (OP_SQPOLL_START, bw),
            (OP_NET_SEND, pledge_class(CLASS_NET)),
            (OP_NET_RECV, pledge_class(CLASS_NET)),
            (OP_FILE_READ, pledge_class(CLASS_READ)),
            (OP_FILE_WRITE, pledge_class(CLASS_WRITE)),
            (OP_FSYNC, pledge_class(CLASS_WRITE)),
            (OP_BUF_REGISTER, pledge_class(CLASS_CTL)),
            (OP_BUF_UNREGISTER, pledge_class(CLASS_CTL)),
        ];
        for (op, mask_bit) in table {
            let gate = opcode_gate(op).expect("an executable opcode");
            let (_, bit) = gate.pledge();
            assert_eq!(1u32 << bit, mask_bit, "opcode {op}: the bit {gate:?} is judged by");
            PLEDGE_DROPPED.store(bit as u32, AOrd::SeqCst);
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            let c = unsafe { submit_one_cqe(id, phys, sqe(op, 0, 0, 1, 0, 0)) };
            assert_eq!(done(c), (IO_ERR_PLEDGE, CQE_F_REFUSED), "opcode {op} ran past a mask without {gate:?}'s bit");
        }
        assert!(motor_seen().is_empty() && SENSOR_CALLS.load(AOrd::SeqCst) == 0);
        assert!(io_seen().is_empty() && block_seen().is_empty(), "a pledged-away entry reached its hook");
        assert_eq!(__io_ring_parked_for_tests(id as usize), 0, "a refused timer or wait parked");
        // The mask gives up one bit only: an entry of another bit still runs
        // (a kernel ring holds every capability).
        PLEDGE_DROPPED.store(pledge_class(CLASS_NET).trailing_zeros(), AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_READ_SENSOR, 0, 0, 8, 0, 0)) };
        assert_eq!(done(c), (7, 0), "dropping the net class stopped a sensor read");
    }

    /// **Containment refuses write entries, with the typed calls' `-EAGAIN`,
    /// and leaves reads running.** A ring without the capability still gets
    /// `-ECAPPERMS`. The motor opcode is not refused here: the halt rule
    /// refuses it in the motor layer, which its entry reaches.
    ///
    /// **Canary.** Delete `not_contained!()` from the `OP_PWM_SET` arm: the PWM
    /// entry completes 0.
    #[test]
    fn containment_refuses_write_entries_and_leaves_reads_running() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::SENSOR, 0, CapPerms::READ);
        grant_dev(OWNER, azos_devif::key::PWM, 0, CapPerms::RW);
        grant_dev(OWNER, azos_devif::key::GPIO, 3, CapPerms::RW);
        grant_dev(OWNER, azos_devif::key::I2C, i2c_badge(0, 0x40), CapPerms::RW);
        grant_dev(OWNER, azos_devif::key::MOTOR, 0, CapPerms::RW);
        grant_dev(OWNER, azos_devif::key::MOTOR, 1, CapPerms::RW);
        CONTAINED.store(true, AOrd::SeqCst);

        let eagain = (-11, CQE_F_REFUSED);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        assert_eq!(done(unsafe { submit_one_cqe(id, phys, sqe(OP_PWM_SET, 0, 50, 0, 0, 0)) }), eagain, "pwm");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        assert_eq!(done(unsafe { submit_one_cqe(id, phys, sqe(OP_WRITE_GPIO, 3, 1, 0, 0, 0)) }), eagain, "gpio");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        assert_eq!(done(unsafe { submit_one_cqe(id, phys, sqe(OP_I2C_WRITE, 0, 0, 2, 0x40, 0)) }), eagain, "i2c");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        assert_eq!(done(unsafe { submit_one_cqe(id, phys, sqe(OP_NET_SEND, 0x77, 0, 4, 0, 0)) }), eagain, "send");
        assert_eq!(i2c_seen(), None, "a contained write reached the bus");

        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        assert_eq!(done(unsafe { submit_one_cqe(id, phys, sqe(OP_READ_SENSOR, 0, 0, 8, 0, 0)) }), (7, 0), "a read");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        assert_eq!(done(unsafe { submit_one_cqe(id, phys, sqe(OP_MOTOR_SPEED, 10, 10, 0, 0, 0)) }), (0, 0), "motor");
        assert_eq!(motor_seen(), vec![(0, 10), (1, 10)]);
        assert_eq!(
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            done(unsafe { submit_one_cqe(id, phys, sqe(OP_PWM_SET, 1, 50, 0, 0, 0)) }),
            (-201, CQE_F_REFUSED),
            "a channel not held learns nothing from containment"
        );
    }

    /// **A motor entry commands both wheels, and a refusal of either refuses
    /// the entry.** A speed above 100 is refused before any wheel is touched.
    ///
    /// **Canaries.** Return at the first wheel's refusal (`?` on the left
    /// call): the right wheel is never commanded. Report only the right
    /// wheel's result: the left refusal completes 0.
    #[test]
    fn a_motor_entry_commands_both_wheels_and_reports_either_refusal() {
        let (_g, id, phys) = setup_unpriv();
        grant_dev(OWNER, azos_devif::key::MOTOR, 0, CapPerms::RW);
        grant_dev(OWNER, azos_devif::key::MOTOR, 1, CapPerms::RW);
        for refusing in [0u32, 1] {
            MOTOR_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
            MOTOR_REFUSES.store(refusing, AOrd::SeqCst);
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            let c = unsafe { submit_one_cqe(id, phys, sqe(OP_MOTOR_SPEED, 40, 40, 0, 0, 0)) };
            assert_eq!(done(c), (-11, CQE_F_REFUSED), "wheel {refusing} refused");
            assert_eq!(motor_seen(), vec![(0, 40), (1, 40)], "wheel {refusing} refused");
        }
        MOTOR_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        MOTOR_REFUSES.store(u32::MAX, AOrd::SeqCst);
        for (l, r) in [(101, 0), (0, 101), (u32::MAX, u32::MAX)] {
            // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
            let c = unsafe { submit_one_cqe(id, phys, sqe(OP_MOTOR_SPEED, l, r, 0, 0, 0)) };
            assert_eq!(done(c), (-22, CQE_F_REFUSED), "({l}, {r})");
        }
        assert!(motor_seen().is_empty(), "an out-of-range speed reached a wheel");
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_MOTOR_SPEED, 0, 25, 0, 0, 0)) };
        assert_eq!(done(c), (0, 0));
        assert_eq!(motor_seen(), vec![(0, 0), (1, 25)]);
    }

    // ── The user mapping of the ring page ──────────────────────────────────

    /// `(va, frees of the ring page when the unmap ran)` for each unmap call.
    static UNMAPS: Mutex<Vec<(usize, u32)>> = Mutex::new(Vec::new());
    static UNMAP_PHYS: AtomicUsize = AtomicUsize::new(0);
    fn record_unmap(va: usize) {
        let frees = azos_mm::shim_free_count(UNMAP_PHYS.load(AOrd::SeqCst));
        UNMAPS.lock().unwrap_or_else(|e| e.into_inner()).push((va, frees));
    }

    /// **A mapped ring's page is freed only by the destroy that unmaps it,
    /// only after the unmap, and only for its owner.** The plain destroys
    /// refuse it; the owner's exit frees it without an unmap, since the dead
    /// address space never runs again.
    ///
    /// **Canaries.** Drop `state.user_va != 0` from `destroy_locked`: the plain
    /// destroy frees a mapped page. Free before calling `unmap` in
    /// `io_ring_destroy_mapped_ref`: the unmap sees one free. Drop the owner
    /// test there: the stranger's destroy succeeds.
    #[test]
    fn a_mapped_ring_is_freed_only_after_its_unmap_and_only_for_its_owner() {
        const VA: usize = 0x6000_0000;
        let _g = setup_gen();
        UNMAPS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let (cap, r) = create_for(OWNER);
        let idx = LAYOUT.idx(r);
        let phys = __io_ring_slot_for_tests(idx).3;
        UNMAP_PHYS.store(phys, AOrd::SeqCst);

        assert_eq!(io_ring_record_user_va(r, OTHER, VA), Err(IoRingCapError::Closed), "not the owner");
        assert_eq!(io_ring_record_user_va(r, OWNER, VA), Ok(()));
        assert_eq!(io_ring_record_user_va(r, OWNER, VA + 0x1000), Err(IoRingCapError::Closed), "one mapping");
        assert_eq!(io_ring_user_va(r), Ok(VA));

        assert!(!io_ring_destroy(idx), "the untyped destroy freed a mapped page");
        assert_eq!(destroy(OWNER, cap), Err(IoRingCapError::Closed), "the unmapping-blind typed destroy");
        assert_eq!(
            io_ring_destroy_mapped_ref(r, OTHER, record_unmap),
            Err(IoRingCapError::Closed),
            "a stranger cannot reach the owner's PTE"
        );
        assert_eq!(azos_mm::shim_free_count(phys), 0);
        assert!(UNMAPS.lock().unwrap_or_else(|e| e.into_inner()).is_empty());

        assert_eq!(io_ring_destroy_mapped_ref(r, OWNER, record_unmap), Ok(()));
        assert_eq!(*UNMAPS.lock().unwrap_or_else(|e| e.into_inner()), vec![(VA, 0)], "unmapped, before the free");
        assert_eq!(azos_mm::shim_free_count(phys), 1);
        assert_eq!(io_ring_owner(idx), None);
        assert_eq!(io_ring_destroy_mapped_ref(r, OWNER, record_unmap), Err(STALE), "once");

        // The exit path: freed with no unmap.
        let (_cap2, r2) = create_for(OWNER);
        let phys2 = __io_ring_slot_for_tests(LAYOUT.idx(r2)).3;
        // The allocator may hand the first page back; count from here.
        let frees = azos_mm::shim_free_count(phys2);
        assert_eq!(io_ring_record_user_va(r2, OWNER, VA), Ok(()));
        io_ring_release_all(OWNER);
        assert_eq!(azos_mm::shim_free_count(phys2), frees + 1);
        assert_eq!(UNMAPS.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);
    }

    // ── File, channel, timer and wait entries ────────────────────────────────

    /// Put one entry on the SQ without submitting it.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test, and nothing else touches that ring meanwhile.
    unsafe fn queue(phys: usize, e: SqEntry) {
        let ring = phys as *mut IoRing;
        let tail = (*ring).sq_tail.load(Ordering::Acquire);
        (*ring).sq_entries[(tail as usize) % RING_SQ_SIZE] = e;
        (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
    }

    fn tagged(mut e: SqEntry, user_data: u64) -> SqEntry {
        e.user_data = user_data;
        e
    }

    /// **The file entries reach their typed call's function with
    /// the ring's OWNER, the handle and the bounded window**, and a refusal the
    /// entry reports completes flagged. The window is checked before the
    /// handle is: an out-of-range window never reaches the hook.
    ///
    /// **Canaries.** Pass `sqe.opcode == OP_FILE_READ` as `write`: the file
    /// rows swap.
    /// Drop the window check: the 4000-byte read reaches the hook.
    #[test]
    fn file_entries_reach_the_typed_call_with_the_owner_and_window() {
        let (_g, id, phys) = setup_unpriv();
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let r = |e| unsafe { done(submit_one_cqe(id, phys, e)) };
        assert_eq!(r(sqe(OP_FILE_READ, 0x11, 0, 16, 0, 0)), (16, 0));
        assert_eq!(r(sqe(OP_FILE_WRITE, 0x12, 64, 8, 0, 0)), (8, CQE_F_QUEUED), "a write completes queued");
        assert_eq!(
            io_seen(),
            vec![(OWNER, 0x11, false, 16), (OWNER, 0x12, true, 8)]
        );
        assert_eq!(r(sqe(OP_FILE_READ, 0x11, 0, 4000, 0, 0)), (IO_ERR_INVALID_PARAM, CQE_F_REFUSED));
        assert_eq!(r(sqe(OP_FILE_READ, BAD_CAP, 0, 16, 0, 0)), (E_STALE, CQE_F_REFUSED));
        assert_eq!(io_seen().len(), 2, "a refused entry reached its hook");
    }

    /// **A refused device entry is recorded, charged to the ring's owner**, the
    /// way the typed call records its refusal; a granted one records nothing.
    ///
    /// **Canary.** Delete the `note_denial` call in `need_dev!`: `denials()`
    /// stays empty after the refusal.
    #[test]
    fn a_refused_device_entry_is_recorded_for_the_owner() {
        let (_g, id, phys) = setup_unpriv();
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_WRITE_GPIO, 7, 1, 0, 0, 0)) };
        assert_eq!(done(c), (IO_ERR_PERM, CQE_F_REFUSED));
        assert_eq!(denials(), vec![(OWNER, ty::ENDPOINT)]);
        grant_dev(OWNER, azos_devif::key::GPIO, 7, CapPerms::RW);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_WRITE_GPIO, 7, 1, 0, 0, 0)) };
        assert_eq!(done(c), (0, 0));
        assert_eq!(denials().len(), 1, "a granted entry was recorded as a denial");
    }

    /// **A timer parks, and completes in the first pass at or after its
    /// deadline, with its own tag.** A deadline already passed completes at
    /// once with 1, as `SYS_SLEEP_UNTIL` answers 1 without blocking.
    ///
    /// **Canaries.** Skip `reap_parked`: the third submit completes nothing.
    /// Complete a parked timer without checking `deadline_reached`: the second
    /// submit completes it early.
    #[test]
    fn a_timer_parks_until_its_deadline_and_completes_with_its_tag() {
        let (_g, id, phys) = setup_unpriv();
        let ring = phys as *mut IoRing;
        NOW_NS.store(100, AOrd::SeqCst);
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue(phys, tagged(sqe(OP_TIMER, 200, 0, 0, 0, 0), 0x7171));
            assert_eq!(io_ring_submit(id), 0, "a future deadline completed at once");
            assert_eq!(__io_ring_parked_for_tests(id as usize), 1);
            assert_eq!((*ring).sq_head.load(Ordering::Acquire), 1, "the entry was consumed");
            NOW_NS.store(199, AOrd::SeqCst);
            assert_eq!(io_ring_submit(id), 0, "completed before its deadline");
            NOW_NS.store(200, AOrd::SeqCst);
            assert_eq!(io_ring_submit(id), 1, "an empty submit reaps the timer");
            assert_eq!((*ring).cq_entries[0].user_data, 0x7171);
            assert_eq!(done((*ring).cq_entries[0]), (0, 0));
            assert_eq!(__io_ring_parked_for_tests(id as usize), 0);
            // The high word is part of the deadline.
            queue(phys, sqe(OP_TIMER, 0, 1, 0, 0, 0));
            assert_eq!(io_ring_submit(id), 0, "a deadline of 2^32 ns read as 0");
            queue(phys, sqe(OP_TIMER, 50, 0, 0, 0, 0));
            assert_eq!(io_ring_submit(id), 1);
            assert_eq!(done((*ring).cq_entries[1]), (1, 0), "a passed deadline answers 1");
        }
    }

    /// **Every parked entry holds its completion slot.** With eight timers
    /// parked only 24 other entries run before the CQ reads full, a ninth
    /// timer is refused with `-EBUSY`, and all eight still complete.
    ///
    /// **Canary.** Drop `- parked.n` from the back-pressure test: 32 NOPs
    /// run, and the parked timers have no slot to complete into.
    #[test]
    fn parked_entries_reserve_their_completion_slots() {
        let (_g, id, phys) = setup_unpriv();
        let ring = phys as *mut IoRing;
        NOW_NS.store(0, AOrd::SeqCst);
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            for i in 0..RING_MAX_PARKED as u32 {
                queue(phys, tagged(sqe(OP_TIMER, 10 + i, 0, 0, 0, 0), 0x500 + i as u64));
            }
            queue(phys, tagged(sqe(OP_TIMER, 99, 0, 0, 0, 0), 0x5FF));
            assert_eq!(io_ring_submit(id), 1, "only the ninth timer completes, refused");
            assert_eq!(done((*ring).cq_entries[0]), (IO_ERR_PARKED_FULL, CQE_F_REFUSED));
            assert_eq!((*ring).cq_entries[0].user_data, 0x5FF);
            (*ring).cq_head.store(1, Ordering::Release);
            for _ in 0..RING_SQ_SIZE {
                queue(phys, sqe(OP_NOP, 0, 0, 0, 0, 0));
            }
            assert_eq!(io_ring_submit(id), (RING_CQ_SIZE - RING_MAX_PARKED) as i32);
            assert_eq!(io_ring_submit(id), IO_ERR_CQ_FULL, "a NOP took a parked entry's slot");
            // The consumer drains everything; the deadlines pass.
            let t = (*ring).cq_tail.load(Ordering::Acquire);
            (*ring).cq_head.store(t, Ordering::Release);
            NOW_NS.store(1000, AOrd::SeqCst);
            let n = io_ring_submit(id);
            assert_eq!(n, (RING_MAX_PARKED + RING_MAX_PARKED) as i32, "eight timers and the eight NOPs left");
            assert_eq!(__io_ring_parked_for_tests(id as usize), 0);
        }
    }

    /// **A wait completes when the word differs from the expected value**:
    /// at once with 1 if it already does, else parked until a pass sees it
    /// change; a capability refused on a later look completes it flagged.
    ///
    /// **Canaries.** Compare `v == expected` for completion: the parked wait
    /// completes on the unchanged word. Keep a refused look parked: the
    /// revoked wait never completes.
    #[test]
    fn a_wait_completes_when_its_word_changes() {
        let (_g, id, phys) = setup_unpriv();
        let ring = phys as *mut IoRing;
        WORD.store(5, AOrd::SeqCst);
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue(phys, sqe(OP_NOTIFY_WAIT, 0x21, 0, 4, 0, 0));
            assert_eq!(io_ring_submit(id), 1);
            assert_eq!(done((*ring).cq_entries[0]), (1, 0), "a word already changed answers 1");
            queue(phys, tagged(sqe(OP_NOTIFY_WAIT, 0x21, 0, 5, 0, 0), 0x9A));
            assert_eq!(io_ring_submit(id), 0);
            assert_eq!(io_ring_submit(id), 0, "completed on an unchanged word");
            WORD.store(6, AOrd::SeqCst);
            assert_eq!(io_ring_submit(id), 1);
            assert_eq!(done((*ring).cq_entries[1]), (0, 0));
            assert_eq!((*ring).cq_entries[1].user_data, 0x9A);
            // Seccomp is asked with `SYS_FUTEX_WAIT`, the call a wait stands for.
            SECCOMP_DENIES.store(azos_abi::syscall_nr::SYS_FUTEX_WAIT, AOrd::SeqCst);
            queue(phys, sqe(OP_NOTIFY_WAIT, 0x21, 0, 6, 0, 0));
            assert_eq!(io_ring_submit(id), 1);
            assert_eq!(done((*ring).cq_entries[2]), (IO_ERR_SECCOMP, CQE_F_REFUSED));
            SECCOMP_DENIES.store(0, AOrd::SeqCst);
            // A handle refused at submit completes at once, flagged...
            queue(phys, sqe(OP_NOTIFY_WAIT, BAD_CAP, 0, 6, 0, 0));
            assert_eq!(io_ring_submit(id), 1);
            assert_eq!(done((*ring).cq_entries[3]), (E_STALE, CQE_F_REFUSED));
            // ...and one revoked while its wait is parked ends that wait.
            queue(phys, tagged(sqe(OP_NOTIFY_WAIT, 0x21, 0, 6, 0, 0), 0x9B));
            assert_eq!(io_ring_submit(id), 0);
            REVOKED.store(true, AOrd::SeqCst);
            assert_eq!(io_ring_submit(id), 1, "a revoked wait stayed parked");
            assert_eq!(done((*ring).cq_entries[4]), (E_STALE, CQE_F_REFUSED));
            assert_eq!((*ring).cq_entries[4].user_data, 0x9B);
        }
    }

    /// A timer is checked against `SYS_SLEEP_UNTIL`'s row before it parks.
    #[test]
    fn a_timer_asks_seccomp_for_sleep_until() {
        let (_g, id, phys) = setup_unpriv();
        SECCOMP_DENIES.store(azos_abi::syscall_nr::SYS_SLEEP_UNTIL, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `submit_one_cqe`).
        let c = unsafe { submit_one_cqe(id, phys, sqe(OP_TIMER, 1000, 0, 0, 0, 0)) };
        assert_eq!(done(c), (IO_ERR_SECCOMP, CQE_F_REFUSED));
        assert_eq!(__io_ring_parked_for_tests(id as usize), 0, "a denied timer parked");
    }

    /// A recreated ring at a slot starts with nothing parked.
    #[test]
    fn a_destroyed_rings_parked_entries_do_not_reach_the_next_ring() {
        let (_g, id, phys) = setup_unpriv();
        NOW_NS.store(0, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `queue`).
        unsafe { queue(phys, sqe(OP_TIMER, 10, 0, 0, 0, 0)); }
        assert_eq!(io_ring_submit(id), 0);
        assert_eq!(__io_ring_parked_for_tests(id as usize), 1);
        assert!(io_ring_destroy(id));
        let (id2, _phys2) = io_ring_create(OWNER as usize).unwrap();
        assert_eq!(id2, id, "the slot was reused");
        assert_eq!(__io_ring_parked_for_tests(id2 as usize), 0, "the old ring's timer survived");
    }

    // ── SQ polling ─────────────────────────────────────────────────────────

    const POLLER: u32 = 0x5A5A;
    /// `(r, owner)` of every spawn asked for.
    static SPAWNS: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());
    /// Every poller TID a wake was sent to.
    static WAKES: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    fn hook_spawn(r: u32, owner: u32) -> Option<u32> {
        SPAWNS.lock().unwrap_or_else(|e| e.into_inner()).push((r, owner));
        Some(POLLER)
    }
    fn hook_wake(t: u32) {
        WAKES.lock().unwrap_or_else(|e| e.into_inner()).push(t);
    }
    fn wakes() -> Vec<u32> {
        WAKES.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    static TEST_SQPOLL: SqpollHooks = SqpollHooks { spawn: hook_spawn, wake: hook_wake };

    /// An unprivileged ring with the poller hooks registered and nothing
    /// permitted: `(guard, slot, page, packed reference)`.
    fn setup_sqpoll() -> (std::sync::MutexGuard<'static, ()>, u32, usize, u32) {
        let (g, id, phys) = setup_unpriv();
        __io_ring_sqpoll_reset_for_tests();
        io_ring_register_sqpoll(&TEST_SQPOLL);
        SPAWNS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        WAKES.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let r = io_ring_ref(id).expect("live");
        (g, id, phys, r)
    }

    fn sq_flags(phys: usize) -> u32 {
        // SAFETY: `ring` is this test's live ring page; this is an atomic access.
        unsafe { (*(phys as *mut IoRing)).sq_flags.load(Ordering::SeqCst) }
    }

    /// **A poller starts only for an owner the topology permits**, in-band:
    /// refused `-EPERM` without a permit (no task spawned, the entries behind
    /// it still run inline), and with one the START completes 0, the page
    /// says `SQ_F_SQPOLL`, and the entries queued behind it are left for the
    /// poller.
    ///
    /// **Canaries.** Drop the `idle_ms == 0` refusal: the first START spawns.
    /// Drop `stop = res.is_ok()`: the NOP behind the START runs inline.
    #[test]
    fn a_poller_starts_only_when_the_topology_permits_it() {
        let (_g, id, phys, r) = setup_sqpoll();
        let ring = phys as *mut IoRing;
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue(phys, sqe(OP_SQPOLL_START, 0, 0, 0, 0, 0));
            queue(phys, sqe(OP_NOP, 0, 0, 0, 0, 0));
            assert_eq!(io_ring_submit_ref(OWNER, r), Ok(2));
            assert_eq!(done((*ring).cq_entries[0]), (IO_ERR_SQPOLL_DENIED, CQE_F_REFUSED));
            assert!(SPAWNS.lock().unwrap().is_empty(), "a poller was spawned without a permit");
            assert_eq!(sq_flags(phys), 0);

            assert!(io_ring_permit_sqpoll(OWNER, 20));
            queue(phys, sqe(OP_SQPOLL_START, 0, 0, 0, 0, 0));
            queue(phys, sqe(OP_NOP, 0, 0, 0, 0, 0));
            assert_eq!(io_ring_submit_ref(OWNER, r), Ok(1), "the NOP behind START ran inline");
            assert_eq!(done((*ring).cq_entries[2]), (0, 0));
            assert_eq!(*SPAWNS.lock().unwrap(), vec![(r, OWNER)]);
            assert_eq!(sq_flags(phys) & SQ_F_SQPOLL, SQ_F_SQPOLL);
            assert_eq!(__io_ring_poller_for_tests(id), (POLLER, 20));
            assert_eq!((*ring).sq_head.load(Ordering::Acquire), 3, "the NOP was consumed inline");
        }
    }

    /// **Once a poller runs the ring, a submit is only its wake-up**: it
    /// claims nothing, runs nothing, answers 0 and wakes the poller; a task
    /// that is not the owner is refused. The poller's own pass runs the entry.
    #[test]
    fn a_submit_on_a_polled_ring_only_wakes_the_poller() {
        let (_g, _id, phys, r) = setup_sqpoll();
        assert!(io_ring_permit_sqpoll(OWNER, 20));
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue(phys, sqe(OP_SQPOLL_START, 0, 0, 0, 0, 0));
            assert_eq!(io_ring_submit_ref(OWNER, r), Ok(1));
            queue(phys, sqe(OP_NOP, 0, 0, 0, 0, 0));
            assert_eq!(io_ring_submit_ref(OWNER, r), Ok(0), "a polled ring's submit ran an entry");
            assert_eq!(wakes(), vec![POLLER]);
            assert_eq!(
                io_ring_submit_ref(OTHER, r),
                Err(IoRingCapError::Cap(crate::cap::CapError::MissingPerms))
            );
            assert_eq!(io_ring_sqpoll_pass(r), SqpollPass::Done { ran: 1, idle_ms: 20, next_deadline_ns: u64::MAX, words: false });
            assert_eq!(done((*(phys as *mut IoRing)).cq_entries[1]), (0, 0));
        }
    }

    /// **The poller's pass authorizes each entry as a submit does, and a
    /// refusal is recorded for the OWNER.** The pass runs with a different
    /// current task (the poller); the capability is the owner's.
    ///
    /// **Canary.** Key `need_dev!` on `current_task_tid()`: the GPIO read the
    /// owner holds is refused.
    #[test]
    fn a_poller_pass_authorizes_on_the_owner_and_records_its_refusals() {
        let (_g, _id, phys, r) = setup_sqpoll();
        assert!(io_ring_permit_sqpoll(OWNER, 20));
        grant_dev(OWNER, azos_devif::key::GPIO, 5, CapPerms::READ);
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue(phys, sqe(OP_SQPOLL_START, 0, 0, 0, 0, 0));
            assert_eq!(io_ring_submit_ref(OWNER, r), Ok(1));
            azos_sched::shim_set_current(POLLER, 0);
            queue(phys, sqe(OP_READ_GPIO, 5, 0, 0, 0, 0));
            queue(phys, sqe(OP_WRITE_GPIO, 5, 1, 0, 0, 0));
            let p = io_ring_sqpoll_pass(r);
            assert!(matches!(p, SqpollPass::Done { ran: 2, .. }), "{p:?}");
            let ring = phys as *mut IoRing;
            assert_eq!(done((*ring).cq_entries[1]), (0, 0), "the owner's READ grant");
            assert_eq!(done((*ring).cq_entries[2]), (IO_ERR_PERM, CQE_F_REFUSED), "no WRITE grant");
            assert_eq!(denials(), vec![(OWNER, ty::ENDPOINT)], "recorded for someone else");
        }
    }

    /// **The park handshake.** An empty SQ parks with `SQ_F_NEED_WAKEUP` set,
    /// the next pass clears it, and an entry already published keeps the
    /// poller from parking.
    ///
    /// **Canary.** Skip the `sq_tail` re-read: the pending case parks.
    #[test]
    fn a_poller_parks_only_on_an_empty_queue_and_its_pass_clears_the_flag() {
        let (_g, _id, phys, r) = setup_sqpoll();
        assert!(io_ring_permit_sqpoll(OWNER, 20));
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue(phys, sqe(OP_SQPOLL_START, 0, 0, 0, 0, 0));
            assert_eq!(io_ring_submit_ref(OWNER, r), Ok(1));
        }
        assert_eq!(io_ring_sqpoll_prepare_park(r), SqpollPark::Parked);
        assert_eq!(sq_flags(phys), SQ_F_SQPOLL | SQ_F_NEED_WAKEUP);
        assert!(matches!(io_ring_sqpoll_pass(r), SqpollPass::Done { ran: 0, .. }));
        assert_eq!(sq_flags(phys), SQ_F_SQPOLL, "the pass left NEED_WAKEUP set");
        // SAFETY: `phys` is this test's live ring page, no other user (see `queue`).
        unsafe { queue(phys, sqe(OP_NOP, 0, 0, 0, 0, 0)); }
        assert_eq!(io_ring_sqpoll_prepare_park(r), SqpollPark::NotIdle);
        assert_eq!(sq_flags(phys), SQ_F_SQPOLL, "NEED_WAKEUP left set on a busy ring");
        // A parked timer is reported for the poller's sleep.
        NOW_NS.store(0, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `queue`).
        unsafe { queue(phys, sqe(OP_TIMER, 500, 0, 0, 0, 0)); }
        let p = io_ring_sqpoll_pass(r);
        assert!(matches!(p, SqpollPass::Done { ran: 1, next_deadline_ns: 500, .. }), "{p:?}");
    }

    /// **A destroyed ring wakes its poller, whose next pass finds it gone**;
    /// the owner's exit does the same and withdraws its permit.
    ///
    /// **Canary.** Drop `sqpoll_wake(poller)` from `io_ring_destroy_ref`: no
    /// wake is recorded and a parked poller would sleep forever.
    #[test]
    fn destroy_and_exit_wake_the_poller_and_the_ring_reads_gone() {
        let (_g, id, phys, r) = setup_sqpoll();
        assert!(io_ring_permit_sqpoll(OWNER, 20));
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue(phys, sqe(OP_SQPOLL_START, 0, 0, 0, 0, 0));
            assert_eq!(io_ring_submit_ref(OWNER, r), Ok(1));
        }
        assert_eq!(io_ring_destroy_ref(r), Ok(()));
        assert_eq!(wakes(), vec![POLLER]);
        assert_eq!(io_ring_sqpoll_pass(r), SqpollPass::Gone);
        assert_eq!(io_ring_sqpoll_prepare_park(r), SqpollPark::Gone);

        let (id2, phys2) = io_ring_create(OWNER as usize).unwrap();
        assert_eq!(id2, id);
        let r2 = io_ring_ref(id2).unwrap();
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            queue(phys2, sqe(OP_SQPOLL_START, 0, 0, 0, 0, 0));
            assert_eq!(io_ring_submit_ref(OWNER, r2), Ok(1));
        }
        io_ring_release_all(OWNER);
        assert_eq!(wakes(), vec![POLLER, POLLER]);
        assert_eq!(io_ring_sqpoll_pass(r2), SqpollPass::Gone);
        assert_eq!(sqpoll_permit(OWNER), 0, "the exit left the permit behind");
    }

    // ── Wave 11 (PORTWAIT): a ring bound to an event port ─────────────────

    /// A pass that writes a completion signals the port the ring is linked
    /// to (one event, type 2); a pass that writes none does not; a completion
    /// unread at link time is reported (`ready`); a pass whose port is gone
    /// clears the link.
    ///
    /// **Canaries.** Signal on every release (`completed` ignored in
    /// `release_ring_with`): the empty submit leaves an event. Skip
    /// `io_ring_clear_link`: the last link is still set and `P2` is `Busy`.
    #[test]
    fn a_pass_with_completions_signals_the_bound_port() {
        use crate::port::{self, PortCapError, PortSourceKind, PORT_EVENT_RING};
        use crate::port_link::{LinkSet, PortLink};
        let (_g, id, phys) = setup_unpriv();
        port::__port_reset_for_tests();
        let r = io_ring_ref(id).expect("live");
        let p = port::port_create_ref(OWNER as usize).expect("port");
        let kind = PortSourceKind::Ring(r);
        let (link, _) = port::port_bind_object(p, kind, 0x99, 0xB0).expect("bind");
        assert_eq!(io_ring_set_link(r, link, PortLink::NONE), Ok(LinkSet::Stored { ready: false }));

        assert_eq!(io_ring_submit(id), 0, "an empty SQ");
        assert_eq!(port::port_poll_ref(p), Err(PortCapError::Empty), "no completion, no event");
        // SAFETY: `phys` is this test's live ring page, no other user (see `queue`).
        unsafe { queue(phys, sqe(OP_NOP, 0, 0, 0, 0, 0)); }
        assert_eq!(io_ring_submit(id), 1);
        let e = port::port_poll_ref(p).expect("an event");
        assert_eq!((e.key, e.source_type, e.source_id), (0xB0, PORT_EVENT_RING, 0x99));

        // The completion is still unread: a new link reports it at once.
        assert_eq!(io_ring_set_link(r, link, PortLink::NONE), Ok(LinkSet::Stored { ready: true }));

        assert_eq!(port::port_destroy_ref(p), Ok(()));
        // SAFETY: `phys` is this test's live ring page, no other user (see `queue`).
        unsafe { queue(phys, sqe(OP_NOP, 0, 0, 0, 0, 0)); }
        assert_eq!(io_ring_submit(id), 1);
        let p2 = PortLink { port: 0x4242, epoch: 0, slot: 0 };
        assert_eq!(io_ring_set_link(r, p2, PortLink::NONE), Ok(LinkSet::Stored { ready: true }), "the dead link was cleared");
    }

    // ── K1 (b)(c): queued writes, a durable fsync, linked entries ─────────

    /// Push `sqes` onto the ring and submit once, then the worker's turn
    /// ([`submit_settled`]); answers the completions written.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test as ring `id`, and nothing else touches that ring meanwhile.
    unsafe fn push_all(id: u32, phys: usize, sqes: &[SqEntry]) -> i32 {
        push_sqes(phys, sqes);
        submit_settled(id)
    }

    /// [`push_all`] without the worker's turn: answers the submit's own count.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test as ring `id`, and nothing else touches that ring meanwhile.
    unsafe fn push_all_unsettled(id: u32, phys: usize, sqes: &[SqEntry]) -> i32 {
        push_sqes(phys, sqes);
        io_ring_submit(id)
    }

    /// Append `sqes` at the SQ tail and publish the new tail.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test, and nothing else touches that ring meanwhile.
    unsafe fn push_sqes(phys: usize, sqes: &[SqEntry]) {
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        let mut tail = (*ring).sq_tail.load(Ordering::Acquire);
        for e in sqes {
            (*ring).sq_entries[(tail as usize) % RING_SQ_SIZE] = *e;
            tail = tail.wrapping_add(1);
        }
        (*ring).sq_tail.store(tail, Ordering::Release);
    }

    /// Every unread completion, consumed: `(user_data, result, flags)`.
    ///
    /// # Safety
    ///
    /// `phys` is the physical address of a live ring page created by the
    /// calling test, and nothing else touches that ring meanwhile.
    unsafe fn drain(phys: usize) -> Vec<(u64, i32, u32)> {
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        let mut head = (*ring).cq_head.load(Ordering::Acquire);
        let tail = (*ring).cq_tail.load(Ordering::Acquire);
        let mut out = Vec::new();
        while head != tail {
            let c = (*ring).cq_entries[(head as usize) % RING_CQ_SIZE];
            out.push((c.user_data, c.result, c.flags));
            head = head.wrapping_add(1);
        }
        (*ring).cq_head.store(head, Ordering::Release);
        out
    }

    fn ent(opcode: u16, cap: u32, flags: u16, ud: u64) -> SqEntry {
        SqEntry { opcode, flags, param0: cap, param1: 0, param2: 8, addr: 0, reg: 0, user_data: ud }
    }

    const FILE: u32 = 7;

    /// A file write completes QUEUED; an fsync behind it does NOT complete in
    /// the submit, and its CQE arrives, DURABLE, only once the flusher has
    /// finished, posted from the flush path with no second submit.
    ///
    /// **Canary** `ioring-sync-fsync-canary` (the fsync answers in the
    /// submit): red at "no fsync CQE before the flush".
    #[test]
    fn a_write_is_queued_and_its_fsync_completes_only_after_the_flush() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        let mut batch = Vec::new();
        for i in 0..4 { batch.push(ent(OP_FILE_WRITE, FILE, 0, i)); }
        batch.push(ent(OP_FSYNC, FILE, 0, 99));
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe { push_all(id, phys, &batch) };
        assert_eq!(n, 4, "the four writes complete in the submit, the fsync does not");
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        let cqes = unsafe { drain(phys) };
        assert_eq!(cqes.len(), 4);
        for (i, c) in cqes.iter().enumerate() {
            assert_eq!(*c, (i as u64, 8, CQE_F_QUEUED), "write {i} completes queued");
        }
        assert!(cqes.iter().all(|c| c.0 != 99), "no fsync CQE before the flush");
        // A second submit with nothing new: still parked.
        assert_eq!(io_ring_submit(id), 0, "the fsync completed before its flush");
        assert_eq!(FLUSH_ASKED.load(AOrd::SeqCst), 1, "the fsync asked for one flush");
        // The flusher finishes: the flush path posts the completion.
        flush_now(false);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        let cqes = unsafe { drain(phys) };
        assert_eq!(cqes, vec![(99, 0, CQE_F_DURABLE)], "the fsync completes durable from the flush path");
        assert!(io_ring_destroy(id));
    }

    /// A failed flush completes the fsync with -EIO and no DURABLE flag.
    #[test]
    fn a_failed_flush_completes_the_fsync_without_durable() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        assert_eq!(unsafe { push_all(id, phys, &[ent(OP_FSYNC, FILE, 0, 5)]) }, 0);
        flush_now(true);
        let eio = azos_abi::error::Errno::EIO.to_syscall_ret() as i32;
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(5, eio, 0)]);
        assert!(io_ring_destroy(id));
    }

    /// Flags: a refusal is REFUSED only (never QUEUED); a read is neither.
    #[test]
    fn a_refused_write_is_not_queued_and_a_read_is_not_queued() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe {
            push_all(id, phys, &[ent(OP_FILE_WRITE, BAD_CAP, 0, 1), ent(OP_FILE_READ, FILE, 0, 2),
                                 ent(OP_FSYNC, BAD_CAP, 0, 3)])
        };
        assert_eq!(n, 3);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, E_STALE, CQE_F_REFUSED), (2, 8, 0), (3, E_STALE, CQE_F_REFUSED)]);
        assert_eq!(FLUSH_ASKED.load(AOrd::SeqCst), 0, "a refused fsync asks for no flush");
        assert!(io_ring_destroy(id));
    }

    /// LINK write -> fsync: a failed write cancels the fsync (no flush is
    /// asked); a good one lets it run. Positive control: without LINK the
    /// fsync runs after the failed write.
    #[test]
    fn a_linked_fsync_is_canceled_by_its_failed_write() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe { push_all(id, phys, &[ent(OP_FILE_WRITE, BAD_CAP, SQE_F_LINK, 1), ent(OP_FSYNC, FILE, 0, 2)]) };
        assert_eq!(n, 2);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, E_STALE, CQE_F_REFUSED), (2, IO_ERR_CANCELED, CQE_F_REFUSED)]);
        assert_eq!(FLUSH_ASKED.load(AOrd::SeqCst), 0, "a canceled fsync asked for a flush");
        // Control: no LINK, the fsync runs (parks).
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe { push_all(id, phys, &[ent(OP_FILE_WRITE, BAD_CAP, 0, 3), ent(OP_FSYNC, FILE, 0, 4)]) };
        assert_eq!(n, 1);
        assert_eq!(FLUSH_ASKED.load(AOrd::SeqCst), 1);
        // A good linked write: the fsync runs.
        flush_now(false);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        let _ = unsafe { drain(phys) };
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe { push_all(id, phys, &[ent(OP_FILE_WRITE, FILE, SQE_F_LINK, 5), ent(OP_FSYNC, FILE, 0, 6)]) };
        assert_eq!(n, 1);
        assert_eq!(FLUSH_ASKED.load(AOrd::SeqCst), 2);
        flush_now(false);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(5, 8, CQE_F_QUEUED), (6, 0, CQE_F_DURABLE)]);
        assert!(io_ring_destroy(id));
    }

    /// LINK fsync -> write: the parked fsync is a barrier; the write behind it
    /// runs only after the flush, and a failed flush cancels it.
    #[test]
    fn a_linked_fsync_is_a_barrier_for_the_next_entry() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe { push_all(id, phys, &[ent(OP_FSYNC, FILE, SQE_F_LINK, 1), ent(OP_FILE_WRITE, FILE, 0, 2)]) };
        assert_eq!(n, 0, "the write ran past its barrier");
        assert!(io_seen().iter().all(|s| !s.2), "the write reached the file before the flush");
        assert_eq!(io_ring_submit(id), 0, "the barrier fell before the flush");
        flush_now(false);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 0, CQE_F_DURABLE)]);
        assert_eq!(submit_settled(id), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(2, 8, CQE_F_QUEUED)]);
        // A failed barrier cancels.
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe { push_all(id, phys, &[ent(OP_FSYNC, FILE, SQE_F_LINK, 3), ent(OP_FILE_WRITE, FILE, 0, 4)]) };
        assert_eq!(n, 0);
        flush_now(true);
        assert_eq!(submit_settled(id), 1, "the flush posted the fsync; the submit cancels the write");
        let eio = azos_abi::error::Errno::EIO.to_syscall_ret() as i32;
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(3, eio, 0), (4, IO_ERR_CANCELED, CQE_F_REFUSED)]);
        assert!(io_ring_destroy(id));
    }

    /// The flush ends while a pass holds the ring: the claim's release posts.
    #[test]
    fn a_flush_ending_mid_pass_is_posted_at_the_release() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        assert_eq!(unsafe { push_all(id, phys, &[ent(OP_FSYNC, FILE, 0, 1)]) }, 0);
        let (p, owner, _) = claim_ring(id).expect("claim");
        assert_eq!((p, owner), (phys, OWNER));
        flush_now(false);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert!(unsafe { drain(phys) }.is_empty(), "posted while another pass held the ring");
        release_ring(id);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 0, CQE_F_DURABLE)]);
        assert!(io_ring_destroy(id));
    }

    /// The RAM `IORING_MAX_PARKED` and `MAX_IO_RINGS` help texts quote.
    #[test]
    fn parked_slot_and_ring_state_sizes_match_the_kconfig_help() {
        assert_eq!(core::mem::size_of::<Parked>(), 32);
        if RING_MAX_PARKED == 8 {
            assert_eq!(core::mem::size_of::<ParkedSet>(), 264);
        }
    }

    // ── K1 hand-off: an RT submitter never runs a file entry ───────────────

    /// A real-time submitter's file and fsync entries are HANDED OFF: the
    /// submit stops at the first one (running what precedes it), wakes the
    /// worker, and the worker's pass runs the rest in SQ order — writes before
    /// the fsync, so the fsync's flush covers them — up to the tail that was
    /// SUBMITTED, never an entry published after it.
    ///
    /// **Canary.** Make `may_block` always true in `submit_claimed`: the
    /// writes run in the submit (`io_seen` non-empty after it).
    #[test]
    fn an_rt_submitters_file_entries_are_handed_off_to_the_worker_in_order() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        MAY_BLOCK.store(false, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe {
            push_all(id, phys, &[ent(OP_NOP, 0, 0, 1), ent(OP_FILE_WRITE, FILE, 0, 2), ent(OP_NOP, 0, 0, 3),
                                 ent(OP_FILE_WRITE, FILE, SQE_F_LINK, 4), ent(OP_FSYNC, FILE, 0, 5)])
        };
        assert_eq!(n, 1, "only the entry before the first file entry runs in the submit");
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 0, 0)]);
        assert!(io_seen().is_empty(), "an RT submit reached the file layer");
        assert_eq!(KICKS.load(AOrd::SeqCst), 1, "the worker was not woken");
        // Published after the submit, never submitted: not the worker's.
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            let t = (*ring).sq_tail.load(Ordering::Acquire);
            (*ring).sq_entries[(t as usize) % RING_SQ_SIZE] = ent(OP_NOP, 0, 0, 6);
            (*ring).sq_tail.store(t.wrapping_add(1), Ordering::Release);
        }
        assert_eq!(io_ring_worker_pass(), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(2, 8, CQE_F_QUEUED), (3, 0, 0), (4, 8, CQE_F_QUEUED)]);
        assert_eq!(
            io_seen(),
            vec![(OWNER, FILE, true, 8), (OWNER, FILE, true, 8), (OWNER, FILE, false, 0)],
            "the fsync asked for its flush before the writes it must cover"
        );
        assert_eq!(io_ring_worker_pass(), 0, "a second worker pass with nothing handed off");
        flush_now(false);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(5, 0, CQE_F_DURABLE)]);
        // The unsubmitted entry runs at the owner's next submit.
        assert_eq!(io_ring_submit(id), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(6, 0, 0)]);
        assert!(io_ring_destroy(id));
    }

    /// An RT submitter's READ is handed off too; it completes (its bytes in the
    /// ring buffer) from the worker's pass, unflagged.
    #[test]
    fn an_rt_submitters_read_completes_from_the_worker() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        MAY_BLOCK.store(false, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        assert_eq!(unsafe { push_all(id, phys, &[ent(OP_FILE_READ, FILE, 0, 1)]) }, 0);
        assert!(io_seen().is_empty());
        assert_eq!(io_ring_worker_pass(), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 8, 0)]);
        assert_eq!(io_seen(), vec![(OWNER, FILE, false, 8)]);
        assert!(io_ring_destroy(id));
    }

    /// Without Kconfig `IORING_ASYNC` a task that may block keeps the inline
    /// path: no hand-off, no wake-up. With it, the file entry of EVERY
    /// submitter is the worker's: the submit completes nothing, wakes the
    /// worker, and the worker's pass completes the write, queued.
    ///
    /// **Canary.** Drop the `IORING_ASYNC` arm of `needs_worker`: the submit
    /// completes the write itself and wakes nobody.
    #[test]
    fn a_non_rt_submitters_file_entry_goes_to_the_worker_only_with_ioring_async() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        if azos_limits::IORING_ASYNC {
            // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
            assert_eq!(unsafe { push_all_unsettled(id, phys, &[ent(OP_FILE_WRITE, FILE, 0, 1)]) }, 0);
            assert!(io_seen().is_empty(), "a submit ran a file entry");
            assert_eq!(KICKS.load(AOrd::SeqCst), 1, "the worker was not woken");
            assert_eq!(io_ring_worker_pass(), 1);
        } else {
            // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
            assert_eq!(unsafe { push_all_unsettled(id, phys, &[ent(OP_FILE_WRITE, FILE, 0, 1)]) }, 1);
            assert_eq!(KICKS.load(AOrd::SeqCst), 0);
            assert_eq!(io_ring_worker_pass(), 0);
        }
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 8, CQE_F_QUEUED)]);
        assert!(io_ring_destroy(id));
    }

    /// The worker finds the ring held by another pass: it leaves the hand-off
    /// marked, and that claim's release wakes it again; it then runs.
    #[test]
    fn a_handoff_found_in_flight_is_rerun_after_the_release() {
        let _g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        MAY_BLOCK.store(false, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        assert_eq!(unsafe { push_all(id, phys, &[ent(OP_FILE_WRITE, FILE, 0, 1)]) }, 0);
        assert_eq!(KICKS.load(AOrd::SeqCst), 1);
        claim_ring(id).expect("claim");
        assert_eq!(io_ring_worker_pass(), 0, "the worker ran a ring another pass held");
        release_ring(id);
        assert_eq!(KICKS.load(AOrd::SeqCst), 2, "the release did not wake the worker");
        assert_eq!(io_ring_worker_pass(), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 8, CQE_F_QUEUED)]);
        assert!(io_ring_destroy(id));
    }

    /// With no worker the RT submitter's file entry is refused (-EAGAIN), not
    /// run inline; a canceled link behind it stays canceled.
    #[test]
    fn with_no_worker_an_rt_file_entry_is_refused_not_run() {
        static NO_WORKER_OPS: IoRingOps = IoRingOps { handoff_kick: None, ..TEST_OPS };
        let _g = setup();
        io_ring_register_ops(&NO_WORKER_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        MAY_BLOCK.store(false, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe { push_all(id, phys, &[ent(OP_FILE_WRITE, FILE, SQE_F_LINK, 1), ent(OP_FSYNC, FILE, 0, 2)]) };
        assert_eq!(n, 2);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, IO_ERR_WOULD_BLOCK, CQE_F_REFUSED), (2, IO_ERR_CANCELED, CQE_F_REFUSED)]);
        assert!(io_seen().is_empty(), "an RT entry ran inline with no worker");
        assert!(io_ring_destroy(id));
    }

    // ── IORING_ASYNC: block entries are queued requests ───────────────────

    /// A block entry: `badge` 1, `len` bytes at the data-buffer offset `off`,
    /// partition-relative sector `sector`.
    fn blk(op: u16, off: u32, len: u32, sector: u16, flags: u16, ud: u64) -> SqEntry {
        SqEntry { opcode: op, flags, param0: 1, param1: off, param2: len, addr: sector, reg: 0, user_data: ud }
    }

    /// A ring of a kernel owner (no capability stands in the way), with the
    /// test's block layer queueing.
    fn block_ring() -> (std::sync::MutexGuard<'static, ()>, u32, usize) {
        let g = setup();
        io_ring_register_ops(&TEST_OPS);
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        (g, id, phys)
    }

    fn slot_of(id: u32) -> usize {
        ring_slot(id)
    }

    /// **A block write is QUEUED by the submit, not run.** The submit completes
    /// nothing, starts no request of its own (only queues one, with the bytes
    /// the window held), wakes the worker; the worker's pass starts it, and the
    /// completion is posted `CQE_F_QUEUED` (on the device, not durable) with
    /// the length, from the worker and not from a later submit.
    ///
    /// **Canaries.** Remove the `IORING_ASYNC` arm from `needs_worker` and the
    /// queue branch from `dispatch_block`: the write runs in the submit
    /// (`BLOCK_INLINE` is 1, the submit returns 1). Complete a polled write
    /// with `0` flags: the flag assertion goes red.
    #[test]
    fn a_block_write_is_queued_by_the_submit_and_completes_queued_from_the_worker() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        // SAFETY: `ring` is this test's live ring page; no pass runs while the data buffer is accessed.
        unsafe { (&mut (*ring).data_buf)[512..1024].fill(0xAB) };
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        let n = unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 512, 512, 3, 0, 7)]) };
        assert_eq!(n, 0, "the submit completed a block write");
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert!(unsafe { drain(phys) }.is_empty());
        assert_eq!(BLOCK_INLINE.load(AOrd::SeqCst), 0, "the write ran in the submit");
        assert_eq!(BLOCK_SERVICED.load(AOrd::SeqCst), 0, "the submit did the worker's turn");
        assert_eq!(KICKS.load(AOrd::SeqCst), 1, "the worker was not woken");
        assert_eq!(__io_ring_parked_for_tests(slot_of(id)), 1);
        assert_eq!(block_seen(), vec![(1, true, 3, 512)]);
        let reqs = block_reqs();
        assert_eq!(reqs.len(), 1);
        assert_eq!((reqs[0].write, reqs[0].len, reqs[0].state), (true, 512, Q));
        assert_eq!(reqs[0].data, vec![0xAB; 512], "the bytes are taken at the submit");

        assert!(io_ring_worker_pass() >= 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(7, 512, CQE_F_QUEUED)]);
        assert_eq!(__io_ring_parked_for_tests(slot_of(id)), 0);
        assert!(block_reqs().is_empty(), "the request was not collected");
        assert!(io_ring_destroy(id));
    }

    /// A block read completes with its bytes in the entry's window and neither
    /// flag set; the rest of the buffer is untouched.
    #[test]
    fn a_block_read_lands_in_its_window_when_the_worker_posts_it() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        // SAFETY: `ring` is this test's live ring page; no pass runs while the data buffer is accessed.
        unsafe { (&mut (*ring).data_buf).fill(0x11) };
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_READ, 1024, 1024, 0, 0, 9)]) }, 0);
        // SAFETY: `ring` is this test's live ring page; no pass runs while the data buffer is accessed.
        assert!(unsafe { (&(*ring).data_buf).iter().all(|b| *b == 0x11) }, "the submit touched the window");
        io_ring_worker_pass();
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(9, 1024, 0)]);
        let want = pattern(1);
        // SAFETY: `phys` and `ring` are this test's live ring page; every access is by the test thread,
        // between passes, and each helper called here states the same contract.
        unsafe {
            assert!((&(*ring).data_buf)[1024..2048].iter().all(|b| *b == want));
            assert!((&(*ring).data_buf)[..1024].iter().all(|b| *b == 0x11), "bytes outside the window moved");
        }
        assert!(io_ring_destroy(id));
    }

    /// A request the device failed completes with `-EIO` and no flag: the
    /// operation ran, it did not fail to be admitted.
    #[test]
    fn a_failed_block_request_completes_eio_without_the_refused_flag() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        BLOCK_FAILS.store(true, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 0, 0, 1)]) }, 0);
        io_ring_worker_pass();
        let eio = azos_abi::error::Errno::EIO.to_syscall_ret() as i32;
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, eio, 0)]);
        assert!(io_ring_destroy(id));
    }

    /// A run the layer refuses completes at the submit, refused, parking nothing.
    #[test]
    fn a_refused_block_run_completes_refused_and_parks_nothing() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        BLOCK_MODE.store(2, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_READ, 0, 512, 0, 0, 1)]) }, 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, IO_ERR_PERM, CQE_F_REFUSED)]);
        assert_eq!(__io_ring_parked_for_tests(slot_of(id)), 0);
        assert!(block_reqs().is_empty());
        assert!(io_ring_destroy(id));
    }

    /// When the layer cannot take a run, a task that may block runs it on the
    /// synchronous path in its submit; one that may not hands it to the worker,
    /// which runs it there. (A board whose disk is not behind the layer, a full
    /// queue, a run longer than one command.)
    #[test]
    fn an_unqueueable_block_run_takes_the_synchronous_path() {
        let (_g, id, phys) = block_ring();
        BLOCK_MODE.store(1, AOrd::SeqCst);
        let ws = if azos_limits::IORING_ASYNC { CQE_F_QUEUED } else { 0 };
        let _ = ws;
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 5, 0, 1)]) }, 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 512, 0)]);
        assert_eq!(BLOCK_INLINE.load(AOrd::SeqCst), 1);
        assert_eq!(KICKS.load(AOrd::SeqCst), 0);
        // An RT submitter: the worker runs it.
        MAY_BLOCK.store(false, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 6, 0, 2)]) }, 0);
        assert_eq!(BLOCK_INLINE.load(AOrd::SeqCst), 1, "an RT submit waited for the device");
        assert_eq!(KICKS.load(AOrd::SeqCst), 1);
        assert!(io_ring_worker_pass() >= 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(2, 512, 0)]);
        assert_eq!(BLOCK_INLINE.load(AOrd::SeqCst), 2);
        assert!(io_ring_destroy(id));
    }

    /// An RT submitter QUEUES a block write and a block read (a copy and a
    /// slot, no waiting); the worker's pass starts them and posts them.
    #[test]
    fn an_rt_submitter_queues_a_block_write_and_a_block_read() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        MAY_BLOCK.store(false, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe {
            push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 1, 0, 1), blk(OP_BLOCK_READ, 512, 512, 2, 0, 2)])
        };
        assert_eq!(n, 0);
        assert_eq!(block_seen(), vec![(1, true, 1, 512), (1, false, 2, 512)], "the read did not reach the layer in the submit");
        assert_eq!(BLOCK_INLINE.load(AOrd::SeqCst), 0, "an RT submit waited for the device");
        assert_eq!(__io_ring_parked_for_tests(slot_of(id)), 2);
        assert_eq!(KICKS.load(AOrd::SeqCst), 1);
        assert!(io_ring_worker_pass() >= 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        let mut got = unsafe { drain(phys) };
        got.sort();
        assert_eq!(got, vec![(1, 512, CQE_F_QUEUED), (2, 512, 0)]);
        assert!(io_ring_destroy(id));
    }

    /// A READ of sectors the write-back cache holds unwritten
    /// ([`BlockStart::Dirty`]) is not run by a submit, whoever submits it: the
    /// submit queues nothing, starts nothing and waits for nothing, the worker
    /// is woken, and the worker's pass runs the synchronous `block_io` (which
    /// writes the cache back first) and posts the answer. A write beside it is
    /// queued as usual.
    ///
    /// **Canaries.** Treat `Dirty` as `Unqueueable` in `dispatch_block`: the
    /// submit of a task that may block runs `block_io` itself (`BLOCK_INLINE`
    /// is 1 and the submit returns 1). Hand it off in the worker's own pass
    /// too: the worker never runs it.
    #[test]
    fn a_block_read_the_write_back_cache_holds_goes_to_the_worker_not_the_submit() {
        if !azos_limits::IORING_ASYNC { return; }
        for may_block in [true, false] {
            let (_g, id, phys) = block_ring();
            MAY_BLOCK.store(may_block, AOrd::SeqCst);
            BLOCK_MODE.store(3, AOrd::SeqCst);
            // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
            let n = unsafe {
                push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 1, 0, 1), blk(OP_BLOCK_READ, 512, 512, 2, 0, 2)])
            };
            assert_eq!(n, 0, "the submit completed an entry (may_block {may_block})");
            assert_eq!(BLOCK_INLINE.load(AOrd::SeqCst), 0, "the submit waited for the device (may_block {may_block})");
            assert_eq!(block_seen(), vec![(1, true, 1, 512)], "only the write was queued");
            assert_eq!(__io_ring_parked_for_tests(slot_of(id)), 1);
            assert_eq!(KICKS.load(AOrd::SeqCst), 1, "the worker was not woken (may_block {may_block})");
            assert!(io_ring_worker_pass() >= 1);
            // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
            let mut got = unsafe { drain(phys) };
            got.sort();
            assert_eq!(got, vec![(1, 512, CQE_F_QUEUED), (2, 512, 0)]);
            assert_eq!(BLOCK_INLINE.load(AOrd::SeqCst), 1, "the worker did not run the read");
            assert!(io_ring_destroy(id));
        }
    }

    /// A ring that cannot park another entry runs the block entry on the
    /// synchronous path instead of refusing it: `RING_MAX_PARKED` are queued,
    /// the next one is run in the submit.
    #[test]
    fn a_ring_with_every_parked_slot_taken_runs_the_next_block_entry_synchronously() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        let mut batch = Vec::new();
        for i in 0..=RING_MAX_PARKED as u64 {
            batch.push(blk(OP_BLOCK_WRITE, 0, 512, i as u16, 0, i));
        }
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &batch) }, 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(RING_MAX_PARKED as u64, 512, 0)]);
        assert_eq!(BLOCK_INLINE.load(AOrd::SeqCst), 1);
        assert_eq!(__io_ring_parked_for_tests(slot_of(id)), RING_MAX_PARKED as u32);
        assert_eq!(block_reqs().len(), RING_MAX_PARKED);
        // The worker completes them all, one request per wait.
        io_ring_worker_pass();
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }.len(), RING_MAX_PARKED);
        assert_eq!(__io_ring_parked_for_tests(slot_of(id)), 0);
        assert!(io_ring_destroy(id));
    }

    /// A LINKed block write is a barrier: the entry behind it does not run
    /// until the request is over, and a failed request cancels it.
    #[test]
    fn a_linked_block_write_is_a_barrier_and_its_failure_cancels_the_next_entry() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe {
            push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 0, SQE_F_LINK, 1), ent(OP_NOP, 0, 0, 2)])
        };
        assert_eq!(n, 0, "the entry behind the barrier ran");
        io_ring_worker_pass();
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 512, CQE_F_QUEUED)]);
        assert_eq!(io_ring_submit(id), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(2, 0, 0)]);
        // A failed one cancels what it guarded.
        BLOCK_FAILS.store(true, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all`).
        let n = unsafe {
            push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 0, SQE_F_LINK, 3), ent(OP_NOP, 0, 0, 4)])
        };
        assert_eq!(n, 0);
        io_ring_worker_pass();
        let eio = azos_abi::error::Errno::EIO.to_syscall_ret() as i32;
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(3, eio, 0)]);
        assert_eq!(io_ring_submit(id), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(4, IO_ERR_CANCELED, CQE_F_REFUSED)]);
        assert!(io_ring_destroy(id));
    }

    /// The device holds a request: the worker posts nothing and takes nothing
    /// from the ring; the owner's next submit reaps what is over.
    #[test]
    fn a_block_entry_stays_parked_while_its_request_is_in_the_device() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        BLOCK_HOLD.store(true, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 0, 0, 1)]) }, 0);
        io_ring_worker_pass();
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert!(unsafe { drain(phys) }.is_empty());
        assert_eq!(io_ring_submit(id), 0);
        assert_eq!(__io_ring_parked_for_tests(slot_of(id)), 1);
        // Over, with nobody to post it: the owner's own pass reaps it.
        BLOCK_HOLD.store(false, AOrd::SeqCst);
        BLOCK_REQS.lock().unwrap_or_else(|e| e.into_inner())[0].state = OK;
        assert_eq!(io_ring_submit(id), 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 512, CQE_F_QUEUED)]);
        assert!(io_ring_destroy(id));
    }

    /// A request is collected once: when the completion cannot be written
    /// (a hostile `cq_head` makes the CQ read full) the entry stays parked and
    /// its request is not polled; with room it completes.
    ///
    /// **Canary.** Poll before the room check in `reap_parked`: the request
    /// disappears and the entry never completes.
    #[test]
    fn a_full_cq_does_not_consume_the_request_it_cannot_post() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        let ring = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 0, 0, 1)]) }, 0);
        BLOCK_REQS.lock().unwrap_or_else(|e| e.into_inner())[0].state = OK;
        // SAFETY: `ring` is this test's live ring page; this is an atomic access.
        unsafe { (*ring).cq_head.store(5, Ordering::Release) };
        io_ring_worker_pass();
        assert_eq!(block_reqs().len(), 1, "the request was collected with no room to post it");
        assert_eq!(__io_ring_parked_for_tests(slot_of(id)), 1);
        // SAFETY: `ring` is this test's live ring page; this is an atomic access.
        unsafe { (*ring).cq_head.store(0, Ordering::Release) };
        io_ring_worker_pass();
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, 512, CQE_F_QUEUED)]);
        assert!(io_ring_destroy(id));
    }

    /// A ring destroyed with a request in flight orphans it: the request layer
    /// keeps its slot until somebody collects it, so the worker is told and
    /// collects it. Every way a ring dies: destroy, the owner's exit, the
    /// owner's exit with a pass in flight (at the release).
    ///
    /// **Canary.** Skip `orphan_blocks` in `destroy_locked`: no orphan, and the
    /// request layer's slot is held for good.
    #[test]
    fn a_ring_that_dies_with_a_request_in_flight_hands_it_to_the_worker() {
        if !azos_limits::IORING_ASYNC { return; }
        let (_g, id, phys) = block_ring();
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        let q = |id: u32, phys: usize| unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 0, 0, 1)]) };
        // Destroyed.
        assert_eq!(q(id, phys), 0);
        let kicks = KICKS.load(AOrd::SeqCst);
        assert!(io_ring_destroy(id));
        assert_eq!(block_orphans(), vec![1]);
        assert_eq!(KICKS.load(AOrd::SeqCst), kicks + 1, "the worker was not told");
        assert_eq!(io_ring_worker_pass(), 0, "a vacated ring was posted");
        assert!(block_reqs().is_empty(), "the worker did not drain the orphan");
        // The owner exits.
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        assert_eq!(q(id, phys), 0);
        io_ring_release_all(OWNER);
        assert_eq!(block_orphans(), vec![1, 2]);
        io_ring_worker_pass();
        assert!(block_reqs().is_empty());
        // The owner exits while a pass holds the ring: orphaned at the release.
        let (id, phys) = io_ring_create(OWNER as usize).unwrap();
        assert_eq!(q(id, phys), 0);
        claim_ring(id).expect("claim");
        io_ring_release_all(OWNER);
        assert_eq!(block_orphans(), vec![1, 2], "orphaned under a live pass");
        release_ring(id);
        assert_eq!(block_orphans(), vec![1, 2, 3]);
        io_ring_worker_pass();
        assert!(block_reqs().is_empty());
    }

    /// The seccomp and pledge questions of a block entry are asked once for a
    /// queued one, and the entry is refused before the layer is reached.
    #[test]
    fn a_block_entry_the_profile_denies_never_reaches_the_layer() {
        let (_g, id, phys) = block_ring();
        IFACE_DENIES.store(azos_devif::key::BLOCK as u32, AOrd::SeqCst);
        // SAFETY: `phys` is this test's live ring page, no other user (see `push_all_unsettled`).
        assert_eq!(unsafe { push_all_unsettled(id, phys, &[blk(OP_BLOCK_WRITE, 0, 512, 0, 0, 1)]) }, 1);
        // SAFETY: `phys` is this test's live ring page, no other user (see `drain`).
        assert_eq!(unsafe { drain(phys) }, vec![(1, IO_ERR_SECCOMP, CQE_F_REFUSED)]);
        assert!(block_seen().is_empty() && block_reqs().is_empty());
        assert!(io_ring_destroy(id));
    }
}
