// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The io_ring page as ring 3 sees it: byte offsets inside the shared page,
//! ring sizes, opcodes and flag bits. ONE definition for both sides.
//!
//! `crates/core/ipc/src/io_ring.rs` (the kernel's `IoRing`) asserts at compile time
//! that its `#[repr(C)]` layout and its opcode/flag constants equal these, and
//! `crates/core/libsys/src/ioring.rs` re-exports them.

/// `sq_head` (kernel consumes from here).
pub const SQ_HEAD: usize = 0;
/// `sq_tail` (ring 3 produces to here).
pub const SQ_TAIL: usize = 4;
/// The SQ: `SQ_SIZE` entries of 32 bytes.
pub const SQ_ENTRIES: usize = 8;
/// `cq_head` (ring 3 consumes from here).
pub const CQ_HEAD: usize = 1032;
/// `cq_tail` (kernel produces to here).
pub const CQ_TAIL: usize = 1036;
/// The CQ: `CQ_SIZE` entries of 16 bytes.
pub const CQ_ENTRIES: usize = 1040;
/// The shared data buffer, `DATA_SIZE` bytes.
pub const DATA: usize = 1552;
/// Length of the data buffer.
pub const DATA_SIZE: usize = 2048;
/// `sq_flags`: `SQ_F_*`, written by the kernel.
pub const SQ_FLAGS: usize = 3600;
/// `version`: `IO_RING_VERSION`, written by the kernel at ring setup, in
/// the 4 bytes that were tail padding of the page.
pub const VERSION: usize = 3604;
/// The layout word the kernel writes at setup. Bump it with any change to
/// an offset, to the SQE/CQE layout or to what an opcode means.
pub const IO_RING_VERSION: u32 = 2;
/// SQ entries.
pub const SQ_SIZE: u32 = 32;
/// CQ entries.
pub const CQ_SIZE: u32 = 32;

/// An SQ poller runs this ring.
pub const SQ_F_SQPOLL: u32 = 1 << 0;
/// The poller has parked: publish `sq_tail`, then kick.
pub const SQ_F_NEED_WAKEUP: u32 = 1 << 1;
/// `CqEntry::flags` bit: the kernel refused the entry; `result` is `-Errno`.
pub const CQE_F_REFUSED: u32 = 1 << 0;
/// `CqEntry::flags` bit: the operation was accepted onto a queue (the FAT32
/// write-back cache, a NIC TX ring) and is not yet durable or on the wire.
pub const CQE_F_QUEUED: u32 = 1 << 1;
/// `CqEntry::flags` bit: an `OP_FSYNC` completed at a flush point: every
/// write queued before it reached the device and the device flushed.
pub const CQE_F_DURABLE: u32 = 1 << 2;
/// `SqEntry::flags` bit: the entry's buffer is a REGISTERED one: `reg` is the
/// buffer's slot ([`OP_BUF_REGISTER`]), `param1` the byte offset inside it and
/// `param2` the length, in place of a window of the data buffer. Only the
/// data-moving opcodes take it ([`OP_NET_SEND`], [`OP_NET_RECV`],
/// [`OP_FILE_READ`], [`OP_FILE_WRITE`]); any other opcode refuses it with
/// `-EINVAL`.
pub const SQE_F_FIXED: u16 = 1 << 1;
/// `SqEntry::flags` bit: link the next entry to this one. The next entry
/// runs only if this one completed now and succeeded; otherwise it
/// completes with `-ECANCELED` and `CQE_F_REFUSED` without running.
pub const SQE_F_LINK: u16 = 1 << 0;

/// No operation: completes with 0 (batching measurements).
pub const OP_NOP: u16 = 0;
/// Read a sensor into the data buffer.
pub const OP_READ_SENSOR: u16 = 1;
/// Write a GPIO pin.
pub const OP_WRITE_GPIO: u16 = 2;
/// Read a GPIO pin.
pub const OP_READ_GPIO: u16 = 3;
/// I2C read into the data buffer.
pub const OP_I2C_READ: u16 = 4;
/// I2C write from the data buffer.
pub const OP_I2C_WRITE: u16 = 5;
/// Set a PWM channel duty.
pub const OP_PWM_SET: u16 = 6;
/// Set a wheel speed (through the actuation gate).
pub const OP_MOTOR_SPEED: u16 = 7;
/// Queue a send on a socket: `param0` is a `Cap<Socket>` handle (WRITE), as the
/// `NODE_SEND` op takes it; completes `CQE_F_QUEUED` without waiting.
pub const OP_NET_SEND: u16 = 8;
/// Receive from a socket without waiting: `param0` is a `Cap<Socket>` handle
/// (`READ`), as the `NODE_RECV` op takes it; `param1`/`param2` the buffer
/// window the bytes land in. Completes with the byte count, `0` when nothing
/// is queued, `-1` for a socket that cannot receive and `-EEOF` once a stream
/// has ended.
pub const OP_NET_RECV: u16 = 9;
/// Register a buffer: pin a range of a `MemObj` this task already maps, so
/// that entries name it by slot ([`SQE_F_FIXED`]) and the kernel reaches it
/// without validating a user range per operation. `param0` is a `Cap<Shm>`
/// handle (`READ | WRITE | MAP`), `param1` the byte offset of the range in the
/// object, `param2` its length, `reg` the slot (`0..IORING_MAX_REGBUFS`) to
/// fill. The range must lie in one physically contiguous run of the object.
/// The slot must be free. Completes with `0`. Takes no `MemObj` slot of its
/// own: the object is the one the task already holds.
pub const OP_BUF_REGISTER: u16 = 10;
/// Unregister the buffer in slot `reg` and give the pin back. Completes with
/// `0`; `-EINVAL` for a slot that holds none.
pub const OP_BUF_UNREGISTER: u16 = 11;
/// Read a file through its `Cap<File>` (twin of the `NODE_READ` op).
pub const OP_FILE_READ: u16 = 12;
/// Write a file through its `Cap<File>` (twin of the `NODE_WRITE` op).
pub const OP_FILE_WRITE: u16 = 13;
/// Complete at an absolute deadline (twin of sleep-until).
pub const OP_TIMER: u16 = 16;
/// Wait on a notify word in a `Cap<Shm>` region.
pub const OP_NOTIFY_WAIT: u16 = 17;
/// Ask for a kernel SQ poller (topology permit required).
pub const OP_SQPOLL_START: u16 = 18;
/// Make the writes queued before it durable (twin of the `NODE_FSYNC` op);
/// completes with `CQE_F_DURABLE` after the flush, never by waiting in submit.
pub const OP_FSYNC: u16 = 19;
/// Read sectors of a partition into the data buffer: `param0` is the `block`
/// endpoint's badge (partition `n` is badge `n + 1`), `param1` the buffer
/// offset, `param2` the length in bytes (a multiple of 512), and the entry's
/// `addr` (low half) and `reg` (high half) the first sector, relative to the
/// partition. Needs `READ`.
pub const OP_BLOCK_READ: u16 = 20;
/// Write sectors of a partition from the data buffer, as [`OP_BLOCK_READ`].
/// Needs `WRITE`, and is refused while contained.
pub const OP_BLOCK_WRITE: u16 = 21;
