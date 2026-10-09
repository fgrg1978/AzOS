// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The io_ring page as ring 3 sees it: byte offsets inside the shared page,
//! ring sizes, opcodes and flag bits. ONE definition for both sides.
//!
//! `crates/core/ipc/src/io_ring.rs` (the kernel's `IoRing`) asserts at compile time
//! that its `#[repr(C)]` layout and its opcode/flag constants equal these, and
//! `crates/core/libsys/src/ioring.rs` re-exports them. Before, libsys carried its
//! own copy of every number with nothing tying it to the kernel's.

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
/// Send on a socket.
pub const OP_NET_SEND: u16 = 8;
/// Receive from a socket.
pub const OP_NET_RECV: u16 = 9;
/// Capture a camera frame.
pub const OP_CAMERA_CAPTURE: u16 = 10;
/// Wait for a bound interrupt.
pub const OP_IRQ_WAIT: u16 = 11;
/// Read a file through its `Cap<File>` (twin of the typed file read).
pub const OP_FILE_READ: u16 = 12;
/// Write a file through its `Cap<File>` (twin of the typed file write).
pub const OP_FILE_WRITE: u16 = 13;
/// Send on a typed channel.
pub const OP_CHAN_SEND: u16 = 14;
/// Receive from a typed channel.
pub const OP_CHAN_RECV: u16 = 15;
/// Complete at an absolute deadline (twin of sleep-until).
pub const OP_TIMER: u16 = 16;
/// Wait on a notify word in a `Cap<Shm>` region.
pub const OP_NOTIFY_WAIT: u16 = 17;
/// Ask for a kernel SQ poller (topology permit required).
pub const OP_SQPOLL_START: u16 = 18;
/// Make the writes queued before it durable (twin of the typed fsync);
/// completes with `CQE_F_DURABLE` after the flush, never by waiting in submit.
pub const OP_FSYNC: u16 = 19;
