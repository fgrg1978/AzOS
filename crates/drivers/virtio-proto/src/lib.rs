// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What virtio says on the wire, for both ends of it: the guest drivers
//! (`crates/drivers/virtio`) and the device models of `userspace/services/vmmd`
//! compile these constants and layouts, so the two sides cannot disagree on
//! one. Values are virtio 1.2's; names follow Linux's `uapi/linux/virtio_*.h`.
//!
//! Register offsets and status bits are `u32` (the MMIO register file is 32
//! bits wide). Feature bits are `u64`, numbered as the specification does
//! (`F_VERSION_1` is bit 32); [`feature::word`] cuts out the 32-bit word a
//! transport reads or writes.
//!
//! * at the root: the virtio-mmio registers, the interrupt and device status
//!   bits, the device ids, and the split virtqueue's flags and layouts.
//! * [`feature`]: the transport and ring feature bits.
//! * [`blk`], [`net`]: the request and configuration formats of the two
//!   devices vmmd models, as the guest drivers speak them.
#![no_std]
#![forbid(unsafe_code)]

pub mod blk;
pub mod feature;
pub mod net;

// ── Transport: virtio-mmio (virtio 1.2, section 4.2.2) ──────────────────

/// `MagicValue`: "virt" read as a little-endian word.
pub const VIRTIO_MAGIC: u32 = 0x7472_6976;

pub const VIRTIO_MMIO_MAGIC: u32 = 0x000;
pub const VIRTIO_MMIO_VERSION: u32 = 0x004;
pub const VIRTIO_MMIO_DEVICE_ID: u32 = 0x008;
pub const VIRTIO_MMIO_VENDOR_ID: u32 = 0x00c;
pub const VIRTIO_MMIO_DEVICE_FEATURES: u32 = 0x010;
pub const VIRTIO_MMIO_DEVICE_FEATURES_SEL: u32 = 0x014;
pub const VIRTIO_MMIO_DRIVER_FEATURES: u32 = 0x020;
pub const VIRTIO_MMIO_DRIVER_FEATURES_SEL: u32 = 0x024;
/// Legacy (version 1) only.
pub const VIRTIO_MMIO_GUEST_PAGE_SIZE: u32 = 0x028;
pub const VIRTIO_MMIO_QUEUE_SEL: u32 = 0x030;
pub const VIRTIO_MMIO_QUEUE_NUM_MAX: u32 = 0x034;
pub const VIRTIO_MMIO_QUEUE_NUM: u32 = 0x038;
/// Legacy (version 1) only.
pub const VIRTIO_MMIO_QUEUE_ALIGN: u32 = 0x03c;
/// Legacy (version 1) only.
pub const VIRTIO_MMIO_QUEUE_PFN: u32 = 0x040;
/// Modern (version 2) only.
pub const VIRTIO_MMIO_QUEUE_READY: u32 = 0x044;
pub const VIRTIO_MMIO_QUEUE_NOTIFY: u32 = 0x050;
pub const VIRTIO_MMIO_INTERRUPT_STATUS: u32 = 0x060;
pub const VIRTIO_MMIO_INTERRUPT_ACK: u32 = 0x064;
pub const VIRTIO_MMIO_STATUS: u32 = 0x070;
pub const VIRTIO_MMIO_QUEUE_DESC_LOW: u32 = 0x080;
pub const VIRTIO_MMIO_QUEUE_DESC_HIGH: u32 = 0x084;
/// The driver area (the available ring); the specification's `QueueDriverLow`.
pub const VIRTIO_MMIO_QUEUE_AVAIL_LOW: u32 = 0x090;
pub const VIRTIO_MMIO_QUEUE_AVAIL_HIGH: u32 = 0x094;
/// The device area (the used ring); the specification's `QueueDeviceLow`.
pub const VIRTIO_MMIO_QUEUE_USED_LOW: u32 = 0x0a0;
pub const VIRTIO_MMIO_QUEUE_USED_HIGH: u32 = 0x0a4;
pub const VIRTIO_MMIO_CONFIG_GENERATION: u32 = 0x0fc;
/// The device-specific configuration space starts here.
pub const VIRTIO_MMIO_CONFIG: u32 = 0x100;

/// `InterruptStatus` bit 0: a buffer was used.
pub const VIRTIO_MMIO_INT_VRING: u32 = 1;
/// `InterruptStatus` bit 1: the configuration changed.
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 2;

// ── Device status (section 2.1) ─────────────────────────────────────────

pub const VIRTIO_STATUS_ACK: u32 = 1;
pub const VIRTIO_STATUS_DRIVER: u32 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u32 = 8;
/// The device hit an error it cannot recover from without a reset.
pub const VIRTIO_STATUS_NEEDS_RESET: u32 = 0x40;
pub const VIRTIO_STATUS_FAILED: u32 = 128;

// ── Device ids (section 5) ──────────────────────────────────────────────

pub const VIRTIO_DEV_NET: u32 = 1;
pub const VIRTIO_DEV_BLOCK: u32 = 2;
pub const VIRTIO_DEV_CONSOLE: u32 = 3;
pub const VIRTIO_DEV_RNG: u32 = 4;
pub const VIRTIO_DEV_GPU: u32 = 16;
pub const VIRTIO_DEV_INPUT: u32 = 18;
pub const VIRTIO_DEV_SND: u32 = 25;

// ── The split virtqueue (section 2.7) ───────────────────────────────────

/// Descriptor flag: the chain continues in `next`.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
/// Descriptor flag: the device writes the buffer (else it only reads it).
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
/// Descriptor flag: the buffer holds a table of descriptors.
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

/// `avail.flags` bit 0: the driver does not want an interrupt when the device
/// consumes a buffer. Advisory: the device may still interrupt, so a driver
/// never relies on its absence.
pub const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;
/// `used.flags` bit 0 (`VRING_USED_F_NO_NOTIFY` on the legacy transport): the
/// device needs no doorbell for buffers added now, it is already processing
/// the queue.
pub const VIRTQ_USED_F_NO_NOTIFY: u16 = 1;

/// One descriptor-table entry.
#[repr(C, packed)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// One used-ring entry.
#[repr(C, packed)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// Byte offsets inside the three areas of a queue: the descriptor fields, the
/// available ring (`flags`, `idx`, then `ring[]`) and the used ring (same).
pub const VIRTQ_DESC_BYTES: u64 = 16;
pub const VIRTQ_DESC_LEN_OFF: u64 = 8;
pub const VIRTQ_DESC_FLAGS_OFF: u64 = 12;
pub const VIRTQ_DESC_NEXT_OFF: u64 = 14;
pub const VIRTQ_AVAIL_IDX_OFF: u64 = 2;
pub const VIRTQ_AVAIL_RING_OFF: u64 = 4;
pub const VIRTQ_USED_IDX_OFF: u64 = 2;
pub const VIRTQ_USED_RING_OFF: u64 = 4;
pub const VIRTQ_USED_ELEM_BYTES: u64 = 8;
pub const VIRTQ_USED_ELEM_LEN_OFF: u64 = 4;

/// Alignment of the descriptor table, the available ring and the used ring.
pub const VIRTQ_DESC_ALIGN: u64 = 16;
pub const VIRTQ_AVAIL_ALIGN: u64 = 2;
pub const VIRTQ_USED_ALIGN: u64 = 4;

/// Bytes of the available ring of a queue of `n` entries (the `used_event`
/// word included).
pub const fn virtq_avail_bytes(n: u64) -> u64 {
    VIRTQ_AVAIL_RING_OFF + 2 * n + 2
}

/// Bytes of the used ring of a queue of `n` entries (the `avail_event` word
/// included).
pub const fn virtq_used_bytes(n: u64) -> u64 {
    VIRTQ_USED_RING_OFF + VIRTQ_USED_ELEM_BYTES * n + 2
}

const _: () = {
    assert!(core::mem::size_of::<VirtqDesc>() as u64 == VIRTQ_DESC_BYTES);
    assert!(core::mem::offset_of!(VirtqDesc, len) as u64 == VIRTQ_DESC_LEN_OFF);
    assert!(core::mem::offset_of!(VirtqDesc, flags) as u64 == VIRTQ_DESC_FLAGS_OFF);
    assert!(core::mem::offset_of!(VirtqDesc, next) as u64 == VIRTQ_DESC_NEXT_OFF);
    assert!(core::mem::size_of::<VirtqUsedElem>() as u64 == VIRTQ_USED_ELEM_BYTES);
    assert!(core::mem::offset_of!(VirtqUsedElem, len) as u64 == VIRTQ_USED_ELEM_LEN_OFF);
};

/// The EVENT_IDX test (section 2.7.7.2; Linux `vring_need_event`): with the
/// index moving `old -> new`, did it pass `event`? Wrapping `u16` arithmetic.
#[inline(always)]
pub const fn vring_need_event(event: u16, new: u16, old: u16) -> bool {
    new.wrapping_sub(event).wrapping_sub(1) < new.wrapping_sub(old)
}
