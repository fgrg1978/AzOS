// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Every constant of `crates/drivers/virtio-proto` against the value the
//! virtio 1.2 specification gives it, written out here and not read back from
//! the crate, and the guest driver's view of the same facts (`virtio/mod.rs`,
//! `blk_proto.rs`, `pci.rs`) against the crate.

use azos_virtio_proto as p;
use azos_virtio_proto::{blk, feature, net};

use crate::virtio as g;
use crate::virtio::blk_proto as gb;

#[test]
fn the_mmio_register_file_is_section_4_2_2() {
    assert_eq!(p::VIRTIO_MAGIC, 0x7472_6976, "\"virt\" little endian");
    let regs = [
        (p::VIRTIO_MMIO_MAGIC, 0x000),
        (p::VIRTIO_MMIO_VERSION, 0x004),
        (p::VIRTIO_MMIO_DEVICE_ID, 0x008),
        (p::VIRTIO_MMIO_VENDOR_ID, 0x00c),
        (p::VIRTIO_MMIO_DEVICE_FEATURES, 0x010),
        (p::VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0x014),
        (p::VIRTIO_MMIO_DRIVER_FEATURES, 0x020),
        (p::VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0x024),
        (p::VIRTIO_MMIO_GUEST_PAGE_SIZE, 0x028),
        (p::VIRTIO_MMIO_QUEUE_SEL, 0x030),
        (p::VIRTIO_MMIO_QUEUE_NUM_MAX, 0x034),
        (p::VIRTIO_MMIO_QUEUE_NUM, 0x038),
        (p::VIRTIO_MMIO_QUEUE_ALIGN, 0x03c),
        (p::VIRTIO_MMIO_QUEUE_PFN, 0x040),
        (p::VIRTIO_MMIO_QUEUE_READY, 0x044),
        (p::VIRTIO_MMIO_QUEUE_NOTIFY, 0x050),
        (p::VIRTIO_MMIO_INTERRUPT_STATUS, 0x060),
        (p::VIRTIO_MMIO_INTERRUPT_ACK, 0x064),
        (p::VIRTIO_MMIO_STATUS, 0x070),
        (p::VIRTIO_MMIO_QUEUE_DESC_LOW, 0x080),
        (p::VIRTIO_MMIO_QUEUE_DESC_HIGH, 0x084),
        (p::VIRTIO_MMIO_QUEUE_AVAIL_LOW, 0x090),
        (p::VIRTIO_MMIO_QUEUE_AVAIL_HIGH, 0x094),
        (p::VIRTIO_MMIO_QUEUE_USED_LOW, 0x0a0),
        (p::VIRTIO_MMIO_QUEUE_USED_HIGH, 0x0a4),
        (p::VIRTIO_MMIO_CONFIG_GENERATION, 0x0fc),
        (p::VIRTIO_MMIO_CONFIG, 0x100),
    ];
    for (i, (got, want)) in regs.iter().enumerate() {
        assert_eq!(got, want, "register {i}");
    }
    assert_eq!((p::VIRTIO_MMIO_INT_VRING, p::VIRTIO_MMIO_INT_CONFIG), (1, 2));
}

#[test]
fn the_status_bits_are_section_2_1() {
    assert_eq!(
        (p::VIRTIO_STATUS_ACK, p::VIRTIO_STATUS_DRIVER, p::VIRTIO_STATUS_DRIVER_OK, p::VIRTIO_STATUS_FEATURES_OK),
        (1, 2, 4, 8)
    );
    assert_eq!((p::VIRTIO_STATUS_NEEDS_RESET, p::VIRTIO_STATUS_FAILED), (0x40, 0x80));
}

#[test]
fn the_device_ids_are_section_5() {
    assert_eq!(
        [p::VIRTIO_DEV_NET, p::VIRTIO_DEV_BLOCK, p::VIRTIO_DEV_CONSOLE, p::VIRTIO_DEV_RNG],
        [1, 2, 3, 4]
    );
    assert_eq!([p::VIRTIO_DEV_GPU, p::VIRTIO_DEV_INPUT, p::VIRTIO_DEV_SND], [16, 18, 25]);
}

#[test]
fn the_split_virtqueue_is_section_2_7() {
    assert_eq!((p::VIRTQ_DESC_F_NEXT, p::VIRTQ_DESC_F_WRITE, p::VIRTQ_DESC_F_INDIRECT), (1, 2, 4));
    assert_eq!((p::VIRTQ_AVAIL_F_NO_INTERRUPT, p::VIRTQ_USED_F_NO_NOTIFY), (1, 1));
    // Descriptor: addr 0, len 8, flags 12, next 14, 16 bytes; used element: id 0, len 4.
    assert_eq!(
        (p::VIRTQ_DESC_BYTES, p::VIRTQ_DESC_LEN_OFF, p::VIRTQ_DESC_FLAGS_OFF, p::VIRTQ_DESC_NEXT_OFF),
        (16, 8, 12, 14)
    );
    assert_eq!((p::VIRTQ_USED_ELEM_BYTES, p::VIRTQ_USED_ELEM_LEN_OFF), (8, 4));
    // Available ring: flags 0, idx 2, ring[] 4; used ring the same.
    assert_eq!((p::VIRTQ_AVAIL_IDX_OFF, p::VIRTQ_AVAIL_RING_OFF), (2, 4));
    assert_eq!((p::VIRTQ_USED_IDX_OFF, p::VIRTQ_USED_RING_OFF), (2, 4));
    assert_eq!((p::VIRTQ_DESC_ALIGN, p::VIRTQ_AVAIL_ALIGN, p::VIRTQ_USED_ALIGN), (16, 2, 4));
    // Plus used_event / avail_event after the ring.
    assert_eq!((p::virtq_avail_bytes(8), p::virtq_used_bytes(8)), (6 + 16, 6 + 64));
}

#[test]
fn the_event_idx_test_is_the_one_of_section_2_7_7_2() {
    // The index moved 5 -> 9 and the other side asked to be told at 7: passed.
    assert!(p::vring_need_event(7, 9, 5));
    assert!(!p::vring_need_event(9, 9, 5));
    assert!(!p::vring_need_event(4, 9, 5));
    // Across the u16 wrap: 0xfffe -> 2 passes 0xffff and 0, not 3.
    assert!(p::vring_need_event(0xffff, 2, 0xfffe));
    assert!(!p::vring_need_event(3, 2, 0xfffe));
}

#[test]
fn the_feature_bits_are_section_6() {
    assert_eq!(feature::INDIRECT_DESC, 1 << 28);
    assert_eq!(feature::EVENT_IDX, 1 << 29);
    assert_eq!(feature::VERSION_1, 1 << 32, "VIRTIO_F_VERSION_1 is bit 32");
    assert_eq!(feature::ACCESS_PLATFORM, 1 << 33);
    let both = feature::VERSION_1 | feature::EVENT_IDX;
    assert_eq!((feature::word(both, 0), feature::word(both, 1)), (1 << 29, 1));
    assert_eq!(feature::word(both, 3), 1, "the selector is one bit wide");
}

#[test]
fn the_block_device_is_section_5_2() {
    assert_eq!((blk::T_IN, blk::T_OUT, blk::T_FLUSH, blk::T_GET_ID, blk::T_DISCARD), (0, 1, 4, 8, 11));
    assert_eq!((blk::S_OK, blk::S_IOERR, blk::S_UNSUPP), (0, 1, 2));
    assert_eq!((blk::F_SEG_MAX, blk::F_RO, blk::F_FLUSH, blk::F_MQ, blk::F_DISCARD), (1 << 2, 1 << 5, 1 << 9, 1 << 12, 1 << 13));
    // num_queues is the le16 at 34; the discard limits follow at 36 and 40.
    assert_eq!(blk::CFG_NUM_QUEUES_WORD + 2, 34);
    assert_eq!((blk::CFG_MAX_DISCARD_SECTORS, blk::CFG_MAX_DISCARD_SEG), (36, 40));
    assert_eq!((blk::SECTOR_SIZE, blk::REQ_HDR_BYTES, blk::DISCARD_SEG_BYTES), (512, 16, 16));
}

#[test]
fn the_network_device_is_section_5_1() {
    assert_eq!((net::F_MAC, net::F_STATUS, net::S_LINK_UP), (1 << 5, 1 << 16, 1));
    assert_eq!((net::HDR_BYTES_LEGACY, net::HDR_BYTES), (10, 12));
}

#[test]
fn the_guest_driver_speaks_the_crates_constants() {
    assert_eq!(g::VIRTIO_MAGIC, p::VIRTIO_MAGIC);
    assert_eq!(g::VIRTIO_MMIO_QUEUE_AVAIL_LOW, p::VIRTIO_MMIO_QUEUE_AVAIL_LOW);
    assert_eq!(g::VIRTIO_MMIO_QUEUE_USED_HIGH, p::VIRTIO_MMIO_QUEUE_USED_HIGH);
    assert_eq!(g::VIRTIO_STATUS_FEATURES_OK, p::VIRTIO_STATUS_FEATURES_OK);
    assert_eq!(g::VIRTQ_DESC_F_WRITE, p::VIRTQ_DESC_F_WRITE);
    assert_eq!(g::VIRTIO_F_EVENT_IDX as u64, feature::EVENT_IDX);
    assert_eq!(gb::T_FLUSH, blk::T_FLUSH);
    assert_eq!(gb::F_DISCARD as u64, blk::F_DISCARD);
    assert_eq!(gb::DISCARD_SEG_BYTES, blk::DISCARD_SEG_BYTES);
    assert_eq!(g::VIRTIO_DEV_SND, 25);
}
