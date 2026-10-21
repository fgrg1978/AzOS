// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! FMMU and sync-manager records: register images and register addresses.

use azos_ethercat::reg::*;

#[test]
fn record_addresses() {
    assert_eq!(fmmu_addr(0), 0x0600);
    assert_eq!(fmmu_addr(2), 0x0620);
    assert_eq!(sm_addr(0), 0x0800);
    assert_eq!(sm_addr(3), 0x0818);
}

#[test]
fn fmmu_image_matches_etg_1000_4_table_57() {
    let f = Fmmu::new(FmmuDir::Read, 0x0001_0000, 6, 0x1100);
    assert_eq!(
        f.encode(),
        [
            0x00, 0x00, 0x01, 0x00, // logical start
            0x06, 0x00, // length
            0x00, // logical start bit
            0x07, // logical stop bit
            0x00, 0x11, // physical start
            0x00, // physical start bit
            0x01, // read
            0x01, // enabled
            0x00, 0x00, 0x00,
        ]
    );
    let w = Fmmu::new(FmmuDir::Write, 0, 4, 0x1000);
    assert_eq!(w.encode()[11], 2);
    assert!(f.byte_aligned());
}

#[test]
fn fmmu_round_trip_and_unconfigured() {
    let f = Fmmu {
        logical_start: 0xDEAD_BEEF,
        len: 0x0123,
        logical_start_bit: 3,
        logical_stop_bit: 5,
        phys_start: 0x1234,
        phys_start_bit: 2,
        dir: FmmuDir::Write,
        enabled: false,
    };
    assert_eq!(Fmmu::decode(&f.encode()), Some(f));
    assert!(!f.byte_aligned());
    assert_eq!(Fmmu::decode(&[0; FMMU_LEN]), None);
}

#[test]
fn sync_manager_image() {
    let mbx = SyncManager::new(0x1000, 128, sm_control::MAILBOX_OUT);
    assert_eq!(mbx.encode(), [0x00, 0x10, 0x80, 0x00, 0x26, 0x00, 0x01, 0x00]);
    let pd = SyncManager::new(0x1100, 6, sm_control::PROCESS_IN);
    assert_eq!(pd.encode(), [0x00, 0x11, 0x06, 0x00, 0x20, 0x00, 0x01, 0x00]);
    for s in [mbx, pd, SyncManager::new(0x1800, 2, sm_control::PROCESS_OUT)] {
        assert_eq!(SyncManager::decode(&s.encode()), s);
    }
    let off = SyncManager { enabled: false, ..mbx };
    assert_eq!(off.encode()[6], 0);
}

#[test]
fn control_byte_fields() {
    // mode (bits 0..1): mailbox is 2, buffered is 0; direction (bits 2..3): 1 = master writes.
    assert_eq!(sm_control::MAILBOX_OUT & 0x03, 2);
    assert_eq!(sm_control::MAILBOX_IN & 0x03, 2);
    assert_eq!(sm_control::PROCESS_OUT & 0x03, 0);
    assert_eq!(sm_control::MAILBOX_OUT & 0x0C, 0x04);
    assert_eq!(sm_control::MAILBOX_IN & 0x0C, 0);
    assert_eq!(sm_control::PROCESS_OUT & 0x0C, 0x04);
    assert_eq!(sm_control::PROCESS_IN & 0x0C, 0);
}
