// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hardware floor backend (`crates/core/ota/src/floor.rs`, Kconfig
//! `OTA_FLOOR_TPM_NV`) beside the BOOTMETA floor: what `ota_read_boot_meta`
//! and `ota_mark_boot_good` do with it. The backend here is a counter with a
//! script of outcomes; the TPM end of it, with the real driver, is
//! `tests/host/tpm-tests/src/wire.rs`.

use crate::floor;
use crate::pure::{ota_confirmed_epoch, ota_mark_boot_good_pure, BootMeta};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// `floor` keeps its state in statics: one test at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// What the fake hardware holds, and how many raises reached it.
static HELD: AtomicU32 = AtomicU32::new(0);
static RAISES: AtomicU32 = AtomicU32::new(0);
/// Non-zero: the next raises fail (that many).
static FAIL: AtomicU32 = AtomicU32::new(0);

fn raise(to: u32) -> Option<u32> {
    RAISES.fetch_add(1, Ordering::SeqCst);
    if FAIL.load(Ordering::SeqCst) > 0 {
        FAIL.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    // The hardware's own rule, as the driver's `floor_raise`: only upward.
    let now = HELD.fetch_max(to, Ordering::SeqCst).max(to);
    Some(now)
}

static BACKEND: floor::Backend = floor::Backend { raise };

fn setup(held: u32) {
    HELD.store(held, Ordering::SeqCst);
    RAISES.store(0, Ordering::SeqCst);
    FAIL.store(0, Ordering::SeqCst);
    floor::install(&BACKEND, held);
}

fn meta_with(active: u8, epoch_a: u32, epoch_b: u32, floor_now: u32) -> BootMeta {
    let mut m = BootMeta::default();
    m.active_slot = active;
    m.sec_epoch_a = epoch_a;
    m.sec_epoch_b = epoch_b;
    m.min_sec_epoch = floor_now;
    m
}

#[test]
fn the_floor_in_force_is_the_higher_of_bootmeta_and_the_backend() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    setup(7);
    assert!(floor::active());
    // A BOOTMETA that was rolled back (or deleted: default 0) does not lower it.
    for stored in [0, 1, 6] {
        assert_eq!(floor::lift(stored), 7, "stored {stored}");
    }
    // A higher one is not capped by the backend.
    assert_eq!(floor::lift(7), 7);
    assert_eq!(floor::lift(9), 9);
    // Reading the floor never reaches the hardware.
    assert_eq!(RAISES.load(Ordering::SeqCst), 0);
}

#[test]
fn boot_good_raises_the_backend_with_the_floor_it_just_computed() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Slot B holds epoch 9 and is the active slot; the floor was 7 everywhere.
    setup(7);
    let mut m = meta_with(1, 3, 9, 7);
    ota_mark_boot_good_pure(&mut m);
    assert_eq!(m.min_sec_epoch, 9);
    floor::commit(ota_confirmed_epoch(&m));
    assert_eq!(HELD.load(Ordering::SeqCst), 9);
    assert_eq!(RAISES.load(Ordering::SeqCst), 1);
    assert_eq!(floor::lift(0), 9);
    // A later confirmation of a set with a lower epoch (a rollback to slot A,
    // epoch 3) cannot lower either floor: the pure rule keeps BOOTMETA's 9 and
    // the backend is not asked.
    let mut back = meta_with(0, 3, 9, 9);
    ota_mark_boot_good_pure(&mut back);
    assert_eq!(back.min_sec_epoch, 9);
    floor::commit(ota_confirmed_epoch(&back));
    assert_eq!(RAISES.load(Ordering::SeqCst), 1);
    assert_eq!(HELD.load(Ordering::SeqCst), 9);
}

// REQ-014
#[test]
fn a_forged_bootmeta_floor_never_reaches_the_backend() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // The hardware holds 7; slot A is confirmed with epoch 7 (no raise due).
    // The volume's record carries a planted floor of u32::MAX.
    setup(7);
    let mut forged = meta_with(0, 7, 2, u32::MAX);
    ota_mark_boot_good_pure(&mut forged);
    // BOOTMETA's own floor keeps the planted value (the volume is the
    // volume's), but what the boot confirmation hands the hardware is the
    // confirmed slot's epoch.
    assert_eq!(forged.min_sec_epoch, u32::MAX);
    assert_eq!(ota_confirmed_epoch(&forged), 7);
    floor::commit(ota_confirmed_epoch(&forged));
    assert_eq!(RAISES.load(Ordering::SeqCst), 0, "the backend was not asked");
    assert_eq!(HELD.load(Ordering::SeqCst), 7, "the TPM floor did not move");
    // A real confirmation of a higher epoch on the same forged record raises
    // the hardware to that epoch, not to the planted value.
    let mut next = meta_with(1, 7, 9, u32::MAX);
    ota_mark_boot_good_pure(&mut next);
    floor::commit(ota_confirmed_epoch(&next));
    assert_eq!(HELD.load(Ordering::SeqCst), 9);
    // Canary: the old call, with the volume's number, ratchets the planted
    // value into the hardware. This is what the asserts above discriminate.
    floor::commit(next.min_sec_epoch);
    assert_eq!(HELD.load(Ordering::SeqCst), u32::MAX, "canary: the old call would lock the TPM out");
}

#[test]
fn a_failed_raise_leaves_the_floor_where_it_was_and_the_next_confirmation_retries() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    setup(4);
    let fails = floor::raise_failures();
    FAIL.store(1, Ordering::SeqCst);
    floor::commit(6);
    assert_eq!(floor::raise_failures(), fails + 1);
    assert_eq!(HELD.load(Ordering::SeqCst), 4, "the hardware did not move");
    // What is known has not moved either: BOOTMETA's own 6 is what holds.
    assert_eq!(floor::lift(0), 4);
    assert_eq!(floor::lift(6), 6);
    floor::commit(6);
    assert_eq!(HELD.load(Ordering::SeqCst), 6);
    assert_eq!(floor::raise_failures(), fails + 1);
    assert_eq!(floor::lift(0), 6);
}

#[test]
fn a_backend_that_is_ahead_is_never_lowered_by_a_stale_cache() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    setup(5);
    // Something else raised the hardware to 12 after the boot read 5.
    HELD.store(12, Ordering::SeqCst);
    floor::commit(8);
    assert_eq!(HELD.load(Ordering::SeqCst), 12);
    // The cache learned the real value from the answer.
    assert_eq!(floor::lift(0), 12);
}

#[test]
fn the_nv_password_follows_the_index_and_is_never_empty() {
    assert_eq!(floor::nv_auth(0x0150_0001), floor::nv_auth(0x0150_0001));
    assert_ne!(floor::nv_auth(0x0150_0001), floor::nv_auth(0x0150_0002));
    assert_ne!(floor::nv_auth(0x0150_0001), [0u8; 32]);
}
