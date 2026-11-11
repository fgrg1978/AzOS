// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Directory-changing operations of one FAT32 volume are serialised.
//!
//! A directory sector and the journal sector are read-modified-written with
//! no per-sector claim, and the device waits inside those sequences let a
//! second task in. Each test parks thread A inside its operation (the shim's
//! before-write hook, before the bytes land) and runs thread B's operation
//! meanwhile. With the volume's mutation claim, B waits until A is done; A's
//! park is bounded, so a correct build finishes in well under a second.
//!
//! Canary: `--features fat-dir-unserialised-canary` (the claim excludes
//! nothing and a handle's entry update does not re-check the name): every
//! test here fails.

#![cfg(test)]

use super::image::*;
use super::{fat32, serial};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::time::{Duration, Instant};

const EOC: u32 = 0x0FFF_FFFF;
const JOURNAL_STATE_PENDING: u8 = 1;

static PARK_ON_PENDING: AtomicBool = AtomicBool::new(false);
/// Park at A's n-th write instead (0: off).
static PARK_AT_WRITE: AtomicU32 = AtomicU32::new(0);
static TIMED_OUT: AtomicBool = AtomicBool::new(false);
static ARMED: AtomicBool = AtomicBool::new(false);
static PARKED: AtomicBool = AtomicBool::new(false);
static B_DONE: AtomicBool = AtomicBool::new(false);
static B_SEEN: AtomicBool = AtomicBool::new(false);
static B_FOUND_PENDING: AtomicBool = AtomicBool::new(false);
static A_WRITES: AtomicU32 = AtomicU32::new(0);
std::thread_local!(static IS_A: core::cell::Cell<bool> = const { core::cell::Cell::new(false) });
std::thread_local!(static IS_B: core::cell::Cell<bool> = const { core::cell::Cell::new(false) });

fn journal_pending() -> bool {
    fs_test_drivers::disk_peek(fat32::JOURNAL_SECTOR as u64).is_some_and(|s| s[4] == JOURNAL_STATE_PENDING)
}

/// A's write that follows its journal record's (or, with `PARK_ON_PENDING`
/// off, its first write) parks until B is done (a build without the claim:
/// B ran its whole operation inside A's window) or 300 ms passed (a correct
/// build: B waits for A's claim). B's first write notes whether a record is
/// pending on the medium.
fn hook() {
    if IS_A.with(|a| a.get()) {
        let n = A_WRITES.fetch_add(1, SeqCst) + 1;
        let at = PARK_AT_WRITE.load(SeqCst);
        let ready = if at != 0 { n == at } else { !PARK_ON_PENDING.load(SeqCst) || journal_pending() };
        if ready && ARMED.swap(false, SeqCst) {
            PARKED.store(true, SeqCst);
            let t0 = Instant::now();
            while !B_DONE.load(SeqCst) && t0.elapsed() < Duration::from_millis(300) {
                std::thread::sleep(Duration::from_millis(1));
            }
            TIMED_OUT.store(!B_DONE.load(SeqCst), SeqCst);
        }
    } else if IS_B.with(|b| b.get()) && !B_SEEN.swap(true, SeqCst) {
        B_FOUND_PENDING.store(journal_pending(), SeqCst);
    }
}

fn race<RA: Send + 'static, RB: Send + 'static>(
    park_on_pending: bool,
    a: impl FnOnce() -> RA + Send + 'static,
    b: impl FnOnce() -> RB + Send + 'static,
) -> (RA, RB) {
    PARK_ON_PENDING.store(park_on_pending, SeqCst);
    PARKED.store(false, SeqCst);
    B_DONE.store(false, SeqCst);
    B_SEEN.store(false, SeqCst);
    B_FOUND_PENDING.store(false, SeqCst);
    A_WRITES.store(0, SeqCst);
    TIMED_OUT.store(false, SeqCst);
    ARMED.store(true, SeqCst);
    fs_test_drivers::disk_before_write(Some(hook));
    let ta = std::thread::spawn(move || { IS_A.with(|x| x.set(true)); a() });
    let t0 = Instant::now();
    while !PARKED.load(SeqCst) {
        assert!(t0.elapsed() < Duration::from_secs(5), "precondition: A never reached its parking write");
        std::thread::sleep(Duration::from_millis(1));
    }
    let tb = std::thread::spawn(move || { IS_B.with(|x| x.set(true)); let r = b(); B_DONE.store(true, SeqCst); r });
    let rb = tb.join().expect("thread B");
    let ra = ta.join().expect("thread A");
    fs_test_drivers::disk_before_write(None);
    ARMED.store(false, SeqCst);
    (ra, rb)
}

fn mount_volume() -> Geom {
    let g = Geom::default();
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, EOC);
    super::swap_medium(img);
    assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
    g
}

fn n83(name: &str) -> [u8; 11] {
    let (b, e) = name.split_once('.').unwrap_or((name, ""));
    let mut r = [b' '; 11];
    r[..b.len()].copy_from_slice(b.as_bytes());
    r[8..8 + e.len()].copy_from_slice(e.as_bytes());
    r
}

/// Live root entries named `name` on the medium.
fn root_entries_named(g: &Geom, name: &str) -> usize {
    let want = n83(name);
    let sec = fs_test_drivers::disk_peek(cluster_sector(g, 2) as u64).expect("root sector");
    (0..SECTOR / 32).filter(|i| sec[i * 32] != 0xE5 && sec[i * 32..i * 32 + 11] == want).count()
}

fn vol() -> fat32::Volume {
    fat32::Volume::assume_mounted()
}

fn create_flags() -> u32 {
    fat32::open_flags::WRITE | fat32::open_flags::CREATE
}

/// **Two creators, one directory sector.** A has found the first free slot
/// and is writing the sector; B creates another file meanwhile. Unserialised,
/// B reads the sector without A's entry, picks the same slot, and one of the
/// two writes replaces the other: a name is gone and the surviving entry's
/// owner updates the wrong file at its close.
#[test]
fn two_creators_in_one_directory_keep_both_names() {
    let _g = serial();
    let _wt = crate::write_through();
    mount_volume();
    let (a, b) = race(
        false,
        || fat32::fat32_open(vol(), b"/A.TXT", create_flags()),
        || fat32::fat32_open(vol(), b"/B.TXT", create_flags()),
    );
    let (a, b) = (a.expect("A creates"), b.expect("B creates"));
    assert!(fat32::fat32_lookup_root(&n83("A.TXT")).is_ok(), "A's name was replaced by B's entry");
    assert!(fat32::fat32_lookup_root(&n83("B.TXT")).is_ok(), "B's name was replaced by A's entry");
    assert_eq!(fat32::fat32_close(a), Ok(()));
    assert_eq!(fat32::fat32_close(b), Ok(()));
}

/// **Two creators of one name.** A has looked the name up and found nothing
/// and is in the middle of its journaled create; B creates the same name.
/// Unserialised, both inserted: two entries, the second unreachable, its
/// chain leaked.
#[test]
fn two_creators_of_one_name_make_one_entry() {
    let _g = serial();
    let _wt = crate::write_through();
    let g = mount_volume();
    let name = n83("SAME.TXT");
    let (a, b) = race(
        true,
        move || fat32::fat32_write_file(&name, b"from A"),
        move || fat32::fat32_write_file(&name, b"from B"),
    );
    assert_eq!((a, b), (Ok(()), Ok(())));
    assert_eq!(root_entries_named(&g, "SAME.TXT"), 1, "one name, one entry");
}

/// **One journal slot.** A's rename over an existing file has its record on
/// the medium and has not applied it; B starts another journaled rename.
/// Unserialised, B's record replaces A's while A's step is half done, and a
/// cut then leaves both names of A's rename on one chain. Serialised, no
/// record is pending when B's first write goes out.
#[test]
fn a_second_journaled_op_never_starts_over_a_pending_record() {
    let _g = serial();
    let _wt = crate::write_through();
    mount_volume();
    for (n, d) in [("X.TXT", "xx"), ("Y.TXT", "yy"), ("P.TXT", "pp"), ("Q.TXT", "qq")] {
        assert_eq!(fat32::fat32_write_file(&n83(n), d.as_bytes()), Ok(()));
    }
    let (a, b) = race(
        true,
        || fat32::fat32_rename(&n83("X.TXT"), &n83("Y.TXT")),
        || fat32::fat32_rename(&n83("P.TXT"), &n83("Q.TXT")),
    );
    assert_eq!((a, b), (Ok(()), Ok(())));
    assert!(!B_FOUND_PENDING.load(SeqCst), "B wrote its record over A's pending one");
}

/// **A stale slot.** A holds a file open and dirty; the file is unlinked and
/// another file takes its directory slot. A's close must not write A's first
/// cluster and size into the other file's entry.
#[test]
fn a_handle_of_an_unlinked_file_does_not_update_the_entry_that_reused_its_slot() {
    let _g = serial();
    let _wt = crate::write_through();
    mount_volume();
    let f = fat32::fat32_open(vol(), b"/F.TXT", create_flags()).expect("create F");
    assert_eq!(fat32::fat32_write(f, b"data of F"), Ok(9));
    assert_eq!(fat32::fat32_unlink_root(&n83("F.TXT")), Ok(()));
    let g = fat32::fat32_open(vol(), b"/G.TXT", create_flags()).expect("create G in F's slot");
    assert_eq!(fat32::fat32_close(g), Ok(()));
    assert!(fat32::fat32_close(f).is_err(), "the entry the handle named is gone");
    assert_eq!(fat32::fat32_lookup_root(&n83("G.TXT")), Ok((0, 0)), "G keeps its own cluster and size");
}

/// **An overwrite's data is not written under the claim.** A rewrites an
/// existing file and is parked after its new chain's first data write, before
/// its journal record; B creates another file in the same directory. B must
/// finish while A is parked, not wait for A to release the volume claim.
#[test]
fn an_overwrite_writes_its_data_before_it_takes_the_volume_claim() {
    let _g = serial();
    let _wt = crate::write_through();
    mount_volume();
    assert_eq!(fat32::fat32_write_file(&n83("OLD.TXT"), b"old"), Ok(()));
    PARK_AT_WRITE.store(3, SeqCst); // two FAT copies of the allocation, then the data
    let (a, b) = race(
        false,
        || fat32::fat32_write_file(&n83("OLD.TXT"), b"new contents"),
        || fat32::fat32_write_file(&n83("OTHER.TXT"), b"other"),
    );
    PARK_AT_WRITE.store(0, SeqCst);
    assert_eq!((a, b), (Ok(()), Ok(())));
    assert!(!TIMED_OUT.load(SeqCst), "B waited for A's claim while A wrote its data");
}
