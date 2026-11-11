// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The bytes of a FAT32 short name are validated where a component becomes an
//! 8.3 name. A first byte of 0xE5 made an entry that was deleted at birth:
//! every later write inserted it again and leaked the chain of the one before.
//!
//! Canary: `--features fat-name-bytes-canary` (no validation).

#![cfg(test)]

use super::image::*;
use super::{fat32, serial};

fn mount_volume() {
    let g = Geom::default();
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
    super::swap_medium(img);
    assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
}

fn open_create(name: &[u8]) -> Result<fat32::Fat32File, fat32::FsError> {
    let mut path = b"/".to_vec();
    path.extend_from_slice(name);
    fat32::fat32_open(fat32::Volume::assume_mounted(), &path, fat32::open_flags::WRITE | fat32::open_flags::CREATE)
}

/// **A name a directory cannot keep is refused.** The first byte 0xE5 (the
/// deleted marker), 0x05, 0x20 and 0x00; a control byte; the bytes FAT
/// forbids; a second dot; a base or extension that ends in a space.
#[test]
fn a_name_that_is_not_a_short_name_is_refused_at_create() {
    let _g = serial();
    mount_volume();
    let bad: [&[u8]; 12] = [
        b"\xE5A.TXT", b"\x05A.TXT", b" A.TXT", b"\x00A.TXT", b"A\x01.TXT", b"A*B.TXT", b"A?.TXT",
        b"A:B", b"A|B", b"A.B.C", b"A .TXT", b"A.TX ",
    ];
    for name in bad {
        assert_eq!(open_create(name).err(), Some(fat32::FsError::InvalidArg), "{name:?} must be refused");
    }
    // What stays legal: a space inside, lower case (stored upper case), a high byte after the first.
    for name in [&b"A B.TXT"[..], b"lower.txt", b"A\xE9.TXT"] {
        let f = open_create(name).unwrap_or_else(|e| panic!("{name:?} must be accepted: {e:?}"));
        assert_eq!(fat32::fat32_close(f), Ok(()));
    }
}

/// **No chain leaks per write.** The name that used to be accepted left one
/// leaked chain per write; it is refused now, and the volume keeps every cluster.
#[test]
fn a_name_born_deleted_costs_no_cluster() {
    let _g = serial();
    mount_volume();
    let before = fs_test_drivers::disk_peek(Geom::default().rsvd as u64).expect("FAT sector");
    for _ in 0..3 {
        if let Ok(f) = open_create(b"\xE5A") {
            let _ = fat32::fat32_write(f, b"data");
            let _ = fat32::fat32_close(f);
        }
    }
    let after = fs_test_drivers::disk_peek(Geom::default().rsvd as u64).expect("FAT sector");
    assert_eq!(before, after, "writes to a refused name changed the FAT");
}
