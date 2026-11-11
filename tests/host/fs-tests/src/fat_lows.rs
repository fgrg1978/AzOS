// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hardening of the FAT32 mount check, journal replay and directory listing
//! against volumes a foreign or hostile writer made.
//!
//! Canary: `--features fat-low-hardening-canary` turns all of it off; each
//! test here fails alone (the limit verdict is
//! `the_check_verdict_follows_the_policy`).

#![cfg(test)]

use super::image::*;
use super::{fat32, serial};

const EOC: u32 = 0x0FFF_FFFF;
const ATTR_DIR: u8 = 0x10;

fn raw_dirent(img: &mut [u8], sector: usize, slot: usize, name83: &[u8; 11], attr: u8, cluster: u32, size: u32) {
    let off = sector * SECTOR + slot * 32;
    img[off..off + 32].fill(0);
    img[off..off + 11].copy_from_slice(name83);
    img[off + 11] = attr;
    img[off + 20..off + 22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    img[off + 26..off + 28].copy_from_slice(&((cluster & 0xFFFF) as u16).to_le_bytes());
    img[off + 28..off + 32].copy_from_slice(&size.to_le_bytes());
}

/// Entry `c` of the first FAT sector (`fat` is that sector).
fn fat_of(fat: &[u8], c: u32) -> u32 {
    let o = c as usize * 4;
    u32::from_le_bytes(fat[o..o + 4].try_into().unwrap()) & 0x0FFF_FFFF
}

fn mount(img: Vec<u8>) {
    super::swap_medium(img);
    assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
}

/// **A directory named `.X` is a child.** The mount check skipped every
/// directory whose short name started with a dot, then gave the clusters of
/// its subtree back as lost. Here `.X` (cluster 3) holds `F.DAT` (cluster 4);
/// the volume reads unclean, so the check runs and repairs.
#[test]
fn the_mount_check_walks_a_directory_whose_name_starts_with_a_dot() {
    let _g = serial();
    let g = Geom::default();
    let mut img = build(&g);
    for c in [2, 3, 4] { set_fat(&mut img, &g, c, EOC); }
    // FAT[1] bit 27 clear: not shut down cleanly.
    let fat1 = g.rsvd as usize * SECTOR + 4;
    img[fat1..fat1 + 4].copy_from_slice(&0x07FF_FFFFu32.to_le_bytes());
    raw_dirent(&mut img, cluster_sector(&g, 2), 0, b".X         ", ATTR_DIR, 3, 0);
    raw_dirent(&mut img, cluster_sector(&g, 3), 0, b".          ", ATTR_DIR, 3, 0);
    raw_dirent(&mut img, cluster_sector(&g, 3), 1, b"..         ", ATTR_DIR, 0, 0);
    raw_dirent(&mut img, cluster_sector(&g, 3), 2, b"F       DAT", 0x20, 4, 5);
    mount(img);
    let r = fat32::fat32_mount_report();
    assert!(r.unclean && r.checked && r.complete, "{r:?}");
    assert_eq!((r.lost_clusters, r.reclaimed), (0, 0), "the subtree was walked, nothing is lost: {r:?}");
    let fat = fs_test_drivers::disk_peek(g.rsvd as u64).unwrap();
    assert_eq!((fat_of(&fat, 3), fat_of(&fat, 4)), (EOC, EOC), "the subtree's clusters stay allocated");
}

/// **A journal offset that is not a dirent boundary is not replayed.** The
/// record's offset is 16: the "dirent" it names straddles two real ones, and
/// the bytes it reads as a start cluster (0) match the record's own. Replayed,
/// recovery wrote a cluster and a size across both entries and freed the
/// chain the record names.
#[test]
fn an_overwrite_record_with_a_misaligned_offset_is_discarded() {
    let _g = serial();
    let g = Geom::default();
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, EOC);
    set_fat(&mut img, &g, 3, EOC);
    let root = cluster_sector(&g, 2);
    raw_dirent(&mut img, root, 0, b"A       DAT", 0x20, 3, 1);
    // The bytes the offset-16 "dirent" reads its start cluster from (B's
    // name[4..6], its last extension byte and attribute) are zero.
    raw_dirent(&mut img, root, 1, b"BBBB\0\0  DA\0", 0, 0, 0);
    let before = img[root * SECTOR..(root + 1) * SECTOR].to_vec();
    let j = fat32::JOURNAL_SECTOR as usize * SECTOR;
    img[j..j + 4].copy_from_slice(b"JRNL");
    img[j + 4] = 0x01; // PENDING
    img[j + 5] = 5; // OVERWRITE
    img[j + 8..j + 12].copy_from_slice(&0u32.to_le_bytes()); // the new chain
    img[j + 12..j + 16].copy_from_slice(&3u32.to_le_bytes()); // the old chain: A's
    img[j + 16..j + 20].copy_from_slice(&(root as u32).to_le_bytes());
    img[j + 20..j + 22].copy_from_slice(&16u16.to_le_bytes());
    img[j + 22..j + 26].copy_from_slice(&0x0BAD_F00Du32.to_le_bytes());
    mount(img);
    let after = fs_test_drivers::disk_peek(root as u64).unwrap();
    assert_eq!(after, before, "the record was replayed across two entries");
    let fat = fs_test_drivers::disk_peek(g.rsvd as u64).unwrap();
    assert_eq!(fat_of(&fat, 3), EOC, "the chain the record named was freed");
}

/// **A name a caller would misread is not listed.** A short name holding `/`
/// reads as two components and one holding a NUL as a shorter name; a crafted
/// directory can carry both, beside an honest entry.
#[test]
fn a_name_with_a_slash_or_a_nul_is_not_listed() {
    let _g = serial();
    let g = Geom::default();
    let mut img = build(&g);
    set_fat(&mut img, &g, 2, EOC);
    let root = cluster_sector(&g, 2);
    raw_dirent(&mut img, root, 0, b"A/B     TXT", 0x20, 0, 0);
    raw_dirent(&mut img, root, 1, b"OK      TXT", 0x20, 0, 0);
    raw_dirent(&mut img, root, 2, b"C\0D     TXT", 0x20, 0, 0);
    mount(img);
    let mut it = fat32::fat32_opendir(fat32::Volume::assume_mounted(), b"/").expect("opendir");
    let mut listed = Vec::new();
    while let Some(e) = it.next() {
        listed.push(e.name[..e.name_len as usize].to_vec());
    }
    assert_eq!(listed, vec![b"OK.TXT".to_vec()]);
    let mut root_ls = Vec::new();
    fat32::fat32_ls_root(|n, _, _| root_ls.push(n.to_vec()));
    assert_eq!(root_ls, vec![b"OK.TXT".to_vec()]);
}
