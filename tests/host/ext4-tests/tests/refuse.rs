// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the parser refuses, and the reason it gives: features it does not
//! read, a journal that needs recovery, checksums that do not match, numbers
//! that point outside the volume.

use azos_ext4::{Corrupt, Error, MountError};
use azos_ext4_tests::{image, mount, read_all, Spec, EXT4};
use std::path::{Path, PathBuf};

fn dir() -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("refuse");
    std::fs::create_dir_all(&d).unwrap();
    d
}

const CSUM: Spec = Spec { name: "csum-1k", block: 1024, inode: 256, features: EXT4, extended: "", mib: 8, htree: false };
const PLAIN: Spec = Spec {
    name: "plain-4k",
    block: 4096,
    inode: 256,
    features: "filetype,extent,flex_bg,sparse_super,large_file,dir_index",
    extended: "",
    mib: 8,
    htree: false,
};

fn feature_image(name: &'static str, features: &'static str, block: u32, mib: u32) -> Vec<u8> {
    image(&dir(), &Spec { name, block, inode: 256, features, extended: "", mib, htree: false })
}

fn sb_u32(img: &mut [u8], off: usize, f: impl FnOnce(u32) -> u32) {
    let at = 1024 + off;
    let v = u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
    img[at..at + 4].copy_from_slice(&f(v).to_le_bytes());
}

fn find(img: &[u8], needle: &[u8]) -> usize {
    let at: Vec<usize> = img.windows(needle.len()).enumerate().filter(|(_, w)| *w == needle).map(|(i, _)| i).collect();
    assert_eq!(at.len(), 1, "{:?} must be on the image once", String::from_utf8_lossy(needle));
    at[0]
}

#[test]
fn features_it_does_not_read_refuse_the_mount() {
    for (name, feats, bit) in [
        ("inline", "filetype,extent,ext_attr,inline_data", 0x8000u32),
        ("metabg", "filetype,extent,meta_bg", 0x10),
        ("encrypt", "filetype,extent,encrypt", 0x10000),
        ("casefold", "filetype,extent,casefold", 0x20000),
    ] {
        let img = feature_image(name, feats, 4096, 8);
        assert_eq!(mount(img).err(), Some(MountError::Incompat(bit)), "{name}");
    }
    let img = feature_image("bigalloc", "filetype,extent,bigalloc", 4096, 32);
    assert_eq!(mount(img).err(), Some(MountError::RoCompat(0x200)));
    let img = feature_image("64k", "filetype,extent", 65536, 64);
    assert_eq!(mount(img).err(), Some(MountError::BlockSize(6)));
}

#[test]
fn bits_set_by_hand_refuse_the_mount() {
    let base = image(&dir(), &PLAIN);
    assert!(mount(base.clone()).is_ok());
    let with = |off: usize, f: fn(u32) -> u32| {
        let mut i = base.clone();
        sb_u32(&mut i, off, f);
        mount(i).err()
    };
    assert_eq!(with(0x60, |v| v | 0x4), Some(MountError::NeedsRecovery));
    assert_eq!(with(0x60, |v| v | 0x100), Some(MountError::Incompat(0x100)), "mmp");
    assert_eq!(with(0x60, |v| v | 0x8000_0000), Some(MountError::Incompat(0x8000_0000)), "an unknown bit");
    assert_eq!(with(0x38, |v| v ^ 1), Some(MountError::BadMagic));
    assert_eq!(with(0x18, |_| 3), Some(MountError::BlockSize(3)));
    assert_eq!(with(0x04, |v| v * 2), Some(MountError::Geometry), "more blocks than the partition");
    assert_eq!(with(0x00, |v| v + 1), Some(MountError::Geometry), "inodes that are not groups x per-group");
    let mut short = base.clone();
    short.truncate(base.len() / 2);
    assert_eq!(mount(short).err(), Some(MountError::Geometry), "a partition shorter than the volume");
    assert_eq!(mount(vec![0u8; 1500]).err(), Some(MountError::Geometry));
}

#[test]
fn checksums_refuse_what_does_not_match() {
    let base = image(&dir(), &CSUM);
    assert!(mount(base.clone()).is_ok());
    // The volume label is checksummed like every other superblock byte.
    let mut i = base.clone();
    i[1024 + 0x78] ^= 0x20;
    assert_eq!(mount(i).err(), Some(MountError::SuperChecksum));
    let mut i = base.clone();
    i[1024 + 0x175] = 2;
    assert_eq!(mount(i).err(), Some(MountError::ChecksumType(2)));
    // Group 0's descriptor (block 2 on a 1 KiB volume): its block bitmap.
    let mut i = base.clone();
    i[2048] ^= 1;
    assert_eq!(mount(i).err(), Some(MountError::Group(0)));
    // A byte of a name in the root directory: the leaf's checksum.
    let mut i = base.clone();
    let at = find(&i, b"empty.txt");
    i[at] ^= 0x20;
    let mut v = mount(i).unwrap();
    assert_eq!(v.resolve(b"hello.txt", true).err(), Some(Error::Corrupt(Corrupt::Checksum)));
}

/// Where inode `ino` is on `img` (the descriptor table read by hand).
fn inode_at(img: &[u8], ino: u32) -> usize {
    let sb = &img[1024..2048];
    let r32 = |o: usize| u32::from_le_bytes(sb[o..o + 4].try_into().unwrap()) as usize;
    let bs = 1024usize << r32(0x18);
    let ipg = r32(0x28);
    let isz = u16::from_le_bytes(sb[0x58..0x5A].try_into().unwrap()) as usize;
    let is64 = r32(0x60) & 0x80 != 0;
    let ds = if is64 { u16::from_le_bytes(sb[0xFE..0x100].try_into().unwrap()) as usize } else { 32 };
    let g = (ino as usize - 1) / ipg;
    let d = (r32(0x14) + 1) * bs + g * ds;
    let mut table = u32::from_le_bytes(img[d + 8..d + 12].try_into().unwrap()) as usize;
    if is64 {
        table |= (u32::from_le_bytes(img[d + 0x28..d + 0x2C].try_into().unwrap()) as usize) << 32;
    }
    table * bs + ((ino as usize - 1) % ipg) * isz
}

#[test]
fn a_flipped_inode_is_refused() {
    let base = image(&dir(), &CSUM);
    let mut v = mount(base.clone()).unwrap();
    let ino = v.resolve(b"hello.txt", true).unwrap().ino;
    let mut i = base.clone();
    // Its modification time: nothing but the checksum can tell.
    i[inode_at(&base, ino) + 0x10] ^= 1;
    let mut v = mount(i).unwrap();
    assert_eq!(v.resolve(b"hello.txt", true).err(), Some(Error::Corrupt(Corrupt::Checksum)));
    // Without metadata_csum the same flip is not seen.
    let base = image(&dir(), &PLAIN);
    let mut v = mount(base.clone()).unwrap();
    let ino = v.resolve(b"hello.txt", true).unwrap().ino;
    let mut i = base.clone();
    i[inode_at(&base, ino) + 0x10] ^= 1;
    let mut v = mount(i).unwrap();
    let f = v.resolve(b"hello.txt", true).unwrap();
    assert_eq!(read_all(&mut v, &f).unwrap(), b"hello ext4\n");
}

#[test]
fn numbers_that_point_outside_the_volume_are_refused() {
    let base = image(&dir(), &PLAIN);
    // The entry's inode number (the 8 bytes before its name).
    let mut i = base.clone();
    let at = find(&i, b"empty.txt") - 8;
    i[at..at + 4].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    let mut v = mount(i).unwrap();
    assert_eq!(v.resolve(b"empty.txt", true).err(), Some(Error::Corrupt(Corrupt::InodeRange)));
    // The file's extent: its first block past the end of the volume.
    let mut v = mount(base.clone()).unwrap();
    let ino = v.resolve(b"hello.txt", true).unwrap().ino;
    let mut i = base.clone();
    let ext = inode_at(&base, ino) + 0x28 + 12;
    i[ext + 8..ext + 12].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    let mut v = mount(i).unwrap();
    let f = v.resolve(b"hello.txt", true).unwrap();
    assert_eq!(read_all(&mut v, &f).err(), Some(Error::Corrupt(Corrupt::Extent)));
    // The extent header's magic.
    let mut i = base.clone();
    i[inode_at(&base, ino) + 0x28] ^= 1;
    let mut v = mount(i).unwrap();
    let f = v.resolve(b"hello.txt", true).unwrap();
    assert_eq!(read_all(&mut v, &f).err(), Some(Error::Corrupt(Corrupt::Extent)));
}
