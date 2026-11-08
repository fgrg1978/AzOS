// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Damaged images: whatever the bytes, a mount and a walk of the whole
//! volume answer a value or a typed refusal, never a panic and never a loop
//! that does not end.
//!
//! Two passes per image. The structured one rewrites the length fields of
//! every directory entry of every directory's first block to the values a
//! parser gets wrong (0, 1 past the block, the largest a field holds). The
//! random one flips bytes of the metadata a clean walk read (superblock,
//! descriptors, inodes, directory, extent and indirect blocks), from a fixed
//! seed so a failure is reproducible.

use azos_ext4::{BlockSource, DirEntry, Error, IoError, Volume, PATH_MAX, ROOT_INO};
use azos_ext4_tests::{image, Mem, Spec, EXT4};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

fn dir() -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("corrupt");
    std::fs::create_dir_all(&d).unwrap();
    d
}

const SPECS: &[Spec] = &[
    Spec { name: "fz-ext4-1k", block: 1024, inode: 256, features: EXT4, extended: "", mib: 4, htree: true },
    Spec { name: "fz-ext3-1k", block: 1024, inode: 128, features: "filetype,sparse_super,dir_index", extended: "", mib: 4, htree: false },
    Spec { name: "fz-ext2-nofiletype", block: 1024, inode: 128, features: "sparse_super", extended: "", mib: 4, htree: false },
    Spec { name: "fz-ext4-4k", block: 4096, inode: 256, features: EXT4, extended: "", mib: 8, htree: false },
];

/// Records every range read (the metadata, when the walk reads no file data).
struct Rec(Mem, Rc<RefCell<Vec<(usize, usize)>>>);

impl BlockSource for Rec {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.1.borrow_mut().push((off as usize, buf.len()));
        self.0.read_at(off, buf)
    }
    fn len(&self) -> u64 {
        self.0.len()
    }
}

/// Walk the tree: list every directory, stat every entry, read at most
/// `data` bytes of each file and every symlink, resolve a few paths. `Ok`
/// with the entries reached, or the first refusal.
fn walk<S: BlockSource>(v: &mut Volume<S>, data: usize) -> Result<usize, Error> {
    let mut seen = 0;
    let mut stack = vec![(v.inode(ROOT_INO)?, 0u32)];
    let mut buf = vec![0u8; data.max(1)];
    while let Some((d, depth)) = stack.pop() {
        let mut e = DirEntry::new();
        let mut pos = 0;
        while let Some(next) = v.readdir(&d, pos, &mut e)? {
            pos = next;
            seen += 1;
            if seen > 2000 {
                return Ok(seen);
            }
            let i = v.inode(e.ino)?;
            if i.is_dir() && depth < 6 {
                stack.push((i, depth + 1));
            } else if i.is_file() && data > 0 {
                v.read(&i, 0, &mut buf)?;
                v.read(&i, i.size.saturating_sub(10), &mut buf[..10.min(data)])?;
            } else if i.is_symlink() {
                let mut t = [0u8; PATH_MAX];
                v.readlink(&i, &mut t)?;
            }
        }
    }
    for p in ["slow", "dirlink/b/c/leaf.txt", "many/an-entry-with-a-rather-long-name-0123", "esc"] {
        let _ = v.resolve(p.as_bytes(), true);
    }
    Ok(seen)
}

/// Mount and walk `img`; a panic names the case.
fn survive(img: Vec<u8>, case: &str) {
    let r = std::panic::catch_unwind(move || {
        if let Ok(mut v) = Volume::mount(Mem(img)) {
            let _ = walk(&mut v, 4096);
        }
    });
    assert!(r.is_ok(), "{case}: the parser panicked");
}

/// xorshift64*: a fixed sequence for a fixed seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The byte offset of every directory's first block: where a `.` entry
/// (ino, rec_len 12, name_len 1, ".") is followed by a `..` entry.
fn first_dir_blocks(img: &[u8], bs: usize) -> Vec<usize> {
    (0..img.len() / bs)
        .map(|b| b * bs)
        .filter(|&at| {
            let d = &img[at..at + 24];
            d[4..6] == [12, 0] && d[6] == 1 && d[8] == b'.' && d[18] == 2 && d[20..22] == *b".."
        })
        .collect()
}

#[test]
fn mangled_images_never_panic() {
    for spec in SPECS {
        let base = image(&dir(), spec);
        let bs = spec.block as usize;
        let filetype = spec.features.contains("filetype");

        // The structured pass.
        let blocks = first_dir_blocks(&base, bs);
        assert!(blocks.len() >= 8, "{}: the directories were found ({})", spec.name, blocks.len());
        for &blk in &blocks {
            let mut at = 0usize;
            let mut n = 0;
            while at < bs && n < 64 {
                let rec = u16::from_le_bytes([base[blk + at + 4], base[blk + at + 5]]) as usize;
                let left = (bs - at) as u16;
                for rec_v in [0u16, 4, 8, 12, left.wrapping_add(4), left, 0xFFFC] {
                    let mut i = base.clone();
                    i[blk + at + 4..blk + at + 6].copy_from_slice(&rec_v.to_le_bytes());
                    survive(i, &format!("{} block {blk:#x} entry {at}: rec_len {rec_v}", spec.name));
                }
                let names: &[u16] = if filetype { &[0, 0xFF] } else { &[0, 0xFF, 0x100, 0x200, 0xFFFF] };
                for &nl in names {
                    let mut i = base.clone();
                    if filetype {
                        i[blk + at + 6] = nl as u8;
                    } else {
                        i[blk + at + 6..blk + at + 8].copy_from_slice(&nl.to_le_bytes());
                    }
                    survive(i, &format!("{} block {blk:#x} entry {at}: name_len {nl}", spec.name));
                }
                if rec < 12 {
                    break;
                }
                at += rec;
                n += 1;
            }
        }

        // The random pass, over what a clean walk read.
        let reads = Rc::new(RefCell::new(Vec::new()));
        let mut v = Volume::mount(Rec(Mem(base.clone()), reads.clone())).unwrap();
        let reached = walk(&mut v, 0).unwrap();
        assert!(reached > 300, "{}: the clean walk reaches the tree ({reached})", spec.name);
        let mut bytes: Vec<usize> = reads.borrow().iter().flat_map(|&(o, l)| o..o + l).collect();
        bytes.sort_unstable();
        bytes.dedup();
        let mut rng = Rng(0x00E4_7A11 ^ spec.block as u64);
        for iter in 0..1500 {
            let mut i = base.clone();
            for _ in 0..1 + rng.below(4) {
                let at = bytes[rng.below(bytes.len())];
                i[at] ^= 1 + rng.below(255) as u8;
            }
            survive(i, &format!("{} flip pass {iter}", spec.name));
        }
    }
}
