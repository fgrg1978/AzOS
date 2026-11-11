// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A directory's walk costs what it maps, not what it claims: a hole is
//! skipped whole, and one call has a step allowance.
//!
//! **Canary.** `hole-walk-canary`: a hole is walked one block at a time.

use azos_ext4::{DirEntry, Error, Inode, Volume};
use azos_ext4_tests::{image, mount, Mem, Spec, EXT4};
use std::path::Path;

fn volume() -> Volume<Mem> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sparse");
    std::fs::create_dir_all(&dir).unwrap();
    let spec = Spec { name: "sparse-1k", block: 1024, inode: 256, features: EXT4, extended: "", mib: 8, htree: false };
    mount(image(&dir, &spec)).unwrap()
}

/// Every entry of `dir` read to the end, and the steps it took.
fn list_steps(v: &mut Volume<Mem>, dir: &Inode) -> Result<(usize, u64), Error> {
    let before = v.work();
    let (mut n, mut pos, mut e) = (0, 0, DirEntry::new());
    while let Some(next) = v.readdir(dir, pos, &mut e)? {
        n += 1;
        pos = next;
    }
    Ok((n, v.work() - before))
}

#[test]
fn a_directory_that_claims_the_partition_but_maps_little_ends_in_a_few_steps() {
    let mut v = volume();
    let mut many = v.resolve(b"many", true).unwrap();
    let (n, mapped) = list_steps(&mut v, &many).unwrap();
    assert_eq!(n, 300);
    let blocks = v.info().blocks_count;
    many.size = blocks * v.info().block_size as u64;
    let (n, claimed) = list_steps(&mut v, &many).unwrap();
    assert_eq!(n, 300);
    assert!(claimed <= mapped + 4, "{claimed} steps for a directory that maps {mapped} blocks of {blocks}");
}

#[test]
fn one_call_has_a_step_allowance() {
    let mut v = volume();
    let many = v.resolve(b"many", true).unwrap();
    v.begin_call(3);
    assert_eq!(v.lookup(&many, b"an-entry-with-a-rather-long-name-0299"), Err(Error::Busy));
    v.begin_call(1 << 16);
    assert!(v.lookup(&many, b"an-entry-with-a-rather-long-name-0299").is_ok());
}
