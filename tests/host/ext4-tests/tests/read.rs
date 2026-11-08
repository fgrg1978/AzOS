// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The parser reads back what `mke2fs -d` put on the volume, for every
//! feature set and block size it mounts: the fixture tree on the host is the
//! oracle.

use azos_ext4::{Error, Volume, PATH_MAX};
use azos_ext4_tests::{big, image, list, long_dir, mount, read_all, Mem, Spec, EXT4};
use std::path::{Path, PathBuf};

const SPECS: &[Spec] = &[
    Spec { name: "ext4-4k-htree", block: 4096, inode: 256, features: EXT4, extended: "", mib: 8, htree: true },
    Spec { name: "ext4-1k-htree", block: 1024, inode: 256, features: EXT4, extended: "", mib: 8, htree: true },
    Spec {
        name: "ext3-htree-1k",
        block: 1024,
        inode: 128,
        features: "has_journal,filetype,sparse_super,large_file,dir_index",
        extended: "",
        mib: 8,
        htree: true,
    },
    Spec { name: "ext4-4k", block: 4096, inode: 256, features: EXT4, extended: "", mib: 8, htree: false },
    Spec { name: "ext4-1k", block: 1024, inode: 256, features: EXT4, extended: "", mib: 8, htree: false },
    Spec { name: "ext4-2k", block: 2048, inode: 512, features: EXT4, extended: "", mib: 8, htree: false },
    Spec {
        name: "ext4-seed",
        block: 4096,
        inode: 256,
        features: "filetype,extent,64bit,flex_bg,sparse_super,dir_index,extra_isize,metadata_csum,metadata_csum_seed",
        extended: "",
        mib: 8,
        htree: false,
    },
    Spec {
        name: "ext4-32bit-nocsum",
        block: 4096,
        inode: 256,
        features: "has_journal,filetype,extent,flex_bg,sparse_super,large_file,dir_index,uninit_bg",
        extended: "",
        mib: 8,
        htree: false,
    },
    Spec {
        name: "ext3-blockmap-1k",
        block: 1024,
        inode: 128,
        features: "has_journal,filetype,sparse_super,large_file,dir_index",
        extended: "",
        mib: 8,
        htree: false,
    },
    Spec { name: "ext2-4k", block: 4096, inode: 256, features: "filetype,sparse_super", extended: "", mib: 8, htree: false },
    Spec { name: "ext2-nofiletype-1k", block: 1024, inode: 128, features: "sparse_super", extended: "", mib: 8, htree: false },
];

fn dir() -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("read");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn mounted(spec: &Spec) -> Volume<Mem> {
    mount(image(&dir(), spec)).unwrap_or_else(|e| panic!("{}: mount refused: {e:?}", spec.name))
}

fn read_path(v: &mut Volume<Mem>, path: &str) -> Result<Vec<u8>, Error> {
    let i = v.resolve(path.as_bytes(), true)?;
    read_all(v, &i)
}

/// Compare the volume's tree with the fixture's, file by file.
fn same_tree(v: &mut Volume<Mem>, host: &Path, path: &str, name: &str) {
    let ino = v.resolve(path.as_bytes(), false).unwrap_or_else(|e| panic!("{name}: resolve {path}: {e:?}"));
    let meta = std::fs::symlink_metadata(host).unwrap();
    if meta.file_type().is_symlink() {
        assert!(ino.is_symlink(), "{name}: {path} is not a symlink");
        let mut t = [0u8; PATH_MAX];
        let n = v.readlink(&ino, &mut t).unwrap();
        assert_eq!(&t[..n], std::fs::read_link(host).unwrap().as_os_str().as_encoded_bytes(), "{name}: {path}");
    } else if meta.is_dir() {
        assert!(ino.is_dir(), "{name}: {path} is not a directory");
        let mut want: Vec<Vec<u8>> =
            std::fs::read_dir(host).unwrap().map(|e| e.unwrap().file_name().as_encoded_bytes().to_vec()).collect();
        if path == "/" {
            want.push(b"lost+found".to_vec());
        }
        want.sort();
        let mut got: Vec<Vec<u8>> = list(v, &ino).unwrap().into_iter().map(|(n, _)| n).collect();
        got.sort();
        assert_eq!(got, want, "{name}: entries of {path}");
        for e in std::fs::read_dir(host).unwrap() {
            let e = e.unwrap();
            let child = format!("{}/{}", path.trim_end_matches('/'), e.file_name().to_str().unwrap());
            same_tree(v, &e.path(), &child, name);
        }
    } else {
        assert!(ino.is_file(), "{name}: {path} is not a file");
        assert_eq!(ino.size, meta.len(), "{name}: size of {path}");
        assert_eq!(read_all(v, &ino).unwrap(), std::fs::read(host).unwrap(), "{name}: contents of {path}");
    }
}

#[test]
fn every_feature_set_reads_the_fixture_tree() {
    for spec in SPECS {
        let mut v = mounted(spec);
        assert_eq!(v.info().block_size, spec.block, "{}", spec.name);
        let host = dir().join("fixture");
        same_tree(&mut v, &host, "/", spec.name);
    }
}

#[test]
fn the_features_tested_are_the_ones_named() {
    let feats = |n: &str| mounted(SPECS.iter().find(|s| s.name == n).unwrap()).info().features;
    let f = feats("ext4-4k");
    assert!(f.extents() && f.is_64bit() && f.metadata_csum() && f.has_journal() && f.filetype());
    let f = feats("ext3-blockmap-1k");
    assert!(!f.extents() && !f.is_64bit() && !f.metadata_csum() && f.has_journal());
    let f = feats("ext2-nofiletype-1k");
    assert!(!f.filetype() && !f.extents());
    // The htree images index the large directory; the others leave it linear.
    for (name, indexed) in [("ext4-4k-htree", true), ("ext4-1k-htree", true), ("ext3-htree-1k", true), ("ext4-4k", false)] {
        let mut v = mounted(SPECS.iter().find(|s| s.name == name).unwrap());
        let many = v.resolve(b"many", true).unwrap();
        assert_eq!(many.flags & 0x1000 != 0, indexed, "{name}: htree index flag");
    }
}

#[test]
fn symlinks_resolve_beneath_the_root() {
    for spec in SPECS {
        let mut v = mounted(spec);
        let n = spec.name;
        assert_eq!(read_path(&mut v, "fast").unwrap(), b"hello ext4\n", "{n}");
        assert_eq!(read_path(&mut v, "slow").unwrap(), b"slow target\n", "{n}");
        assert_eq!(read_path(&mut v, "abs").unwrap(), b"hello ext4\n", "{n}");
        // `..` past the root stays at the root.
        assert_eq!(read_path(&mut v, "esc").unwrap(), b"hello ext4\n", "{n}");
        assert_eq!(read_path(&mut v, "dirlink/b/c/leaf.txt").unwrap(), b"leaf\n", "{n}");
        assert_eq!(read_path(&mut v, "deep/a/../a/./b/c/leaf.txt").unwrap(), b"leaf\n", "{n}");
        assert_eq!(read_path(&mut v, "../../hello.txt").unwrap(), b"hello ext4\n", "{n}");
        assert_eq!(v.resolve(b"loop1", true).err(), Some(Error::Loop), "{n}");
        assert!(v.resolve(b"loop1", false).unwrap().is_symlink(), "{n}");
        assert_eq!(v.resolve(b"hello.txt/x", true).err(), Some(Error::NotDir), "{n}");
        assert_eq!(v.resolve(b"nope", true).err(), Some(Error::NotFound), "{n}");
        let slow = v.resolve(b"slow", false).unwrap();
        assert!(slow.size >= 60, "{n}: the slow symlink is in a block");
    }
}

#[test]
fn reads_at_any_offset_match_the_file() {
    let want = big();
    for spec in SPECS {
        let mut v = mounted(spec);
        let i = v.resolve(b"big.bin", true).unwrap();
        for &(off, len) in &[(0u64, 1usize), (1023, 2), (4095, 4097), (12 * 1024 - 1, 70_000), (want.len() as u64 - 5, 100)] {
            let mut buf = vec![0u8; len];
            let n = v.read(&i, off, &mut buf).unwrap();
            let end = (off as usize + len).min(want.len());
            assert_eq!(&buf[..n], &want[off as usize..end], "{} at {off}+{len}", spec.name);
        }
        let mut buf = [0u8; 8];
        assert_eq!(v.read(&i, want.len() as u64, &mut buf).unwrap(), 0, "{}: at the end", spec.name);
        // A hole reads zeros, the tail after it its bytes.
        let s = v.resolve(b"sparse.bin", true).unwrap();
        let mut b = [0xFFu8; 16];
        assert_eq!(v.read(&s, 1000, &mut b).unwrap(), 16);
        assert_eq!(b, [0u8; 16], "{}", spec.name);
        assert_eq!(v.read(&s, 64 * 1024, &mut b).unwrap(), 4);
        assert_eq!(&b[..4], b"tail", "{}", spec.name);
    }
}

#[test]
fn a_large_directory_lists_every_entry_once() {
    for spec in SPECS {
        let mut v = mounted(spec);
        let many = v.resolve(b"many", true).unwrap();
        assert!(many.size > spec.block as u64, "{}: the directory spans blocks", spec.name);
        let names = list(&mut v, &many).unwrap();
        assert_eq!(names.len(), 300, "{}", spec.name);
        let mut uniq: Vec<_> = names.iter().map(|(n, _)| n.clone()).collect();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), 300, "{}", spec.name);
        let i = v.resolve(b"many/an-entry-with-a-rather-long-name-0299", true).unwrap();
        assert_eq!(read_all(&mut v, &i).unwrap(), b"299\n");
        let long = format!("deep/{}/f", long_dir());
        assert_eq!(read_path(&mut v, &long).unwrap(), b"slow target\n");
    }
}
