// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Power cuts in a subdirectory: the same protocols as the root's
//! (`power_cut`), run on files below it, cut at every flush boundary and in
//! every subset of the writes between two (`cut_everywhere`), then the volume
//! is mounted (recovery and the check) and judged.
//!
//! The judge reads through the driver (`read_back`), not the fixture's own
//! root-only helpers, so a file below the root is judged as the reader sees
//! it. The tree-soundness and leak checks of `cut_everywhere` walk every
//! directory.
//!
//! A cross-directory rename onto a free name is the case the root never has:
//! the target is first made an empty entry, and the one rename record then
//! moves the chain onto it. Its legal outcomes are the source whole with the
//! target absent or empty, or the target whole with the source gone; never
//! both names on one chain, never neither.

use super::*;
use vfs::FileSystem as _;

use super::super::vfs;

fn key(sub: &[u8]) -> vfs::InodeKey {
    fat32::FAT32_FS.key_for(sub).expect("a legal path")
}

/// A volume whose directories `/D1` and `/D2` exist and whose files are
/// durable: `files` are `(path below the mount, bytes)`.
fn image_with(files: &[(&[u8], &[u8])]) -> Vec<u8> {
    remount(fresh_image());
    for d in [&b"/D1"[..], b"/D2"] {
        assert_eq!(fat32::fat32_mkdir(fat32::Volume::assume_mounted(), d), Ok(()));
    }
    for (path, data) in files {
        assert_eq!(fat32::FAT32_FS.write_all(&key(path), data), Ok(()));
    }
    assert_eq!(fat32::fat32_sync(), Ok(()));
    disk_durable_image()
}

/// The root directory's clusters, so the first remount can tell the fixture
/// from what a cut leaves.
fn got(path: &[u8]) -> Option<Vec<u8>> {
    read_back(path)
}

#[test]
fn a_create_in_a_subdirectory_cut_anywhere_leaves_nothing_or_the_whole_file() {
    let _g = serial();
    let data = pattern(OLD, 0x31);
    let flushes = cut_everywhere(
        image_with(&[]),
        || assert_eq!(fat32::FAT32_FS.write_all(&key(b"D1/REC.DAT"), &data), Ok(())),
        |_| one_of_content(b"/D1/REC.DAT", &[None, Some(&data[..])]),
    );
    println!("create in a subdirectory: {flushes} flushes");
}

#[test]
fn an_overwrite_in_a_subdirectory_cut_anywhere_leaves_the_old_or_the_new_file() {
    let _g = serial();
    let (old, new) = (pattern(OLD, 0x11), pattern(NEW, 0x77));
    let flushes = cut_everywhere(
        image_with(&[(b"D1/REC.DAT", &old)]),
        || assert_eq!(fat32::FAT32_FS.write_all(&key(b"D1/REC.DAT"), &new), Ok(())),
        |_| one_of_content(b"/D1/REC.DAT", &[Some(&old[..]), Some(&new[..])]),
    );
    println!("overwrite in a subdirectory: {flushes} flushes");
}

#[test]
fn an_unlink_in_a_subdirectory_cut_anywhere_leaves_the_file_or_nothing() {
    let _g = serial();
    let old = pattern(OLD, 0x11);
    let flushes = cut_everywhere(
        image_with(&[(b"D1/REC.DAT", &old)]),
        || assert_eq!(fat32::FAT32_FS.unlink(&key(b"D1/REC.DAT")), Ok(())),
        |_| one_of_content(b"/D1/REC.DAT", &[Some(&old[..]), None]),
    );
    println!("unlink in a subdirectory: {flushes} flushes");
}

#[test]
fn a_rename_over_a_file_in_a_subdirectory_cut_anywhere_never_loses_the_source() {
    let _g = serial();
    let (old, new) = (pattern(OLD, 0x11), pattern(NEW, 0x77));
    let flushes = cut_everywhere(
        image_with(&[(b"D1/LIVE.BIN", &old), (b"D1/STAGE.BIN", &new)]),
        || assert_eq!(fat32::FAT32_FS.rename(b"D1/STAGE.BIN", b"D1/LIVE.BIN"), Ok(())),
        |_| {
            let (live, stage) = (got(b"/D1/LIVE.BIN"), got(b"/D1/STAGE.BIN"));
            one_of_content(b"/D1/LIVE.BIN", &[Some(&old[..]), Some(&new[..])])?;
            one_of_content(b"/D1/STAGE.BIN", &[Some(&new[..]), None])?;
            if live.as_deref() == Some(&old[..]) && stage.is_none() {
                return Err("both names lost the new image".into());
            }
            if live.as_deref() == Some(&new[..]) && stage.is_some() {
                return Err("both names on one chain".into());
            }
            Ok(())
        },
    );
    println!("rename over a file in a subdirectory: {flushes} flushes");
}

/// **The staged image becomes the live one in another directory**: the target
/// name is free. Legal: the source whole and the target absent or empty, or
/// the target whole and the source gone.
#[test]
fn a_rename_to_a_free_name_in_another_directory_cut_anywhere_has_one_name_on_the_chain() {
    let _g = serial();
    let data = pattern(OLD, 0x45);
    let flushes = cut_everywhere(
        image_with(&[(b"D1/STAGE.BIN", &data)]),
        || assert_eq!(fat32::FAT32_FS.rename(b"D1/STAGE.BIN", b"D2/LIVE.BIN"), Ok(())),
        |_| {
            let (src, dst) = (got(b"/D1/STAGE.BIN"), got(b"/D2/LIVE.BIN"));
            match (src.as_deref(), dst.as_deref()) {
                (Some(s), None) | (Some(s), Some(&[])) if s == &data[..] => Ok(()),
                (None, Some(d)) if d == &data[..] => Ok(()),
                (Some(_), Some(d)) if d == &data[..] => Err("both names on one chain".into()),
                (None, _) => Err(format!("the source is gone and the target holds {:?} bytes", dst.map(|v| v.len()))),
                _ => Err(format!("source {:?} bytes, target {:?} bytes", src.map(|v| v.len()), dst.map(|v| v.len()))),
            }
        },
    );
    println!("rename across directories to a free name: {flushes} flushes");
}

/// Up into the root, the other direction of the same.
#[test]
fn a_rename_from_a_subdirectory_to_the_root_cut_anywhere_has_one_name_on_the_chain() {
    let _g = serial();
    let (old, new) = (pattern(OLD, 0x11), pattern(NEW, 0x77));
    let flushes = cut_everywhere(
        image_with(&[(b"D1/STAGE.BIN", &new), (b"LIVE.BIN", &old)]),
        || assert_eq!(fat32::FAT32_FS.rename(b"D1/STAGE.BIN", b"LIVE.BIN"), Ok(())),
        |_| {
            let (live, stage) = (got(b"/LIVE.BIN"), got(b"/D1/STAGE.BIN"));
            match (live.as_deref(), stage.as_deref()) {
                (Some(l), Some(s)) if l == &old[..] && s == &new[..] => Ok(()),
                (Some(l), None) if l == &new[..] => Ok(()),
                (Some(l), Some(_)) if l == &new[..] => Err("both names on one chain".into()),
                _ => Err(format!("live {:?} bytes, staged {:?} bytes", live.map(|v| v.len()), stage.map(|v| v.len()))),
            }
        },
    );
    println!("rename from a subdirectory to the root: {flushes} flushes");
}
