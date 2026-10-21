// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The crash dump of a ring-3 task (`crash_log::write_beneath`).
//!
//! `kernel/src/trap/crash.rs` writes `CRASHn.DMP` beneath the first write tree
//! the faulting Domain holds (the root path of its `Cap<Dir>`), through
//! `write_beneath` (in the root of the tree: the FAT32 backend names
//! root-directory files only), and picks the slot to rewrite by reading the
//! heads of the existing files with `read_head_beneath`. The layout and the
//! slot choice are `tests/host/panic-policy-tests`; this is the mechanism
//! against the real VFS and FAT32.

use super::vfs_open_close::{fresh_volume, on_disk};
use super::{crash_log, serial, vfs};

fn read_back(t: &mut vfs::ScratchFds, root: &[u8], rel: &[u8]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let n = crash_log::read_head_beneath(t, root, rel, &mut buf)?;
    buf.truncate(n);
    Some(buf)
}

/// **The dump lands in the tree's root and reads back whole**, and each
/// slot is a file of its own.
///
/// **Canary.** Make `write_beneath` open the file by `rel` alone (relative
/// to `/`): the file lands beside the mounts, and every read-back fails.
#[test]
fn crash_dump_beneath_a_directory() {
    let _g = serial();
    fresh_volume();
    let mut t = vfs::ScratchFds::new();
    let dump: Vec<u8> = (0..700u32).map(|i| (i * 7) as u8).collect();
    assert_eq!(
        crash_log::write_beneath(&mut t, b"/fat", b"CRASH0.DMP", &dump),
        crash_log::WriteResult::Written,
    );
    assert_eq!(read_back(&mut t, b"/fat", b"CRASH0.DMP").as_deref(), Some(&dump[..]));
    assert_eq!(on_disk(b"crash0.dmp"), dump, "on the volume, by the backend's own reading");
    assert_eq!(read_back(&mut t, b"/", b"fat/CRASH0.DMP").as_deref(), Some(&dump[..]), "the same file from the root");
    assert_eq!(
        crash_log::write_beneath(&mut t, b"/fat", b"CRASH3.DMP", &dump[..100]),
        crash_log::WriteResult::Written,
    );
    assert_eq!(read_back(&mut t, b"/fat", b"CRASH3.DMP").as_deref(), Some(&dump[..100]));
    assert_eq!(read_back(&mut t, b"/fat", b"CRASH0.DMP").as_deref(), Some(&dump[..]), "the other slot is untouched");
    assert_eq!(read_back(&mut t, b"/fat", b"CRASH1.DMP"), None, "a slot never written reads as empty");
}

/// **Rewriting a slot replaces it whole**: a shorter dump leaves no tail of
/// the longer one behind (the reader's CRC would fail a mix).
///
/// **Canary.** Drop `O_TRUNC` from `write_beneath`: the 300-byte file keeps
/// the last 400 bytes of the old dump.
#[test]
fn a_rewritten_dump_slot_holds_only_the_new_dump() {
    let _g = serial();
    fresh_volume();
    let mut t = vfs::ScratchFds::new();
    let (old, new) = (vec![0xAAu8; 700], vec![0x55u8; 300]);
    for bytes in [&old, &new] {
        assert_eq!(
            crash_log::write_beneath(&mut t, b"/fat", b"CRASH1.DMP", bytes),
            crash_log::WriteResult::Written,
        );
    }
    assert_eq!(read_back(&mut t, b"/fat", b"CRASH1.DMP").as_deref(), Some(&new[..]));
}

/// **A name that leaves the directory writes nothing.**
///
/// **Canary.** Join by concatenation: `../ESC.DMP` lands in the root.
#[test]
fn crash_dump_cannot_leave_its_directory() {
    let _g = serial();
    fresh_volume();
    let mut t = vfs::ScratchFds::new();
    for rel in [&b"../ESC.DMP"[..], b"x/../../ESC.DMP", b"/fat/ESC.DMP"] {
        assert_eq!(
            crash_log::write_beneath(&mut t, b"/fat", rel, b"x"),
            crash_log::WriteResult::NotWritten,
            "{:?}", String::from_utf8_lossy(rel),
        );
    }
    assert_eq!(read_back(&mut t, b"/fat", b"ESC.DMP"), None, "nothing was created in the tree");
    assert_eq!(read_back(&mut t, b"/", b"ESC.DMP"), None, "nor above it");
}
