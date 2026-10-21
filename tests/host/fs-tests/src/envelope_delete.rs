// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The delete gate (`storage_delete` of the effect gate): the VFS asks it
//! before an unlink, a rename over a file, a cut below a file's size (by
//! `truncate` or by `O_TRUNC`), and the azvol engine before it drops a
//! snapshot. The hook here records what it was asked and answers as told; the
//! effect gate behind it is tested in `actuation-tests`.
//!
//! **Canary.** `--features envelope-delete-canary` (the gate is never asked):
//! every `*_is_refused` row goes red.

#![cfg(test)]

use super::vfs_open_close::fresh_volume;
use super::{serial, vfs};
use std::sync::Mutex;
use vfs::{DeleteOp, FsErr};

static ASKED: Mutex<Vec<(u8, u64)>> = Mutex::new(Vec::new());
static ANSWER: Mutex<bool> = Mutex::new(true);

fn gate(op: DeleteOp, volume: u64) -> bool {
    ASKED.lock().unwrap().push((op as u8, volume));
    *ANSWER.lock().unwrap()
}

/// Installs the recording gate; removes it again when the test ends, so the
/// suites that run after this one see none.
struct Installed;

impl Installed {
    fn answering(yes: bool) -> Installed {
        ASKED.lock().unwrap().clear();
        *ANSWER.lock().unwrap() = yes;
        vfs::set_delete_gate(gate);
        Installed
    }
    fn asked(&self) -> Vec<u8> {
        ASKED.lock().unwrap().iter().map(|a| a.0).collect()
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        vfs::clear_delete_gate_for_test();
    }
}

fn put(path: &[u8], data: &[u8]) -> bool {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path, vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
    if fd < 0 {
        return false;
    }
    let wrote = data.is_empty() || vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()) == data.len() as i32;
    vfs::vfs_close(&mut t, fd) == 0 && wrote
}

fn size(path: &[u8]) -> Option<u64> {
    vfs::vfs_stat(path).map(|s| s.size)
}

#[test]
fn an_unlink_is_asked_once_and_a_refused_one_changes_nothing() {
    let _g = serial();
    fresh_volume();
    assert!(put(b"/fat/A.TXT", b"hello"));
    let gate = Installed::answering(false);
    assert_eq!(vfs::vfs_unlink(b"/fat/A.TXT"), Err(FsErr::Denied), "unlink_is_refused");
    assert_eq!(gate.asked(), [DeleteOp::Unlink as u8]);
    assert_eq!(size(b"/fat/A.TXT"), Some(5), "the file is still there");
    *ANSWER.lock().unwrap() = true;
    assert_eq!(vfs::vfs_unlink(b"/fat/A.TXT"), Ok(()));
    assert_eq!(size(b"/fat/A.TXT"), None);
    // Nothing to delete: the answer is NotFound and the gate is not asked
    // (a refused delete of a missing file would leave a receipt for nothing).
    ASKED.lock().unwrap().clear();
    assert_eq!(vfs::vfs_unlink(b"/fat/A.TXT"), Err(FsErr::NotFound));
    assert_eq!(vfs::vfs_unlink(b"/fat/NOPE/A.TXT"), Err(FsErr::NotFound));
    assert!(gate.asked().is_empty());
}

#[test]
fn a_rename_is_a_delete_only_over_a_file() {
    let _g = serial();
    fresh_volume();
    assert!(put(b"/fat/ONE.TXT", b"one"));
    assert!(put(b"/fat/TWO.TXT", b"two!"));
    let gate = Installed::answering(false);
    // To a free name: nothing is lost, the gate is not asked.
    assert_eq!(vfs::vfs_rename(b"/fat/ONE.TXT", b"/fat/FREE.TXT"), Ok(()));
    assert!(gate.asked().is_empty());
    // Over TWO.TXT: that file would be gone.
    assert_eq!(vfs::vfs_rename(b"/fat/FREE.TXT", b"/fat/TWO.TXT"), Err(FsErr::Denied), "rename_is_refused");
    assert_eq!(gate.asked(), [DeleteOp::Replace as u8]);
    assert_eq!(size(b"/fat/TWO.TXT"), Some(4), "the target is intact");
    assert_eq!(size(b"/fat/FREE.TXT"), Some(3), "and the source stays where it was");
    *ANSWER.lock().unwrap() = true;
    assert_eq!(vfs::vfs_rename(b"/fat/FREE.TXT", b"/fat/TWO.TXT"), Ok(()));
    assert_eq!(size(b"/fat/TWO.TXT"), Some(3));
    // A rename onto itself loses nothing.
    ASKED.lock().unwrap().clear();
    let _ = vfs::vfs_rename(b"/fat/TWO.TXT", b"/fat/TWO.TXT");
    assert!(gate.asked().is_empty());
}

#[test]
fn only_a_cut_below_the_size_is_a_delete() {
    let _g = serial();
    fresh_volume();
    assert!(put(b"/fat/LOG.TXT", &[7u8; 700]));
    let gate = Installed::answering(false);
    assert_eq!(vfs::vfs_truncate(b"/fat/LOG.TXT", 700), Ok(()), "to its own size");
    assert_eq!(vfs::vfs_truncate(b"/fat/LOG.TXT", 900), Ok(()), "longer");
    assert!(gate.asked().is_empty());
    assert_eq!(vfs::vfs_truncate(b"/fat/LOG.TXT", 100), Err(FsErr::Denied), "truncate_is_refused");
    assert_eq!(gate.asked(), [DeleteOp::Truncate as u8]);
    assert_eq!(size(b"/fat/LOG.TXT"), Some(900), "not cut");
    *ANSWER.lock().unwrap() = true;
    assert_eq!(vfs::vfs_truncate(b"/fat/LOG.TXT", 100), Ok(()));
    assert_eq!(size(b"/fat/LOG.TXT"), Some(100));
}

/// An open with `O_TRUNC` cuts a file to zero like `truncate(0)`; it is held
/// by the same row. A new file, or an empty one, loses nothing.
#[test]
fn an_open_that_truncates_is_a_cut_too() {
    let _g = serial();
    fresh_volume();
    assert!(put(b"/fat/DATA.BIN", &[9u8; 300]));
    let gate = Installed::answering(false);
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, b"/fat/DATA.BIN", vfs::O_WRONLY | vfs::O_TRUNC);
    assert!(fd < 0, "open_truncate_is_refused");
    assert_eq!(gate.asked(), [DeleteOp::Truncate as u8]);
    assert_eq!(size(b"/fat/DATA.BIN"), Some(300));
    // A file that is not there yet is created, not cut.
    ASKED.lock().unwrap().clear();
    let fd = vfs::vfs_open(&mut t, b"/fat/NEW.BIN", vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
    assert!(fd >= 0);
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    assert!(gate.asked().is_empty());
    *ANSWER.lock().unwrap() = true;
    let fd = vfs::vfs_open(&mut t, b"/fat/DATA.BIN", vfs::O_WRONLY | vfs::O_TRUNC);
    assert!(fd >= 0);
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    assert_eq!(size(b"/fat/DATA.BIN"), Some(0));
}

/// No gate installed: today's behaviour, every delete goes.
#[test]
fn with_no_gate_every_delete_goes() {
    let _g = serial();
    fresh_volume();
    vfs::clear_delete_gate_for_test();
    assert!(put(b"/fat/X.TXT", b"x"));
    assert!(put(b"/fat/Y.TXT", b"yy"));
    assert_eq!(vfs::vfs_rename(b"/fat/X.TXT", b"/fat/Y.TXT"), Ok(()));
    assert_eq!(vfs::vfs_truncate(b"/fat/Y.TXT", 0), Ok(()));
    assert_eq!(vfs::vfs_unlink(b"/fat/Y.TXT"), Ok(()));
}
