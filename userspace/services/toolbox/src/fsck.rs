// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `fsck [-s] [VOLUME...]`: the check of a mounted volume, run by hand.
//!
//! A volume is a number (`azos_devif::volume`): 0 the boot volume, `p` the
//! `[volume.NAME]` row on partition `p`; without one, every volume the row
//! grants (`volume.<n>`). The kernel walks it (`Volume::check` on that
//! endpoint): FAT32's chains from the root and every directory,
//! its FAT copies, its lost clusters; azvol's trees, free-space map, inode
//! list and directories, and with `-s` every data block against its checksum.
//! It counts and repairs nothing: the repairs are the mount's, on a volume
//! that was not shut down cleanly.
//!
//! The exit status is `fsck`'s: 0 no problem found, 4 problems left
//! uncorrected, 8 an operational error (no endpoint, no such volume, a walk
//! that could not read it or did not reach the whole volume), 16 a usage
//! error. The text is here, with no system call, and the calls are
//! `main.rs`'s `fsck()`.

use azos_devif::volume::{FLAG_COMPLETE, FLAG_READ_ONLY};
use azos_devif::VolumeReport;
use core::fmt::{self, Write};

/// No problem found.
pub const EXIT_CLEAN: i32 = 0;
/// Problems found and left as they are.
pub const EXIT_PROBLEMS: i32 = 4;
/// The check could not be run.
pub const EXIT_ERROR: i32 = 8;
/// Bad arguments.
pub const EXIT_USAGE: i32 = 16;

/// One line: the volume, the verdict and the counts.
pub fn write_report(w: &mut dyn Write, volume: u32, r: &VolumeReport) -> fmt::Result {
    write!(w, "volume {}: ", volume)?;
    if r.problems == 0 {
        w.write_str("clean")?;
    } else {
        write!(w, "{} problem(s)", r.problems)?;
    }
    if r.leaked != 0 {
        write!(w, ", {} leaked", r.leaked)?;
    }
    if r.mismatched != 0 {
        write!(w, ", {} FAT sector(s) differ from copy 0", r.mismatched)?;
    }
    if r.items != 0 {
        write!(w, ", {} file(s) and directories", r.items)?;
    }
    if r.scrubbed != 0 {
        write!(w, ", {} block(s) scrubbed", r.scrubbed)?;
    }
    if r.flags & FLAG_COMPLETE == 0 {
        w.write_str(", walk incomplete")?;
    }
    if r.flags & FLAG_READ_ONLY != 0 {
        w.write_str(", served read-only (its mount-time check failed)")?;
    }
    w.write_char('\n')
}

/// The exit status a report leaves: problems first; a walk that did not
/// reach the whole volume vouches for nothing.
pub fn status(r: &VolumeReport) -> i32 {
    if r.problems != 0 {
        EXIT_PROBLEMS
    } else if r.flags & FLAG_COMPLETE == 0 {
        EXIT_ERROR
    } else {
        EXIT_CLEAN
    }
}
