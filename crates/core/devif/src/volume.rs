// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Volume` interface: the volumes the kernel mounts, for the tool that
//! looks after them.
//!
//! The kernel hosts it on `volume.<n>` endpoints, one per volume: the
//! badge names the volume, so a row holds the check of the volumes it is
//! granted and of no other, and nothing in a request names one (no path
//! crosses the call). `volume.0` is the boot volume (FAT32, `/fat`);
//! `volume.<p>` is the `[volume.NAME]` row on partition `p` (1-based, as the
//! row spells it). Its one op today is [`Volume::check`], the check of the
//! mounted volume run by hand: the toolbox's `fsck`
//! (`userspace/services/toolbox`). The same walk runs by itself at mount when
//! a volume was not shut down cleanly (`azos_fs::fat32`,
//! `azos_fs::azvol_mount::open_plain`), and that one repairs what it can and
//! decides whether the volume is served; this one counts and writes nothing,
//! so it is safe beside the volume's users. The change group and snapshot ops
//! the engine has (`azos_fs::azvol::group`, `snap`) would join this interface
//! when a task needs them.
//!
//! The endpoint's `WRITE` right is the right to run the walk: it holds the
//! volume for its length (a scrub reads every data block), which the volume's
//! users wait out.
//!
//! # Outcomes
//!
//! `OK` with the [`Report`]; `DENIED` without `WRITE`; `NO_RESOURCE` when the
//! badge's volume is not mounted (no such row, a mount that was refused);
//! `BUSY` while an azvol volume holds an open transaction (the check would
//! have to commit it, and the commit is its owner's); `UNSUPPORTED` when the
//! kernel has no check; `FAULT` when the walk could not read the volume.

use crate::outcome::Out;
use azos_idl::{azos_interface, Reader, Wire, Writer};

/// The interface id (ASCII "VOLU").
pub const VOLUME_ID: u32 = 0x564F_4C55;

/// Volumes the interface names: the boot volume and one per partition of the
/// block layer's table (`crate::block::PARTS`).
pub const VOLUMES: u32 = crate::block::PARTS + 1;

/// The badge of volume `n` (0 the boot volume, `p` the row on partition `p`):
/// `n + 1`, so an unbadged capability names none.
pub const fn badge(n: u32) -> u32 {
    n + 1
}

/// [`Report::flags`]: the walk reached the whole volume.
pub const FLAG_COMPLETE: u32 = 1 << 0;
/// [`Report::flags`]: the volume is served read-only because its mount-time
/// check found damage (Kconfig `FS_CHECK_FAILED_READ_ONLY`).
pub const FLAG_READ_ONLY: u32 = 1 << 1;

/// What a check found (`azos_fs::FsCheck`, the same fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Damage: a chain or tree that leaves the volume, two owners of one
    /// block, a record that names what is not there, a walk stopped by a read
    /// error. 0 on a sound volume.
    pub problems: u32,
    /// Allocated space nothing names: FAT32's lost clusters; azvol says only
    /// that there is some (1).
    pub leaked: u64,
    /// Redundant copies that differ (FAT32's FAT copies).
    pub mismatched: u32,
    /// Files and directories the walk accounted for (0: not counted).
    pub items: u64,
    /// Data blocks read against their checksum (a scrub).
    pub scrubbed: u64,
    /// [`FLAG_COMPLETE`] | [`FLAG_READ_ONLY`].
    pub flags: u32,
}

impl Wire for Report {
    const WORDS: usize = 6;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.problems.put(w);
        self.leaked.put(w);
        self.mismatched.put(w);
        self.items.put(w);
        self.scrubbed.put(w);
        self.flags.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let problems = u32::get(r);
        let leaked = u64::get(r);
        let mismatched = u32::get(r);
        let items = u64::get(r);
        let scrubbed = u64::get(r);
        Report { problems, leaked, mismatched, items, scrubbed, flags: u32::get(r) }
    }
}

#[azos_interface(id = 0x564F_4C55, level = 1)]
pub trait Volume {
    /// Check the endpoint's volume, counting only; `scrub` also reads every
    /// data block against its checksum where the format has them (azvol).
    /// Needs `WRITE`.
    #[idempotent]
    fn check(&mut self, scrub: bool) -> Out<Report>;
}
