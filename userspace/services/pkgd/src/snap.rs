// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The restore points of the staging volume: what the installer lists and what
//! it deletes.
//!
//! The kernel's boot-time apply snapshots the volume before it writes a new
//! package's programs, and keeps the snapshot as a restore point once the boot
//! is confirmed (`azos_pkg::apply`). Ring 3 has no call for a snapshot, so the
//! two programs talk through the volume, as they do for the packages
//! themselves: the kernel writes `APPLY.TBL`, the list of the snapshots with
//! their state; the installer reads it, decides which are old (the oldest
//! beyond [`KEPT`], never the one on trial) and appends their ids to
//! `SNAPDEL.REQ`; the kernel deletes them at the next boot, when nothing else
//! holds the volume, and removes the request file. A volume that holds no
//! restore points is a volume the installer has nothing to say about: the
//! installer that does not prune lets the snapshots fill the table, and the
//! kernel then stops applying new packages (`SNAP_MAX`) rather than take one
//! it could not undo.
//!
//! The paths are the installer library's (`/fat/PKG/...`); with no native
//! volume mounted for staging they stay on the boot volume, where the kernel
//! applies nothing, and there is nothing to prune.

use azos_packages::{Read, VolErr};
use azos_pkg::apply::{self, SnapState, Table, SNAP_MAX, TABLE_MAX};

use super::stage::{Files, Paths};

/// Restore points kept (Kconfig `PKG_SNAPSHOTS_KEPT`).
pub const KEPT: usize = azos_limits::PKG_SNAPSHOTS_KEPT as usize;
/// The buffer [`prune`] and [`list`] work in: the table and the requests.
pub const BUF: usize = TABLE_MAX + REQUESTS_MAX;
/// Most bytes of `SNAPDEL.REQ` read; the kernel reads no more either.
const REQUESTS_MAX: usize = 8 * 1024;

const TABLE_PATH: &[u8] = b"/fat/PKG/APPLY.TBL";
const REQUESTS_PATH: &[u8] = b"/fat/PKG/SNAPDEL.REQ";

/// The restore points, as the kernel last wrote them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Points {
    /// Snapshots kept as restore points.
    pub kept: usize,
    /// A trial is on probation.
    pub trial: bool,
}

/// Read the table into the front of `buf`: its length, `None` when the volume
/// has none (nothing applied yet, or no native volume).
fn read_table<F: Files + Clone>(paths: &mut Paths<F>, buf: &mut [u8]) -> Result<Option<usize>, VolErr> {
    if !paths.on_volume() {
        return Ok(None);
    }
    match paths.read_file(TABLE_PATH, &mut buf[..TABLE_MAX]) {
        Ok(Read { n, more: false }) => Ok(Some(n)),
        Ok(_) => Err(VolErr::TooLarge),
        Err(VolErr::Missing) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The restore points of the volume.
pub fn list<F: Files + Clone>(paths: &mut Paths<F>, buf: &mut [u8; BUF]) -> Result<Points, VolErr> {
    let Some(n) = read_table(paths, buf)? else { return Ok(Points::default()) };
    // A table the kernel did not write is none: the next boot writes a fresh one.
    let Ok(t) = Table::parse(&buf[..n]) else { return Ok(Points::default()) };
    Ok(Points {
        kept: t.snaps().filter(|s| s.state == SnapState::Kept).count(),
        trial: t.trial().is_some(),
    })
}

/// Ask for the oldest restore points beyond `kept` to be deleted at the next
/// boot: the number of requests added. The ones already asked for are not asked
/// again, and the trial's is never asked for.
pub fn prune<F: Files + Clone>(paths: &mut Paths<F>, kept: usize, buf: &mut [u8; BUF]) -> Result<usize, VolErr> {
    let Some(n) = read_table(paths, buf)? else { return Ok(0) };
    let (tbl, asked) = buf.split_at_mut(TABLE_MAX);
    let a = match paths.read_file(REQUESTS_PATH, &mut asked[..REQUESTS_MAX]) {
        Ok(r) => r.n,
        Err(VolErr::Missing) => 0,
        Err(e) => return Err(e),
    };
    let Ok(t) = Table::parse(&tbl[..n]) else { return Ok(0) };
    let mut out = [0u8; 8 * SNAP_MAX];
    let mut count = 0;
    for id in apply::excess(&t, kept, &asked[..a]).take(SNAP_MAX) {
        out[count * 8..count * 8 + 8].copy_from_slice(&apply::request(id));
        count += 1;
    }
    if count != 0 {
        // One append, one commit: the requests are durable together.
        paths.append(REQUESTS_PATH, &out[..count * 8])?;
    }
    Ok(count)
}
