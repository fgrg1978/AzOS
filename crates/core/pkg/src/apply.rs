// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the installer and the boot-time apply agree on, as bytes: the files
//! they share on the staging volume, and the rule that turns "the boot after an
//! apply was or was not confirmed" into confirm, wait or roll back.
//!
//! ```text
//!   pkgd (ring 3, at run time)              kernel (boot, before services)
//!   ──────────────────────────              ──────────────────────────────
//!   stages   XXXXXXXX.PKG      ───────►     verifies and admits each, merges
//!   removes  XXXXXXXX.PKG                   its rows into the topology, writes
//!   requests SNAPDEL.REQ       ───────►     its images to APPS/NAME.ELF, after a
//!                                           snapshot of the volume
//!   lists    APPLY.TBL         ◄───────     records the snapshots (APPLY.TBL)
//! ```
//!
//! The volume is the mailbox: the installer owns the staging, the kernel owns
//! `APPS/`, `APPLY.TBL` and the snapshots, and neither opens the other's
//! files for writing (the installer's `SNAPDEL.REQ` is the one file the kernel
//! reads and removes). Ring 3 has no call for a snapshot, so a request is a
//! record the kernel acts on at the next boot, when nothing else holds the
//! volume.
//!
//! # A trial, and how it ends
//!
//! An apply that brings a program in for the first time is a **trial**: the
//! volume is snapshotted, the program is written, and the boot is on probation
//! exactly as a whole-system update's first boot is (`azos_ota`). The rule is
//! the A/B one, kept apart from the slot logic only because the counter it reads
//! is BOOTMETA's `boot_count`, which a second subsystem must not write:
//!
//! * the boot after the trial finds the counter at 0: `ota_mark_boot_good` (or
//!   an orderly restart, which voids the mark) cleared it: **confirm**, the
//!   snapshot stays as a restore point;
//! * the counter is up but fewer than `max_attempts` boots have failed since
//!   the trial began: **wait**, nothing changes;
//! * `max_attempts` boots failed since: **roll back**, the volume's `APPS/` goes
//!   back to the snapshot and the packages of the trial are removed with a
//!   refusal on record.

/// The staging volume's mount point (a `[volume.NAME]` row of the topology).
pub const STAGE_MOUNT: &[u8] = b"/pkg";
/// Applied programs, `APPS/NAME.ELF`: the kernel's, in the volume root.
pub const APPS_DIR: &[u8] = b"APPS";
/// The install journal: `ProvenanceRecord` wire records, appended by the
/// installer and, at boot, by the kernel.
pub const JOURNAL: &[u8] = b"JOURNAL.BIN";
/// The snapshot table the kernel keeps ([`Table`]).
pub const TABLE: &[u8] = b"APPLY.TBL";
/// Snapshot deletions the installer asks for: 8-byte little-endian ids.
pub const DELETE_REQUESTS: &[u8] = b"SNAPDEL.REQ";
/// A staged package's name: eight upper-case hex digits and `.PKG`.
pub const STAGED_LEN: usize = 12;
/// Is `name` the file name of a staged package?
pub fn staged_name(name: &[u8]) -> bool {
    name.len() == STAGED_LEN
        && name[8..] == *b".PKG"
        && name[..8].iter().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c))
}
/// The label of the snapshot an apply takes.
pub const SNAPSHOT_LABEL: &[u8] = b"pkg-apply";

/// Snapshots the table lists, and the most the volume may hold before the
/// kernel stops taking new ones (the installer prunes to Kconfig
/// `PKG_SNAPSHOTS_KEPT`, far below this).
pub const SNAP_MAX: usize = 32;
/// Package ids a trial lists: `PKG_MAX_STAGED`.
pub const IDS_MAX: usize = azos_limits::PKG_MAX_STAGED as usize;
const MAGIC: [u8; 8] = *b"AZPKGTB1";
const HEAD: usize = 16;
/// Bytes of one snapshot record.
pub const SNAP_REC: usize = 64;
const LABEL_LEN: usize = 40;
/// The largest table: header, [`SNAP_MAX`] snapshots, [`IDS_MAX`] ids.
pub const TABLE_MAX: usize = HEAD + SNAP_MAX * SNAP_REC + IDS_MAX * 32;

/// What a snapshot is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SnapState {
    /// Taken by the apply whose boot is still on probation.
    Trial = 1,
    /// The trial was confirmed: a restore point, deleted on request.
    Kept = 2,
}

/// One snapshot of the table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SnapRec {
    /// The engine's id.
    pub id: u64,
    /// When it was taken, ns.
    pub created_ns: u64,
    /// `boot_count` before the boot that took it: the failed boots of the
    /// trial are counted from here.
    pub base_prior: u32,
    /// Trial or restore point.
    pub state: SnapState,
    label_len: u8,
    label: [u8; LABEL_LEN],
}

impl SnapRec {
    /// A record for snapshot `id`.
    pub fn new(id: u64, created_ns: u64, base_prior: u32, state: SnapState, label: &[u8]) -> Self {
        let n = label.len().min(LABEL_LEN);
        let mut l = [0u8; LABEL_LEN];
        l[..n].copy_from_slice(&label[..n]);
        SnapRec { id, created_ns, base_prior, state, label_len: n as u8, label: l }
    }

    /// Its label.
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len as usize]
    }

    fn encode(&self, out: &mut [u8]) {
        out[..SNAP_REC].fill(0);
        out[0..8].copy_from_slice(&self.id.to_le_bytes());
        out[8..16].copy_from_slice(&self.created_ns.to_le_bytes());
        out[16..20].copy_from_slice(&self.base_prior.to_le_bytes());
        out[20] = self.state as u8;
        out[21] = self.label_len;
        out[24..24 + LABEL_LEN].copy_from_slice(&self.label);
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let state = match b[20] {
            1 => SnapState::Trial,
            2 => SnapState::Kept,
            _ => return None,
        };
        let label_len = b[21];
        if label_len as usize > LABEL_LEN {
            return None;
        }
        let mut label = [0u8; LABEL_LEN];
        label.copy_from_slice(&b[24..24 + LABEL_LEN]);
        Some(SnapRec {
            id: u64::from_le_bytes(b[0..8].try_into().ok()?),
            created_ns: u64::from_le_bytes(b[8..16].try_into().ok()?),
            base_prior: u32::from_le_bytes(b[16..20].try_into().ok()?),
            state,
            label_len,
            label,
        })
    }
}

/// Why a table is not read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TableError {
    /// Not a table (short, wrong magic, a count past its ceiling, a length
    /// that is not the counts').
    Format,
    /// A record that is none (an unknown state, a label past its length).
    Record,
}

/// The table the kernel writes after every boot's apply: the snapshots of the
/// volume with their state, and the ids of the packages of the open trial.
/// Borrowed from the bytes read.
#[derive(Clone, Copy, Debug)]
pub struct Table<'a> {
    snaps: &'a [u8],
    ids: &'a [u8],
}

impl<'a> Table<'a> {
    /// The table in `b`. A file the kernel did not write fails, and the kernel
    /// then starts a fresh one (the snapshots themselves are the engine's).
    pub fn parse(b: &'a [u8]) -> Result<Self, TableError> {
        if b.len() < HEAD || b[..8] != MAGIC {
            return Err(TableError::Format);
        }
        let ns = u32::from_le_bytes([b[8], b[9], b[10], b[11]]) as usize;
        let ni = u32::from_le_bytes([b[12], b[13], b[14], b[15]]) as usize;
        if ns > SNAP_MAX || ni > IDS_MAX || b.len() != HEAD + ns * SNAP_REC + ni * 32 {
            return Err(TableError::Format);
        }
        let (snaps, ids) = b[HEAD..].split_at(ns * SNAP_REC);
        let t = Table { snaps, ids };
        if t.snapshots().any(|s| s.is_none()) {
            return Err(TableError::Record);
        }
        Ok(t)
    }

    /// The snapshots, oldest first; `None` for a record that is none (only
    /// before [`Table::parse`] has checked them all).
    fn snapshots(&self) -> impl Iterator<Item = Option<SnapRec>> + 'a {
        self.snaps.chunks_exact(SNAP_REC).map(SnapRec::decode)
    }

    /// The snapshots, oldest first.
    pub fn snaps(&self) -> impl Iterator<Item = SnapRec> + 'a {
        self.snapshots().flatten()
    }

    /// How many snapshots.
    pub fn snap_count(&self) -> usize {
        self.snaps.len() / SNAP_REC
    }

    /// The snapshot on probation, if there is one.
    pub fn trial(&self) -> Option<SnapRec> {
        self.snaps().find(|s| s.state == SnapState::Trial)
    }

    /// The ids of the packages of the open trial.
    pub fn ids(&self) -> impl Iterator<Item = [u8; 32]> + 'a {
        self.ids.chunks_exact(32).map(|c| {
            let mut id = [0u8; 32];
            id.copy_from_slice(c);
            id
        })
    }
}

/// Write a table of `snaps` and `ids` into `out`: the bytes used. `None` when
/// a count is past its ceiling or `out` is shorter than [`TABLE_MAX`] needs.
pub fn encode_table(snaps: &[SnapRec], ids: &[[u8; 32]], out: &mut [u8]) -> Option<usize> {
    let n = HEAD + snaps.len() * SNAP_REC + ids.len() * 32;
    if snaps.len() > SNAP_MAX || ids.len() > IDS_MAX || out.len() < n {
        return None;
    }
    out[..8].copy_from_slice(&MAGIC);
    out[8..12].copy_from_slice(&(snaps.len() as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(ids.len() as u32).to_le_bytes());
    for (i, s) in snaps.iter().enumerate() {
        s.encode(&mut out[HEAD + i * SNAP_REC..HEAD + (i + 1) * SNAP_REC]);
    }
    let at = HEAD + snaps.len() * SNAP_REC;
    for (i, id) in ids.iter().enumerate() {
        out[at + i * 32..at + (i + 1) * 32].copy_from_slice(id);
    }
    Some(n)
}

/// The ids a deletion-request file asks for (a trailing partial record is
/// ignored: a request is whole or it is not one).
pub fn requested(b: &[u8]) -> impl Iterator<Item = u64> + '_ {
    b.chunks_exact(8).map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
}

/// The record that asks for snapshot `id` to be deleted.
pub const fn request(id: u64) -> [u8; 8] {
    id.to_le_bytes()
}

/// The restore points to delete to keep `kept`: the oldest ones, never the
/// trial, never one already asked for (`asked`). The installer's retention
/// (Kconfig `PKG_SNAPSHOTS_KEPT`), the one place that decides which snapshot
/// is old.
pub fn excess<'a>(t: &'a Table<'a>, kept: usize, asked: &'a [u8]) -> impl Iterator<Item = u64> + 'a {
    let live = t.snaps().filter(move |s| s.state == SnapState::Kept && !requested(asked).any(|r| r == s.id)).count();
    t.snaps()
        .filter(move |s| s.state == SnapState::Kept && !requested(asked).any(|r| r == s.id))
        .take(live.saturating_sub(kept))
        .map(|s| s.id)
}

/// What the boot after a trial does with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Next {
    /// The boot was confirmed: the trial's snapshot is kept as a restore point.
    Confirm,
    /// Still on probation.
    Wait,
    /// The attempts are spent: restore the snapshot.
    RollBack,
}

/// The A/B rule for a trial begun when `boot_count` read `base_prior`, judged
/// at a boot where it reads `prior_unconfirmed`, with `max_attempts` boots to
/// confirm (`azos_ota::OTA_DEFAULT_MAX_BOOT_ATTEMPTS`, Kconfig
/// `OTA_MAX_BOOT_ATTEMPTS`).
#[must_use]
pub fn trial_next(base_prior: u32, prior_unconfirmed: u32, max_attempts: u32) -> Next {
    if prior_unconfirmed == 0 {
        Next::Confirm
    } else if !cfg!(feature = "pkg-trial-canary") && prior_unconfirmed.saturating_sub(base_prior) >= max_attempts {
        Next::RollBack
    } else {
        Next::Wait
    }
}

/// Why the boot-time apply refused a package that the installer admitted
/// ([`crate::Refusal::Boot`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BootWhy {
    /// The merged topology broke the kernel's boot admission (deadlines, the
    /// real-time band, memory) that the package-level checks cannot see.
    Admission,
    /// The boots after the package's first spent their attempts unconfirmed.
    Unconfirmed,
    /// The staging volume could not take the package's programs.
    Volume,
}
