// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Is this verified package acceptable HERE, and what does it add to the
//! topology?
//!
//! The device is a [`Device`]: its hardware class, its ABI version and the
//! level of each IDL interface it serves. The package's rows are merged into
//! the topology the device already has, and the merged topology is judged by
//! the same `Topology::admission_check` a signed CAPS.TOM is, so the
//! `neverallow` rules, the scheduling classes, one writer per motor and the
//! real-time admission apply to a package row exactly as they do to a row of
//! the device's owner. What is additional is the signer's ceiling: a package
//! row may hold only what its signer's `warrants` cover, ask for real time (a
//! reservation, the band, locked or huge memory, a ring poller) only if the
//! signer may, and no more frames, over all its instances, than the signer's
//! maximum.
//!
//! `topo` is left as it was when [`admit`] refuses (the rows it parsed in are
//! rolled back), and holds the package's rows when it admits. The rows' text
//! must outlive the topology (the rows borrow it), so [`admit`] takes it as an
//! argument: the caller that merges several packages keeps each one's rows
//! where they stay put, not in the buffer the next package is read into.

use azos_topology::{parse_caps, Topology};

use crate::meta::HwClass;
use crate::verify::Verified;
use crate::Refusal;

/// The device a package is admitted on.
#[derive(Clone, Copy, Debug)]
pub struct Device<'d> {
    /// The hardware class (Kconfig `HWCLASS`, [`HwClass::THIS`]).
    pub hwclass: HwClass,
    /// The ABI version (`azos_abi::ABI_VERSION`).
    pub abi: u32,
    /// The security epoch floor in force (`azos_ota`: BOOTMETA's
    /// `min_sec_epoch`, lifted by the hardware floor): a package signed
    /// against a lower epoch is refused. The ring-3 installer cannot read it
    /// and passes 0; the boot-time apply (`kernel/src/boot/pkg_apply.rs`)
    /// passes the real one.
    pub epoch_floor: u32,
    /// The interfaces this device serves and the level of each: what a
    /// package's `[api]` is checked against. The caller builds it from the IDL
    /// interfaces it links (`<Name>Idl::LEVEL`), so it cannot name an
    /// interface that does not exist.
    pub api: &'d [(&'d str, u32)],
}

impl<'d> Device<'d> {
    /// This build's class and ABI, with the interface table `api`.
    pub const fn this(api: &'d [(&'d str, u32)]) -> Self {
        Self { hwclass: HwClass::THIS, abi: azos_abi::ABI_VERSION, epoch_floor: 0, api }
    }

    /// The same device with epoch floor `floor`.
    pub const fn with_epoch_floor(mut self, floor: u32) -> Self {
        self.epoch_floor = floor;
        self
    }
}

/// What a package added.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Admitted {
    /// Index of the first row the package added to the topology.
    pub first_row: usize,
    /// How many rows it added: one per image.
    pub rows: usize,
}

/// The sections of the rows text: every one must be `[task.NAME]`. A line
/// that begins a section is a line whose first non-blank byte is `[`; a grant
/// list continues on lines that begin with `{` or `]`, never `[`.
fn only_task_sections(rows: &[u8]) -> bool {
    rows.split(|&b| b == b'\n').all(|l| {
        let l = &l[l.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(l.len())..];
        !l.starts_with(b"[") || l.starts_with(b"[task.")
    })
}

/// Admit `v` on `dev`, merging `rows` (the package's rows text, `v.pkg.rows`
/// or a copy of it that lives as long as `topo`) into `topo`.
pub fn admit<'a>(
    v: &Verified<'_, 'a>,
    rows: &'a [u8],
    topo: &mut Topology<'a>,
    dev: &Device<'_>,
) -> Result<Admitted, Refusal> {
    let meta = &v.meta;
    if !meta.runs_on(dev.hwclass) {
        return Err(Refusal::Hardware);
    }
    if meta.abi != dev.abi {
        return Err(Refusal::Abi { wanted: meta.abi, have: dev.abi });
    }
    if !cfg!(feature = "pkg-epoch-canary") && meta.sec_epoch < dev.epoch_floor {
        return Err(Refusal::Epoch { have: meta.sec_epoch, floor: dev.epoch_floor });
    }
    for (i, (name, need)) in meta.api().iter().enumerate() {
        if !dev.api.iter().any(|(n, have)| n == name && have >= need) {
            return Err(Refusal::Api(i as u16));
        }
    }
    if !only_task_sections(rows) {
        return Err(Refusal::ForeignSection);
    }
    let mark = topo.checkpoint();
    let r = merge(v, rows, topo);
    if r.is_err() {
        topo.rollback(mark);
    }
    r
}

fn merge<'a>(v: &Verified<'_, 'a>, rows: &'a [u8], topo: &mut Topology<'a>) -> Result<Admitted, Refusal> {
    let meta = &v.meta;
    let first_row = topo.tasks_len();
    parse_caps(rows, topo).map_err(Refusal::Rows)?;
    let rows = topo.tasks_len() - first_row;

    // One row per image, by name; the names are unique among the rows (a
    // repeat would leave an image without a row).
    if rows == 0
        || rows != meta.images().len()
        || !topo.tasks()[first_row..].iter().all(|t| meta.images().iter().any(|i| i.name.as_bytes() == t.name.as_bytes()))
    {
        return Err(Refusal::RowsImages);
    }

    let signer = &v.signer;
    for (r, ti) in (first_row..first_row + rows).enumerate() {
        let task = &topo.tasks()[ti];
        for (g, c) in topo.caps_of(task).iter().enumerate() {
            if !topo.signer_covers(signer, c) {
                return Err(Refusal::OutsideWarrants { row: r as u16, grant: g as u16 });
            }
        }
        // A name is authority: the name server lends a held endpoint (`term`,
        // say) to any row that imports it, so an import is held to the
        // signer's ceiling like an `endpoint` grant of that name.
        for (m, name) in topo.imports_of(task).iter().enumerate() {
            if !cfg!(feature = "pkg-import-canary") && !topo.signer_covers_import(signer, name) {
                return Err(Refusal::OutsideImports { row: r as u16, import: m as u16 });
            }
        }
        // Real time, in the broad sense: a reservation, a priority in the
        // band, memory pinned for the task's life, a poller that spins for
        // the ring. All of it is the owner's to give, with `rt = true`.
        let rt = task.profile != azos_topology::SchedProfile::NONE
            || topo.row_band_entry(ti) != azos_topology::BandEntry::NotBand
            || task.mem_locked
            || task.mem_huge_mib != 0
            || task.sqpoll_idle_ms != 0;
        if rt && !signer.rt {
            return Err(Refusal::RealTime(r as u16));
        }
        // The ceiling is the row's whole budget: every instance, and the
        // 2 MiB leaves of a huge region (256 pages a MiB) as well.
        let one = if task.mem_pages == 0 { azos_topology::RING3_DEFAULT_PAGES } else { task.mem_pages } as u64;
        let frames = (one + task.mem_huge_mib as u64 * 256) * task.instance_count() as u64;
        if frames > signer.mem_pages_max as u64 {
            return Err(Refusal::Frames(r as u16));
        }
    }

    topo.admission_check().map_err(Refusal::Admission)?;
    Ok(Admitted { first_row, rows })
}
