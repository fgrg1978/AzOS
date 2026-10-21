// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Guest-physical mapping over the frames of a MemObj.
//!
//! A guest's RAM is MemObjs the VM's monitor (`VMMD.ELF`) creates, charged to
//! the monitor's own Domain: its row's `mem_pages` bounds them (the boot
//! refuses a guest the row cannot hold, `azos_topology::builder::vmmd_pages`),
//! and so does the memory-object table ([`crate::admit::HostFacts::max_guest_mib`]).
//! The kernel pins each one and keeps a reference until `destroy`. This module
//! maps their frames into the guest's stage-2 tables through [`Hypervisor`],
//! the same on the three ISAs.
//! It knows nothing of MemObj itself: the kernel gives it a [`FrameSource`]
//! (frame `i` of the object is at host-physical address `a`), so the whole
//! thing runs under the host tests against a fake source.
//!
//! A kernel frame is one translation granule (`PAGE_SIZE`: 4 KiB, or 16/64 KiB
//! on aarch64); stage-2 maps in 4 KiB pages whatever the granule, so a frame
//! becomes `frame_bytes / 4096` consecutive guest pages.

use azos_arch_api::{Hypervisor, Stage2Root, StageError, StagePerms, StageTableMem, STAGE_PAGE};

/// The frames of one memory object, in order.
pub trait FrameSource {
    /// Frames in the object.
    fn frames(&self) -> usize;
    /// Host-physical address of frame `idx`, `None` past the end.
    fn frame(&self, idx: usize) -> Option<u64>;
    /// Bytes per frame: a multiple of [`STAGE_PAGE`].
    fn frame_bytes(&self) -> u64;
}

/// Why a mapping stopped. Whatever the call had mapped before the error is
/// unmapped again, so a refused `map_frames` leaves the tables as they were
/// (but for interior table pages, which [`Hypervisor::stage2_destroy`] frees).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapFailure {
    pub err: StageError,
    /// The guest-physical address of the page that could not be mapped.
    pub at: u64,
}

/// Map every frame of `src` to consecutive guest-physical addresses from
/// `gpa`, with `perms`. Returns the bytes mapped.
pub fn map_frames(
    hv: &dyn Hypervisor,
    s2: &Stage2Root,
    mem: &mut dyn StageTableMem,
    gpa: u64,
    src: &dyn FrameSource,
    perms: StagePerms,
) -> Result<u64, MapFailure> {
    let fb = src.frame_bytes();
    if fb == 0 || fb % STAGE_PAGE != 0 {
        return Err(MapFailure { err: StageError::Misaligned, at: gpa });
    }
    if gpa % STAGE_PAGE != 0 {
        return Err(MapFailure { err: StageError::Misaligned, at: gpa });
    }
    let total = (src.frames() as u64).checked_mul(fb);
    let end = total.and_then(|t| gpa.checked_add(t));
    match end {
        Some(e) if e <= 1u64 << hv.gpa_bits() => {}
        _ => return Err(MapFailure { err: StageError::OutOfRange, at: gpa }),
    }
    let mut at = gpa;
    for i in 0..src.frames() {
        let Some(base) = src.frame(i) else {
            // The object shrank under us: what is mapped is a prefix.
            rollback(hv, s2, mem, gpa, at);
            return Err(MapFailure { err: StageError::NotMapped, at });
        };
        let mut off = 0;
        while off < fb {
            if let Err(err) = hv.stage2_map(s2, mem, at, base + off, perms) {
                rollback(hv, s2, mem, gpa, at);
                return Err(MapFailure { err, at });
            }
            at += STAGE_PAGE;
            off += STAGE_PAGE;
        }
    }
    Ok(at - gpa)
}

/// Unmap what a failed call had mapped in `[from, to)`.
fn rollback(hv: &dyn Hypervisor, s2: &Stage2Root, mem: &mut dyn StageTableMem, from: u64, to: u64) {
    if cfg!(feature = "canary-no-rollback") {
        return;
    }
    let mut a = from;
    while a < to {
        let _ = hv.stage2_unmap(s2, mem, a);
        a += STAGE_PAGE;
    }
}

/// Unmap `bytes` of guest-physical memory from `gpa`; the number of pages
/// that were mapped (a hole is skipped, not an error: a range may be mapped
/// in pieces). The caller flushes the guest TLB before reusing the frames.
pub fn unmap_range(
    hv: &dyn Hypervisor,
    s2: &Stage2Root,
    mem: &mut dyn StageTableMem,
    gpa: u64,
    bytes: u64,
) -> Result<u64, StageError> {
    if gpa % STAGE_PAGE != 0 || bytes % STAGE_PAGE != 0 {
        return Err(StageError::Misaligned);
    }
    let mut n = 0;
    let mut a = gpa;
    let end = gpa.checked_add(bytes).ok_or(StageError::OutOfRange)?;
    while a < end {
        match hv.stage2_unmap(s2, mem, a) {
            Ok(_) => n += 1,
            Err(StageError::NotMapped) => {}
            Err(e) => return Err(e),
        }
        a += STAGE_PAGE;
    }
    Ok(n)
}
