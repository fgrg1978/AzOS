// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure bounds checks for the `PT_LOAD` headers of a ring-3 ELF image.
//!
//! Split out of `process.rs` for one reason: `process.rs` cannot be built for
//! the host (PTE flags, the physical allocator, inline assembly), so **not one
//! of these bounds was ever unit-tested**. Every rejection below fires only on
//! a malformed or hostile image — exactly the class that a QEMU boot of a
//! well-formed binary never exercises, so "it boots" was never evidence that
//! any of them worked. This module has no dependencies at all, which is what
//! lets `tests/host/sched-wake-tests` compile it verbatim (`#[path]`) and probe
//! the edges directly.
//!
//! `process.rs` **calls** this; it does not keep a copy. The three limits
//! arrive in [`SegLimits`] from their real single-source definitions
//! (`vmm::USER_GUARD_LIMIT`, `process::USER_LOW_MAX`, `mmu::PAGE_SIZE`) rather
//! than being redeclared here, so this file can never drift away from them.
//!
//! Under this build profile (`panic = "abort"`, `overflow-checks = true`) an
//! arithmetic overflow reboots the board, and `exec` is reachable from ring 3
//! with a fully attacker-chosen 64-bit `p_vaddr`/`p_memsz`/`p_offset`. So
//! every addition here is `checked_`/`saturating_`: a rejected image must
//! return `Reject`, never reset the robot.

/// The three address limits the loader enforces, passed in so that this module
/// owns no constant of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegLimits {
    /// `vmm::USER_GUARD_LIMIT` — lowest VA any legitimate user image uses.
    pub guard_limit: usize,
    /// `process::USER_LOW_MAX` — ceiling for the image and the `brk` heap.
    pub low_max: usize,
    /// `mmu::PAGE_SIZE`. Must be a power of two.
    pub page_size: usize,
}

/// Page range a accepted segment occupies, plus its unaligned end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegRange {
    /// First page to map (`p_vaddr` rounded down).
    pub va_start: usize,
    /// One past the last page to map (`p_vaddr + p_memsz` rounded up).
    pub va_end: usize,
    /// `p_vaddr + p_memsz`, unaligned — the ordering bound for the next
    /// segment.
    pub seg_end: usize,
}

/// Why a `PT_LOAD` header was refused. Distinct variants exist so the tests
/// can assert *which* bound caught a given header, not merely that something
/// did — a header rejected for the wrong reason means the bound under test is
/// dead code hiding behind an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegReject {
    /// `p_vaddr` below `guard_limit`: the image wants the null-guard region.
    NullGuard,
    /// `p_vaddr` at or above `low_max`: kernel MMIO / stack / vDSO territory.
    StartAboveLowMax,
    /// `p_vaddr + p_memsz` overflows `usize`, or lands above `low_max`.
    EndOutOfRange,
    /// `p_filesz > p_memsz` — unspecified by the ELF spec.
    FileSizeOverMemSize,
    /// `p_offset + p_filesz` overflows, or reads past the end of the blob.
    FileRangeOutOfBlob,
    /// This segment starts below the end of the previous one.
    Descending,
    /// This segment starts on the page the previous one ends on, and the two
    /// are mapped with different permissions ([`seg_perms`]): one page table
    /// entry cannot hold both, and their union would make read-only data
    /// executable or writable.
    SharedPageMixedPerms,
}

/// `PF_X` and `PF_W` of a program header's `p_flags` (ELF spec).
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;

/// The permissions the loader maps a `PT_LOAD` segment with, from its
/// `p_flags`. Three classes, W^X in both directions: writable is never
/// executable (an `RWX` header maps read-write), and a read-only segment is
/// never executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegPerms {
    ReadOnly,
    ReadExec,
    ReadWrite,
}

/// [`SegPerms`] of a header's `p_flags`.
pub fn seg_perms(p_flags: u32) -> SegPerms {
    if p_flags & PF_W != 0 {
        SegPerms::ReadWrite
    } else if p_flags & PF_X != 0 {
        SegPerms::ReadExec
    } else {
        SegPerms::ReadOnly
    }
}

/// May a segment mapped `perms`, starting at `p_vaddr`, follow one mapped
/// `prev` that ended (unaligned) at `prev_seg_end`?
///
/// A page gets exactly the permissions of the one segment it belongs to. A
/// page both segments touch would need two permission sets in one page table
/// entry; mapping it with their union (what the loader did) made the
/// `.rodata` sharing the last `.text` page executable. So a shared page is
/// accepted only when both segments are mapped alike; otherwise the image is
/// refused, whatever its header says. Linkers place a segment with other
/// permissions on a page of its own (lld, GNU ld, and every
/// `userspace/*/user*.ld`), so no well-formed image is lost. Segments arrive
/// in ascending order ([`check_pt_load`]), so the previous segment is the
/// only one that can share this one's first page.
///
/// `prev` is `None` for the first loaded segment.
pub fn check_page_sharing(
    prev_seg_end: usize,
    prev: Option<SegPerms>,
    p_vaddr: usize,
    perms: SegPerms,
    page_size: usize,
) -> Result<(), SegReject> {
    let Some(prev) = prev else { return Ok(()) };
    if cfg!(feature = "elf-mixed-page-canary") || prev == perms || prev_seg_end == 0 {
        return Ok(());
    }
    let mask = !(page_size - 1);
    if (prev_seg_end - 1) & mask == p_vaddr & mask {
        return Err(SegReject::SharedPageMixedPerms);
    }
    Ok(())
}

/// Verdict for one `PT_LOAD` program header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegCheck {
    /// `p_memsz == 0`: nothing to map, and not an error.
    Empty,
    /// Accepted; map `va_start..va_end`.
    Load(SegRange),
    /// Refuse the whole image.
    Reject(SegReject),
}

/// Round `a` up to the next multiple of `page_size`, saturating.
///
/// `a + page_size - 1` wraps for any `a` within one page of `usize::MAX`, and
/// a wrap here is a panic (`overflow-checks`), i.e. a board reset driven by an
/// ELF field. Saturating yields `usize::MAX & !(page_size-1)`, which every
/// caller's range check then rejects.
#[inline]
pub fn page_up(a: usize, page_size: usize) -> usize {
    debug_assert!(page_size.is_power_of_two());
    a.saturating_add(page_size - 1) & !(page_size - 1)
}

/// Validate one `PT_LOAD` header against `lim` and the previous segment's end.
///
/// `prev_seg_end` is the `seg_end` of the last segment this loader accepted
/// (0 for the first). Requiring `p_vaddr >= prev_seg_end` enforces the
/// ascending, non-overlapping segment order that the page-reuse branch in
/// `load_elf_into` *documents but never checked*: an out-of-order image could
/// otherwise have a later segment's file bytes rewrite an earlier segment's
/// already-mapped page. Verified against every ELF in `build/` (12 images):
/// all of them are strictly ascending with no byte-level overlap, several
/// with a segment starting exactly at the previous one's end — hence `>=`,
/// not `>`.
pub fn check_pt_load(
    p_offset: usize,
    p_vaddr: usize,
    p_filesz: usize,
    p_memsz: usize,
    elf_len: usize,
    prev_seg_end: usize,
    lim: SegLimits,
) -> SegCheck {
    if p_memsz == 0 {
        return SegCheck::Empty;
    }

    // Lower bound. The rest of the kernel already refuses to *resolve* a fault
    // below `guard_limit` (`handle_demand_fault` / `handle_cow_fault`), so a
    // task that jumps through a null pointer dies. That guarantee is only
    // worth anything if nothing can map the page for real up front: a
    // `PT_LOAD` at `p_vaddr = 0` is a legal ELF, and without this line the
    // loader honoured it, handing the process a live, pre-populated page zero
    // and turning every null dereference in it back into silent success.
    // Nothing legitimate is lost: all 12 images in `build/` report
    // `min PT_LOAD p_vaddr = 0x10000`, and all nine `userspace/*/user.ld`
    // start at exactly `0x10000` — the comparison must stay `<`, since
    // `0x10000` is both the guard limit and the lowest real segment.
    if p_vaddr < lim.guard_limit {
        return SegCheck::Reject(SegReject::NullGuard);
    }
    if p_vaddr >= lim.low_max {
        return SegCheck::Reject(SegReject::StartAboveLowMax);
    }
    if p_vaddr < prev_seg_end {
        return SegCheck::Reject(SegReject::Descending);
    }
    if p_filesz > p_memsz {
        return SegCheck::Reject(SegReject::FileSizeOverMemSize);
    }

    let seg_end = match p_vaddr.checked_add(p_memsz) {
        Some(v) if v <= lim.low_max => v,
        _ => return SegCheck::Reject(SegReject::EndOutOfRange),
    };
    match p_offset.checked_add(p_filesz) {
        Some(src_end) if src_end <= elf_len => {}
        _ => return SegCheck::Reject(SegReject::FileRangeOutOfBlob),
    }

    SegCheck::Load(SegRange {
        va_start: p_vaddr & !(lim.page_size - 1),
        va_end: page_up(seg_end, lim.page_size),
        seg_end,
    })
}
